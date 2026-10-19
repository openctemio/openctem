package postgres

// Remediation tasks created from a custom query
// (docs/rfcs/RFC-098-remediation-tasks.md, "Tasks from a query").

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/api/pkg/domain/remediation"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

var _ remediation.TaskQueryRepository = (*RemediationTaskRepository)(nil)

const taskQueryCols = `task_id, tenant_id, query_text, query_version, mode, auto_state, auto_reason, member_cap,
	owner_user_id, last_run_at, last_added_count, total_added, created_at, updated_at`

func insertTaskQueryInTx(ctx context.Context, tx *sql.Tx, t *remediation.Task, q *remediation.TaskQuery) error {
	var state, reason any
	if q.AutoState != nil {
		state = string(*q.AutoState)
	}
	if q.AutoReason != nil {
		reason = string(*q.AutoReason)
	}
	_, err := tx.ExecContext(ctx, `
		INSERT INTO remediation_task_queries (task_id, tenant_id, query_text, query_version, mode, auto_state,
			auto_reason, member_cap, owner_user_id, last_run_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, now())`,
		t.ID.String(), t.TenantID.String(), q.Text, q.Version, string(q.Mode), state, reason, q.Cap, idArg(q.OwnerUserID))
	if err != nil {
		return fmt.Errorf("store task query: %w", err)
	}
	return nil
}

func scanTaskQuery(scan func(dest ...any) error) (*remediation.TaskQuery, error) {
	var (
		q                    remediation.TaskQuery
		taskID, tenantID     string
		mode                 string
		state, reason, owner sql.NullString
		lastRun              sql.NullTime
	)
	if err := scan(&taskID, &tenantID, &q.Text, &q.Version, &mode, &state, &reason, &q.Cap,
		&owner, &lastRun, &q.LastAddedCount, &q.TotalAdded, &q.CreatedAt, &q.UpdatedAt); err != nil {
		return nil, err
	}
	var err error
	if q.TaskID, err = shared.IDFromString(taskID); err != nil {
		return nil, fmt.Errorf("scan task query: %w", err)
	}
	if q.TenantID, err = shared.IDFromString(tenantID); err != nil {
		return nil, fmt.Errorf("scan task query: %w", err)
	}
	q.Mode = remediation.QueryMode(mode)
	if state.Valid {
		st := remediation.AutoState(state.String)
		q.AutoState = &st
	}
	if reason.Valid {
		r := remediation.AutoReason(reason.String)
		q.AutoReason = &r
	}
	q.OwnerUserID = rtNullID(owner)
	q.LastRunAt = rtTimePtr(lastRun)
	return &q, nil
}

// GetTaskQuery returns the query a task of the tenant was created from.
func (r *RemediationTaskRepository) GetTaskQuery(ctx context.Context, tenantID, taskID shared.ID) (*remediation.TaskQuery, error) {
	q, err := scanTaskQuery(r.db.QueryRowContext(ctx, `SELECT `+taskQueryCols+`
		FROM remediation_task_queries WHERE tenant_id = $1 AND task_id = $2`, tenantID.String(), taskID.String()).Scan)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, remediation.ErrTaskNotFromQuery
	}
	if err != nil {
		return nil, fmt.Errorf("get task query: %w", err)
	}
	return q, nil
}

// SetAutoState changes the auto-mode state of a task's query (auto mode
// only; a reason is stored with suspended alone). A suspension applies only
// to an active query, so two concurrent passes (several API replicas)
// suspend it once: the second answers ErrNotAutoMode.
func (r *RemediationTaskRepository) SetAutoState(ctx context.Context, tenantID, taskID shared.ID, state remediation.AutoState, reason *remediation.AutoReason) error {
	var rs any
	if state == remediation.AutoStateSuspended {
		if reason == nil {
			return fmt.Errorf("%w: a suspension needs a reason", shared.ErrValidation)
		}
		rs = string(*reason)
	}
	res, err := r.db.ExecContext(ctx, `
		UPDATE remediation_task_queries SET auto_state = $3, auto_reason = $4, updated_at = now()
		WHERE tenant_id = $1 AND task_id = $2 AND mode = 'auto'
		  AND ($3 <> 'suspended' OR auto_state = 'active')`,
		tenantID.String(), taskID.String(), string(state), rs)
	if err != nil {
		return fmt.Errorf("set task query auto state: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return remediation.ErrNotAutoMode
	}
	return nil
}

// RecordQueryRun stores when a task's query last ran and what it added.
func (r *RemediationTaskRepository) RecordQueryRun(ctx context.Context, tenantID, taskID shared.ID, added int, at time.Time) error {
	_, err := r.db.ExecContext(ctx, `
		UPDATE remediation_task_queries
		SET last_run_at = $3, last_added_count = $4, total_added = total_added + $4, updated_at = now()
		WHERE tenant_id = $1 AND task_id = $2`, tenantID.String(), taskID.String(), at, added)
	if err != nil {
		return fmt.Errorf("record task query run: %w", err)
	}
	return nil
}

// ClaimQueryFindings adds findings a task's query found: open findings that
// no active task holds, up to the task's cap of active primary members. A
// finding another active task holds is skipped, never taken; the partial
// unique index ux_remediation_task_members_primary settles concurrent
// claims (the loser's row is not inserted and is reported skipped).
func (r *RemediationTaskRepository) ClaimQueryFindings(ctx context.Context, c remediation.QueryClaim) (*remediation.QueryClaimResult, error) {
	out := &remediation.QueryClaimResult{}
	if len(c.IDs) == 0 {
		return out, nil
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin query claim: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	t, err := lockTaskInTx(ctx, tx, c.TenantID, c.TaskID, 0)
	if err != nil {
		return nil, err
	}
	if t.State.IsTerminal() {
		return nil, remediation.ErrTaskTerminal
	}
	// The shared claim: locks the findings in id order, drops closed ones
	// and skips the ones another active task holds (never taken).
	claim, err := r.claimFindingsInTx(ctx, tx, claimInput{tenantID: c.TenantID, ids: c.IDs, except: &c.TaskID,
		res: remediation.ConflictResolution{Skip: true}, actor: c.ActorID,
		into: func(shared.ID) claimTarget { return claimTarget{id: t.ID, title: t.Title} }})
	if err != nil {
		return nil, err
	}
	free, err := r.notMembersInTx(ctx, tx, c.TenantID, c.TaskID, claim.keep(c.IDs))
	if err != nil {
		return nil, err
	}
	var current int
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM remediation_task_members
		WHERE tenant_id = $1 AND task_id = $2 AND left_at IS NULL AND role = 'primary'`,
		c.TenantID.String(), c.TaskID.String()).Scan(&current); err != nil {
		return nil, fmt.Errorf("count task members: %w", err)
	}
	room := c.Cap - current
	if room < 0 {
		room = 0
	}
	take := free
	if len(take) > room {
		out.Capped = append(out.Capped, take[room:]...)
		take = take[:room]
	}
	if len(take) > 0 {
		joined, err := queryIDsInTx(ctx, tx, `
			INSERT INTO remediation_task_members (tenant_id, task_id, finding_id, role, join_source, joined_by)
			SELECT $1, $2, f.id, 'primary', $4, $5 FROM findings f
			WHERE f.tenant_id = $1 AND f.id = ANY($3::uuid[])
			ON CONFLICT DO NOTHING
			RETURNING finding_id`,
			c.TenantID.String(), c.TaskID.String(), pq.Array(rtIDStrings(take)), string(remediation.JoinSourceQuery), idArg(c.ActorID))
		if err != nil {
			return nil, fmt.Errorf("add query members: %w", err)
		}
		out.Added = joined
		if err := insertFindingTaskActivityInTx(ctx, tx, t, joined, "joined", remediation.MemberRolePrimary, c.ActorID,
			map[string]any{"source": string(remediation.JoinSourceQuery)}); err != nil {
			return nil, err
		}
	}
	added := make(map[shared.ID]bool, len(out.Added))
	for _, id := range out.Added {
		added[id] = true
	}
	capped := make(map[shared.ID]bool, len(out.Capped))
	for _, id := range out.Capped {
		capped[id] = true
	}
	for _, id := range c.IDs {
		if !added[id] && !capped[id] {
			out.Skipped = append(out.Skipped, id)
		}
	}
	if len(out.Added) == 0 {
		// Nothing changed: no version bump, no timeline entry.
		if err := tx.Commit(); err != nil {
			return nil, fmt.Errorf("commit query claim: %w", err)
		}
		return out, nil
	}
	if _, err := tx.ExecContext(ctx, `UPDATE remediation_tasks SET version = version + 1, updated_at = now()
		WHERE tenant_id = $1 AND id = $2`, c.TenantID.String(), c.TaskID.String()); err != nil {
		return nil, fmt.Errorf("bump task version: %w", err)
	}
	data := map[string]any{"count": len(out.Added), "role": string(remediation.MemberRolePrimary),
		"source": string(remediation.JoinSourceQuery), "auto": c.Auto}
	if err := insertTaskEventInTx(ctx, tx, c.TenantID, c.TaskID, remediation.TaskEventMembersAdded, c.ActorID, data); err != nil {
		return nil, err
	}
	if err := r.recomputeInTx(ctx, tx, c.TenantID, []shared.ID{c.TaskID}, c.ActorID); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit query claim: %w", err)
	}
	return out, nil
}

// notMembersInTx keeps the findings that are not already active members of
// the task, oldest first.
func (r *RemediationTaskRepository) notMembersInTx(ctx context.Context, tx *sql.Tx, tenantID, taskID shared.ID, ids []shared.ID) ([]shared.ID, error) {
	if len(ids) == 0 {
		return nil, nil
	}
	free, err := queryIDsInTx(ctx, tx, `
		SELECT f.id FROM findings f
		WHERE f.tenant_id = $1 AND f.id = ANY($2::uuid[])
		  AND NOT EXISTS (SELECT 1 FROM remediation_task_members m
		                  WHERE m.tenant_id = f.tenant_id AND m.task_id = $3 AND m.finding_id = f.id AND m.left_at IS NULL)
		ORDER BY f.created_at, f.id`,
		tenantID.String(), pq.Array(rtIDStrings(ids)), taskID.String())
	if err != nil {
		return nil, fmt.Errorf("read free findings: %w", err)
	}
	return free, nil
}

// PrimaryHolders returns, for each finding that is the primary member of an
// active task, that task (title and owner; the caller decides what of it
// to show).
func (r *RemediationTaskRepository) PrimaryHolders(ctx context.Context, tenantID shared.ID, ids []shared.ID) ([]remediation.PrimaryHolder, error) {
	if len(ids) == 0 {
		return nil, nil
	}
	rows, err := r.db.QueryContext(ctx, `
		SELECT m.finding_id, COALESCE(f.title, ''), t.id, t.title, t.assignee_user_id, t.assignee_group_id
		FROM remediation_task_members m
		JOIN remediation_tasks t ON t.tenant_id = m.tenant_id AND t.id = m.task_id
		JOIN findings f ON f.tenant_id = m.tenant_id AND f.id = m.finding_id
		WHERE m.tenant_id = $1 AND m.finding_id = ANY($2::uuid[]) AND m.left_at IS NULL AND m.role = 'primary'
		ORDER BY t.id, m.finding_id`,
		tenantID.String(), pq.Array(rtIDStrings(ids)))
	if err != nil {
		return nil, fmt.Errorf("read primary holders: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []remediation.PrimaryHolder
	for rows.Next() {
		var (
			h           remediation.PrimaryHolder
			user, group sql.NullString
		)
		if err := rows.Scan(&h.FindingID, &h.FindingTitle, &h.TaskID, &h.TaskTitle, &user, &group); err != nil {
			return nil, fmt.Errorf("scan primary holder: %w", err)
		}
		h.AssigneeUserID, h.AssigneeGroupID = rtNullID(user), rtNullID(group)
		out = append(out, h)
	}
	return out, rows.Err()
}

// DueAutoQueryTasksForPlatform lists auto-mode tasks (every tenant) whose
// query last ran before olderThan, least recently run first.
func (r *RemediationTaskRepository) DueAutoQueryTasksForPlatform(ctx context.Context, olderThan time.Time, limit int) ([]remediation.DueQueryTask, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT tenant_id, task_id FROM remediation_task_queries
		WHERE mode = 'auto' AND auto_state = 'active' AND (last_run_at IS NULL OR last_run_at < $1)
		ORDER BY last_run_at NULLS FIRST
		LIMIT $2`, olderThan, limit)
	if err != nil {
		return nil, fmt.Errorf("list due query tasks: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []remediation.DueQueryTask
	for rows.Next() {
		var d remediation.DueQueryTask
		if err := rows.Scan(&d.TenantID, &d.TaskID); err != nil {
			return nil, fmt.Errorf("scan due query task: %w", err)
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// previewTop bounds the asset and owner breakdowns of a preview.
const previewTop = 10

// QueryPreviewStats returns the breakdowns of findings a query matched:
// counts by severity, the top assets and the top primary owners of those
// assets, a sample and the earliest SLA deadline among them. Every read is
// scoped to the tenant and to the given ids.
func (r *RemediationTaskRepository) QueryPreviewStats(ctx context.Context, tenantID shared.ID, ids []shared.ID, sample int) (*remediation.QueryPreviewStats, error) {
	out := &remediation.QueryPreviewStats{}
	if len(ids) == 0 {
		return out, nil
	}
	tenant, arr := tenantID.String(), pq.Array(rtIDStrings(ids))
	collect := func(q string, args []any, scan func(rows *sql.Rows) error) error {
		rows, err := r.db.QueryContext(ctx, q, args...)
		if err != nil {
			return err
		}
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			if err := scan(rows); err != nil {
				return err
			}
		}
		return rows.Err()
	}
	if err := collect(`SELECT f.severity, count(*) FROM findings f
		WHERE f.tenant_id = $1 AND f.id = ANY($2::uuid[]) GROUP BY f.severity ORDER BY count(*) DESC, f.severity`,
		[]any{tenant, arr}, func(rows *sql.Rows) error {
			var b remediation.QueryBreakdown
			if err := rows.Scan(&b.Key, &b.Count); err != nil {
				return err
			}
			b.Name = b.Key
			out.Severity = append(out.Severity, b)
			return nil
		}); err != nil {
		return nil, fmt.Errorf("preview severity breakdown: %w", err)
	}
	if err := collect(`SELECT f.asset_id, COALESCE(a.name, ''), count(*) FROM findings f
		LEFT JOIN assets a ON a.tenant_id = f.tenant_id AND a.id = f.asset_id
		WHERE f.tenant_id = $1 AND f.id = ANY($2::uuid[]) AND f.asset_id IS NOT NULL
		GROUP BY f.asset_id, a.name ORDER BY count(*) DESC, a.name LIMIT $3`,
		[]any{tenant, arr, previewTop}, func(rows *sql.Rows) error {
			var b remediation.QueryBreakdown
			if err := rows.Scan(&b.Key, &b.Name, &b.Count); err != nil {
				return err
			}
			out.Assets = append(out.Assets, b)
			return nil
		}); err != nil {
		return nil, fmt.Errorf("preview asset breakdown: %w", err)
	}
	// The primary owner of each finding's asset: the first primary user who
	// is a member, else the first primary group of the tenant.
	if err := collect(`
		WITH o AS (
			SELECT f.id,
			       (SELECT ao.user_id FROM asset_owners ao
			         JOIN tenant_members tm ON tm.user_id = ao.user_id AND tm.tenant_id = f.tenant_id
			        WHERE ao.asset_id = f.asset_id AND ao.ownership_type = 'primary' AND ao.user_id IS NOT NULL
			        ORDER BY ao.assigned_at, ao.id LIMIT 1) AS user_id,
			       (SELECT ao.group_id FROM asset_owners ao
			         JOIN groups g ON g.id = ao.group_id AND g.tenant_id = f.tenant_id
			        WHERE ao.asset_id = f.asset_id AND ao.ownership_type = 'primary' AND ao.group_id IS NOT NULL
			        ORDER BY ao.assigned_at, ao.id LIMIT 1) AS group_id
			FROM findings f
			WHERE f.tenant_id = $1 AND f.id = ANY($2::uuid[]) AND f.asset_id IS NOT NULL)
		SELECT o.user_id, CASE WHEN o.user_id IS NULL THEN o.group_id END AS group_id,
		       COALESCE(u.name, u.email, g.name, ''), count(*)
		FROM o
		LEFT JOIN users u ON u.id = o.user_id
		LEFT JOIN groups g ON o.user_id IS NULL AND g.tenant_id = $1 AND g.id = o.group_id
		WHERE o.user_id IS NOT NULL OR o.group_id IS NOT NULL
		GROUP BY 1, 2, 3 ORDER BY count(*) DESC, 3 LIMIT $3`,
		[]any{tenant, arr, previewTop}, func(rows *sql.Rows) error {
			var (
				b           remediation.QueryBreakdown
				user, group sql.NullString
			)
			if err := rows.Scan(&user, &group, &b.Name, &b.Count); err != nil {
				return err
			}
			b.UserID, b.GroupID = rtNullID(user), rtNullID(group)
			b.Key = remediation.Owner{UserID: b.UserID, GroupID: b.GroupID}.Key()
			out.Owners = append(out.Owners, b)
			return nil
		}); err != nil {
		return nil, fmt.Errorf("preview owner breakdown: %w", err)
	}
	if err := collect(`SELECT f.id, f.title, f.severity, f.status, f.asset_id, COALESCE(a.name, ''), f.sla_deadline
		FROM findings f
		LEFT JOIN assets a ON a.tenant_id = f.tenant_id AND a.id = f.asset_id
		WHERE f.tenant_id = $1 AND f.id = ANY($2::uuid[])
		ORDER BY `+FindingRiskPointsSQL+` DESC, f.sla_deadline NULLS LAST, f.id LIMIT $3`,
		[]any{tenant, arr, sample}, func(rows *sql.Rows) error {
			var (
				s     remediation.QuerySampleRow
				asset sql.NullString
				sla   sql.NullTime
			)
			if err := rows.Scan(&s.FindingID, &s.Title, &s.Severity, &s.Status, &asset, &s.AssetName, &sla); err != nil {
				return err
			}
			s.AssetID, s.SLADeadline = rtNullID(asset), rtTimePtr(sla)
			out.Sample = append(out.Sample, s)
			return nil
		}); err != nil {
		return nil, fmt.Errorf("preview sample: %w", err)
	}
	var earliest sql.NullTime
	if err := r.db.QueryRowContext(ctx, `SELECT min(f.sla_deadline) FROM findings f
		WHERE f.tenant_id = $1 AND f.id = ANY($2::uuid[]) AND f.status <> ALL($3::text[])`,
		tenant, arr, closedStatusArray()).Scan(&earliest); err != nil {
		return nil, fmt.Errorf("preview earliest deadline: %w", err)
	}
	out.EarliestDeadline = rtTimePtr(earliest)
	return out, nil
}

package postgres

// Remediation actions, tasks, members and the task timeline
// (docs/rfcs/RFC-098-remediation-tasks.md). Every statement carries the
// tenant; member reads join findings on the same tenant.

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/api/pkg/domain/remediation"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
	"github.com/openctemio/openctem/api/pkg/pagination"
)

// RemediationTaskRepository stores remediation actions and tasks.
type RemediationTaskRepository struct {
	db *DB
}

// NewRemediationTaskRepository creates the repository.
func NewRemediationTaskRepository(db *DB) *RemediationTaskRepository {
	return &RemediationTaskRepository{db: db}
}

// FindingRiskPointsSQL is the risk weight of one finding "f": its priority
// class (P0 8, P1 4, P2 2, P3 1), or its severity when it has no class
// (critical 4, high 2, medium and low 1). A task's or a suggestion's risk
// reduced is the sum over its open members.
const FindingRiskPointsSQL = `(CASE f.priority_class
	WHEN 'P0' THEN 8 WHEN 'P1' THEN 4 WHEN 'P2' THEN 2 WHEN 'P3' THEN 1
	ELSE CASE f.severity WHEN 'critical' THEN 4 WHEN 'high' THEN 2 WHEN 'medium' THEN 1 WHEN 'low' THEN 1 ELSE 0 END
	END)`

// verifiedFixedSQL: a finding resolved as fixed with proof of the fix (a
// covered scan, a retest, or a reviewer holding findings:verify). Gone
// without a fix (obsolete), mitigated, or closed on a claim alone is not
// verified fixed.
const verifiedFixedSQL = `(f.status = 'resolved' AND f.closure_reason = 'fixed' AND f.verification IN ('covered_scan', 'retest', 'security_review'))`

func closedStatusArray() pq.StringArray {
	return pq.StringArray(statusStrings(vulnerability.ClosedFindingStatuses()))
}

// fixAppliedStatuses are claimed fixed and await verification.
var fixAppliedStatuses = pq.StringArray{string(vulnerability.FindingStatusFixApplied)}

const taskSelectCols = `t.id, t.tenant_id, t.action_id, a.action_key, a.kind, a.title, t.campaign_id,
	t.title, t.description, t.assignee_user_id, t.assignee_group_id,
	t.manual_state, t.manual_state_note, t.state, t.deadline, t.deadline_source, t.manual_deadline,
	t.member_count, t.open_count, t.in_progress_count, t.fix_applied_count, t.closed_count,
	t.verified_count, t.related_count, t.risk_points, t.regression_of, t.archived_at, t.archived_note,
	t.closed_at, t.version, t.created_by, t.created_at, t.updated_at`

const taskFrom = ` FROM remediation_tasks t
	JOIN remediation_actions a ON a.id = t.action_id AND a.tenant_id = t.tenant_id`

func rtNullID(s sql.NullString) *shared.ID {
	if !s.Valid {
		return nil
	}
	id, err := shared.IDFromString(s.String)
	if err != nil {
		return nil
	}
	return &id
}

func rtTimePtr(t sql.NullTime) *time.Time {
	if !t.Valid {
		return nil
	}
	v := t.Time
	return &v
}

func idArg(id *shared.ID) any {
	if id == nil {
		return nil
	}
	return id.String()
}

func timeArg(t *time.Time) any {
	if t == nil {
		return nil
	}
	return *t
}

func scanTask(scan func(dest ...any) error) (*remediation.Task, error) {
	var (
		t                                         remediation.Task
		id, tenantID, actionID                    string
		campaignID, assigneeUser, assigneeGroup   sql.NullString
		manualState, deadlineSource               sql.NullString
		state                                     string
		deadline, manualDeadline, archivedAt      sql.NullTime
		closedAt                                  sql.NullTime
		regressionOf, createdBy                   sql.NullString
		member, open, inProg, fixApp, closed, ver int
		related, risk                             int
	)
	if err := scan(&id, &tenantID, &actionID, &t.ActionKey, &t.ActionKind, &t.ActionTitle, &campaignID,
		&t.Title, &t.Description, &assigneeUser, &assigneeGroup,
		&manualState, &t.ManualStateNote, &state, &deadline, &deadlineSource, &manualDeadline,
		&member, &open, &inProg, &fixApp, &closed, &ver, &related, &risk, &regressionOf, &archivedAt, &t.ArchivedNote,
		&closedAt, &t.Version, &createdBy, &t.CreatedAt, &t.UpdatedAt); err != nil {
		return nil, err
	}
	var err error
	if t.ID, err = shared.IDFromString(id); err != nil {
		return nil, fmt.Errorf("scan task id: %w", err)
	}
	if t.TenantID, err = shared.IDFromString(tenantID); err != nil {
		return nil, fmt.Errorf("scan task tenant: %w", err)
	}
	if t.ActionID, err = shared.IDFromString(actionID); err != nil {
		return nil, fmt.Errorf("scan task action: %w", err)
	}
	t.CampaignID = rtNullID(campaignID)
	t.AssigneeUserID = rtNullID(assigneeUser)
	t.AssigneeGroupID = rtNullID(assigneeGroup)
	if manualState.Valid {
		ms := remediation.ManualState(manualState.String)
		t.ManualState = &ms
	}
	t.State = remediation.TaskState(state)
	t.Deadline = rtTimePtr(deadline)
	if deadlineSource.Valid {
		ds := remediation.DeadlineSource(deadlineSource.String)
		t.DeadlineSource = &ds
	}
	t.ManualDeadline = rtTimePtr(manualDeadline)
	t.Counts = remediation.TaskCounts{Total: member, Open: open, InProgress: inProg, FixApplied: fixApp,
		Closed: closed, Verified: ver, Related: related, RiskPoints: risk}
	t.RegressionOf = rtNullID(regressionOf)
	t.ArchivedAt = rtTimePtr(archivedAt)
	t.ClosedAt = rtTimePtr(closedAt)
	t.CreatedBy = rtNullID(createdBy)
	return &t, nil
}

// GetTask returns a task of the tenant.
func (r *RemediationTaskRepository) GetTask(ctx context.Context, tenantID, taskID shared.ID) (*remediation.Task, error) {
	q := `SELECT ` + taskSelectCols + taskFrom + ` WHERE t.tenant_id = $1 AND t.id = $2`
	t, err := scanTask(r.db.QueryRowContext(ctx, q, tenantID.String(), taskID.String()).Scan)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, remediation.ErrTaskNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get remediation task: %w", err)
	}
	return t, nil
}

// GetAction returns an action of the tenant.
func (r *RemediationTaskRepository) GetAction(ctx context.Context, tenantID, actionID shared.ID) (*remediation.Action, error) {
	const q = `SELECT id, tenant_id, action_key, kind, title, fix_spec, origin, auto_join, created_by, created_at, updated_at
		FROM remediation_actions WHERE tenant_id = $1 AND id = $2`
	var (
		a               remediation.Action
		id, tid, origin string
		spec            []byte
		createdBy       sql.NullString
	)
	err := r.db.QueryRowContext(ctx, q, tenantID.String(), actionID.String()).Scan(
		&id, &tid, &a.Key, &a.Kind, &a.Title, &spec, &origin, &a.AutoJoin, &createdBy, &a.CreatedAt, &a.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("%w: remediation action not found", shared.ErrNotFound)
	}
	if err != nil {
		return nil, fmt.Errorf("get remediation action: %w", err)
	}
	a.ID, _ = shared.IDFromString(id)
	a.TenantID, _ = shared.IDFromString(tid)
	a.Origin = remediation.ActionOrigin(origin)
	a.CreatedBy = rtNullID(createdBy)
	_ = json.Unmarshal(spec, &a.FixSpec)
	return &a, nil
}

// taskListWhere builds the WHERE clause of a task list.
func taskListWhere(tenantID shared.ID, f remediation.TaskFilter) (string, []any) {
	args := []any{tenantID.String()}
	conds := []string{"t.tenant_id = $1"}
	next := func(v any) string {
		args = append(args, v)
		return fmt.Sprintf("$%d", len(args))
	}
	if len(f.States) > 0 {
		ss := make([]string, len(f.States))
		for i, s := range f.States {
			ss[i] = string(s)
		}
		conds = append(conds, "t.state = ANY("+next(pq.StringArray(ss))+"::text[])")
	}
	if f.AssigneeID != nil {
		p := next(f.AssigneeID.String())
		if f.Mine {
			conds = append(conds, "(t.assignee_user_id = "+p+" OR t.assignee_group_id IN (SELECT gm.group_id FROM group_members gm JOIN groups g ON g.id = gm.group_id AND g.tenant_id = t.tenant_id WHERE gm.user_id = "+p+"))")
		} else {
			conds = append(conds, "t.assignee_user_id = "+p)
		}
	}
	if f.GroupID != nil {
		conds = append(conds, "t.assignee_group_id = "+next(f.GroupID.String()))
	}
	if f.ActionID != nil {
		conds = append(conds, "t.action_id = "+next(f.ActionID.String()))
	}
	if f.ActionKind != "" {
		conds = append(conds, "a.kind = "+next(f.ActionKind))
	}
	if f.CampaignID != nil {
		conds = append(conds, "t.campaign_id = "+next(f.CampaignID.String()))
	}
	if f.FindingID != nil {
		conds = append(conds, "EXISTS (SELECT 1 FROM remediation_task_members fm WHERE fm.tenant_id = t.tenant_id AND fm.task_id = t.id AND fm.left_at IS NULL AND fm.finding_id = "+next(f.FindingID.String())+")")
	}
	if s := strings.TrimSpace(f.Search); s != "" {
		p := next("%" + escapeLikePattern(s) + "%")
		conds = append(conds, "(t.title ILIKE "+p+" OR a.title ILIKE "+p+")")
	}
	if f.Scope != nil {
		cond, scopeArgs := dataScopeCondAt("sf.asset_id", f.Scope, len(args)+1)
		args = append(args, scopeArgs...)
		conds = append(conds, `EXISTS (SELECT 1 FROM remediation_task_members sm
			JOIN findings sf ON sf.id = sm.finding_id AND sf.tenant_id = sm.tenant_id
			WHERE sm.tenant_id = t.tenant_id AND sm.task_id = t.id AND sm.left_at IS NULL AND `+cond+`)`)
	}
	return strings.Join(conds, " AND "), args
}

func taskOrderBy(s remediation.TaskSort) string {
	switch s {
	case remediation.TaskSortRisk:
		return "t.risk_points DESC, t.deadline ASC NULLS LAST, t.id"
	case remediation.TaskSortUpdated:
		return "t.updated_at DESC, t.id"
	case remediation.TaskSortCreated:
		return "t.created_at DESC, t.id"
	default:
		return "t.deadline ASC NULLS LAST, t.risk_points DESC, t.id"
	}
}

// ListTasks lists the tenant's tasks.
func (r *RemediationTaskRepository) ListTasks(ctx context.Context, tenantID shared.ID, f remediation.TaskFilter, page pagination.Pagination) (pagination.Result[*remediation.Task], error) {
	where, args := taskListWhere(tenantID, f)
	var total int64
	if err := r.db.QueryRowContext(ctx, `SELECT COUNT(*)`+taskFrom+` WHERE `+where, args...).Scan(&total); err != nil {
		return pagination.Result[*remediation.Task]{}, fmt.Errorf("count remediation tasks: %w", err)
	}
	q := `SELECT ` + taskSelectCols + taskFrom + ` WHERE ` + where + ` ORDER BY ` + taskOrderBy(f.Sort) +
		fmt.Sprintf(` LIMIT %d OFFSET %d`, page.Limit(), page.Offset())
	rows, err := r.db.QueryContext(ctx, q, args...)
	if err != nil {
		return pagination.Result[*remediation.Task]{}, fmt.Errorf("list remediation tasks: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := make([]*remediation.Task, 0)
	for rows.Next() {
		t, err := scanTask(rows.Scan)
		if err != nil {
			return pagination.Result[*remediation.Task]{}, fmt.Errorf("scan remediation task: %w", err)
		}
		out = append(out, t)
	}
	if err := rows.Err(); err != nil {
		return pagination.Result[*remediation.Task]{}, fmt.Errorf("list remediation tasks: %w", err)
	}
	return pagination.NewResult(out, total, page), nil
}

// FindingStatuses returns the status of each of the tenant's findings among
// ids; an id of another tenant or of no finding is absent.
func (r *RemediationTaskRepository) FindingStatuses(ctx context.Context, tenantID shared.ID, ids []shared.ID) (map[shared.ID]string, error) {
	out := make(map[shared.ID]string, len(ids))
	if len(ids) == 0 {
		return out, nil
	}
	rows, err := r.db.QueryContext(ctx, `SELECT id, status FROM findings WHERE tenant_id = $1 AND id = ANY($2::uuid[])`,
		tenantID.String(), pq.Array(rtIDStrings(ids)))
	if err != nil {
		return nil, fmt.Errorf("read finding statuses: %w", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var id shared.ID
		var st string
		if err := rows.Scan(&id, &st); err != nil {
			return nil, fmt.Errorf("read finding statuses: %w", err)
		}
		out[id] = st
	}
	return out, rows.Err()
}

func rtIDStrings(ids []shared.ID) []string {
	out := make([]string, len(ids))
	for i, id := range ids {
		out[i] = id.String()
	}
	return out
}

// CreateTask stores a task with its members in one transaction: the action
// (created or reused by key), the task, the members, the "created" timeline
// entry and a timeline entry on every member finding. A finding that is
// already the primary member of another active task refuses the whole
// create with a FindingsInOtherTaskError.
func (r *RemediationTaskRepository) CreateTask(ctx context.Context, rec *remediation.NewTaskRecord) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin create task: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	tenant := rec.Task.TenantID.String()
	if rec.Action.ID.IsZero() {
		spec, merr := json.Marshal(rec.Action.FixSpec)
		if merr != nil || rec.Action.FixSpec == nil {
			spec = []byte("{}")
		}
		var id string
		err = tx.QueryRowContext(ctx, `
			INSERT INTO remediation_actions (tenant_id, action_key, kind, title, fix_spec, origin, created_by)
			VALUES ($1, $2, $3, $4, $5, $6, $7)
			ON CONFLICT (tenant_id, action_key) DO UPDATE SET updated_at = remediation_actions.updated_at
			RETURNING id`,
			tenant, rec.Action.Key, rec.Action.Kind, rec.Action.Title, spec, string(rec.Action.Origin), idArg(rec.Action.CreatedBy)).Scan(&id)
		if err != nil {
			return fmt.Errorf("create remediation action: %w", err)
		}
		if rec.Action.ID, err = shared.IDFromString(id); err != nil {
			return fmt.Errorf("create remediation action: %w", err)
		}
	}
	rec.Task.ActionID = rec.Action.ID

	if err := lockFindingsInTx(ctx, tx, rec.Task.TenantID, append(append([]shared.ID{}, rec.Members...), rec.Related...)); err != nil {
		return err
	}
	if err := refuseOtherPrimaryInTx(ctx, tx, rec.Task.TenantID, rec.Task.ID, rec.Members); err != nil {
		return err
	}

	t := &rec.Task
	_, err = tx.ExecContext(ctx, `
		INSERT INTO remediation_tasks (id, tenant_id, action_id, campaign_id, title, description,
			assignee_user_id, assignee_group_id, manual_deadline, regression_of, created_by)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`,
		t.ID.String(), tenant, t.ActionID.String(), idArg(t.CampaignID), t.Title, t.Description,
		idArg(t.AssigneeUserID), idArg(t.AssigneeGroupID), timeArg(t.ManualDeadline), idArg(t.RegressionOf), idArg(t.CreatedBy))
	if err != nil {
		return fmt.Errorf("create remediation task: %w", err)
	}
	if err := insertMembersInTx(ctx, tx, t, rec.Members, remediation.MemberRolePrimary, rec.Source, rec.ActorID); err != nil {
		return err
	}
	if err := insertMembersInTx(ctx, tx, t, rec.Related, remediation.MemberRoleRelated, rec.Source, rec.ActorID); err != nil {
		return err
	}
	data := rec.EventData
	if data == nil {
		data = map[string]any{}
	}
	data["members"] = len(rec.Members)
	data["related"] = len(rec.Related)
	if err := insertTaskEventInTx(ctx, tx, t.TenantID, t.ID, remediation.TaskEventCreated, rec.ActorID, data); err != nil {
		return err
	}
	if err := r.recomputeInTx(ctx, tx, t.TenantID, []shared.ID{t.ID}, rec.ActorID); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit create task: %w", err)
	}
	return nil
}

// ActiveTaskByActionKey returns the newest task of the action with this key
// that still takes members (open or in progress), or nil when there is none.
func (r *RemediationTaskRepository) ActiveTaskByActionKey(ctx context.Context, tenantID shared.ID, actionKey string) (*remediation.Task, error) {
	q := `SELECT ` + taskSelectCols + taskFrom + `
		WHERE t.tenant_id = $1 AND a.action_key = $2 AND t.state IN ('open', 'in_progress')
		ORDER BY t.created_at DESC LIMIT 1`
	t, err := scanTask(r.db.QueryRowContext(ctx, q, tenantID.String(), actionKey).Scan)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("find active task by action key: %w", err)
	}
	return t, nil
}

// lockFindingsInTx locks the findings' rows in id order, so two operations on
// overlapping findings serialize instead of deadlocking.
func lockFindingsInTx(ctx context.Context, tx *sql.Tx, tenantID shared.ID, ids []shared.ID) error {
	if len(ids) == 0 {
		return nil
	}
	_, err := tx.ExecContext(ctx, `SELECT 1 FROM findings WHERE tenant_id = $1 AND id = ANY($2::uuid[]) ORDER BY id FOR UPDATE`,
		tenantID.String(), pq.Array(rtIDStrings(ids)))
	if err != nil {
		return fmt.Errorf("lock findings: %w", err)
	}
	return nil
}

// queryIDsInTx runs a statement that returns one id column and collects the
// ids (the rows are fully read and closed before the next statement).
func queryIDsInTx(ctx context.Context, tx *sql.Tx, q string, args ...any) ([]shared.ID, error) {
	rows, err := tx.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []shared.ID
	for rows.Next() {
		var id shared.ID
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// refuseOtherPrimaryInTx refuses findings that are already the primary
// member of an active task other than taskID.
func refuseOtherPrimaryInTx(ctx context.Context, tx *sql.Tx, tenantID, taskID shared.ID, ids []shared.ID) error {
	if len(ids) == 0 {
		return nil
	}
	rows, err := tx.QueryContext(ctx, `
		SELECT finding_id FROM remediation_task_members
		WHERE tenant_id = $1 AND finding_id = ANY($2::uuid[]) AND left_at IS NULL AND role = 'primary' AND task_id <> $3
		ORDER BY finding_id`,
		tenantID.String(), pq.Array(rtIDStrings(ids)), taskID.String())
	if err != nil {
		return fmt.Errorf("check primary tasks: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var taken []shared.ID
	for rows.Next() {
		var id shared.ID
		if err := rows.Scan(&id); err != nil {
			return fmt.Errorf("check primary tasks: %w", err)
		}
		taken = append(taken, id)
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("check primary tasks: %w", err)
	}
	if len(taken) > 0 {
		return &remediation.FindingsInOtherTaskError{FindingIDs: taken}
	}
	return nil
}

// insertMembersInTx adds members (skipping a finding already active in the
// task) and writes a timeline entry on each finding that joined.
func insertMembersInTx(ctx context.Context, tx *sql.Tx, t *remediation.Task, ids []shared.ID, role remediation.MemberRole, src remediation.JoinSource, actor *shared.ID) error {
	if len(ids) == 0 {
		return nil
	}
	joined, err := queryIDsInTx(ctx, tx, `
		INSERT INTO remediation_task_members (tenant_id, task_id, finding_id, role, join_source, joined_by)
		SELECT $1, $2, f.id, $4, $5, $6 FROM findings f
		WHERE f.tenant_id = $1 AND f.id = ANY($3::uuid[])
		ON CONFLICT DO NOTHING
		RETURNING finding_id`,
		t.TenantID.String(), t.ID.String(), pq.Array(rtIDStrings(ids)), string(role), string(src), idArg(actor))
	if err != nil {
		if isUniqueViolation(err) {
			return &remediation.FindingsInOtherTaskError{}
		}
		return fmt.Errorf("add task members: %w", err)
	}
	return insertFindingTaskActivityInTx(ctx, tx, t, joined, "joined", role, actor, nil)
}

// insertFindingTaskActivityInTx writes a remediation_task_changed entry on
// each finding's timeline.
func insertFindingTaskActivityInTx(ctx context.Context, tx *sql.Tx, t *remediation.Task, ids []shared.ID, op string, role remediation.MemberRole, actor *shared.ID, extra map[string]any) error {
	if len(ids) == 0 {
		return nil
	}
	changes := map[string]any{"task_id": t.ID.String(), "task_title": t.Title, "operation": op, "role": string(role)}
	for k, v := range extra {
		changes[k] = v
	}
	cj, err := json.Marshal(changes)
	if err != nil {
		return fmt.Errorf("encode task activity: %w", err)
	}
	actorType := "user"
	if actor == nil {
		actorType = "system"
	}
	msg := fmt.Sprintf("%s remediation task %q", strings.ToUpper(op[:1])+op[1:], t.Title)
	_, err = tx.ExecContext(ctx, `
		INSERT INTO finding_activities (tenant_id, finding_id, activity_type, actor_type, actor_id, changes, source, message)
		SELECT $1, f.id, 'remediation_task_changed', $3, $4, $5, 'remediation', $6
		FROM findings f WHERE f.tenant_id = $1 AND f.id = ANY($2::uuid[])`,
		t.TenantID.String(), pq.Array(rtIDStrings(ids)), actorType, idArg(actor), cj, msg)
	if err != nil {
		return fmt.Errorf("write finding task activity: %w", err)
	}
	return nil
}

func insertTaskEventInTx(ctx context.Context, tx *sql.Tx, tenantID, taskID shared.ID, kind string, actor *shared.ID, data map[string]any) error {
	if data == nil {
		data = map[string]any{}
	}
	dj, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("encode task event: %w", err)
	}
	actorType := "user"
	if actor == nil {
		actorType = "system"
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO remediation_task_events (tenant_id, task_id, kind, actor_id, actor_type, data)
		VALUES ($1, $2, $3, $4, $5, $6)`, tenantID.String(), taskID.String(), kind, idArg(actor), actorType, dj)
	if err != nil {
		return fmt.Errorf("write task event: %w", err)
	}
	return nil
}

// releaseMembersInTx ends every active membership of a task and writes a
// timeline entry on each finding; it returns how many findings left.
func releaseMembersInTx(ctx context.Context, tx *sql.Tx, t *remediation.Task, reason remediation.LeftReason, actor *shared.ID) (int, error) {
	n := 0
	for _, role := range []remediation.MemberRole{remediation.MemberRolePrimary, remediation.MemberRoleRelated} {
		ids, err := queryIDsInTx(ctx, tx, `
			UPDATE remediation_task_members SET left_at = now(), left_reason = $3, left_by = $4
			WHERE tenant_id = $1 AND task_id = $2 AND left_at IS NULL AND role = $5
			RETURNING finding_id`,
			t.TenantID.String(), t.ID.String(), string(reason), idArg(actor), string(role))
		if err != nil {
			return 0, fmt.Errorf("release task members: %w", err)
		}
		if err := insertFindingTaskActivityInTx(ctx, tx, t, ids, "left", role, actor, map[string]any{"reason": string(reason)}); err != nil {
			return 0, err
		}
		n += len(ids)
	}
	return n, nil
}

// lockTaskInTx locks a task row and checks the caller's version.
func lockTaskInTx(ctx context.Context, tx *sql.Tx, tenantID, taskID shared.ID, expectedVersion int) (*remediation.Task, error) {
	q := `SELECT ` + taskSelectCols + taskFrom + ` WHERE t.tenant_id = $1 AND t.id = $2 FOR UPDATE OF t`
	t, err := scanTask(tx.QueryRowContext(ctx, q, tenantID.String(), taskID.String()).Scan)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, remediation.ErrTaskNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("lock remediation task: %w", err)
	}
	if expectedVersion > 0 && t.Version != expectedVersion {
		return nil, remediation.ErrTaskVersionConflict
	}
	return t, nil
}

// AddMembers adds findings to a task (primary or related), checked against
// the caller's version of the task. Returns the findings that joined.
func (r *RemediationTaskRepository) AddMembers(ctx context.Context, tenantID, taskID shared.ID, expectedVersion int, ids []shared.ID, role remediation.MemberRole, src remediation.JoinSource, actor *shared.ID) (*remediation.Task, error) {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin add members: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	t, err := lockTaskInTx(ctx, tx, tenantID, taskID, expectedVersion)
	if err != nil {
		return nil, err
	}
	if t.State.IsTerminal() {
		return nil, remediation.ErrTaskTerminal
	}
	if err := lockFindingsInTx(ctx, tx, tenantID, ids); err != nil {
		return nil, err
	}
	if role == remediation.MemberRolePrimary {
		if err := refuseOtherPrimaryInTx(ctx, tx, tenantID, taskID, ids); err != nil {
			return nil, err
		}
	}
	if err := insertMembersInTx(ctx, tx, t, ids, role, src, actor); err != nil {
		return nil, err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE remediation_tasks SET version = version + 1, updated_at = now()
		WHERE tenant_id = $1 AND id = $2`, tenantID.String(), taskID.String()); err != nil {
		return nil, fmt.Errorf("bump task version: %w", err)
	}
	if err := insertTaskEventInTx(ctx, tx, tenantID, taskID, remediation.TaskEventMembersAdded, actor,
		map[string]any{"count": len(ids), "role": string(role), "source": string(src)}); err != nil {
		return nil, err
	}
	if err := r.recomputeInTx(ctx, tx, tenantID, []shared.ID{taskID}, actor); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit add members: %w", err)
	}
	return r.GetTask(ctx, tenantID, taskID)
}

// UpdateTask applies changes to a task at the caller's version, records one
// "updated" (or "state_changed") timeline entry with the changed fields and
// recomputes the derived state. A terminal task refuses every change but
// none.
func (r *RemediationTaskRepository) UpdateTask(ctx context.Context, tenantID, taskID shared.ID, expectedVersion int, ch remediation.TaskChanges, actor *shared.ID, eventKind string, eventData map[string]any) (*remediation.Task, error) {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin update task: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	t, err := lockTaskInTx(ctx, tx, tenantID, taskID, expectedVersion)
	if err != nil {
		return nil, err
	}
	if t.State.IsTerminal() {
		return nil, remediation.ErrTaskTerminal
	}
	sets := []string{"version = version + 1", "updated_at = now()"}
	args := []any{tenantID.String(), taskID.String()}
	set := func(col string, v any) {
		args = append(args, v)
		sets = append(sets, fmt.Sprintf("%s = $%d", col, len(args)))
	}
	if ch.Title != nil {
		set("title", *ch.Title)
	}
	if ch.Description != nil {
		set("description", *ch.Description)
	}
	if ch.AssigneeUserID != nil {
		set("assignee_user_id", idArg(*ch.AssigneeUserID))
	}
	if ch.AssigneeGroupID != nil {
		set("assignee_group_id", idArg(*ch.AssigneeGroupID))
	}
	if ch.ManualDeadline != nil {
		set("manual_deadline", timeArg(*ch.ManualDeadline))
	}
	if ch.CampaignID != nil {
		set("campaign_id", idArg(*ch.CampaignID))
	}
	if ch.ManualState != nil {
		var v any
		if *ch.ManualState != nil {
			v = string(**ch.ManualState)
		}
		set("manual_state", v)
	}
	if ch.ManualStateNote != nil {
		set("manual_state_note", *ch.ManualStateNote)
	}
	// The SET list holds fixed column names only; every value is a parameter.
	if _, err := tx.ExecContext(ctx, `UPDATE remediation_tasks SET `+strings.Join(sets, ", ")+ //nolint:gosec // G202: fixed column names, values bound

		` WHERE tenant_id = $1 AND id = $2`, args...); err != nil {
		return nil, fmt.Errorf("update remediation task: %w", err)
	}
	if ch.ManualState != nil && *ch.ManualState != nil && **ch.ManualState == remediation.ManualStateCanceled {
		// A canceled task lets its findings go: they may join another task.
		// The rows stay, with left_at set, as the task's history.
		released, rerr := releaseMembersInTx(ctx, tx, t, remediation.LeftReasonCanceled, actor)
		if rerr != nil {
			return nil, rerr
		}
		if eventData == nil {
			eventData = map[string]any{}
		}
		eventData["released"] = released
	}
	if err := insertTaskEventInTx(ctx, tx, tenantID, taskID, eventKind, actor, eventData); err != nil {
		return nil, err
	}
	if err := r.recomputeInTx(ctx, tx, tenantID, []shared.ID{taskID}, actor); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit update task: %w", err)
	}
	return r.GetTask(ctx, tenantID, taskID)
}

// memberCountsSQL aggregates the active members of tasks; $1 tenant,
// $2 task ids, $3 closed statuses, $4 claimed-fixed statuses. scopeCond
// limits the members counted (TRUE for all).
func memberCountsSQL(scopeCond string) string {
	return `
		SELECT tm.task_id,
		       COUNT(*) FILTER (WHERE tm.role = 'primary'),
		       COUNT(*) FILTER (WHERE tm.role = 'primary' AND f.status = 'in_progress'),
		       COUNT(*) FILTER (WHERE tm.role = 'primary' AND f.status = ANY($4::text[])),
		       COUNT(*) FILTER (WHERE tm.role = 'primary' AND f.status = ANY($3::text[])),
		       COUNT(*) FILTER (WHERE tm.role = 'primary' AND ` + verifiedFixedSQL + `),
		       COUNT(*) FILTER (WHERE tm.role = 'related'),
		       COALESCE(SUM(` + FindingRiskPointsSQL + `) FILTER (WHERE tm.role = 'primary' AND f.status <> ALL($3::text[])), 0),
		       MIN(f.sla_deadline) FILTER (WHERE tm.role = 'primary' AND f.status <> ALL($3::text[]))
		FROM remediation_task_members tm
		JOIN findings f ON f.id = tm.finding_id AND f.tenant_id = tm.tenant_id
		WHERE tm.tenant_id = $1 AND tm.task_id = ANY($2::uuid[]) AND tm.left_at IS NULL AND ` + scopeCond + `
		GROUP BY tm.task_id`
}

type rowsQuerier interface {
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
}

func memberCounts(ctx context.Context, q rowsQuerier, tenantID shared.ID, taskIDs []shared.ID, scope *shared.DataScope) (map[shared.ID]remediation.TaskCounts, error) {
	args := []any{tenantID.String(), pq.Array(rtIDStrings(taskIDs)), closedStatusArray(), fixAppliedStatuses}
	cond, args := dataScopeCond("f.asset_id", scope, args)
	rows, err := q.QueryContext(ctx, memberCountsSQL(cond), args...)
	if err != nil {
		return nil, fmt.Errorf("count task members: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := make(map[shared.ID]remediation.TaskCounts, len(taskIDs))
	for rows.Next() {
		var (
			id shared.ID
			c  remediation.TaskCounts
			dl sql.NullTime
		)
		if err := rows.Scan(&id, &c.Total, &c.InProgress, &c.FixApplied, &c.Closed, &c.Verified, &c.Related, &c.RiskPoints, &dl); err != nil {
			return nil, fmt.Errorf("count task members: %w", err)
		}
		c.Open = c.Total - c.InProgress - c.FixApplied - c.Closed
		if c.Open < 0 {
			c.Open = 0
		}
		c.MemberDeadline = rtTimePtr(dl)
		out[id] = c
	}
	return out, rows.Err()
}

// ScopedCounts returns each task's member counters over the members in the
// scope only (what a restricted reader may see).
func (r *RemediationTaskRepository) ScopedCounts(ctx context.Context, tenantID shared.ID, taskIDs []shared.ID, scope *shared.DataScope) (map[shared.ID]remediation.TaskCounts, error) {
	if len(taskIDs) == 0 {
		return map[shared.ID]remediation.TaskCounts{}, nil
	}
	return memberCounts(ctx, r.db, tenantID, taskIDs, scope)
}

// Recompute derives the state, deadline and counters of the tenant's tasks
// from their members and stores what changed; a state change is recorded on
// the task's timeline (actor nil = the platform).
func (r *RemediationTaskRepository) Recompute(ctx context.Context, tenantID shared.ID, taskIDs []shared.ID, actor *shared.ID) error {
	if len(taskIDs) == 0 {
		return nil
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin recompute: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if err := r.recomputeInTx(ctx, tx, tenantID, taskIDs, actor); err != nil {
		return err
	}
	return tx.Commit()
}

type taskDerivationInput struct {
	manual   *remediation.ManualState
	archived bool
	manualDL *time.Time
	campDL   *time.Time
	state    remediation.TaskState
	closedAt *time.Time
}

// readDerivationInputs locks the tasks (so a background recompute and a
// person's change never interleave) and reads what their state derives from
// besides the members.
func readDerivationInputs(ctx context.Context, tx *sql.Tx, tenantID shared.ID, taskIDs []shared.ID) (map[shared.ID]taskDerivationInput, error) {
	rows, err := tx.QueryContext(ctx, `
		SELECT t.id, t.manual_state, t.archived_at IS NOT NULL, t.manual_deadline,
		       (c.due_date::timestamp AT TIME ZONE 'UTC') + interval '1 day' - interval '1 second',
		       t.state, t.closed_at
		FROM remediation_tasks t
		LEFT JOIN remediation_campaigns c ON c.id = t.campaign_id AND c.tenant_id = t.tenant_id
		WHERE t.tenant_id = $1 AND t.id = ANY($2::uuid[])
		ORDER BY t.id
		FOR UPDATE OF t`,
		tenantID.String(), pq.Array(rtIDStrings(taskIDs)))
	if err != nil {
		return nil, fmt.Errorf("read tasks to recompute: %w", err)
	}
	defer func() { _ = rows.Close() }()
	inputs := map[shared.ID]taskDerivationInput{}
	for rows.Next() {
		var (
			id               shared.ID
			manual           sql.NullString
			in               taskDerivationInput
			manualDL, campDL sql.NullTime
			closedAt         sql.NullTime
			state            string
		)
		if err := rows.Scan(&id, &manual, &in.archived, &manualDL, &campDL, &state, &closedAt); err != nil {
			return nil, fmt.Errorf("read tasks to recompute: %w", err)
		}
		if manual.Valid {
			ms := remediation.ManualState(manual.String)
			in.manual = &ms
		}
		in.manualDL, in.campDL = rtTimePtr(manualDL), rtTimePtr(campDL)
		in.state, in.closedAt = remediation.TaskState(state), rtTimePtr(closedAt)
		inputs[id] = in
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("read tasks to recompute: %w", err)
	}
	return inputs, nil
}

func (r *RemediationTaskRepository) recomputeInTx(ctx context.Context, tx *sql.Tx, tenantID shared.ID, taskIDs []shared.ID, actor *shared.ID) error {
	counts, err := memberCounts(ctx, tx, tenantID, taskIDs, nil)
	if err != nil {
		return err
	}
	inputs, err := readDerivationInputs(ctx, tx, tenantID, taskIDs)
	if err != nil {
		return err
	}
	var regressions []shared.ID
	for id, in := range inputs {
		c := counts[id]
		if isRegression(in, c) {
			// A closed task is never reopened: its reopened findings move to
			// a new task linked to it, and it keeps its closed history.
			newID, err := r.regressInTx(ctx, tx, tenantID, id, actor)
			if err != nil {
				return err
			}
			regressions = append(regressions, newID)
			again, err := memberCounts(ctx, tx, tenantID, []shared.ID{id}, nil)
			if err != nil {
				return err
			}
			c = again[id]
		}
		state := remediation.DeriveState(in.manual, in.archived, c)
		dl, src := remediation.EffectiveDeadline(c.MemberDeadline, in.manualDL, in.campDL)
		if c.Total > 0 && c.Closed >= c.Total {
			// Nothing left to fix: no deadline.
			dl, src = nil, nil
		}
		closedAt := in.closedAt
		if state == remediation.TaskStateDone || state == remediation.TaskStateClosedUnverified {
			if closedAt == nil {
				now := time.Now().UTC()
				closedAt = &now
			}
		} else if state != remediation.TaskStateCanceled && state != remediation.TaskStateArchived {
			closedAt = nil
		}
		var srcArg any
		if src != nil {
			srcArg = string(*src)
		}
		if _, err := tx.ExecContext(ctx, `
			UPDATE remediation_tasks SET state = $3, deadline = $4, deadline_source = $5,
				member_count = $6, open_count = $7, in_progress_count = $8, fix_applied_count = $9,
				closed_count = $10, verified_count = $11, related_count = $12, risk_points = $13,
				closed_at = $14, recomputed_at = now()
			WHERE tenant_id = $1 AND id = $2`,
			tenantID.String(), id.String(), string(state), timeArg(dl), srcArg,
			c.Total, c.Open, c.InProgress, c.FixApplied, c.Closed, c.Verified, c.Related, c.RiskPoints,
			timeArg(closedAt)); err != nil {
			return fmt.Errorf("store recomputed task: %w", err)
		}
		if state != in.state {
			if err := insertTaskEventInTx(ctx, tx, tenantID, id, remediation.TaskEventStateChanged, actor,
				map[string]any{"from": string(in.state), "to": string(state)}); err != nil {
				return err
			}
		}
	}
	if len(regressions) > 0 {
		return r.recomputeInTx(ctx, tx, tenantID, regressions, actor)
	}
	return nil
}

// StaleTasksForPlatform lists, across tenants, live tasks with a member
// finding changed since the task was last recomputed (oldest first). Only the
// background reconcile calls it.
func (r *RemediationTaskRepository) StaleTasksForPlatform(ctx context.Context, limit int) ([]remediation.StaleTaskRef, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT t.tenant_id, t.id FROM remediation_tasks t
		WHERE t.state NOT IN ('canceled', 'archived')
		  AND EXISTS (SELECT 1 FROM remediation_task_members tm
		              JOIN findings f ON f.id = tm.finding_id AND f.tenant_id = tm.tenant_id
		              WHERE tm.tenant_id = t.tenant_id AND tm.task_id = t.id AND tm.left_at IS NULL
		                AND f.updated_at > t.recomputed_at)
		ORDER BY t.recomputed_at
		LIMIT $1`, limit)
	if err != nil {
		return nil, fmt.Errorf("list stale tasks: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []remediation.StaleTaskRef
	for rows.Next() {
		var ref remediation.StaleTaskRef
		if err := rows.Scan(&ref.TenantID, &ref.TaskID); err != nil {
			return nil, fmt.Errorf("list stale tasks: %w", err)
		}
		out = append(out, ref)
	}
	return out, rows.Err()
}

// ListMembers lists a task's active members (in the scope, when set).
func (r *RemediationTaskRepository) ListMembers(ctx context.Context, tenantID, taskID shared.ID, f remediation.MemberFilter, page pagination.Pagination) (pagination.Result[remediation.TaskMember], error) {
	args := []any{tenantID.String(), taskID.String()}
	conds := []string{"tm.tenant_id = $1", "tm.task_id = $2", "tm.left_at IS NULL"}
	if f.Role != "" {
		args = append(args, string(f.Role))
		conds = append(conds, fmt.Sprintf("tm.role = $%d", len(args)))
	}
	switch f.Status {
	case "":
	case "open":
		args = append(args, closedStatusArray())
		conds = append(conds, fmt.Sprintf("f.status <> ALL($%d::text[])", len(args)))
	case "closed":
		args = append(args, closedStatusArray())
		conds = append(conds, fmt.Sprintf("f.status = ANY($%d::text[])", len(args)))
	default:
		args = append(args, f.Status)
		conds = append(conds, fmt.Sprintf("f.status = $%d", len(args)))
	}
	cond, args := dataScopeCond("f.asset_id", f.Scope, args)
	conds = append(conds, cond)
	from := ` FROM remediation_task_members tm
		JOIN findings f ON f.id = tm.finding_id AND f.tenant_id = tm.tenant_id
		LEFT JOIN assets a ON a.id = f.asset_id AND a.tenant_id = f.tenant_id
		WHERE ` + strings.Join(conds, " AND ")
	var total int64
	if err := r.db.QueryRowContext(ctx, `SELECT COUNT(*)`+from, args...).Scan(&total); err != nil {
		return pagination.Result[remediation.TaskMember]{}, fmt.Errorf("count task members: %w", err)
	}
	q := `SELECT f.id, tm.role, tm.join_source, tm.joined_at, tm.joined_by,
		COALESCE(f.title, f.message, ''), f.severity, f.status, COALESCE(f.priority_class, ''),
		f.asset_id, COALESCE(a.name, ''), f.sla_deadline, ` + verifiedFixedSQL + from +
		` ORDER BY (tm.role = 'primary') DESC, f.sla_deadline ASC NULLS LAST, f.id` +
		fmt.Sprintf(` LIMIT %d OFFSET %d`, page.Limit(), page.Offset())
	rows, err := r.db.QueryContext(ctx, q, args...)
	if err != nil {
		return pagination.Result[remediation.TaskMember]{}, fmt.Errorf("list task members: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := make([]remediation.TaskMember, 0)
	for rows.Next() {
		var (
			m                 remediation.TaskMember
			role, src         string
			joinedBy, assetID sql.NullString
			sla               sql.NullTime
		)
		if err := rows.Scan(&m.FindingID, &role, &src, &m.JoinedAt, &joinedBy, &m.Title, &m.Severity, &m.Status,
			&m.PriorityClass, &assetID, &m.AssetName, &sla, &m.Verified); err != nil {
			return pagination.Result[remediation.TaskMember]{}, fmt.Errorf("scan task member: %w", err)
		}
		m.Role, m.JoinSource = remediation.MemberRole(role), remediation.JoinSource(src)
		m.JoinedBy, m.AssetID, m.SLADeadline = rtNullID(joinedBy), rtNullID(assetID), rtTimePtr(sla)
		out = append(out, m)
	}
	if err := rows.Err(); err != nil {
		return pagination.Result[remediation.TaskMember]{}, fmt.Errorf("list task members: %w", err)
	}
	return pagination.NewResult(out, total, page), nil
}

// ListEvents lists a task's timeline, newest first.
func (r *RemediationTaskRepository) ListEvents(ctx context.Context, tenantID, taskID shared.ID, page pagination.Pagination) (pagination.Result[remediation.TaskEvent], error) {
	var total int64
	if err := r.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM remediation_task_events WHERE tenant_id = $1 AND task_id = $2`,
		tenantID.String(), taskID.String()).Scan(&total); err != nil {
		return pagination.Result[remediation.TaskEvent]{}, fmt.Errorf("count task events: %w", err)
	}
	rows, err := r.db.QueryContext(ctx, `SELECT id, task_id, kind, actor_id, actor_type, data, created_at
		FROM remediation_task_events WHERE tenant_id = $1 AND task_id = $2
		ORDER BY created_at DESC, id DESC`+fmt.Sprintf(` LIMIT %d OFFSET %d`, page.Limit(), page.Offset()),
		tenantID.String(), taskID.String())
	if err != nil {
		return pagination.Result[remediation.TaskEvent]{}, fmt.Errorf("list task events: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := make([]remediation.TaskEvent, 0)
	for rows.Next() {
		var (
			e     remediation.TaskEvent
			actor sql.NullString
			data  []byte
		)
		if err := rows.Scan(&e.ID, &e.TaskID, &e.Kind, &actor, &e.ActorType, &data, &e.CreatedAt); err != nil {
			return pagination.Result[remediation.TaskEvent]{}, fmt.Errorf("scan task event: %w", err)
		}
		e.ActorID = rtNullID(actor)
		_ = json.Unmarshal(data, &e.Data)
		out = append(out, e)
	}
	if err := rows.Err(); err != nil {
		return pagination.Result[remediation.TaskEvent]{}, fmt.Errorf("list task events: %w", err)
	}
	return pagination.NewResult(out, total, page), nil
}

// CampaignInTenant reports whether a remediation campaign belongs to the
// tenant.
func (r *RemediationTaskRepository) CampaignInTenant(ctx context.Context, tenantID, campaignID shared.ID) (bool, error) {
	var ok bool
	err := r.db.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM remediation_campaigns WHERE tenant_id = $1 AND id = $2)`,
		tenantID.String(), campaignID.String()).Scan(&ok)
	if err != nil {
		return false, fmt.Errorf("check campaign: %w", err)
	}
	return ok, nil
}

var _ remediation.TaskRepository = (*RemediationTaskRepository)(nil)

// isRegression reports a done or closed task with an open member again.
func isRegression(in taskDerivationInput, c remediation.TaskCounts) bool {
	if in.archived || in.manual != nil {
		return false
	}
	closed := in.state == remediation.TaskStateDone || in.state == remediation.TaskStateClosedUnverified
	return closed && c.Total > 0 && c.Closed < c.Total
}

// regressInTx opens a regression task linked to a closed task (same fix,
// owner, campaign and manual deadline) and moves the reopened findings into
// it. Returns the new task's id.
func (r *RemediationTaskRepository) regressInTx(ctx context.Context, tx *sql.Tx, tenantID, taskID shared.ID, actor *shared.ID) (shared.ID, error) {
	src, err := lockTaskInTx(ctx, tx, tenantID, taskID, 0)
	if err != nil {
		return shared.ID{}, err
	}
	reopened, err := queryIDsInTx(ctx, tx, `
		SELECT tm.finding_id FROM remediation_task_members tm
		JOIN findings f ON f.id = tm.finding_id AND f.tenant_id = tm.tenant_id
		WHERE tm.tenant_id = $1 AND tm.task_id = $2 AND tm.left_at IS NULL AND tm.role = 'primary'
		  AND f.status <> ALL($3::text[])
		ORDER BY tm.finding_id`, tenantID.String(), taskID.String(), closedStatusArray())
	if err != nil {
		return shared.ID{}, fmt.Errorf("read reopened findings: %w", err)
	}
	child := &remediation.Task{ID: shared.NewID(), TenantID: tenantID, Title: clipTitle("Regression: " + src.Title)}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO remediation_tasks (id, tenant_id, action_id, campaign_id, title, description, assignee_user_id,
			assignee_group_id, manual_deadline, regression_of, created_by)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, NULL)`,
		child.ID.String(), tenantID.String(), src.ActionID.String(), idArg(src.CampaignID), child.Title, src.Description,
		idArg(src.AssigneeUserID), idArg(src.AssigneeGroupID), timeArg(src.ManualDeadline), src.ID.String()); err != nil {
		return shared.ID{}, fmt.Errorf("create regression task: %w", err)
	}
	if err := leaveInTx(ctx, tx, src, reopened, remediation.LeftReasonRegressed, actor,
		map[string]any{"to_task_id": child.ID.String(), "to_task_title": child.Title}); err != nil {
		return shared.ID{}, err
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO remediation_task_members (tenant_id, task_id, finding_id, role, join_source, joined_by)
		SELECT $1, $2, f.id, 'primary', 'regression', NULL FROM findings f WHERE f.tenant_id = $1 AND f.id = ANY($3::uuid[])`,
		tenantID.String(), child.ID.String(), pq.Array(rtIDStrings(reopened))); err != nil {
		return shared.ID{}, fmt.Errorf("join regression task: %w", err)
	}
	if err := insertFindingTaskActivityInTx(ctx, tx, child, reopened, "joined", remediation.MemberRolePrimary, actor,
		map[string]any{"from_task_id": src.ID.String(), "from_task_title": src.Title, "reason": "regressed"}); err != nil {
		return shared.ID{}, err
	}
	if err := insertTaskEventInTx(ctx, tx, tenantID, child.ID, remediation.TaskEventCreated, actor,
		map[string]any{"title": child.Title, "members": len(reopened), "regression_of": src.ID.String(), "regression_of_title": src.Title}); err != nil {
		return shared.ID{}, err
	}
	if err := insertTaskEventInTx(ctx, tx, tenantID, src.ID, remediation.TaskEventRegressed, actor,
		map[string]any{"count": len(reopened), "regression_task_id": child.ID.String()}); err != nil {
		return shared.ID{}, err
	}
	return child.ID, nil
}

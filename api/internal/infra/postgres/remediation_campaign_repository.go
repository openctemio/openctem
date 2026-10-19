package postgres

// Remediation campaigns: programs of remediation tasks
// (docs/architecture/remediation-campaigns.md). A campaign holds tasks
// (remediation_tasks.campaign_id), never findings; its summary is derived
// from its tasks and their findings on every read, over the reader's scope.

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
	"github.com/openctemio/openctem/api/pkg/pagination"
)

// RemediationCampaignRepository implements remediation.CampaignRepository.
type RemediationCampaignRepository struct {
	db *DB
}

// NewRemediationCampaignRepository creates a new repository.
func NewRemediationCampaignRepository(db *DB) *RemediationCampaignRepository {
	return &RemediationCampaignRepository{db: db}
}

var _ remediation.CampaignRepository = (*RemediationCampaignRepository)(nil)

const rcSelectCols = `c.id, c.tenant_id, c.name, c.description, c.status, c.priority,
	c.assigned_to, c.assigned_team, c.start_date, c.due_date, c.completed_at,
	c.tags, c.created_by, c.created_at, c.updated_at, c.version`

// liveTaskStates are the task states that still take work.
const liveTaskStatesSQL = `('open', 'in_progress', 'verifying', 'on_hold')`

func (r *RemediationCampaignRepository) scanCampaign(scan func(dest ...any) error) (*remediation.Campaign, error) {
	var (
		id, tenantID                    shared.ID
		name, description               string
		status, priority                string
		assignedTo, assignedTeam        sql.NullString
		startDate, dueDate, completedAt sql.NullTime
		tags                            pq.StringArray
		createdBy                       sql.NullString
		createdAt, updatedAt            time.Time
		version                         int
	)
	if err := scan(&id, &tenantID, &name, &description, &status, &priority,
		&assignedTo, &assignedTeam, &startDate, &dueDate, &completedAt,
		&tags, &createdBy, &createdAt, &updatedAt, &version); err != nil {
		return nil, err
	}
	return remediation.ReconstituteCampaign(
		id, tenantID, name, description,
		remediation.CampaignStatus(status), remediation.CampaignPriority(priority),
		rtNullID(assignedTo), rtNullID(assignedTeam),
		rtTimePtr(startDate), rtTimePtr(dueDate), rtTimePtr(completedAt),
		[]string(tags), rtNullID(createdBy),
		createdAt, updatedAt, version,
	), nil
}

// Create inserts a campaign.
func (r *RemediationCampaignRepository) Create(ctx context.Context, c *remediation.Campaign) error {
	_, err := r.db.ExecContext(ctx, `INSERT INTO remediation_campaigns (
		id, tenant_id, name, description, status, priority,
		assigned_to, assigned_team, start_date, due_date,
		tags, created_by, created_at, updated_at, version
	) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)`,
		c.ID().String(), c.TenantID().String(),
		c.Name(), c.Description(), string(c.Status()), string(c.Priority()),
		idArg(c.AssignedTo()), idArg(c.AssignedTeam()), c.StartDate(), c.DueDate(),
		pq.StringArray(c.Tags()), idArg(c.CreatedBy()),
		c.CreatedAt(), c.UpdatedAt(), c.Version(),
	)
	if err != nil {
		return fmt.Errorf("failed to create remediation campaign: %w", err)
	}
	return nil
}

// GetByID returns a campaign of the tenant.
func (r *RemediationCampaignRepository) GetByID(ctx context.Context, tenantID, id shared.ID) (*remediation.Campaign, error) {
	query := "SELECT " + rcSelectCols + " FROM remediation_campaigns c WHERE c.tenant_id = $1 AND c.id = $2"
	c, err := r.scanCampaign(r.db.QueryRowContext(ctx, query, tenantID.String(), id.String()).Scan)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, remediation.ErrCampaignNotFound
		}
		return nil, fmt.Errorf("failed to get remediation campaign: %w", err)
	}
	return c, nil
}

// Update saves every field when the stored version is the campaign's.
func (r *RemediationCampaignRepository) Update(ctx context.Context, c *remediation.Campaign) error {
	var newVersion int
	err := r.db.QueryRowContext(ctx, `UPDATE remediation_campaigns SET
		name=$3, description=$4, status=$5, priority=$6,
		assigned_to=$7, assigned_team=$8, start_date=$9, due_date=$10, completed_at=$11,
		tags=$12, updated_at=$13, version = version + 1
		WHERE tenant_id=$1 AND id=$2 AND version=$14
		RETURNING version`,
		c.TenantID().String(), c.ID().String(),
		c.Name(), c.Description(), string(c.Status()), string(c.Priority()),
		idArg(c.AssignedTo()), idArg(c.AssignedTeam()), c.StartDate(), c.DueDate(), c.CompletedAt(),
		pq.StringArray(c.Tags()), c.UpdatedAt(), c.Version(),
	).Scan(&newVersion)
	if errors.Is(err, sql.ErrNoRows) {
		var exists bool
		if qerr := r.db.QueryRowContext(ctx,
			"SELECT EXISTS (SELECT 1 FROM remediation_campaigns WHERE tenant_id = $1 AND id = $2)",
			c.TenantID().String(), c.ID().String()).Scan(&exists); qerr != nil {
			return fmt.Errorf("failed to update remediation campaign: %w", qerr)
		}
		if !exists {
			return remediation.ErrCampaignNotFound
		}
		return remediation.ErrCampaignVersionConflict
	}
	if err != nil {
		return fmt.Errorf("failed to update remediation campaign: %w", err)
	}
	c.SetVersion(newVersion)
	return nil
}

// Delete removes a campaign; its tasks stay and leave it (ON DELETE SET NULL).
func (r *RemediationCampaignRepository) Delete(ctx context.Context, tenantID, id shared.ID) error {
	res, err := r.db.ExecContext(ctx,
		"DELETE FROM remediation_campaigns WHERE tenant_id = $1 AND id = $2",
		tenantID.String(), id.String(),
	)
	if err != nil {
		return fmt.Errorf("failed to delete remediation campaign: %w", err)
	}
	return deletedOne(res, "remediation campaign")
}

// campaignVisibleCond is the predicate on campaign alias c for what the
// viewer may see. Anyone not restricted sees every campaign of the tenant
// (hidden program findings only leave the counts); a restricted viewer sees
// the campaigns they created or own and those with a task holding a finding
// in their scope.
func campaignVisibleCond(v remediation.CampaignViewer, args []any) (string, []any) {
	if !v.Restricted() {
		return sqlTrue, args
	}
	conds := make([]string, 0, 3)
	if v.UserID != nil {
		args = append(args, v.UserID.String())
		p := fmt.Sprintf("$%d", len(args))
		conds = append(conds, "c.created_by = "+p, "c.assigned_to = "+p)
	}
	scopeCond, args := dataScopeCond("vf.asset_id", v.Scope, args)
	conds = append(conds, `EXISTS (SELECT 1 FROM remediation_tasks vt
		JOIN remediation_task_members vm ON vm.tenant_id = vt.tenant_id AND vm.task_id = vt.id AND vm.left_at IS NULL
		JOIN findings vf ON vf.tenant_id = vm.tenant_id AND vf.id = vm.finding_id
		WHERE vt.tenant_id = c.tenant_id AND vt.campaign_id = c.id AND `+scopeCond+`)`)
	return "(" + strings.Join(conds, " OR ") + ")", args
}

func campaignListWhere(filter remediation.CampaignFilter) (string, []any) {
	args := []any{}
	conds := []string{}
	next := func(v any) string {
		args = append(args, v)
		return fmt.Sprintf("$%d", len(args))
	}
	if filter.TenantID != nil {
		conds = append(conds, "c.tenant_id = "+next(filter.TenantID.String()))
	} else {
		conds = append(conds, "FALSE")
	}
	if filter.Status != nil {
		conds = append(conds, "c.status = "+next(string(*filter.Status)))
	}
	if filter.Priority != nil {
		conds = append(conds, "c.priority = "+next(string(*filter.Priority)))
	}
	if filter.Search != nil && strings.TrimSpace(*filter.Search) != "" {
		p := next("%" + escapeLikePattern(strings.TrimSpace(*filter.Search)) + "%")
		conds = append(conds, "(c.name ILIKE "+p+" OR c.description ILIKE "+p+")")
	}
	vis, args := campaignVisibleCond(filter.Viewer, args)
	conds = append(conds, vis)
	return strings.Join(conds, " AND "), args
}

// List lists the campaigns the viewer may see: active first, then draft,
// completed and canceled; the earliest due date first within a status.
func (r *RemediationCampaignRepository) List(ctx context.Context, filter remediation.CampaignFilter, page pagination.Pagination) (pagination.Result[*remediation.Campaign], error) {
	where, args := campaignListWhere(filter)
	var total int64
	if err := r.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM remediation_campaigns c WHERE "+where, args...).Scan(&total); err != nil {
		return pagination.Result[*remediation.Campaign]{}, fmt.Errorf("failed to count campaigns: %w", err)
	}
	query := "SELECT " + rcSelectCols + " FROM remediation_campaigns c WHERE " + where +
		` ORDER BY CASE c.status WHEN 'active' THEN 0 WHEN 'draft' THEN 1 WHEN 'completed' THEN 2 ELSE 3 END,
		  c.due_date ASC NULLS LAST, c.created_at DESC, c.id` +
		fmt.Sprintf(" LIMIT %d OFFSET %d", page.PerPage, page.Offset())
	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return pagination.Result[*remediation.Campaign]{}, fmt.Errorf("failed to list campaigns: %w", err)
	}
	defer func() { _ = rows.Close() }()
	items := make([]*remediation.Campaign, 0, page.PerPage)
	for rows.Next() {
		c, err := r.scanCampaign(rows.Scan)
		if err != nil {
			return pagination.Result[*remediation.Campaign]{}, fmt.Errorf("failed to scan campaign: %w", err)
		}
		items = append(items, c)
	}
	if err := rows.Err(); err != nil {
		return pagination.Result[*remediation.Campaign]{}, fmt.Errorf("failed to iterate campaigns: %w", err)
	}
	return pagination.NewResult(items, total, page), nil
}

// CountByStatus counts the campaigns that match the filter (its status
// ignored), per status.
func (r *RemediationCampaignRepository) CountByStatus(ctx context.Context, filter remediation.CampaignFilter) (map[remediation.CampaignStatus]int, error) {
	filter.Status = nil
	where, args := campaignListWhere(filter)
	rows, err := r.db.QueryContext(ctx, "SELECT c.status, COUNT(*) FROM remediation_campaigns c WHERE "+where+" GROUP BY c.status", args...)
	if err != nil {
		return nil, fmt.Errorf("count campaigns by status: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := map[remediation.CampaignStatus]int{}
	for rows.Next() {
		var (
			st string
			n  int
		)
		if err := rows.Scan(&st, &n); err != nil {
			return nil, fmt.Errorf("count campaigns by status: %w", err)
		}
		out[remediation.CampaignStatus(st)] = n
	}
	return out, rows.Err()
}

// Visible reports whether the viewer may see the campaign.
func (r *RemediationCampaignRepository) Visible(ctx context.Context, tenantID, id shared.ID, viewer remediation.CampaignViewer) (bool, error) {
	args := []any{tenantID.String(), id.String()}
	cond, args := campaignVisibleCond(viewer, args)
	var ok bool
	if err := r.db.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM remediation_campaigns c
		WHERE c.tenant_id = $1 AND c.id = $2 AND `+cond+`)`, args...).Scan(&ok); err != nil {
		return false, fmt.Errorf("check campaign visibility: %w", err)
	}
	return ok, nil
}

// HasTaskOutsideScope reports whether a task of the campaign has a finding
// outside the scope.
func (r *RemediationCampaignRepository) HasTaskOutsideScope(ctx context.Context, tenantID, id shared.ID, scope *shared.DataScope) (bool, error) {
	if scope == nil {
		return false, nil
	}
	args := []any{tenantID.String(), id.String()}
	cond, args := dataScopeCond("f.asset_id", scope, args)
	var out bool
	if err := r.db.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM remediation_tasks t
		JOIN remediation_task_members m ON m.tenant_id = t.tenant_id AND m.task_id = t.id AND m.left_at IS NULL
		JOIN findings f ON f.tenant_id = m.tenant_id AND f.id = m.finding_id
		WHERE t.tenant_id = $1 AND t.campaign_id = $2 AND NOT (`+cond+`))`, args...).Scan(&out); err != nil {
		return false, fmt.Errorf("check campaign task scope: %w", err)
	}
	return out, nil
}

// Summaries derives each campaign's summary from its tasks (archived tasks
// left out), counting only the findings in the scope. A task is visible when
// it has a finding in the scope, or, for a reader who is not restricted, when
// it has no active member at all (a canceled task released them).
func (r *RemediationCampaignRepository) Summaries(ctx context.Context, tenantID shared.ID, ids []shared.ID, scope *shared.DataScope) (map[shared.ID]remediation.CampaignSummary, error) {
	out := make(map[shared.ID]remediation.CampaignSummary, len(ids))
	if len(ids) == 0 {
		return out, nil
	}
	args := []any{tenantID.String(), pq.Array(rtIDStrings(ids)), closedStatusArray(), scope.Restricted()}
	sc, args := dataScopeCond("f.asset_id", scope, args)
	q := `
		SELECT x.campaign_id,
		       COUNT(*) FILTER (WHERE x.visible),
		       COUNT(*) FILTER (WHERE x.visible AND x.state IN ` + liveTaskStatesSQL + `),
		       COUNT(*) FILTER (WHERE x.visible AND x.state = 'done'),
		       COUNT(*) FILTER (WHERE x.visible AND x.state IN ` + liveTaskStatesSQL + ` AND x.late),
		       COUNT(*) FILTER (WHERE NOT x.visible),
		       COALESCE(SUM(x.prim) FILTER (WHERE x.visible), 0),
		       COALESCE(SUM(x.closed) FILTER (WHERE x.visible), 0),
		       COALESCE(SUM(x.verified) FILTER (WHERE x.visible), 0)
		FROM (
			SELECT t.campaign_id, t.state,
			       (COUNT(m.id) FILTER (WHERE ` + sc + `) > 0 OR (NOT $4 AND COUNT(m.id) = 0)) AS visible,
			       COUNT(m.id) FILTER (WHERE m.role = 'primary' AND ` + sc + `) AS prim,
			       COUNT(m.id) FILTER (WHERE m.role = 'primary' AND ` + sc + ` AND f.status = ANY($3::text[])) AS closed,
			       COUNT(m.id) FILTER (WHERE m.role = 'primary' AND ` + sc + ` AND ` + verifiedFixedSQL + `) AS verified,
			       (COALESCE(bool_or(m.role = 'primary' AND ` + sc + ` AND f.status <> ALL($3::text[]) AND f.sla_deadline < now()), false)
			        OR (t.deadline_source IN ('manual', 'campaign') AND t.deadline < now())) AS late
			FROM remediation_tasks t
			LEFT JOIN remediation_task_members m ON m.tenant_id = t.tenant_id AND m.task_id = t.id AND m.left_at IS NULL
			LEFT JOIN findings f ON f.tenant_id = m.tenant_id AND f.id = m.finding_id
			WHERE t.tenant_id = $1 AND t.campaign_id = ANY($2::uuid[]) AND t.state <> 'archived'
			GROUP BY t.campaign_id, t.id, t.state, t.deadline_source, t.deadline
		) x
		GROUP BY x.campaign_id`
	rows, err := r.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("summarize campaigns: %w", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var (
			id shared.ID
			s  remediation.CampaignSummary
		)
		if err := rows.Scan(&id, &s.Tasks, &s.LiveTasks, &s.DoneTasks, &s.OverdueTasks, &s.HiddenTasks,
			&s.Findings, &s.ClosedFindings, &s.VerifiedFindings); err != nil {
			return nil, fmt.Errorf("summarize campaigns: %w", err)
		}
		out[id] = s
	}
	return out, rows.Err()
}

// TaskRefs returns the campaign of each of the tenant's tasks.
func (r *RemediationCampaignRepository) TaskRefs(ctx context.Context, tenantID shared.ID, taskIDs []shared.ID) ([]remediation.CampaignTaskRef, error) {
	if len(taskIDs) == 0 {
		return nil, nil
	}
	rows, err := r.db.QueryContext(ctx, `
		SELECT t.id, t.campaign_id, COALESCE(c.name, '')
		FROM remediation_tasks t
		LEFT JOIN remediation_campaigns c ON c.tenant_id = t.tenant_id AND c.id = t.campaign_id
		WHERE t.tenant_id = $1 AND t.id = ANY($2::uuid[])
		ORDER BY t.id`, tenantID.String(), pq.Array(rtIDStrings(taskIDs)))
	if err != nil {
		return nil, fmt.Errorf("read task campaigns: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []remediation.CampaignTaskRef
	for rows.Next() {
		var (
			ref  remediation.CampaignTaskRef
			camp sql.NullString
		)
		if err := rows.Scan(&ref.TaskID, &camp, &ref.CampaignName); err != nil {
			return nil, fmt.Errorf("read task campaigns: %w", err)
		}
		ref.CampaignID = rtNullID(camp)
		out = append(out, ref)
	}
	return out, rows.Err()
}

// SetTasksCampaign puts the tasks in the campaign (nil: none), bumps their
// version and writes an "updated" entry on each task's timeline.
func (r *RemediationCampaignRepository) SetTasksCampaign(ctx context.Context, tenantID shared.ID, taskIDs []shared.ID, campaignID *shared.ID, actor *shared.ID) ([]shared.ID, error) {
	if len(taskIDs) == 0 {
		return nil, nil
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin set task campaign: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	changed, err := queryIDsInTx(ctx, tx, `
		UPDATE remediation_tasks SET campaign_id = $3, version = version + 1, updated_at = now()
		WHERE tenant_id = $1 AND id = ANY($2::uuid[]) AND campaign_id IS DISTINCT FROM $3::uuid
		RETURNING id`, tenantID.String(), pq.Array(rtIDStrings(taskIDs)), idArg(campaignID))
	if err != nil {
		return nil, fmt.Errorf("set task campaign: %w", err)
	}
	data := map[string]any{"campaign_id": ""}
	if campaignID != nil {
		data["campaign_id"] = campaignID.String()
	}
	dj, err := json.Marshal(data)
	if err != nil {
		return nil, fmt.Errorf("encode task event: %w", err)
	}
	actorType := actorTypeUser
	if actor == nil {
		actorType = "system"
	}
	if len(changed) > 0 {
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO remediation_task_events (tenant_id, task_id, kind, actor_id, actor_type, data)
			SELECT $1, id, $3, $4, $5, $6 FROM unnest($2::uuid[]) AS id`,
			tenantID.String(), pq.Array(rtIDStrings(changed)), remediation.TaskEventUpdated, idArg(actor), actorType, dj); err != nil {
			return nil, fmt.Errorf("write task events: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit set task campaign: %w", err)
	}
	return changed, nil
}

// ListForReconcile returns active and completed campaigns across tenants,
// least recently reconciled first, and stamps them reconciled.
func (r *RemediationCampaignRepository) ListForReconcile(ctx context.Context, limit int) ([]*remediation.Campaign, error) {
	if limit <= 0 {
		limit = 500
	}
	rows, err := r.db.QueryContext(ctx, `
		WITH picked AS (
			SELECT id FROM remediation_campaigns
			WHERE status IN ('active', 'completed')
			ORDER BY last_reconciled_at ASC NULLS FIRST, id
			LIMIT $1
			FOR UPDATE SKIP LOCKED
		), stamped AS (
			UPDATE remediation_campaigns c SET last_reconciled_at = now()
			FROM picked WHERE c.id = picked.id
			RETURNING c.*
		)
		SELECT `+rcSelectCols+` FROM stamped c ORDER BY c.id`, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to list campaigns to reconcile: %w", err)
	}
	defer func() { _ = rows.Close() }()
	items := make([]*remediation.Campaign, 0)
	for rows.Next() {
		c, err := r.scanCampaign(rows.Scan)
		if err != nil {
			return nil, fmt.Errorf("failed to scan campaign: %w", err)
		}
		items = append(items, c)
	}
	return items, rows.Err()
}

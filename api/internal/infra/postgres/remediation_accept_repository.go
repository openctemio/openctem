package postgres

// Accepting remediation suggestions and the auto-join rule
// (docs/rfcs/RFC-098-remediation-tasks.md §6). Each accept is one
// transaction: the suggestion is locked at the caller's version, the
// findings are locked in id order and re-checked (closed or taken findings
// are dropped and reported), then the action, the tasks and the memberships
// are written and the suggestion is marked accepted.

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/api/pkg/domain/remediation"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// AcceptSuggestion stores an accept plan.
func (r *RemediationSuggestionRepository) AcceptSuggestion(ctx context.Context, plan remediation.AcceptPlan) (*remediation.AcceptResult, error) {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin accept: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	tenant := plan.TenantID.String()

	key, err := lockOpenSuggestionInTx(ctx, tx, plan)
	if err != nil {
		return nil, err
	}

	all := append([]shared.ID{}, plan.JoinIDs...)
	for _, t := range plan.Tasks {
		all = append(all, t.FindingIDs...)
	}
	if err := lockFindingsInTx(ctx, tx, plan.TenantID, all); err != nil {
		return nil, err
	}
	gone, err := unavailableFindingsInTx(ctx, tx, plan.TenantID, all)
	if err != nil {
		return nil, err
	}
	res := &remediation.AcceptResult{SuggestionID: plan.SuggestionID, TaskIDs: []shared.ID{}, Dropped: []shared.ID{}}
	for id := range gone {
		res.Dropped = append(res.Dropped, id)
	}
	keep := func(ids []shared.ID) []shared.ID {
		out := make([]shared.ID, 0, len(ids))
		for _, id := range ids {
			if !gone[id] {
				out = append(out, id)
			}
		}
		return out
	}

	actionID, err := ensureActionInTx(ctx, tx, plan)
	if err != nil {
		return nil, err
	}
	res.ActionID = actionID

	tr := &RemediationTaskRepository{db: r.db}
	created, err := tr.createPlanTasksInTx(ctx, tx, plan, actionID, keep, res)
	if err != nil {
		return nil, err
	}

	if res.Joined, err = tr.joinPlanInTx(ctx, tx, plan, keep(plan.JoinIDs)); err != nil {
		return nil, err
	}
	if created == 0 && res.Joined == 0 {
		return nil, remediation.ErrNothingToAccept
	}

	if len(plan.Excluded) > 0 {
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO remediation_key_exclusions (tenant_id, action_key, finding_id, reason, created_by)
			SELECT $1, $2, f.id, 'removed', $4 FROM findings f WHERE f.tenant_id = $1 AND f.id = ANY($3::uuid[])
			ON CONFLICT DO NOTHING`, tenant, key, pq.Array(rtIDStrings(plan.Excluded)), idArg(plan.ActorID)); err != nil {
			return nil, fmt.Errorf("record exclusions: %w", err)
		}
	}
	if _, err := tx.ExecContext(ctx, `UPDATE remediation_suggestions SET state = 'accepted', decided_by = $3, decided_at = now(),
		version = version + 1, updated_at = now(), target_action_id = COALESCE(target_action_id, $4)
		WHERE tenant_id = $1 AND id = $2`, tenant, plan.SuggestionID.String(), idArg(plan.ActorID), actionID.String()); err != nil {
		return nil, fmt.Errorf("mark suggestion accepted: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit accept: %w", err)
	}
	return res, nil
}

// lockOpenSuggestionInTx locks the suggestion and checks it is still open at
// the caller's version; it returns the suggestion's key.
func lockOpenSuggestionInTx(ctx context.Context, tx *sql.Tx, plan remediation.AcceptPlan) (string, error) {
	var (
		state   string
		version int
		key     string
	)
	err := tx.QueryRowContext(ctx, `SELECT state, version, action_key FROM remediation_suggestions
		WHERE tenant_id = $1 AND id = $2 FOR UPDATE`, plan.TenantID.String(), plan.SuggestionID.String()).Scan(&state, &version, &key)
	if errors.Is(err, sql.ErrNoRows) {
		return "", remediation.ErrSuggestionNotFound
	}
	if err != nil {
		return "", fmt.Errorf("lock suggestion: %w", err)
	}
	if !remediation.SuggestionState(state).IsOpen() || version != plan.Version {
		return "", remediation.ErrSuggestionDecided
	}
	return key, nil
}

// ensureActionInTx creates the action of a new group (or reuses one a
// concurrent accept just created for the same key), or checks the existing
// action of a join or task route belongs to the tenant.
func ensureActionInTx(ctx context.Context, tx *sql.Tx, plan remediation.AcceptPlan) (shared.ID, error) {
	tenant := plan.TenantID.String()
	var (
		actionID shared.ID
		err      error
	)
	switch {
	case plan.NewAction != nil:
		spec, merr := json.Marshal(plan.NewAction.FixSpec)
		if merr != nil || plan.NewAction.FixSpec == nil {
			spec = []byte("{}")
		}
		var autoBy any
		if plan.AutoJoin {
			autoBy = idArg(plan.ActorID)
		}
		err = tx.QueryRowContext(ctx, `
			INSERT INTO remediation_actions (tenant_id, action_key, kind, title, fix_spec, origin, created_by,
				auto_join, auto_join_by, auto_join_at)
			VALUES ($1, $2, $3, $4, $5, 'suggestion', $6, $7, $8, CASE WHEN $7 THEN now() END)
			ON CONFLICT (tenant_id, action_key) DO UPDATE SET updated_at = now()
			RETURNING id`,
			tenant, plan.NewAction.Key, plan.NewAction.Kind, plan.NewAction.Title, spec, idArg(plan.ActorID),
			plan.AutoJoin, autoBy).Scan(&actionID)
		if err != nil {
			return shared.ID{}, fmt.Errorf("create remediation action: %w", err)
		}
	case plan.ActionID != nil:
		actionID = *plan.ActionID
		if err := tx.QueryRowContext(ctx, `SELECT id FROM remediation_actions WHERE tenant_id = $1 AND id = $2`,
			tenant, actionID.String()).Scan(&actionID); err != nil {
			return shared.ID{}, fmt.Errorf("%w: the remediation action was not found", shared.ErrValidation)
		}
	default:
		return shared.ID{}, fmt.Errorf("%w: accept plan without an action", shared.ErrValidation)
	}
	return actionID, nil
}

// createPlanTasksInTx creates the accept plan's tasks with their findings
// (those still available); it returns how many findings joined them.
func (r *RemediationTaskRepository) createPlanTasksInTx(ctx context.Context, tx *sql.Tx, plan remediation.AcceptPlan, actionID shared.ID, keep func([]shared.ID) []shared.ID, res *remediation.AcceptResult) (int, error) {
	tenant := plan.TenantID.String()
	created := 0
	for _, pt := range plan.Tasks {
		members := keep(pt.FindingIDs)
		if len(members) == 0 {
			continue
		}
		t := &remediation.Task{ID: shared.NewID(), TenantID: plan.TenantID, ActionID: actionID, Title: pt.Title,
			AssigneeUserID: pt.Owner.UserID, AssigneeGroupID: pt.Owner.GroupID, ManualDeadline: pt.Deadline, CreatedBy: plan.ActorID}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO remediation_tasks (id, tenant_id, action_id, title, assignee_user_id, assignee_group_id, manual_deadline, created_by)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
			t.ID.String(), tenant, actionID.String(), t.Title, idArg(t.AssigneeUserID), idArg(t.AssigneeGroupID),
			timeArg(t.ManualDeadline), idArg(t.CreatedBy)); err != nil {
			return 0, fmt.Errorf("create remediation task: %w", err)
		}
		if err := insertMembersInTx(ctx, tx, t, members, remediation.MemberRolePrimary, remediation.JoinSourceSuggestion, plan.ActorID); err != nil {
			return 0, err
		}
		if err := insertTaskEventInTx(ctx, tx, plan.TenantID, t.ID, remediation.TaskEventCreated, plan.ActorID,
			map[string]any{"title": t.Title, "members": len(members), "related": 0, "suggestion_id": plan.SuggestionID.String()}); err != nil {
			return 0, err
		}
		if err := r.recomputeInTx(ctx, tx, plan.TenantID, []shared.ID{t.ID}, plan.ActorID); err != nil {
			return 0, err
		}
		res.TaskIDs = append(res.TaskIDs, t.ID)
		created += len(members)
	}
	return created, nil
}

// joinPlanInTx adds a join's findings to its live target task.
func (r *RemediationTaskRepository) joinPlanInTx(ctx context.Context, tx *sql.Tx, plan remediation.AcceptPlan, joins []shared.ID) (int, error) {
	if plan.TargetTaskID == nil || len(joins) == 0 {
		return 0, nil
	}
	t, err := lockTaskInTx(ctx, tx, plan.TenantID, *plan.TargetTaskID, 0)
	if err != nil {
		return 0, err
	}
	if t.State.IsTerminal() {
		return 0, remediation.ErrTaskTerminal
	}
	if err := insertMembersInTx(ctx, tx, t, joins, remediation.MemberRolePrimary, remediation.JoinSourceSuggestion, plan.ActorID); err != nil {
		return 0, err
	}
	if err := bumpTaskInTx(ctx, tx, plan.TenantID, t.ID, remediation.TaskEventMembersAdded, plan.ActorID,
		map[string]any{"count": len(joins), "role": "primary", "source": "suggestion", "suggestion_id": plan.SuggestionID.String()}); err != nil {
		return 0, err
	}
	if err := r.recomputeInTx(ctx, tx, plan.TenantID, []shared.ID{t.ID}, plan.ActorID); err != nil {
		return 0, err
	}
	return len(joins), nil
}

// unavailableFindingsInTx returns the findings that are closed, gone or the
// primary member of an active task.
func unavailableFindingsInTx(ctx context.Context, tx *sql.Tx, tenantID shared.ID, ids []shared.ID) (map[shared.ID]bool, error) {
	out := map[shared.ID]bool{}
	if len(ids) == 0 {
		return out, nil
	}
	ok, err := queryIDsInTx(ctx, tx, `
		SELECT f.id FROM findings f
		WHERE f.tenant_id = $1 AND f.id = ANY($2::uuid[]) AND f.status <> ALL($3::text[])
		  AND NOT EXISTS (SELECT 1 FROM remediation_task_members m
		                  WHERE m.tenant_id = f.tenant_id AND m.finding_id = f.id AND m.left_at IS NULL AND m.role = 'primary')`,
		tenantID.String(), pq.Array(rtIDStrings(ids)), closedStatusArray())
	if err != nil {
		return nil, fmt.Errorf("check findings: %w", err)
	}
	avail := make(map[shared.ID]bool, len(ok))
	for _, id := range ok {
		avail[id] = true
	}
	for _, id := range ids {
		if !avail[id] {
			out[id] = true
		}
	}
	return out, nil
}

// bumpTaskInTx bumps a task's version and records a timeline entry.
func bumpTaskInTx(ctx context.Context, tx *sql.Tx, tenantID, taskID shared.ID, kind string, actor *shared.ID, data map[string]any) error {
	if _, err := tx.ExecContext(ctx, `UPDATE remediation_tasks SET version = version + 1, updated_at = now()
		WHERE tenant_id = $1 AND id = $2`, tenantID.String(), taskID.String()); err != nil {
		return fmt.Errorf("bump task version: %w", err)
	}
	return insertTaskEventInTx(ctx, tx, tenantID, taskID, kind, actor, data)
}

// AutoJoin adds findings to an action's task as the platform, under the
// action's auto-join rule: only while the action has the rule on, the task
// belongs to the action and is open or in progress, and within the daily cap
// per action. Returns how many joined (the rest stay suggestions).
func (r *RemediationSuggestionRepository) AutoJoin(ctx context.Context, tenantID, actionID, taskID shared.ID, findingIDs []shared.ID) (int, error) {
	if len(findingIDs) == 0 {
		return 0, nil
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("begin auto-join: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	var on bool
	err = tx.QueryRowContext(ctx, `SELECT auto_join FROM remediation_actions WHERE tenant_id = $1 AND id = $2 FOR SHARE`,
		tenantID.String(), actionID.String()).Scan(&on)
	if errors.Is(err, sql.ErrNoRows) || (err == nil && !on) {
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("read auto-join rule: %w", err)
	}
	t, err := lockTaskInTx(ctx, tx, tenantID, taskID, 0)
	if err != nil {
		return 0, err
	}
	if t.ActionID != actionID || !remediation.CanAutoJoinInto(t.State) {
		return 0, nil
	}
	var today int
	if err := tx.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM remediation_task_members m
		JOIN remediation_tasks t ON t.id = m.task_id AND t.tenant_id = m.tenant_id
		WHERE m.tenant_id = $1 AND t.action_id = $2 AND m.join_source = 'auto_join' AND m.joined_at > now() - interval '24 hours'`,
		tenantID.String(), actionID.String()).Scan(&today); err != nil {
		return 0, fmt.Errorf("count auto-joins: %w", err)
	}
	room := remediation.AutoJoinDailyCap - today
	if room <= 0 {
		return 0, nil
	}
	if len(findingIDs) > room {
		findingIDs = findingIDs[:room]
	}
	if err := lockFindingsInTx(ctx, tx, tenantID, findingIDs); err != nil {
		return 0, err
	}
	gone, err := unavailableFindingsInTx(ctx, tx, tenantID, findingIDs)
	if err != nil {
		return 0, err
	}
	ids := make([]shared.ID, 0, len(findingIDs))
	for _, id := range findingIDs {
		if !gone[id] {
			ids = append(ids, id)
		}
	}
	if len(ids) == 0 {
		return 0, nil
	}
	if err := insertMembersInTx(ctx, tx, t, ids, remediation.MemberRolePrimary, remediation.JoinSourceAutoJoin, nil); err != nil {
		return 0, err
	}
	if err := bumpTaskInTx(ctx, tx, tenantID, taskID, remediation.TaskEventMembersAdded, nil,
		map[string]any{"count": len(ids), "role": "primary", "source": "auto_join"}); err != nil {
		return 0, err
	}
	tr := &RemediationTaskRepository{db: r.db}
	if err := tr.recomputeInTx(ctx, tx, tenantID, []shared.ID{taskID}, nil); err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("commit auto-join: %w", err)
	}
	return len(ids), nil
}

// SetAutoJoin turns an action's auto-join rule on or off. Only exact keys
// (upgrade, rotate) may turn it on (also a CHECK in the table).
func (r *RemediationSuggestionRepository) SetAutoJoin(ctx context.Context, tenantID, actionID shared.ID, on bool, actor *shared.ID) (*remediation.Action, error) {
	var kind string
	err := r.db.QueryRowContext(ctx, `SELECT kind FROM remediation_actions WHERE tenant_id = $1 AND id = $2`,
		tenantID.String(), actionID.String()).Scan(&kind)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("%w: remediation action not found", shared.ErrNotFound)
	}
	if err != nil {
		return nil, fmt.Errorf("read remediation action: %w", err)
	}
	if on && !remediation.AutoJoinAllowed(kind) {
		return nil, fmt.Errorf("%w: auto-join is only for package upgrades and secret rotations (an exact fix)", shared.ErrValidation)
	}
	if _, err := r.db.ExecContext(ctx, `UPDATE remediation_actions SET auto_join = $3,
		auto_join_by = CASE WHEN $3 THEN $4::uuid ELSE NULL END, auto_join_at = CASE WHEN $3 THEN now() ELSE NULL END,
		updated_at = now() WHERE tenant_id = $1 AND id = $2`, tenantID.String(), actionID.String(), on, idArg(actor)); err != nil {
		return nil, fmt.Errorf("set auto-join: %w", err)
	}
	return (&RemediationTaskRepository{db: r.db}).GetAction(ctx, tenantID, actionID)
}

// IsGroupMember reports whether the user belongs to the group, and the group
// to the tenant.
func (r *RemediationSuggestionRepository) IsGroupMember(ctx context.Context, tenantID, groupID, userID shared.ID) (bool, error) {
	var ok bool
	err := r.db.QueryRowContext(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM group_members gm
			JOIN groups g ON g.id = gm.group_id AND g.tenant_id = $1
			WHERE gm.group_id = $2 AND gm.user_id = $3)`,
		tenantID.String(), groupID.String(), userID.String()).Scan(&ok)
	if err != nil {
		return false, fmt.Errorf("check group member: %w", err)
	}
	return ok, nil
}

// OwnsFindingAssets reports whether every finding exists in the tenant and is
// on an asset the user owns as primary or secondary owner, directly or
// through a group of the tenant they belong to. A finding without an asset is
// not owned.
func (r *RemediationSuggestionRepository) OwnsFindingAssets(ctx context.Context, tenantID, userID shared.ID, findingIDs []shared.ID) (bool, error) {
	if len(findingIDs) == 0 {
		return false, nil
	}
	ids := rtIDStrings(findingIDs)
	var owned, total int
	err := r.db.QueryRowContext(ctx, `
		SELECT count(*) FILTER (WHERE EXISTS (
		           SELECT 1 FROM asset_owners ao
		           JOIN assets a ON a.id = ao.asset_id AND a.tenant_id = $1
		           WHERE ao.asset_id = f.asset_id
		             AND ao.ownership_type IN ('primary', 'secondary')
		             AND (ao.user_id = $2 OR ao.group_id IN (
		                 SELECT gm.group_id FROM group_members gm
		                 JOIN groups g ON g.id = gm.group_id AND g.tenant_id = $1
		                 WHERE gm.user_id = $2)))),
		       count(*)
		FROM findings f
		WHERE f.tenant_id = $1 AND f.id = ANY($3::uuid[])`,
		tenantID.String(), userID.String(), pq.Array(ids)).Scan(&owned, &total)
	if err != nil {
		return false, fmt.Errorf("check finding asset owners: %w", err)
	}
	return total == len(dedupeStrings(ids)) && owned == total, nil
}

func dedupeStrings(in []string) []string {
	seen := make(map[string]bool, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

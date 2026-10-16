package postgres

// Moving findings between remediation tasks, splitting and merging tasks
// (docs/rfcs/RFC-098-remediation-tasks.md §7). Every operation is one
// transaction: both tasks are locked in id order at the caller's versions,
// then the findings in id order; both sides are recomputed; a task emptied by
// a move is archived with a note; every finding and both tasks get one
// timeline entry.

import (
	"context"
	"database/sql"
	"fmt"
	"sort"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/api/pkg/domain/remediation"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// lockTasksInOrder locks tasks in id order (no deadlock between two moves in
// opposite directions) and checks each caller version.
func lockTasksInOrder(ctx context.Context, tx *sql.Tx, tenantID shared.ID, versions map[shared.ID]int) (map[shared.ID]*remediation.Task, error) {
	ids := make([]shared.ID, 0, len(versions))
	for id := range versions {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i].String() < ids[j].String() })
	out := make(map[shared.ID]*remediation.Task, len(ids))
	for _, id := range ids {
		t, err := lockTaskInTx(ctx, tx, tenantID, id, versions[id])
		if err != nil {
			return nil, err
		}
		out[id] = t
	}
	return out, nil
}

// activePrimaryInTx returns which of ids are active primary members of the
// task.
func activePrimaryInTx(ctx context.Context, tx *sql.Tx, tenantID, taskID shared.ID, ids []shared.ID) (map[shared.ID]bool, error) {
	got, err := queryIDsInTx(ctx, tx, `SELECT finding_id FROM remediation_task_members
		WHERE tenant_id = $1 AND task_id = $2 AND finding_id = ANY($3::uuid[]) AND left_at IS NULL AND role = 'primary'`,
		tenantID.String(), taskID.String(), pq.Array(rtIDStrings(ids)))
	if err != nil {
		return nil, fmt.Errorf("read task members: %w", err)
	}
	out := make(map[shared.ID]bool, len(got))
	for _, id := range got {
		out[id] = true
	}
	return out, nil
}

// leaveInTx ends the active memberships of findings in a task.
func leaveInTx(ctx context.Context, tx *sql.Tx, t *remediation.Task, ids []shared.ID, reason remediation.LeftReason, actor *shared.ID, extra map[string]any) error {
	if len(ids) == 0 {
		return nil
	}
	if _, err := tx.ExecContext(ctx, `UPDATE remediation_task_members SET left_at = now(), left_reason = $4, left_by = $5
		WHERE tenant_id = $1 AND task_id = $2 AND finding_id = ANY($3::uuid[]) AND left_at IS NULL`,
		t.TenantID.String(), t.ID.String(), pq.Array(rtIDStrings(ids)), string(reason), idArg(actor)); err != nil {
		return fmt.Errorf("leave task: %w", err)
	}
	data := map[string]any{"reason": string(reason)}
	for k, v := range extra {
		data[k] = v
	}
	return insertFindingTaskActivityInTx(ctx, tx, t, ids, "left", remediation.MemberRolePrimary, actor, data)
}

// archiveIfEmptyInTx archives a task with no active primary member.
func archiveIfEmptyInTx(ctx context.Context, tx *sql.Tx, tenantID, taskID shared.ID, note string) (bool, error) {
	res, err := tx.ExecContext(ctx, `UPDATE remediation_tasks SET archived_at = now(), archived_note = $3, updated_at = now(), version = version + 1
		WHERE tenant_id = $1 AND id = $2 AND archived_at IS NULL
		  AND NOT EXISTS (SELECT 1 FROM remediation_task_members m
		                  WHERE m.tenant_id = $1 AND m.task_id = $2 AND m.left_at IS NULL AND m.role = 'primary')`,
		tenantID.String(), taskID.String(), clipNote(note))
	if err != nil {
		return false, fmt.Errorf("archive task: %w", err)
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

func clipNote(s string) string {
	if len(s) <= remediation.MaxStateNote {
		return s
	}
	n := remediation.MaxStateNote
	for n > 0 && s[n]&0xC0 == 0x80 {
		n--
	}
	return s[:n]
}

// MoveMembers moves findings from one task to another (or out of any task)
// in one transaction. The caller has checked the compatibility rules and the
// data scope; this enforces the invariants: both tasks of the tenant, at the
// caller's versions, neither closed; the findings active primary members of
// the source (others are skipped and reported).
func (r *RemediationTaskRepository) MoveMembers(ctx context.Context, m remediation.MoveRequest) (*remediation.MoveResult, error) {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin move: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	res, err := r.moveInTx(ctx, tx, m)
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit move: %w", err)
	}
	return res, nil
}

// moveInTx is MoveMembers inside the caller's transaction.
func (r *RemediationTaskRepository) moveInTx(ctx context.Context, tx *sql.Tx, m remediation.MoveRequest) (*remediation.MoveResult, error) {
	versions := map[shared.ID]int{m.FromTaskID: m.FromVersion}
	if m.ToTaskID != nil {
		if *m.ToTaskID == m.FromTaskID {
			return nil, fmt.Errorf("%w: the source and the target are the same task", shared.ErrValidation)
		}
		versions[*m.ToTaskID] = m.ToVersion
	}
	tasks, err := lockTasksInOrder(ctx, tx, m.TenantID, versions)
	if err != nil {
		return nil, err
	}
	src := tasks[m.FromTaskID]
	if src.State.IsTerminal() {
		return nil, remediation.ErrTaskTerminal
	}
	var dst *remediation.Task
	if m.ToTaskID != nil {
		dst = tasks[*m.ToTaskID]
		if dst.State.IsTerminal() {
			return nil, remediation.ErrTaskTerminal
		}
	}
	if err := lockFindingsInTx(ctx, tx, m.TenantID, m.FindingIDs); err != nil {
		return nil, err
	}
	in, err := activePrimaryInTx(ctx, tx, m.TenantID, src.ID, m.FindingIDs)
	if err != nil {
		return nil, err
	}
	res := &remediation.MoveResult{Skipped: []shared.ID{}}
	moving := make([]shared.ID, 0, len(m.FindingIDs))
	for _, id := range m.FindingIDs {
		if in[id] {
			moving = append(moving, id)
		} else {
			res.Skipped = append(res.Skipped, id)
		}
	}
	if len(moving) == 0 {
		return nil, fmt.Errorf("%w: none of the findings is in the source task", shared.ErrValidation)
	}
	reason := remediation.LeftReasonMoved
	if m.Reason != "" {
		reason = m.Reason
	}
	extra := map[string]any{}
	if dst != nil {
		extra["to_task_id"], extra["to_task_title"] = dst.ID.String(), dst.Title
	}
	if err := leaveInTx(ctx, tx, src, moving, reason, m.ActorID, extra); err != nil {
		return nil, err
	}
	if dst != nil {
		src := src
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO remediation_task_members (tenant_id, task_id, finding_id, role, join_source, joined_by)
			SELECT $1, $2, f.id, 'primary', $4, $5 FROM findings f WHERE f.tenant_id = $1 AND f.id = ANY($3::uuid[])
			ON CONFLICT (task_id, finding_id) WHERE left_at IS NULL DO UPDATE SET role = 'primary'`,
			m.TenantID.String(), dst.ID.String(), pq.Array(rtIDStrings(moving)), string(joinSourceFor(reason)), idArg(m.ActorID)); err != nil {
			return nil, fmt.Errorf("join target task: %w", err)
		}
		if err := insertFindingTaskActivityInTx(ctx, tx, dst, moving, "joined", remediation.MemberRolePrimary, m.ActorID,
			map[string]any{"from_task_id": src.ID.String(), "from_task_title": src.Title}); err != nil {
			return nil, err
		}
	} else if m.ExcludeKey != "" {
		// Detached findings are not proposed for this fix again until a
		// person lets suggestions manage them.
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO remediation_key_exclusions (tenant_id, action_key, finding_id, reason, created_by)
			SELECT $1, $2, f.id, 'detached', $4 FROM findings f WHERE f.tenant_id = $1 AND f.id = ANY($3::uuid[])
			ON CONFLICT DO NOTHING`, m.TenantID.String(), m.ExcludeKey, pq.Array(rtIDStrings(moving)), idArg(m.ActorID)); err != nil {
			return nil, fmt.Errorf("record detach: %w", err)
		}
	}
	srcData := map[string]any{"count": len(moving), "operation": string(reason)}
	if dst != nil {
		srcData["to_task_id"], srcData["to_task_title"] = dst.ID.String(), dst.Title
	}
	if err := bumpTaskInTx(ctx, tx, m.TenantID, src.ID, remediation.TaskEventMembersRemoved, m.ActorID, srcData); err != nil {
		return nil, err
	}
	recompute := []shared.ID{src.ID}
	if dst != nil {
		if err := bumpTaskInTx(ctx, tx, m.TenantID, dst.ID, remediation.TaskEventMembersAdded, m.ActorID,
			map[string]any{"count": len(moving), "source": string(joinSourceFor(reason)), "from_task_id": src.ID.String(), "from_task_title": src.Title}); err != nil {
			return nil, err
		}
		recompute = append(recompute, dst.ID)
	}
	note := "Emptied: its findings were taken out"
	if dst != nil {
		note = fmt.Sprintf("Emptied: its findings moved to %q", dst.Title)
	}
	archived, err := archiveIfEmptyInTx(ctx, tx, m.TenantID, src.ID, note)
	if err != nil {
		return nil, err
	}
	if archived {
		if err := insertTaskEventInTx(ctx, tx, m.TenantID, src.ID, remediation.TaskEventStateChanged, m.ActorID,
			map[string]any{"to": string(remediation.TaskStateArchived), "note": note}); err != nil {
			return nil, err
		}
	}
	if err := r.recomputeInTx(ctx, tx, m.TenantID, recompute, m.ActorID); err != nil {
		return nil, err
	}
	res.Moved, res.SourceArchived = moving, archived
	return res, nil
}

func joinSourceFor(reason remediation.LeftReason) remediation.JoinSource {
	switch reason {
	case remediation.LeftReasonSplit:
		return remediation.JoinSourceSplit
	case remediation.LeftReasonMerged:
		return remediation.JoinSourceMerge
	case remediation.LeftReasonRegressed:
		return remediation.JoinSourceRegression
	}
	return remediation.JoinSourceMove
}

// SplitTask creates a task of the same fix (campaign, manual deadline, the
// given owner) and moves some of a task's findings to it, in one
// transaction. Returns the new task's id.
func (r *RemediationTaskRepository) SplitTask(ctx context.Context, sp remediation.SplitRequest) (shared.ID, *remediation.MoveResult, error) {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return shared.ID{}, nil, fmt.Errorf("begin split: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	src, err := lockTaskInTx(ctx, tx, sp.TenantID, sp.TaskID, sp.Version)
	if err != nil {
		return shared.ID{}, nil, err
	}
	if src.State.IsTerminal() {
		return shared.ID{}, nil, remediation.ErrTaskTerminal
	}
	child := shared.NewID()
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO remediation_tasks (id, tenant_id, action_id, campaign_id, title, description, assignee_user_id,
			assignee_group_id, manual_deadline, created_by)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
		child.String(), sp.TenantID.String(), src.ActionID.String(), idArg(src.CampaignID), sp.Title, src.Description,
		idArg(sp.Owner.UserID), idArg(sp.Owner.GroupID), timeArg(src.ManualDeadline), idArg(sp.ActorID)); err != nil {
		return shared.ID{}, nil, fmt.Errorf("create split task: %w", err)
	}
	if err := insertTaskEventInTx(ctx, tx, sp.TenantID, child, remediation.TaskEventCreated, sp.ActorID,
		map[string]any{"title": sp.Title, "split_from": src.ID.String(), "split_from_title": src.Title}); err != nil {
		return shared.ID{}, nil, err
	}
	res, err := r.moveInTx(ctx, tx, remediation.MoveRequest{TenantID: sp.TenantID, FromTaskID: src.ID, FromVersion: src.Version,
		ToTaskID: &child, ToVersion: 1, FindingIDs: sp.FindingIDs, Reason: remediation.LeftReasonSplit, ActorID: sp.ActorID})
	if err != nil {
		return shared.ID{}, nil, err
	}
	if err := tx.Commit(); err != nil {
		return shared.ID{}, nil, fmt.Errorf("commit split: %w", err)
	}
	return child, res, nil
}

// MergeTasks moves every finding of the source tasks into the target, in
// one transaction; the emptied sources are archived with a note. All tasks
// must be of the same action (the caller checked; this checks again).
func (r *RemediationTaskRepository) MergeTasks(ctx context.Context, mg remediation.MergeRequest) (int, error) {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("begin merge: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	versions := map[shared.ID]int{mg.TargetID: mg.TargetVersion}
	for id, v := range mg.Sources {
		versions[id] = v
	}
	tasks, err := lockTasksInOrder(ctx, tx, mg.TenantID, versions)
	if err != nil {
		return 0, err
	}
	target := tasks[mg.TargetID]
	moved := 0
	for id := range mg.Sources {
		src := tasks[id]
		if src.ActionID != target.ActionID {
			return 0, remediation.ErrMergeDifferentFix
		}
		ids, err := queryIDsInTx(ctx, tx, `SELECT finding_id FROM remediation_task_members
			WHERE tenant_id = $1 AND task_id = $2 AND left_at IS NULL AND role = 'primary'`, mg.TenantID.String(), id.String())
		if err != nil {
			return 0, fmt.Errorf("read merge members: %w", err)
		}
		if len(ids) == 0 {
			continue
		}
		// The locks are held: pass the current versions.
		cur := map[shared.ID]int{}
		for _, tid := range []shared.ID{id, mg.TargetID} {
			var v int
			if err := tx.QueryRowContext(ctx, `SELECT version FROM remediation_tasks WHERE tenant_id = $1 AND id = $2`,
				mg.TenantID.String(), tid.String()).Scan(&v); err != nil {
				return 0, fmt.Errorf("read task version: %w", err)
			}
			cur[tid] = v
		}
		target := mg.TargetID
		if _, err := r.moveInTx(ctx, tx, remediation.MoveRequest{TenantID: mg.TenantID, FromTaskID: id, FromVersion: cur[id],
			ToTaskID: &target, ToVersion: cur[target], FindingIDs: ids, Reason: remediation.LeftReasonMerged, ActorID: mg.ActorID}); err != nil {
			return 0, err
		}
		moved += len(ids)
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("commit merge: %w", err)
	}
	return moved, nil
}

// CountActivePrimary counts how many of ids are active primary members of
// the task.
func (r *RemediationTaskRepository) CountActivePrimary(ctx context.Context, tenantID, taskID shared.ID, ids []shared.ID) (int, error) {
	var n int
	err := r.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM remediation_task_members
		WHERE tenant_id = $1 AND task_id = $2 AND finding_id = ANY($3::uuid[]) AND left_at IS NULL AND role = 'primary'`,
		tenantID.String(), taskID.String(), pq.Array(rtIDStrings(ids))).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("count task members: %w", err)
	}
	return n, nil
}

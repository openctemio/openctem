package postgres

// Claiming findings as primary members of a task
// (docs/rfcs/RFC-098-remediation-tasks.md §6.1). A finding is the primary
// member of at most one active task. Every path that adds primary members
// (accepting a suggestion, creating a task, adding members) claims them here,
// inside its own transaction:
//
//  1. the tasks findings are to be moved out of are locked in id order;
//  2. the findings are locked in id order (with any other rows the caller
//     names), so two claims of one finding serialize;
//  3. each finding is classified: closed or gone (the caller drops it),
//     taken by another active task (refused, skipped or moved as the request
//     says), or free;
//  4. a refused finding fails the whole claim with a
//     *remediation.FindingsInOtherTaskError naming the finding and its task
//     only (the service decides what of that task the caller may read);
//  5. moved findings leave their source task (left_reason 'moved'), with a
//     timeline entry on each finding and on the source, which is recomputed
//     and archived when emptied.
//
// The caller then inserts the members and calls recordClaimMovesInTx for the
// target side of each move. The partial unique index
// ux_remediation_task_members_primary stays the last word: if a concurrent
// claim slipped past, the insert fails and the request answers 409.

import (
	"context"
	"database/sql"
	"fmt"
	"sort"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/api/pkg/domain/remediation"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// claimTarget is the task a claimed finding goes to.
type claimTarget struct {
	id    shared.ID
	title string
}

// claimInput is one claim of findings as primary members.
type claimInput struct {
	tenantID shared.ID
	// ids are the findings to claim.
	ids []shared.ID
	// alsoLock are other findings of the request (related links) locked in
	// the same id-ordered pass.
	alsoLock []shared.ID
	// except is the target task when it already exists: being its member
	// already is not a conflict.
	except *shared.ID
	res    remediation.ConflictResolution
	// into returns the target task of a finding (for the move records).
	into  func(shared.ID) claimTarget
	actor *shared.ID
}

// claimOutcome is what a claim decided.
type claimOutcome struct {
	closed  map[shared.ID]bool
	skipped map[shared.ID]bool
	report  remediation.ClaimReport
}

// keep returns ids without the closed and the skipped findings.
func (o *claimOutcome) keep(ids []shared.ID) []shared.ID {
	out := make([]shared.ID, 0, len(ids))
	for _, id := range ids {
		if !o.closed[id] && !o.skipped[id] {
			out = append(out, id)
		}
	}
	return out
}

func (o *claimOutcome) closedIDs() []shared.ID  { return sortedIDs(o.closed) }
func (o *claimOutcome) skippedIDs() []shared.ID { return sortedIDs(o.skipped) }

func (o *claimOutcome) moved() int {
	n := 0
	for _, m := range o.report.Moves {
		n += len(m.FindingIDs)
	}
	return n
}

func sortedIDs(m map[shared.ID]bool) []shared.ID {
	out := make([]shared.ID, 0, len(m))
	for id := range m {
		out = append(out, id)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].String() < out[j].String() })
	return out
}

// takenRow is a finding that is the primary member of another active task.
type takenRow struct {
	findingID shared.ID
	title     string
	taskID    shared.ID
}

// activePrimaryRowsInTx returns, for the findings, their active primary
// membership in a task other than except.
func activePrimaryRowsInTx(ctx context.Context, q rowsQuerier, tenantID shared.ID, ids []shared.ID, except *shared.ID) ([]takenRow, error) {
	rows, err := q.QueryContext(ctx, `
		SELECT m.finding_id, f.title, m.task_id
		FROM remediation_task_members m
		JOIN findings f ON f.tenant_id = m.tenant_id AND f.id = m.finding_id
		WHERE m.tenant_id = $1 AND m.finding_id = ANY($2::uuid[]) AND m.left_at IS NULL AND m.role = 'primary'
		  AND ($3::uuid IS NULL OR m.task_id <> $3::uuid)
		ORDER BY m.finding_id`,
		tenantID.String(), pq.Array(rtIDStrings(ids)), idArg(except))
	if err != nil {
		return nil, fmt.Errorf("read primary tasks: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []takenRow
	for rows.Next() {
		var r takenRow
		if err := rows.Scan(&r.findingID, &r.title, &r.taskID); err != nil {
			return nil, fmt.Errorf("read primary tasks: %w", err)
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("read primary tasks: %w", err)
	}
	return out, nil
}

// ActivePrimaryTasks maps each finding that is the primary member of an
// active task to that task.
func (r *RemediationTaskRepository) ActivePrimaryTasks(ctx context.Context, tenantID shared.ID, findingIDs []shared.ID) (map[shared.ID]shared.ID, error) {
	out := map[shared.ID]shared.ID{}
	if len(findingIDs) == 0 {
		return out, nil
	}
	rows, err := activePrimaryRowsInTx(ctx, r.db, tenantID, findingIDs, nil)
	if err != nil {
		return nil, err
	}
	for _, row := range rows {
		out[row.findingID] = row.taskID
	}
	return out, nil
}

// claimFindingsInTx claims findings as primary members (see the file
// comment). It is shared by every path that adds primary members.
func (r *RemediationTaskRepository) claimFindingsInTx(ctx context.Context, tx *sql.Tx, in claimInput) (*claimOutcome, error) {
	out := &claimOutcome{closed: map[shared.ID]bool{}, skipped: map[shared.ID]bool{}, report: remediation.ClaimReport{Reason: in.res.MoveReason}}
	if len(in.ids) == 0 {
		return out, lockFindingsInTx(ctx, tx, in.tenantID, in.alsoLock)
	}
	// 1. The source tasks of the moves first (tasks before findings, the
	// order moves and member changes use), in id order.
	sources, err := lockMoveSourcesInTx(ctx, tx, in)
	if err != nil {
		return nil, err
	}
	// 2. The findings.
	if err := lockFindingsInTx(ctx, tx, in.tenantID, append(append([]shared.ID{}, in.ids...), in.alsoLock...)); err != nil {
		return nil, err
	}
	// 3-4. Classify; refuse what the request does not resolve.
	if out.closed, err = closedFindingsInTx(ctx, tx, in.tenantID, in.ids); err != nil {
		return nil, err
	}
	moving, err := classifyTakenInTx(ctx, tx, in, sources, out)
	if err != nil {
		return nil, err
	}
	// 5. Move: end the source memberships, per source and target.
	srcIDs := make([]shared.ID, 0, len(moving))
	for id := range moving {
		srcIDs = append(srcIDs, id)
	}
	sort.Slice(srcIDs, func(i, j int) bool { return srcIDs[i].String() < srcIDs[j].String() })
	for _, sid := range srcIDs {
		moves, err := r.moveOutInTx(ctx, tx, in, sources[sid], moving[sid])
		if err != nil {
			return nil, err
		}
		out.report.Moves = append(out.report.Moves, moves...)
	}
	return out, nil
}

// lockMoveSourcesInTx locks, in id order, the tasks the findings to move are
// in now, among those the service cleared.
func lockMoveSourcesInTx(ctx context.Context, tx *sql.Tx, in claimInput) (map[shared.ID]*remediation.Task, error) {
	if len(in.res.Move) == 0 {
		return map[shared.ID]*remediation.Task{}, nil
	}
	pre, err := activePrimaryRowsInTx(ctx, tx, in.tenantID, in.res.Move, in.except)
	if err != nil {
		return nil, err
	}
	ids := map[shared.ID]int{}
	for _, row := range pre {
		if in.res.MovableFrom[row.taskID] {
			ids[row.taskID] = 0
		}
	}
	return lockTasksInOrder(ctx, tx, in.tenantID, ids)
}

// closedFindingsInTx returns the findings that are closed or gone.
func closedFindingsInTx(ctx context.Context, tx *sql.Tx, tenantID shared.ID, ids []shared.ID) (map[shared.ID]bool, error) {
	open, err := queryIDsInTx(ctx, tx, `SELECT id FROM findings
		WHERE tenant_id = $1 AND id = ANY($2::uuid[]) AND status <> ALL($3::text[])`,
		tenantID.String(), pq.Array(rtIDStrings(ids)), closedStatusArray())
	if err != nil {
		return nil, fmt.Errorf("check findings: %w", err)
	}
	isOpen := make(map[shared.ID]bool, len(open))
	for _, id := range open {
		isOpen[id] = true
	}
	closed := map[shared.ID]bool{}
	for _, id := range ids {
		if !isOpen[id] {
			closed[id] = true
		}
	}
	return closed, nil
}

// classifyTakenInTx sorts the open findings taken by another active task:
// moved (from a locked, cleared source), skipped, or refused. Refusals fail
// the claim; it returns the findings to move per source task.
func classifyTakenInTx(ctx context.Context, tx *sql.Tx, in claimInput, sources map[shared.ID]*remediation.Task, out *claimOutcome) (map[shared.ID][]shared.ID, error) {
	taken, err := activePrimaryRowsInTx(ctx, tx, in.tenantID, in.ids, in.except)
	if err != nil {
		return nil, err
	}
	move := make(map[shared.ID]bool, len(in.res.Move))
	for _, id := range in.res.Move {
		move[id] = true
	}
	var refused []remediation.FindingConflict
	moving := map[shared.ID][]shared.ID{}
	for _, row := range taken {
		switch {
		case out.closed[row.findingID]:
		case move[row.findingID] && sources[row.taskID] != nil:
			moving[row.taskID] = append(moving[row.taskID], row.findingID)
		case !move[row.findingID] && in.res.Resolves():
			out.skipped[row.findingID] = true
		default:
			// Not resolved, or named for a move out of a task the caller
			// was not cleared to change (it changed task since the check).
			refused = append(refused, remediation.FindingConflict{FindingID: row.findingID, FindingTitle: row.title, TaskID: row.taskID})
		}
	}
	if len(refused) > 0 {
		ids := make([]shared.ID, len(refused))
		for i, c := range refused {
			ids[i] = c.FindingID
		}
		return nil, &remediation.FindingsInOtherTaskError{FindingIDs: ids, Conflicts: refused}
	}
	return moving, nil
}

// moveOutInTx ends the memberships of findings in their source task, grouped
// by target, with timeline entries; the source is recomputed and archived
// when emptied.
func (r *RemediationTaskRepository) moveOutInTx(ctx context.Context, tx *sql.Tx, in claimInput, src *remediation.Task, ids []shared.ID) ([]remediation.ClaimMove, error) {
	if src.State.IsTerminal() {
		return nil, remediation.ErrTaskTerminal
	}
	byTarget := map[claimTarget][]shared.ID{}
	var order []claimTarget
	for _, fid := range ids {
		tg := in.into(fid)
		if _, ok := byTarget[tg]; !ok {
			order = append(order, tg)
		}
		byTarget[tg] = append(byTarget[tg], fid)
	}
	moves := make([]remediation.ClaimMove, 0, len(order))
	for _, tg := range order {
		group := byTarget[tg]
		if err := leaveInTx(ctx, tx, src, group, remediation.LeftReasonMoved, in.actor,
			map[string]any{"to_task_id": tg.id.String(), "to_task_title": tg.title, "move_reason": in.res.MoveReason}); err != nil {
			return nil, err
		}
		if err := bumpTaskInTx(ctx, tx, in.tenantID, src.ID, remediation.TaskEventMembersRemoved, in.actor,
			map[string]any{"count": len(group), "operation": string(remediation.LeftReasonMoved), "to_task_id": tg.id.String(),
				"to_task_title": tg.title, "move_reason": in.res.MoveReason}); err != nil {
			return nil, err
		}
		moves = append(moves, remediation.ClaimMove{FromTaskID: src.ID, FromTitle: src.Title, ToTaskID: tg.id, ToTitle: tg.title, FindingIDs: group})
	}
	if err := r.recomputeInTx(ctx, tx, in.tenantID, []shared.ID{src.ID}, in.actor); err != nil {
		return nil, err
	}
	archived, err := archiveIfEmptyInTx(ctx, tx, in.tenantID, src.ID, fmt.Sprintf("Emptied: its findings moved to %q", order[0].title))
	if err != nil {
		return nil, err
	}
	for i := range moves {
		moves[i].SourceArchived = archived
	}
	return moves, nil
}

// recordClaimMovesInTx writes the target side of each move: one timeline
// entry on the target task naming the source. Call it after the members are
// inserted.
func recordClaimMovesInTx(ctx context.Context, tx *sql.Tx, tenantID shared.ID, rep remediation.ClaimReport, actor *shared.ID) error {
	for _, m := range rep.Moves {
		if err := insertTaskEventInTx(ctx, tx, tenantID, m.ToTaskID, remediation.TaskEventMembersAdded, actor,
			map[string]any{"count": len(m.FindingIDs), "role": "primary", "source": "moved", "from_task_id": m.FromTaskID.String(),
				"from_task_title": m.FromTitle, "move_reason": rep.Reason}); err != nil {
			return err
		}
	}
	return nil
}

package integration

// Claim conflicts (docs/rfcs/RFC-098-remediation-tasks.md §6.1) on a
// migrated database: findings that already belong to another active task
// refuse a task create, an add and an accept with the holding task's
// details (its title and owner only when the caller can read it, and
// whether they may move the finding); the request may skip them or move
// named ones (audited, a timeline entry on both tasks, the trackers told,
// the SLA kept); a caller who cannot change the holding task cannot move;
// two concurrent accepts of one finding: exactly one wins.

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	remediationapp "github.com/openctemio/openctem/api/internal/app/remediation"
	auditdom "github.com/openctemio/openctem/api/pkg/domain/audit"
	"github.com/openctemio/openctem/api/pkg/domain/remediation"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

type claimAudit struct {
	mu     sync.Mutex
	events []auditapp.AuditEvent
}

func (a *claimAudit) LogEvent(_ context.Context, _ auditapp.AuditContext, ev auditapp.AuditEvent) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.events = append(a.events, ev)
	return nil
}

func (a *claimAudit) of(action auditdom.Action) []auditapp.AuditEvent {
	a.mu.Lock()
	defer a.mu.Unlock()
	var out []auditapp.AuditEvent
	for _, e := range a.events {
		if e.Action == action {
			out = append(out, e)
		}
	}
	return out
}

type claimMoves struct {
	mu     sync.Mutex
	events []remediation.TaskMoveEvent
}

func (m *claimMoves) TaskMembersMoved(_ context.Context, ev remediation.TaskMoveEvent) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.events = append(m.events, ev)
}

func claimRig(t *testing.T) (*rsRig, *claimAudit, *claimMoves) {
	r := newAcceptRig(t)
	au, mv := &claimAudit{}, &claimMoves{}
	r.svc.SetAuditLogger(au)
	r.svc.SetMoveNotifier(mv)
	return r, au, mv
}

func (r *rsRig) mustTask(ctx context.Context, title string, owner *shared.ID, ids ...shared.ID) *remediation.Task {
	r.t.Helper()
	t, err := r.svc.CreateTask(ctx, remediationapp.CreateTaskInput{TenantID: r.tenant, ActorID: &r.admin, Title: title,
		AssigneeGroupID: owner, FindingIDs: ids}, auditapp.AuditContext{})
	require.NoError(r.t, err)
	return t
}

func (r *rsRig) primaryTaskOf(f shared.ID) shared.ID {
	r.t.Helper()
	var id shared.ID
	require.NoError(r.t, r.db.QueryRow(`SELECT task_id FROM remediation_task_members
		WHERE tenant_id = $1 AND finding_id = $2 AND left_at IS NULL AND role = 'primary'`, r.tenant.String(), f.String()).Scan(&id))
	return id
}

func conflictsOf(t *testing.T, err error) []remediation.FindingConflict {
	t.Helper()
	require.Error(t, err)
	assert.ErrorIs(t, err, remediation.ErrFindingsInOtherTask)
	assert.ErrorIs(t, err, shared.ErrConflict)
	e, ok := remediation.AsFindingsInOtherTask(err)
	require.True(t, ok, "a FindingsInOtherTaskError, got %v", err)
	return e.Conflicts
}

func TestRemediationClaim_CreateRefusesSkipsAndMoves(t *testing.T) {
	r, au, mv := claimRig(t)
	ctx := r.adminCtx()
	f1 := r.finding(r.assetA, "new", nil)
	f2 := r.finding(r.assetA, "new", nil)
	f3 := r.finding(r.assetB, "new", nil)
	held := r.mustTask(ctx, "Held by the team", &r.group, f1, f3)
	var sla1 any
	require.NoError(t, r.db.QueryRow(`SELECT sla_deadline FROM findings WHERE id = $1`, f1.String()).Scan(&sla1))

	// Refused, with the details of the holding task.
	_, err := r.svc.CreateTask(ctx, remediationapp.CreateTaskInput{TenantID: r.tenant, ActorID: &r.admin, Title: "New",
		FindingIDs: []shared.ID{f1, f2}}, auditapp.AuditContext{})
	cs := conflictsOf(t, err)
	require.Len(t, cs, 1)
	assert.Equal(t, f1, cs[0].FindingID)
	assert.Equal(t, "rt finding", cs[0].FindingTitle)
	assert.Equal(t, held.ID, cs[0].TaskID)
	require.NotNil(t, cs[0].TaskTitle)
	assert.Equal(t, "Held by the team", *cs[0].TaskTitle)
	require.NotNil(t, cs[0].AssigneeGroupID)
	assert.Equal(t, r.group, *cs[0].AssigneeGroupID)
	assert.True(t, cs[0].CanMove)

	// Skip: the task takes only the free finding.
	skipped, err := r.svc.CreateTask(ctx, remediationapp.CreateTaskInput{TenantID: r.tenant, ActorID: &r.admin, Title: "Skip",
		FindingIDs: []shared.ID{f1, f2}, Conflicts: remediation.ConflictResolution{Skip: true}}, auditapp.AuditContext{})
	require.NoError(t, err)
	assert.Equal(t, 1, skipped.Counts.Total)
	assert.Equal(t, held.ID, r.primaryTaskOf(f1), "a skipped finding stays where it was")
	assert.Equal(t, skipped.ID, r.primaryTaskOf(f2))

	// A move needs a reason, and only names findings of the request.
	_, err = r.svc.CreateTask(ctx, remediationapp.CreateTaskInput{TenantID: r.tenant, ActorID: &r.admin, Title: "Move",
		FindingIDs: []shared.ID{f1}, Conflicts: remediation.ConflictResolution{Move: []shared.ID{f1}}}, auditapp.AuditContext{})
	assert.ErrorIs(t, err, shared.ErrValidation)
	_, err = r.svc.CreateTask(ctx, remediationapp.CreateTaskInput{TenantID: r.tenant, ActorID: &r.admin, Title: "Move",
		FindingIDs: []shared.ID{f1}, Conflicts: remediation.ConflictResolution{Move: []shared.ID{f3}, MoveReason: "x"}}, auditapp.AuditContext{})
	assert.ErrorIs(t, err, shared.ErrValidation)

	// Move: f1 leaves the holding task (history kept), keeps its SLA.
	moved, err := r.svc.CreateTask(ctx, remediationapp.CreateTaskInput{TenantID: r.tenant, ActorID: &r.admin, Title: "Moved here",
		FindingIDs: []shared.ID{f1}, Conflicts: remediation.ConflictResolution{Move: []shared.ID{f1}, MoveReason: "Owned by payments now"}},
		auditapp.AuditContext{})
	require.NoError(t, err)
	assert.Equal(t, moved.ID, r.primaryTaskOf(f1))
	var reason string
	require.NoError(t, r.db.QueryRow(`SELECT left_reason FROM remediation_task_members
		WHERE task_id = $1 AND finding_id = $2 AND left_at IS NOT NULL`, held.ID.String(), f1.String()).Scan(&reason))
	assert.Equal(t, "moved", reason)
	var sla2 any
	require.NoError(t, r.db.QueryRow(`SELECT sla_deadline FROM findings WHERE id = $1`, f1.String()).Scan(&sla2))
	assert.Equal(t, sla1, sla2, "a moved finding keeps its SLA")
	var srcEvents, dstEvents int
	require.NoError(t, r.db.QueryRow(`SELECT count(*) FROM remediation_task_events WHERE task_id = $1 AND kind = 'members_removed'
		AND data->>'to_task_id' = $2 AND data->>'move_reason' = 'Owned by payments now'`, held.ID.String(), moved.ID.String()).Scan(&srcEvents))
	require.NoError(t, r.db.QueryRow(`SELECT count(*) FROM remediation_task_events WHERE task_id = $1 AND kind = 'members_added'
		AND data->>'source' = 'moved' AND data->>'from_task_id' = $2`, moved.ID.String(), held.ID.String()).Scan(&dstEvents))
	assert.Equal(t, 1, srcEvents, "timeline entry on the source")
	assert.Equal(t, 1, dstEvents, "timeline entry on the target")

	audits := au.of(auditdom.ActionRemediationTaskFindingsMoved)
	require.Len(t, audits, 1, "one audit row per source task")
	assert.Equal(t, held.ID.String(), audits[0].ResourceID)
	assert.Equal(t, "Owned by payments now", audits[0].Metadata["reason"])
	require.Len(t, mv.events, 1, "both trackers are told")
	assert.Equal(t, held.ID, mv.events[0].FromTaskID)
	require.NotNil(t, mv.events[0].ToTaskID)
	assert.Equal(t, moved.ID, *mv.events[0].ToTaskID)

	src, err := r.svc.GetTask(ctx, r.tenant, held.ID)
	require.NoError(t, err)
	assert.Equal(t, 1, src.Counts.Total, "the source is recomputed")
}

func TestRemediationClaim_AddMembersConflict(t *testing.T) {
	r, _, _ := claimRig(t)
	ctx := r.adminCtx()
	f1 := r.finding(r.assetA, "new", nil)
	f2 := r.finding(r.assetA, "new", nil)
	held := r.mustTask(ctx, "Held", nil, f1)
	target := r.mustTask(ctx, "Target", nil, f2)

	_, err := r.svc.AddMembers(ctx, remediationapp.AddMembersInput{TenantID: r.tenant, TaskID: target.ID, ActorID: &r.admin,
		Version: target.Version, FindingIDs: []shared.ID{f1, f2}}, auditapp.AuditContext{})
	cs := conflictsOf(t, err)
	require.Len(t, cs, 1, "already being a member of the target is no conflict")
	assert.Equal(t, held.ID, cs[0].TaskID)

	// Related links carry no status: never a conflict.
	got, err := r.svc.AddMembers(ctx, remediationapp.AddMembersInput{TenantID: r.tenant, TaskID: target.ID, ActorID: &r.admin,
		Version: target.Version, FindingIDs: []shared.ID{f1}, Role: remediation.MemberRoleRelated}, auditapp.AuditContext{})
	require.NoError(t, err)

	got, err = r.svc.AddMembers(ctx, remediationapp.AddMembersInput{TenantID: r.tenant, TaskID: target.ID, ActorID: &r.admin,
		Version: got.Version, FindingIDs: []shared.ID{f1},
		Conflicts: remediation.ConflictResolution{Move: []shared.ID{f1}, MoveReason: "same fix"}}, auditapp.AuditContext{})
	require.NoError(t, err)
	assert.Equal(t, target.ID, r.primaryTaskOf(f1))
	assert.Equal(t, 2, got.Counts.Total)
	var archived bool
	require.NoError(t, r.db.QueryRow(`SELECT archived_at IS NOT NULL FROM remediation_tasks WHERE id = $1`, held.ID.String()).Scan(&archived))
	assert.True(t, archived, "a source emptied by a move is archived")
}

func TestRemediationClaim_RestrictedCallerCannotMove(t *testing.T) {
	r, _, _ := claimRig(t)
	admin := r.adminCtx()
	member := r.memberCtx()
	fa := r.finding(r.assetA, "new", nil)
	fb := r.finding(r.assetB, "new", nil) // outside the member's scope
	fa2 := r.finding(r.assetA, "new", nil)
	held := r.mustTask(admin, "Mixed", &r.group, fa, fb)

	_, err := r.svc.CreateTask(member, remediationapp.CreateTaskInput{TenantID: r.tenant, ActorID: &r.member, Title: "Mine",
		FindingIDs: []shared.ID{fa, fa2}}, auditapp.AuditContext{})
	cs := conflictsOf(t, err)
	require.Len(t, cs, 1)
	assert.Equal(t, held.ID, cs[0].TaskID)
	require.NotNil(t, cs[0].TaskTitle, "the member sees the task through their own finding")
	assert.False(t, cs[0].CanMove, "the task has findings outside the member's scope")

	_, err = r.svc.CreateTask(member, remediationapp.CreateTaskInput{TenantID: r.tenant, ActorID: &r.member, Title: "Mine",
		FindingIDs: []shared.ID{fa, fa2}, Conflicts: remediation.ConflictResolution{Move: []shared.ID{fa}, MoveReason: "mine"}},
		auditapp.AuditContext{})
	assert.ErrorIs(t, err, remediation.ErrMoveNotAllowed)
	assert.ErrorIs(t, err, shared.ErrForbidden)
	assert.Equal(t, held.ID, r.primaryTaskOf(fa), "nothing moved")

	// Skipping is always allowed.
	mine, err := r.svc.CreateTask(member, remediationapp.CreateTaskInput{TenantID: r.tenant, ActorID: &r.member, Title: "Mine",
		FindingIDs: []shared.ID{fa, fa2}, Conflicts: remediation.ConflictResolution{Skip: true}}, auditapp.AuditContext{})
	require.NoError(t, err)
	assert.Equal(t, mine.ID, r.primaryTaskOf(fa2))

	// Another tenant cannot claim, skip or move this tenant's findings.
	_, err = r.svc.CreateTask(admin, remediationapp.CreateTaskInput{TenantID: r.other, ActorID: &r.admin, Title: "Other",
		FindingIDs: []shared.ID{fa}, Conflicts: remediation.ConflictResolution{Move: []shared.ID{fa}, MoveReason: "x"}}, auditapp.AuditContext{})
	assert.ErrorIs(t, err, shared.ErrNotFound)
	assert.Equal(t, held.ID, r.primaryTaskOf(fa))
}

func TestRemediationClaim_AcceptConflictSkipMove(t *testing.T) {
	r, au, _ := claimRig(t)
	ctx := r.adminCtx()
	a1 := r.keyed(r.assetA, djangoKey, "P1")
	a2 := r.keyed(r.assetA, djangoKey, "P2")
	a3 := r.keyed(r.assetA, djangoKey, "P2")
	r.run()
	sg := r.list(ctx)[0]
	require.ElementsMatch(t, []shared.ID{a1, a2, a3}, sg.FindingIDs)
	// Since the suggestion was made, a2 and a3 joined a task by hand.
	held := r.mustTask(ctx, "By hand", nil, a2, a3)

	_, err := r.sug.Accept(ctx, remediationapp.AcceptInput{TenantID: r.tenant, ID: sg.ID, Version: sg.Version, ActorID: &r.admin},
		auditapp.AuditContext{})
	cs := conflictsOf(t, err)
	require.Len(t, cs, 2, "taken findings are no longer dropped silently")
	got, err := r.sug.Get(ctx, r.tenant, sg.ID)
	require.NoError(t, err)
	assert.True(t, got.State.IsOpen(), "a refused accept changes nothing")

	res, err := r.sug.Accept(ctx, remediationapp.AcceptInput{TenantID: r.tenant, ID: sg.ID, Version: sg.Version, ActorID: &r.admin,
		Conflicts: remediation.ConflictResolution{Move: []shared.ID{a2}, MoveReason: "belongs to the upgrade"}}, auditapp.AuditContext{})
	require.NoError(t, err)
	assert.Equal(t, []shared.ID{a3}, res.Skipped, "unnamed taken findings are skipped")
	assert.Equal(t, 1, res.Moved)
	require.Len(t, res.TaskIDs, 1)
	assert.Equal(t, res.TaskIDs[0], r.primaryTaskOf(a1))
	assert.Equal(t, res.TaskIDs[0], r.primaryTaskOf(a2))
	assert.Equal(t, held.ID, r.primaryTaskOf(a3))
	require.Len(t, au.of(auditdom.ActionRemediationTaskFindingsMoved), 1)
}

func TestRemediationClaim_ConcurrentAcceptsOneWins(t *testing.T) {
	r, _, _ := claimRig(t)
	ctx := r.adminCtx()
	r.keyed(r.assetA, djangoKey, "P1")
	r.keyed(r.assetA, djangoKey, "P2")
	r.run()
	sg := r.list(ctx)[0]
	// A second open suggestion over the same findings (another key).
	twin := shared.NewID()
	r.exec(`INSERT INTO remediation_suggestions (id, tenant_id, kind, algorithm, algorithm_version, action_key, key_kind, title,
			identity, partitions, finding_ids, member_count, risk_points, risk_parts, has_urgent, confidence, fix_spec, state, surfaced_at)
		SELECT $2::uuid, tenant_id, kind, algorithm, algorithm_version, action_key || ':twin', key_kind, title,
			md5($3), partitions, finding_ids, member_count, risk_points, risk_parts, has_urgent, confidence, fix_spec, state, surfaced_at
		FROM remediation_suggestions WHERE id = $1`, sg.ID.String(), twin.String(), twin.String())

	var wg sync.WaitGroup
	errs := make([]error, 2)
	for i, id := range []shared.ID{sg.ID, twin} {
		wg.Add(1)
		go func(i int, id shared.ID) {
			defer wg.Done()
			_, errs[i] = r.sug.Accept(ctx, remediationapp.AcceptInput{TenantID: r.tenant, ID: id, Version: 1, ActorID: &r.admin},
				auditapp.AuditContext{})
		}(i, id)
	}
	wg.Wait()
	wins, conflicts := 0, 0
	for _, err := range errs {
		switch {
		case err == nil:
			wins++
		case errors.Is(err, remediation.ErrFindingsInOtherTask):
			conflicts++
			e, _ := remediation.AsFindingsInOtherTask(err)
			assert.Len(t, e.Conflicts, 2)
		default:
			t.Fatalf("unexpected error: %v", err)
		}
	}
	assert.Equal(t, 1, wins, "exactly one accept wins")
	assert.Equal(t, 1, conflicts, "the other answers 409")
}

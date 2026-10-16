package integration

// Moving findings between remediation tasks, splitting and merging
// (docs/rfcs/RFC-098-remediation-tasks.md §7) on a migrated database: the
// compatibility warnings, versions, archiving an emptied task, undo, detach
// with the exclusion, split and merge rules, tenant isolation and data scope.

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	remediationapp "github.com/openctemio/openctem/api/internal/app/remediation"
	"github.com/openctemio/openctem/api/pkg/domain/remediation"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

func (r *rtRig) newTask(ctx context.Context, title string, action *shared.ID, user, group *shared.ID, findings ...shared.ID) *remediation.Task {
	r.t.Helper()
	t, err := r.svc.CreateTask(ctx, remediationapp.CreateTaskInput{TenantID: r.tenant, ActorID: &r.admin, Title: title,
		ActionID: action, AssigneeUserID: user, AssigneeGroupID: group, FindingIDs: findings}, auditapp.AuditContext{})
	require.NoError(r.t, err)
	return t
}

func (r *rtRig) actionFor(key string) shared.ID {
	r.t.Helper()
	id := shared.NewID()
	r.exec(`INSERT INTO remediation_actions (id, tenant_id, action_key, kind, title, origin) VALUES ($1, $2, $3, 'upgrade', $3, 'suggestion')`,
		id.String(), r.tenant.String(), key)
	return id
}

func TestRemediationMoves_WarningsVersionsArchiveUndo(t *testing.T) {
	r := newRTRig(t)
	ctx := r.adminCtx()
	act := r.actionFor("upgrade:pypi:django:4.2.30")
	f1, f2, f3 := r.finding(r.assetA, "new", nil), r.finding(r.assetA, "new", nil), r.finding(r.assetA, "new", nil)
	src := r.newTask(ctx, "Payments", &act, &r.admin, nil, f1, f2)
	same := r.newTask(ctx, "Payments 2", &act, &r.admin, nil, f3)
	other := r.newTask(ctx, "Search", &act, nil, &r.group, r.finding(r.assetA, "new", nil))

	// Same fix, same owner: no warning.
	p, err := r.svc.PreviewMove(ctx, remediationapp.MoveInput{TenantID: r.tenant, FromTaskID: src.ID, FromVersion: src.Version,
		ToTaskID: &same.ID, ToVersion: same.Version, FindingIDs: []shared.ID{f1}})
	require.NoError(t, err)
	assert.Empty(t, p.Warnings)
	out, err := r.svc.Move(ctx, remediationapp.MoveInput{TenantID: r.tenant, FromTaskID: src.ID, FromVersion: src.Version,
		ToTaskID: &same.ID, ToVersion: same.Version, FindingIDs: []shared.ID{f1}, ActorID: &r.admin}, auditapp.AuditContext{})
	require.NoError(t, err)
	assert.Equal(t, []shared.ID{f1}, out.Moved)
	assert.Equal(t, 1, out.Source.Counts.Total)
	assert.Equal(t, 2, out.Target.Counts.Total)

	// A stale version is refused.
	_, err = r.svc.Move(ctx, remediationapp.MoveInput{TenantID: r.tenant, FromTaskID: src.ID, FromVersion: src.Version,
		ToTaskID: &same.ID, ToVersion: out.Target.Version, FindingIDs: []shared.ID{f2}, Confirm: true}, auditapp.AuditContext{})
	assert.ErrorIs(t, err, remediation.ErrTaskVersionConflict)

	// Another owner, and emptying the source: needs confirmation.
	_, err = r.svc.Move(ctx, remediationapp.MoveInput{TenantID: r.tenant, FromTaskID: src.ID, FromVersion: out.Source.Version,
		ToTaskID: &other.ID, ToVersion: other.Version, FindingIDs: []shared.ID{f2}}, auditapp.AuditContext{})
	var mc *remediation.MoveNeedsConfirmationError
	require.ErrorAs(t, err, &mc)
	assert.ElementsMatch(t, []remediation.MoveWarning{remediation.MoveWarnDifferentOwner, remediation.MoveWarnEmptiesSource}, mc.Warnings)
	moved, err := r.svc.Move(ctx, remediationapp.MoveInput{TenantID: r.tenant, FromTaskID: src.ID, FromVersion: out.Source.Version,
		ToTaskID: &other.ID, ToVersion: other.Version, FindingIDs: []shared.ID{f2}, Confirm: true, ActorID: &r.admin}, auditapp.AuditContext{})
	require.NoError(t, err)
	assert.True(t, moved.SourceArchived)
	assert.Equal(t, remediation.TaskStateArchived, moved.Source.State)
	assert.Contains(t, moved.Source.ArchivedNote, "Search")

	// An archived task takes nothing back: undo goes to a live task.
	_, err = r.svc.Move(ctx, remediationapp.MoveInput{TenantID: r.tenant, FromTaskID: other.ID, FromVersion: moved.Target.Version,
		ToTaskID: &src.ID, ToVersion: moved.Source.Version, FindingIDs: []shared.ID{f2}, Confirm: true}, auditapp.AuditContext{})
	assert.ErrorIs(t, err, remediation.ErrTaskTerminal)
	undo, err := r.svc.Move(ctx, remediationapp.MoveInput{TenantID: r.tenant, FromTaskID: other.ID, FromVersion: moved.Target.Version,
		ToTaskID: &same.ID, ToVersion: out.Target.Version, FindingIDs: []shared.ID{f2}, Confirm: true, ActorID: &r.admin}, auditapp.AuditContext{})
	require.NoError(t, err)
	assert.Equal(t, 3, undo.Target.Counts.Total)

	// Every moved finding's timeline names both tasks.
	var n int
	require.NoError(t, r.db.QueryRow(`SELECT COUNT(*) FROM finding_activities WHERE tenant_id = $1 AND finding_id = $2
		AND activity_type = 'remediation_task_changed'`, r.tenant.String(), f2.String()).Scan(&n))
	assert.Equal(t, 5, n, "joined src, left src, joined other, left other, joined same")
}

func TestRemediationMoves_DetachSplitMerge(t *testing.T) {
	r := newRTRig(t)
	ctx := r.adminCtx()
	key := "upgrade:npm:lodash:4.17.21"
	act := r.actionFor(key)
	f1, f2, f3, f4 := r.finding(r.assetA, "new", nil), r.finding(r.assetA, "new", nil), r.finding(r.assetA, "new", nil), r.finding(r.assetA, "new", nil)
	task := r.newTask(ctx, "Lodash", &act, &r.admin, nil, f1, f2, f3)

	// Detach: back to the pool, excluded from this fix.
	out, err := r.svc.Move(ctx, remediationapp.MoveInput{TenantID: r.tenant, FromTaskID: task.ID, FromVersion: task.Version,
		FindingIDs: []shared.ID{f3}, ActorID: &r.admin}, auditapp.AuditContext{})
	require.NoError(t, err)
	assert.Nil(t, out.Target)
	var ex int
	require.NoError(t, r.db.QueryRow(`SELECT COUNT(*) FROM remediation_key_exclusions WHERE tenant_id = $1 AND action_key = $2 AND finding_id = $3 AND reason = 'detached'`,
		r.tenant.String(), key, f3.String()).Scan(&ex))
	assert.Equal(t, 1, ex)

	// Split: a new task of the same fix for another owner; at least one stays.
	_, err = r.svc.Split(ctx, remediationapp.SplitInput{TenantID: r.tenant, TaskID: task.ID, Version: out.Source.Version,
		FindingIDs: []shared.ID{f1, f2}}, auditapp.AuditContext{})
	assert.ErrorIs(t, err, shared.ErrValidation)
	sp, err := r.svc.Split(ctx, remediationapp.SplitInput{TenantID: r.tenant, TaskID: task.ID, Version: out.Source.Version,
		FindingIDs: []shared.ID{f2}, AssigneeGroupID: &r.group, ActorID: &r.admin}, auditapp.AuditContext{})
	require.NoError(t, err)
	assert.Equal(t, act, sp.Target.ActionID)
	require.NotNil(t, sp.Target.AssigneeGroupID)
	assert.Equal(t, r.group, *sp.Target.AssigneeGroupID)
	assert.Equal(t, 1, sp.Source.Counts.Total)
	assert.Equal(t, 1, sp.Target.Counts.Total)

	// Merge: same fix only; the source is archived.
	otherFix := r.newTask(ctx, "Other fix", nil, nil, nil, f4)
	_, err = r.svc.Merge(ctx, remediationapp.MergeInput{TenantID: r.tenant, TargetID: task.ID, TargetVersion: sp.Source.Version,
		Sources: map[shared.ID]int{otherFix.ID: otherFix.Version}}, auditapp.AuditContext{})
	assert.ErrorIs(t, err, remediation.ErrMergeDifferentFix)
	merged, err := r.svc.Merge(ctx, remediationapp.MergeInput{TenantID: r.tenant, TargetID: task.ID, TargetVersion: sp.Source.Version,
		Sources: map[shared.ID]int{sp.Target.ID: sp.Target.Version}, ActorID: &r.admin}, auditapp.AuditContext{})
	require.NoError(t, err)
	assert.Equal(t, 2, merged.Counts.Total)
	child, err := r.svc.GetTask(ctx, r.tenant, sp.Target.ID)
	require.NoError(t, err)
	assert.Equal(t, remediation.TaskStateArchived, child.State)
}

func TestRemediationMoves_IsolationAndScope(t *testing.T) {
	r := newRTRig(t)
	admin, member := r.adminCtx(), r.memberCtx()
	a1, a2 := r.finding(r.assetA, "new", nil), r.finding(r.assetA, "new", nil)
	b1 := r.finding(r.assetB, "new", nil)
	mineA := r.newTask(admin, "A", nil, nil, nil, a1, a2)
	mixed := r.newTask(admin, "Mixed", nil, nil, nil, b1, r.finding(r.assetA, "new", nil))

	// Another tenant: not found.
	_, err := r.svc.Move(admin, remediationapp.MoveInput{TenantID: r.other, FromTaskID: mineA.ID, FromVersion: mineA.Version,
		FindingIDs: []shared.ID{a1}}, auditapp.AuditContext{})
	assert.ErrorIs(t, err, shared.ErrNotFound)

	// A restricted member cannot move into (or out of) a task with findings
	// outside their scope.
	_, err = r.svc.Move(member, remediationapp.MoveInput{TenantID: r.tenant, FromTaskID: mineA.ID, FromVersion: mineA.Version,
		ToTaskID: &mixed.ID, ToVersion: mixed.Version, FindingIDs: []shared.ID{a1}, Confirm: true}, auditapp.AuditContext{})
	assert.ErrorIs(t, err, remediation.ErrTaskHiddenMembers)
	// ... nor name a finding outside their scope.
	_, err = r.svc.Move(member, remediationapp.MoveInput{TenantID: r.tenant, FromTaskID: mineA.ID, FromVersion: mineA.Version,
		FindingIDs: []shared.ID{b1}, Confirm: true}, auditapp.AuditContext{})
	assert.ErrorIs(t, err, remediationapp.ErrTaskFindingNotFound)
	// A finding that is not in the source is skipped, not moved.
	out, err := r.svc.Move(member, remediationapp.MoveInput{TenantID: r.tenant, FromTaskID: mineA.ID, FromVersion: mineA.Version,
		FindingIDs: []shared.ID{a1, r.finding(r.assetA, "new", nil)}, ActorID: &r.member}, auditapp.AuditContext{})
	require.NoError(t, err)
	assert.Len(t, out.Moved, 1)
	assert.Len(t, out.Skipped, 1)
}

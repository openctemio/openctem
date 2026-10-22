package integration

// The task owner's access to the findings they are asked to fix
// (docs/architecture/remediation-tasks.md, "Task owner access"), on a
// migrated database: a restricted owner reads and works exactly the task's
// findings, claims the task fixed without being the assignee, may not decide
// dispositions, and loses all of it when the relation ends.

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/internal/app/datascope"
	"github.com/openctemio/openctem/api/internal/app/finding"
	remediationapp "github.com/openctemio/openctem/api/internal/app/remediation"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/remediation"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// ownerAudit records the audit events of a task owner's moves.
type ownerAudit struct{ events []auditapp.AuditEvent }

// ownerMoves counts the task-owner move events; every status move also
// writes its own finding.status_changed event, which is not counted here.
func (a *ownerAudit) ownerMoves() []auditapp.AuditEvent {
	var out []auditapp.AuditEvent
	for _, e := range a.events {
		if string(e.Action) == "remediation_task.owner_moved_finding" {
			out = append(out, e)
		}
	}
	return out
}

func (a *ownerAudit) LogEvent(_ context.Context, _ auditapp.AuditContext, e auditapp.AuditEvent) error {
	a.events = append(a.events, e)
	return nil
}

func (r *rtRig) wireOwnerAccess() *finding.VulnerabilityService {
	r.t.Helper()
	db := &postgres.DB{DB: r.db}
	log := logger.NewNop()
	enforcer := datascope.New(postgres.NewDataScopeRepository(db), func(ctx context.Context) datascope.Caller {
		c, _ := ctx.Value(rtCallerKey{}).(datascope.Caller)
		return c
	}, log)
	findingRepo := postgres.NewFindingRepository(db)
	accessRepo := postgres.NewAccessControlRepository(db)
	vuln := finding.NewVulnerabilityService(postgres.NewVulnerabilityRepository(db), findingRepo, log)
	vuln.SetAccessControlRepository(accessRepo)
	vuln.SetDataScope(enforcer)
	r.audit = &ownerAudit{}
	vuln.SetAuditService(r.audit)
	actions := finding.NewFindingActionsService(findingRepo, accessRepo, nil, postgres.NewAssetRepository(db), nil, r.db, log)
	actions.SetDataScope(enforcer)
	vuln.SetFixApplierCheck(actions.FixAppliers)
	vuln.SetProofOfFixQueuer(func(_ context.Context, _ shared.ID, ids []shared.ID) int { return len(ids) })
	r.svc.SetFixClaimer(vuln, nil)
	return vuln
}

func TestTaskOwnerAccess_ReadFixWorkAndEnd(t *testing.T) {
	r := newRTRig(t)
	vuln := r.wireOwnerAccess()
	admin, member := r.adminCtx(), r.memberCtx()
	tenant := r.tenant.String()

	// The member is restricted to asset A. The task holds a finding on A and
	// two on asset B (outside their scope); a third finding on B is not in
	// the task.
	inA := r.finding(r.assetA, "new", nil)
	inB, inB2 := r.finding(r.assetB, "new", nil), r.finding(r.assetB, "confirmed", nil)
	otherOnB := r.finding(r.assetB, "new", nil)
	task := r.newTask(admin, "Patch", nil, &r.member, nil, inA, inB, inB2)

	// The request-level flag is set by the by-id guard for a fix-workflow
	// route only; without it the relation grants nothing.
	viaTask := shared.WithTaskOwnerView(member)
	_, err := vuln.GetFindingWithScope(member, tenant, inB.String(), r.member.String(), false)
	assert.ErrorIs(t, err, shared.ErrNotFound, "no guard flag: real scope only")
	f, err := vuln.GetFindingWithScope(viaTask, tenant, inB.String(), r.member.String(), false)
	require.NoError(t, err, "the task's finding on an asset outside their scope")
	assert.Equal(t, inB, f.ID())
	_, err = vuln.GetFindingWithScope(viaTask, tenant, otherOnB.String(), r.member.String(), false)
	assert.ErrorIs(t, err, shared.ErrNotFound, "the asset's other finding stays hidden")
	// Another tenant's member id and the flag change nothing.
	_, err = vuln.GetFindingWithScope(shared.WithTaskOwnerView(r.adminCtx()), r.other.String(), inB.String(), r.admin.String(), false)
	assert.ErrorIs(t, err, shared.ErrNotFound)

	// The task owner sees the whole task (no hidden members) and so can act
	// on it as a whole.
	got, err := r.svc.GetTask(member, r.tenant, task.ID)
	require.NoError(t, err)
	assert.Equal(t, 0, got.HiddenMembers)
	assert.Equal(t, 3, got.Counts.Total)

	// Dispositions and a resolve are not part of the fix workflow.
	for _, to := range []string{"false_positive", "accepted", "resolved"} {
		_, err = vuln.UpdateFindingStatus(viaTask, inB.String(), tenant, finding.UpdateFindingStatusInput{
			Status: to, ActorID: r.member.String(), HasVerifyPermission: true, HasFixApplyPermission: true, HasApprovePermission: true})
		assert.ErrorIs(t, err, shared.ErrForbidden, to)
	}
	assert.Equal(t, "new", r.status(inB))
	assert.Empty(t, r.audit.ownerMoves(), "refused moves are not audited as moves")

	// The fix workflow is open to them: start work, audited.
	_, err = vuln.UpdateFindingStatus(viaTask, inB2.String(), tenant, finding.UpdateFindingStatusInput{
		Status: "in_progress", ActorID: r.member.String()})
	require.NoError(t, err)
	assert.Equal(t, "in_progress", r.status(inB2))
	require.Len(t, r.audit.ownerMoves(), 1)
	// The same move on a finding in their own scope is not a task-owner move.
	ownScope := r.finding(r.assetA, "confirmed", nil)
	_, err = vuln.UpdateFindingStatus(member, ownScope.String(), tenant, finding.UpdateFindingStatusInput{
		Status: "in_progress", ActorID: r.member.String()})
	require.NoError(t, err)
	assert.Len(t, r.audit.ownerMoves(), 1)

	// Mark fixed by the unassigned owner claims every open finding, on the
	// asset outside their scope too (S13), and nothing outside the task.
	res, err := r.svc.MarkFixed(member, remediationapp.MarkFixedInput{TenantID: r.tenant, TaskID: task.ID, Version: got.Version,
		Note: "bumped", ActorID: &r.member, HasFixApplyPermission: true}, auditapp.AuditContext{})
	require.NoError(t, err)
	assert.Equal(t, 3, res.Updated)
	assert.Equal(t, 0, res.Failed)
	for _, id := range []shared.ID{inA, inB, inB2} {
		assert.Equal(t, "fix_applied", r.status(id))
	}
	assert.Equal(t, "new", r.status(otherOnB))
}

func TestTaskOwnerAccess_EndsWithTheRelation(t *testing.T) {
	r := newRTRig(t)
	vuln := r.wireOwnerAccess()
	admin, member := r.adminCtx(), r.memberCtx()
	inB, inB2 := r.finding(r.assetB, "new", nil), r.finding(r.assetB, "new", nil)
	task := r.newTask(admin, "Patch", nil, &r.member, nil, inB, inB2)
	viaTask := shared.WithTaskOwnerView(member)
	read := func(id shared.ID) error {
		_, err := vuln.GetFindingWithScope(viaTask, r.tenant.String(), id.String(), r.member.String(), false)
		return err
	}
	require.NoError(t, read(inB))

	// The owner changes: access is gone with the next read.
	r.exec(`UPDATE remediation_tasks SET assignee_user_id = $1 WHERE id = $2`, r.admin.String(), task.ID.String())
	assert.ErrorIs(t, read(inB), shared.ErrNotFound, "owner changed")
	r.exec(`UPDATE remediation_tasks SET assignee_user_id = $1 WHERE id = $2`, r.member.String(), task.ID.String())
	require.NoError(t, read(inB))

	// The finding leaves the task: only that finding is lost.
	r.exec(`UPDATE remediation_task_members SET left_at = now(), left_reason = 'removed' WHERE task_id = $1 AND finding_id = $2`,
		task.ID.String(), inB.String())
	assert.ErrorIs(t, read(inB), shared.ErrNotFound, "left the task")
	require.NoError(t, read(inB2))

	// The task closes.
	r.exec(`UPDATE remediation_tasks SET state = 'canceled' WHERE id = $1`, task.ID.String())
	assert.ErrorIs(t, read(inB2), shared.ErrNotFound, "task closed")
	r.exec(`UPDATE remediation_tasks SET state = 'open' WHERE id = $1`, task.ID.String())
	require.NoError(t, read(inB2))

	// The membership is suspended.
	r.exec(`UPDATE tenant_members SET status = 'suspended' WHERE user_id = $1 AND tenant_id = $2`, r.member.String(), r.tenant.String())
	assert.ErrorIs(t, read(inB2), shared.ErrNotFound, "suspended")
}

func TestTaskOwnerAccess_TeamOwnerAndNonOwner(t *testing.T) {
	r := newRTRig(t)
	r.wireOwnerAccess()
	admin := r.adminCtx()
	inB := r.finding(r.assetB, "new", nil)
	// The team owns the task; the member is in the team until it expires.
	r.exec(`INSERT INTO group_members (group_id, user_id) VALUES ($1, $2)`, r.group.String(), r.member.String())
	task := r.newTask(admin, "Team patch", nil, nil, &r.group, inB)

	got, err := r.svc.GetTask(r.memberCtx(), r.tenant, task.ID)
	require.NoError(t, err, "a team member sees the task through the relation")
	assert.Equal(t, 1, got.Counts.Total)

	r.exec(`UPDATE group_members SET expires_at = now() - interval '1 minute' WHERE group_id = $1 AND user_id = $2`, r.group.String(), r.member.String())
	_, err = r.svc.GetTask(r.memberCtx(), r.tenant, task.ID)
	assert.ErrorIs(t, err, remediation.ErrTaskNotFound, "membership expired: the task is gone for them")
}

package integration

// Marking a remediation task fixed and regressions
// (docs/rfcs/RFC-098-remediation-tasks.md §3, §8) on a migrated database:
// every open finding of the task is claimed fixed through the legal steps
// with a proof-of-fix re-check each; nothing closes; only the asset owner's
// claim is accepted; a finding that reopens after the task is done opens a
// new linked task instead of reopening the done one.

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/internal/app/finding"
	remediationapp "github.com/openctemio/openctem/api/internal/app/remediation"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/remediation"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/pagination"
)

func (r *rtRig) wireMarkFixed() *int {
	r.t.Helper()
	db := &postgres.DB{DB: r.db}
	log := logger.NewNop()
	findingRepo := postgres.NewFindingRepository(db)
	accessRepo := postgres.NewAccessControlRepository(db)
	vuln := finding.NewVulnerabilityService(postgres.NewVulnerabilityRepository(db), findingRepo, log)
	vuln.SetAccessControlRepository(accessRepo)
	actions := finding.NewFindingActionsService(findingRepo, accessRepo, nil, postgres.NewAssetRepository(db), nil, r.db, log)
	vuln.SetFixApplierCheck(actions.FixAppliers)
	queued := 0
	vuln.SetProofOfFixQueuer(func(_ context.Context, _ shared.ID, ids []shared.ID) int { queued += len(ids); return len(ids) })
	r.svc.SetFixClaimer(vuln, nil)
	return &queued
}

func (r *rtRig) status(id shared.ID) string {
	r.t.Helper()
	var s string
	require.NoError(r.t, r.db.QueryRow(`SELECT status FROM findings WHERE tenant_id = $1 AND id = $2`, r.tenant.String(), id.String()).Scan(&s))
	return s
}

func TestRemediationMarkFixed_ClaimsEachFindingNeverCloses(t *testing.T) {
	r := newRTRig(t)
	ctx := r.adminCtx()
	queued := r.wireMarkFixed()
	// The admin owns asset A; nobody owns asset B.
	r.exec(`INSERT INTO asset_owners (asset_id, user_id, ownership_type, assignment_source) VALUES ($1, $2, 'primary', 'manual')`,
		r.assetA.String(), r.admin.String())
	fNew, fConfirmed, fClaimed := r.finding(r.assetA, "new", nil), r.finding(r.assetA, "confirmed", nil), r.finding(r.assetA, "new", nil)
	notMine := r.finding(r.assetB, "new", nil)
	task := r.newTask(ctx, "Patch", nil, &r.admin, nil, fNew, fConfirmed, fClaimed, notMine)
	r.setStatus(fClaimed, "in_progress", "")
	r.setStatus(fClaimed, "fix_applied", "")

	in := remediationapp.MarkFixedInput{TenantID: r.tenant, TaskID: task.ID, Version: task.Version, ActorID: &r.admin, HasFixApplyPermission: true}
	_, err := r.svc.MarkFixed(ctx, in, auditapp.AuditContext{})
	assert.ErrorIs(t, err, finding.ErrNoteRequired)
	in.Note = "bumped to 4.2.30"
	noPerm := in
	noPerm.HasFixApplyPermission = false
	_, err = r.svc.MarkFixed(ctx, noPerm, auditapp.AuditContext{})
	assert.ErrorIs(t, err, finding.ErrFixApplyRequiresPermission)
	stale := in
	stale.Version = task.Version + 3
	_, err = r.svc.MarkFixed(ctx, stale, auditapp.AuditContext{})
	assert.ErrorIs(t, err, remediation.ErrTaskVersionConflict)

	res, err := r.svc.MarkFixed(ctx, in, auditapp.AuditContext{})
	require.NoError(t, err)
	assert.Equal(t, 2, res.Updated, "new and confirmed walk to fix_applied")
	assert.Equal(t, 1, res.Skipped, "already claimed")
	assert.Equal(t, 1, res.Failed, "not the caller's asset")
	assert.Equal(t, 2, *queued, "one proof-of-fix re-check per claimed finding")
	for _, id := range []shared.ID{fNew, fConfirmed, fClaimed} {
		assert.Equal(t, "fix_applied", r.status(id))
	}
	assert.Equal(t, "new", r.status(notMine))
	assert.Equal(t, remediation.TaskStateInProgress, res.Task.State, "nothing closed; one finding still open")

	// A restricted member cannot mark a task with findings outside their scope.
	_, err = r.svc.MarkFixed(r.memberCtx(), remediationapp.MarkFixedInput{TenantID: r.tenant, TaskID: task.ID,
		Version: res.Task.Version, Note: "x", ActorID: &r.member, HasFixApplyPermission: true}, auditapp.AuditContext{})
	assert.ErrorIs(t, err, remediation.ErrTaskHiddenMembers)
	// Another tenant: not found.
	_, err = r.svc.MarkFixed(ctx, remediationapp.MarkFixedInput{TenantID: r.other, TaskID: task.ID,
		Version: res.Task.Version, Note: "x", HasFixApplyPermission: true}, auditapp.AuditContext{})
	assert.ErrorIs(t, err, shared.ErrNotFound)
}

func TestRemediationMarkFixed_RegressionOpensLinkedTask(t *testing.T) {
	r := newRTRig(t)
	ctx := r.adminCtx()
	f1, f2 := r.finding(r.assetA, "new", nil), r.finding(r.assetA, "new", nil)
	task := r.newTask(ctx, "Upgrade django", nil, &r.admin, &r.group, f1, f2)
	r.setStatus(f1, "resolved", "covered_scan")
	r.setStatus(f2, "resolved", "retest")
	_, err := r.svc.Reconcile(context.Background())
	require.NoError(t, err)
	done, err := r.svc.GetTask(ctx, r.tenant, task.ID)
	require.NoError(t, err)
	require.Equal(t, remediation.TaskStateDone, done.State)

	// f2 comes back.
	r.exec(`UPDATE findings SET status = 'confirmed', closure_reason = NULL, verification = NULL, updated_at = now() + interval '2 seconds'
		WHERE tenant_id = $1 AND id = $2`, r.tenant.String(), f2.String())
	_, err = r.svc.Reconcile(context.Background())
	require.NoError(t, err)

	done, err = r.svc.GetTask(ctx, r.tenant, task.ID)
	require.NoError(t, err)
	assert.Equal(t, remediation.TaskStateDone, done.State, "the done task is not reopened")
	assert.Equal(t, 1, done.Counts.Total)

	list, err := r.svc.ListTasks(ctx, remediationapp.ListTasksInput{TenantID: r.tenant, Filter: remediation.TaskFilter{FindingID: &f2}}, pagination.New(1, 10))
	require.NoError(t, err)
	require.Len(t, list.Data, 1)
	reg := list.Data[0]
	require.NotNil(t, reg.RegressionOf)
	assert.Equal(t, task.ID, *reg.RegressionOf)
	assert.Equal(t, task.ActionID, reg.ActionID, "same fix")
	assert.Equal(t, r.admin, *reg.AssigneeUserID, "same owner")
	assert.Equal(t, remediation.TaskStateOpen, reg.State)
	assert.Contains(t, reg.Title, "Regression")
}

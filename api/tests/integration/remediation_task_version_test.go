package integration

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/internal/app/finding"
	remediationapp "github.com/openctemio/openctem/api/internal/app/remediation"
	"github.com/openctemio/openctem/api/pkg/domain/remediation"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

// Every write to a task names the version the caller read, and the version is
// checked inside the transaction that reads or changes the task (research 217
// S5). The service refuses a missing version; the repository refuses a stale
// one even when the service-level check was skipped.

type stubExceptions struct{ called int }

func (s *stubExceptions) PreviewGroupException(context.Context, finding.GroupExceptionInput) (*finding.GroupExceptionPreview, error) {
	s.called++
	return &finding.GroupExceptionPreview{}, nil
}

func (s *stubExceptions) RequestGroupException(context.Context, finding.GroupExceptionInput) (*finding.GroupExceptionResult, error) {
	s.called++
	return &finding.GroupExceptionResult{Batch: &vulnerability.ApprovalBatch{ID: shared.NewID()}}, nil
}

func TestRemediationTaskWrites_SplitNeedsCurrentVersion(t *testing.T) {
	r := newRTRig(t)
	ctx := r.adminCtx()
	f1, f2 := r.finding(r.assetA, "new", nil), r.finding(r.assetA, "new", nil)
	task := r.newTask(ctx, "Split me", nil, &r.admin, nil, f1, f2)
	in := remediationapp.SplitInput{TenantID: r.tenant, TaskID: task.ID, FindingIDs: []shared.ID{f2}, ActorID: &r.admin}

	_, err := r.svc.Split(ctx, in, auditapp.AuditContext{})
	assert.ErrorIs(t, err, remediationapp.ErrTaskVersionRequired, "version 0 is refused, it used to skip the lock check")

	in.Version = task.Version + 7
	_, err = r.svc.Split(ctx, in, auditapp.AuditContext{})
	assert.ErrorIs(t, err, remediation.ErrTaskVersionConflict)
	assert.Equal(t, 2, len(memberIDs2(t, r, task.ID)), "nothing moved")

	in.Version = task.Version
	_, err = r.svc.Split(ctx, in, auditapp.AuditContext{})
	require.NoError(t, err)
}

func TestRemediationTaskWrites_RepositoryChecksVersionInTransaction(t *testing.T) {
	r := newRTRig(t)
	ctx := r.adminCtx()
	f1 := r.finding(r.assetA, "new", nil)
	task := r.newTask(ctx, "Locked", nil, &r.admin, nil, f1)
	stale := task.Version + 3

	// The member snapshot behind mark fixed and exceptions.
	_, err := r.repo.OpenPrimaryIDs(ctx, r.tenant, task.ID, stale)
	assert.ErrorIs(t, err, remediation.ErrTaskVersionConflict)
	ids, err := r.repo.OpenPrimaryIDs(ctx, r.tenant, task.ID, task.Version)
	require.NoError(t, err)
	assert.Equal(t, []shared.ID{f1}, ids)

	// A query claim and an auto-state change by a person.
	_, err = r.repo.ClaimQueryFindings(ctx, remediation.QueryClaim{TenantID: r.tenant, TaskID: task.ID,
		IDs: []shared.ID{r.finding(r.assetA, "new", nil)}, Cap: 10, ExpectedVersion: stale})
	assert.ErrorIs(t, err, remediation.ErrTaskVersionConflict)
	err = r.repo.SetAutoState(ctx, r.tenant, task.ID, stale, remediation.AutoStatePaused, nil)
	assert.ErrorIs(t, err, remediation.ErrTaskVersionConflict)
	// The current version gets past the lock (this task has no auto query).
	err = r.repo.SetAutoState(ctx, r.tenant, task.ID, task.Version, remediation.AutoStatePaused, nil)
	assert.ErrorIs(t, err, remediation.ErrNotAutoMode)
	// The platform passes 0: no check.
	err = r.repo.SetAutoState(ctx, r.tenant, task.ID, 0, remediation.AutoStatePaused, nil)
	assert.ErrorIs(t, err, remediation.ErrNotAutoMode)
}

func TestRemediationTaskWrites_ExceptionNeedsCurrentVersion(t *testing.T) {
	r := newRTRig(t)
	ctx := r.adminCtx()
	stub := &stubExceptions{}
	r.svc.SetExceptionRequester(stub)
	f1 := r.finding(r.assetA, "new", nil)
	task := r.newTask(ctx, "Exception", nil, &r.admin, nil, f1)
	in := remediationapp.TaskExceptionInput{TenantID: r.tenant, TaskID: task.ID, RequestedStatus: "accepted", ActorID: r.admin}

	_, err := r.svc.RequestException(ctx, in, auditapp.AuditContext{})
	assert.ErrorIs(t, err, remediationapp.ErrTaskVersionRequired)

	in.Version = task.Version + 2
	_, err = r.svc.RequestException(ctx, in, auditapp.AuditContext{})
	assert.ErrorIs(t, err, remediation.ErrTaskVersionConflict)
	_, err = r.svc.PreviewException(ctx, in)
	assert.ErrorIs(t, err, remediation.ErrTaskVersionConflict, "a preview that names a version is checked too")
	assert.Equal(t, 0, stub.called, "no exception is created for a stale view")

	in.Version = task.Version
	_, err = r.svc.RequestException(ctx, in, auditapp.AuditContext{})
	require.NoError(t, err)
	assert.Equal(t, 1, stub.called)
}

func TestRemediationTaskWrites_QueryRerunAndAutoStateNeedCurrentVersion(t *testing.T) {
	r := newQTRig(t)
	ctx := r.adminCtx()
	_ = r.finding(r.assetA, "new", nil)
	res, err := r.createQueryTask(ctx, r.adminCaller(), r.admin, qtHigh, remediation.QueryModeAuto, 0, remediation.ConflictResolution{})
	require.NoError(t, err)
	extra := r.finding(r.assetB, "new", nil)
	cur := r.taskVersion(res.Task.ID)

	rerun := remediationapp.RerunQueryInput{TenantID: r.tenant, TaskID: res.Task.ID, Caller: r.adminCaller(), ActorID: &r.admin}
	_, _, err = r.svc.RerunQuery(ctx, rerun, auditapp.AuditContext{})
	assert.ErrorIs(t, err, remediationapp.ErrTaskVersionRequired)
	rerun.Version = cur + 1
	_, _, err = r.svc.RerunQuery(ctx, rerun, auditapp.AuditContext{})
	assert.ErrorIs(t, err, remediation.ErrTaskVersionConflict)
	assert.NotContains(t, memberIDs(t, r, res.Task.ID), extra, "a stale re-run adds nothing")

	auto := remediationapp.SetQueryAutoStateInput{TenantID: r.tenant, TaskID: res.Task.ID, ActorID: &r.admin, Paused: true}
	_, err = r.svc.SetQueryAutoState(ctx, auto, auditapp.AuditContext{})
	assert.ErrorIs(t, err, remediationapp.ErrTaskVersionRequired)
	auto.Version = cur + 1
	_, err = r.svc.SetQueryAutoState(ctx, auto, auditapp.AuditContext{})
	assert.ErrorIs(t, err, remediation.ErrTaskVersionConflict)
	q, err := r.repo.GetTaskQuery(ctx, r.tenant, res.Task.ID)
	require.NoError(t, err)
	assert.Equal(t, remediation.AutoStateActive, *q.AutoState, "a stale pause changes nothing")

	rerun.Version = cur
	out, _, err := r.svc.RerunQuery(ctx, rerun, auditapp.AuditContext{})
	require.NoError(t, err)
	assert.Equal(t, []shared.ID{extra}, out.Added)
}

func memberIDs2(t *testing.T, r *rtRig, id shared.ID) []shared.ID {
	t.Helper()
	ids, err := r.repo.OpenPrimaryIDs(context.Background(), r.tenant, id, 0)
	require.NoError(t, err)
	return ids
}

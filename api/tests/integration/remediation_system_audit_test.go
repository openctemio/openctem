package integration

import (
	"context"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	remediationapp "github.com/openctemio/openctem/api/internal/app/remediation"
	auditdom "github.com/openctemio/openctem/api/pkg/domain/audit"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Changes no person made to a task are in the audit log with the system as
// the actor: a background state change, the regression task opened when a
// closed task's finding reopens, and a finding joining under the auto-join
// rule (research 217 S7). The task timeline already recorded them.

type sysAuditEntry struct {
	actx auditapp.AuditContext
	ev   auditapp.AuditEvent
}

type sysAudit struct {
	mu      sync.Mutex
	entries []sysAuditEntry
}

func (a *sysAudit) LogEvent(_ context.Context, actx auditapp.AuditContext, ev auditapp.AuditEvent) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.entries = append(a.entries, sysAuditEntry{actx, ev})
	return nil
}

func (a *sysAudit) of(action auditdom.Action) []sysAuditEntry {
	a.mu.Lock()
	defer a.mu.Unlock()
	var out []sysAuditEntry
	for _, e := range a.entries {
		if e.ev.Action == action {
			out = append(out, e)
		}
	}
	return out
}

func TestRemediationSystemAudit_ReconcileStateChangeAndRegression(t *testing.T) {
	r := newRTRig(t)
	ctx := r.adminCtx()
	au := &sysAudit{}
	r.svc.SetAuditLogger(au)
	f1, f2 := r.finding(r.assetA, "new", nil), r.finding(r.assetA, "new", nil)
	task := r.newTask(ctx, "Reconciled", nil, &r.admin, nil, f1, f2)

	// A scan closes both findings with proof: the background reconcile moves
	// the task to done.
	r.setStatus(f1, "resolved", "covered_scan")
	r.setStatus(f2, "resolved", "covered_scan")
	n, err := r.svc.Reconcile(context.Background())
	require.NoError(t, err)
	require.Equal(t, 1, n)

	changed := au.of(auditdom.ActionRemediationTaskStateChanged)
	require.Len(t, changed, 1)
	assert.Equal(t, "system", changed[0].actx.ActorEmail)
	assert.Equal(t, r.tenant.String(), changed[0].actx.TenantID)
	assert.Equal(t, task.ID.String(), changed[0].ev.ResourceID)
	assert.Equal(t, "reconcile", changed[0].ev.Metadata["trigger"])
	assert.Equal(t, "Reconciled", changed[0].ev.ResourceName)

	// One finding comes back: the closed task keeps its history and a new
	// task opens; that is audited too.
	r.setStatus(f1, "new", "")
	_, err = r.svc.Reconcile(context.Background())
	require.NoError(t, err)
	reg := au.of(auditdom.ActionRemediationTaskRegressed)
	require.Len(t, reg, 1)
	assert.Equal(t, "system", reg[0].actx.ActorEmail)
	assert.Equal(t, r.tenant.String(), reg[0].actx.TenantID)
	assert.Equal(t, task.ID.String(), reg[0].ev.Metadata["regression_of"])
	assert.Equal(t, 1, reg[0].ev.Metadata["findings"])
	assert.NotEqual(t, task.ID.String(), reg[0].ev.ResourceID, "the row is about the new task")
	var linked int
	require.NoError(t, r.db.QueryRow(`SELECT COUNT(*) FROM remediation_tasks WHERE tenant_id = $1 AND id = $2 AND regression_of = $3`,
		r.tenant.String(), reg[0].ev.ResourceID, task.ID.String()).Scan(&linked))
	assert.Equal(t, 1, linked)

	// A recompute nobody asked to audit (a person's own path) writes none.
	before := len(au.of(auditdom.ActionRemediationTaskStateChanged))
	require.NoError(t, r.repo.Recompute(context.Background(), r.tenant, []shared.ID{task.ID}, nil))
	assert.Len(t, au.of(auditdom.ActionRemediationTaskStateChanged), before)
}

func TestRemediationSystemAudit_AutoJoin(t *testing.T) {
	r := newAcceptRig(t)
	ctx := r.adminCtx()
	au := &sysAudit{}
	r.sug.SetAuditLogger(au)
	r.keyed(r.assetA, djangoKey, "P1")
	r.keyed(r.assetA, djangoKey, "P1")
	r.run()
	var sgID shared.ID
	var ver int
	for _, s := range r.list(ctx) {
		if s.KeyKind == "upgrade" {
			sgID, ver = s.ID, s.Version
		}
	}
	res, err := r.sug.Accept(ctx, remediationapp.AcceptInput{TenantID: r.tenant, ID: sgID, Version: ver, ActorID: &r.admin,
		AutoJoin: true}, auditapp.AuditContext{})
	require.NoError(t, err)

	r.keyed(r.assetA, djangoKey, "P2")
	st := r.run()
	require.Equal(t, 1, st.AutoJoined)

	rows := au.of(auditdom.ActionRemediationTaskMembersAdded)
	require.Len(t, rows, 1, "the accept is audited as its own action; only the auto-join is a members_added row")
	assert.Equal(t, "system", rows[0].actx.ActorEmail)
	assert.Equal(t, r.tenant.String(), rows[0].actx.TenantID)
	assert.Equal(t, res.TaskIDs[0].String(), rows[0].ev.ResourceID)
	assert.Equal(t, "auto_join", rows[0].ev.Metadata["trigger"])
	assert.Equal(t, 1, rows[0].ev.Metadata["findings"])
	assert.Equal(t, res.ActionID.String(), rows[0].ev.Metadata["action_id"])
}

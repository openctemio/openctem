package integration

// Accepting remediation suggestions (docs/rfcs/RFC-098-remediation-tasks.md
// §6) on a migrated database: as is or edited (removed findings remembered,
// other owners, title, deadline); join and task route; findings that closed
// since are left out; stale and repeated accepts are refused; bulk accept;
// the opt-in auto-join rule for exact keys, never into a verifying task;
// a restricted member can neither accept a suggestion with hidden findings
// nor turn auto-join on.

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	remediationapp "github.com/openctemio/openctem/api/internal/app/remediation"
	"github.com/openctemio/openctem/api/pkg/domain/remediation"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/pagination"
)

func (r *rsRig) taskMembers(taskID shared.ID) map[shared.ID]string {
	r.t.Helper()
	rows, err := r.db.Query(`SELECT finding_id, join_source FROM remediation_task_members WHERE tenant_id = $1 AND task_id = $2 AND left_at IS NULL`,
		r.tenant.String(), taskID.String())
	require.NoError(r.t, err)
	defer rows.Close()
	out := map[shared.ID]string{}
	for rows.Next() {
		var id shared.ID
		var src string
		require.NoError(r.t, rows.Scan(&id, &src))
		out[id] = src
	}
	return out
}

func newAcceptRig(t *testing.T) *rsRig {
	r := newRSRig(t)
	r.sug.SetTasks(r.svc)
	return r
}

func TestRemediationAccept_NewGroupWithEdits(t *testing.T) {
	r := newAcceptRig(t)
	ctx := r.adminCtx()
	a1 := r.keyed(r.assetA, djangoKey, "P1")
	a2 := r.keyed(r.assetA, djangoKey, "P2")
	b1 := r.keyed(r.assetB, djangoKey, "P0")
	b2 := r.keyed(r.assetB, djangoKey, "P3")
	r.run()
	sg := r.list(ctx)[0]
	require.Len(t, sg.Partitions, 2)
	userPart := 1
	if sg.Partitions[0].OwnerUser != "" {
		userPart = 0
	}

	title := "Upgrade django on the payment services"
	r.setStatus(b2, "resolved", "") // closes before the accept: dropped
	res, err := r.sug.Accept(ctx, remediationapp.AcceptInput{TenantID: r.tenant, ID: sg.ID, Version: sg.Version, ActorID: &r.admin,
		Title: &title, Exclude: []shared.ID{a2},
		Owners: []remediationapp.PartitionOwner{{Index: userPart, GroupID: &r.group}}}, auditapp.AuditContext{})
	require.NoError(t, err)
	assert.Len(t, res.TaskIDs, 2, "one task per owner")
	assert.Equal(t, []shared.ID{b2}, res.Dropped)

	a, err := r.repo.GetAction(context.Background(), r.tenant, res.ActionID)
	require.NoError(t, err)
	assert.Equal(t, djangoKey, a.Key)
	assert.Equal(t, remediation.ActionOriginSuggestion, a.Origin)
	assert.Equal(t, "upgrade", a.Kind)

	all := map[shared.ID]string{}
	for _, tid := range res.TaskIDs {
		task, err := r.svc.GetTask(ctx, r.tenant, tid)
		require.NoError(t, err)
		assert.Equal(t, title, task.Title)
		require.NotNil(t, task.AssigneeGroupID, "the user partition was given to the group")
		assert.Equal(t, r.group, *task.AssigneeGroupID)
		for id, src := range r.taskMembers(tid) {
			all[id] = src
		}
	}
	assert.Equal(t, map[shared.ID]string{a1: "suggestion", b1: "suggestion"}, all, "removed and closed findings left out")

	got, err := r.sug.Get(ctx, r.tenant, sg.ID)
	require.NoError(t, err)
	assert.Equal(t, remediation.SuggestionAccepted, got.State)

	// Accepting again, or at a stale version, is refused.
	_, err = r.sug.Accept(ctx, remediationapp.AcceptInput{TenantID: r.tenant, ID: sg.ID, Version: got.Version, ActorID: &r.admin}, auditapp.AuditContext{})
	assert.ErrorIs(t, err, remediation.ErrSuggestionDecided)

	// The removed finding is not proposed for this fix again.
	r.run()
	for _, s := range r.list(ctx) {
		assert.NotContains(t, s.FindingIDs, a2)
	}
}

func TestRemediationAccept_StaleAndJoin(t *testing.T) {
	r := newAcceptRig(t)
	ctx := r.adminCtx()
	first := r.keyed(r.assetA, djangoKey, "P1")
	r.keyed(r.assetA, djangoKey, "P1")
	r.run()
	sg := r.list(ctx)[0]
	_, err := r.sug.Accept(ctx, remediationapp.AcceptInput{TenantID: r.tenant, ID: sg.ID, Version: sg.Version + 1, ActorID: &r.admin}, auditapp.AuditContext{})
	assert.ErrorIs(t, err, remediation.ErrSuggestionDecided)
	_, err = r.sug.Accept(ctx, remediationapp.AcceptInput{TenantID: r.tenant, ID: sg.ID, Version: sg.Version, ActorID: &r.admin,
		Exclude: []shared.ID{r.otherF}}, auditapp.AuditContext{})
	assert.ErrorIs(t, err, shared.ErrValidation, "only the suggestion's findings can be removed")
	res, err := r.sug.Accept(ctx, remediationapp.AcceptInput{TenantID: r.tenant, ID: sg.ID, Version: sg.Version, ActorID: &r.admin}, auditapp.AuditContext{})
	require.NoError(t, err)
	require.Len(t, res.TaskIDs, 1)
	assert.Contains(t, r.taskMembers(res.TaskIDs[0]), first)

	// A new finding of the same fix and owner: a join proposal into that task.
	late := r.keyed(r.assetA, djangoKey, "P2")
	r.run()
	ss := r.list(ctx)
	require.Len(t, ss, 1)
	require.Equal(t, remediation.SuggestionJoin, ss[0].Kind)
	jr, err := r.sug.Accept(ctx, remediationapp.AcceptInput{TenantID: r.tenant, ID: ss[0].ID, Version: ss[0].Version, ActorID: &r.admin}, auditapp.AuditContext{})
	require.NoError(t, err)
	assert.Equal(t, 1, jr.Joined)
	assert.Equal(t, "suggestion", r.taskMembers(res.TaskIDs[0])[late])
}

func TestRemediationAccept_AutoJoinRule(t *testing.T) {
	r := newAcceptRig(t)
	ctx := r.adminCtx()
	r.keyed(r.assetA, djangoKey, "P1")
	r.keyed(r.assetA, djangoKey, "P1")
	r.keyed(r.assetA, "sol:dast:"+djangoKey, "P1")
	r.keyed(r.assetA, "sol:dast:"+djangoKey, "P1")
	r.run()
	var upgrade, sol *remediation.Suggestion
	for _, s := range r.list(ctx) {
		if s.KeyKind == "upgrade" {
			upgrade = s
		} else {
			sol = s
		}
	}
	require.NotNil(t, upgrade)
	require.NotNil(t, sol)

	// A restricted member may not turn auto-join on; a text match never.
	_, err := r.sug.Accept(r.memberCtx(), remediationapp.AcceptInput{TenantID: r.tenant, ID: upgrade.ID, Version: upgrade.Version,
		ActorID: &r.member, AutoJoin: true}, auditapp.AuditContext{})
	assert.ErrorIs(t, err, shared.ErrForbidden)
	_, err = r.sug.Accept(ctx, remediationapp.AcceptInput{TenantID: r.tenant, ID: sol.ID, Version: sol.Version, ActorID: &r.admin, AutoJoin: true}, auditapp.AuditContext{})
	assert.ErrorIs(t, err, shared.ErrValidation)

	res, err := r.sug.Accept(ctx, remediationapp.AcceptInput{TenantID: r.tenant, ID: upgrade.ID, Version: upgrade.Version, ActorID: &r.admin,
		AutoJoin: true}, auditapp.AuditContext{})
	require.NoError(t, err)
	a, err := r.repo.GetAction(context.Background(), r.tenant, res.ActionID)
	require.NoError(t, err)
	assert.True(t, a.AutoJoin)

	// A new finding with the key joins the owner's open task by itself.
	late := r.keyed(r.assetA, djangoKey, "P2")
	st := r.run()
	assert.Equal(t, 1, st.AutoJoined)
	assert.Equal(t, "auto_join", r.taskMembers(res.TaskIDs[0])[late])
	var status string
	require.NoError(t, r.db.QueryRow(`SELECT status FROM findings WHERE id = $1`, late.String()).Scan(&status))
	assert.Equal(t, "new", status, "auto-join never changes a finding's status")

	// A verifying task takes no auto-join: a suggestion instead.
	r.exec(`UPDATE findings SET status = 'fix_applied', updated_at = now() + interval '1 second'
		WHERE tenant_id = $1 AND id IN (SELECT finding_id FROM remediation_task_members WHERE task_id = $2)`, r.tenant.String(), res.TaskIDs[0].String())
	require.NoError(t, r.repo.Recompute(context.Background(), r.tenant, res.TaskIDs, nil))
	later := r.keyed(r.assetA, djangoKey, "P2")
	st = r.run()
	assert.Equal(t, 0, st.AutoJoined)
	assert.NotContains(t, r.taskMembers(res.TaskIDs[0]), later)
	joins := 0
	for _, s := range r.list(ctx) {
		if s.Kind == remediation.SuggestionJoin && s.TargetTaskID != nil && *s.TargetTaskID == res.TaskIDs[0] {
			joins++
			assert.Contains(t, s.FindingIDs, later)
		}
	}
	assert.Equal(t, 1, joins, "a join suggestion instead")

	// Off again.
	off, err := r.sug.SetActionAutoJoin(ctx, r.tenant, res.ActionID, false, &r.admin, auditapp.AuditContext{})
	require.NoError(t, err)
	assert.False(t, off.AutoJoin)
	_, err = r.sug.SetActionAutoJoin(r.memberCtx(), r.tenant, res.ActionID, true, &r.member, auditapp.AuditContext{})
	assert.ErrorIs(t, err, shared.ErrForbidden)
	_, err = r.sug.SetActionAutoJoin(ctx, r.other, res.ActionID, true, &r.admin, auditapp.AuditContext{})
	assert.ErrorIs(t, err, shared.ErrNotFound, "another tenant's action")
}

func TestRemediationAccept_BulkAndScope(t *testing.T) {
	r := newAcceptRig(t)
	ctx := r.adminCtx()
	for _, k := range []string{djangoKey, "upgrade:npm:lodash:4.17.21"} {
		r.keyed(r.assetA, k, "P1")
		r.keyed(r.assetA, k, "P1")
	}
	r.keyed(r.assetB, "upgrade:npm:axios:1.7.4", "P1")
	r.keyed(r.assetA, "upgrade:npm:axios:1.7.4", "P1")
	r.run()
	var ids []shared.ID
	var mixed *remediation.Suggestion
	for _, s := range r.list(ctx) {
		if s.Key == "upgrade:npm:axios:1.7.4" {
			mixed = s
			continue
		}
		ids = append(ids, s.ID)
	}
	require.NotNil(t, mixed)
	// The restricted member sees the axios suggestion but may not accept it.
	_, err := r.sug.Accept(r.memberCtx(), remediationapp.AcceptInput{TenantID: r.tenant, ID: mixed.ID, Version: mixed.Version,
		ActorID: &r.member}, auditapp.AuditContext{})
	assert.ErrorIs(t, err, remediation.ErrSuggestionHiddenMembers)
	// Another tenant cannot reach it.
	_, err = r.sug.AcceptMany(ctx, r.other, []shared.ID{mixed.ID}, &r.admin, auditapp.AuditContext{})
	assert.ErrorIs(t, err, shared.ErrNotFound)

	items, err := r.sug.AcceptMany(ctx, r.tenant, ids, &r.admin, auditapp.AuditContext{})
	require.NoError(t, err)
	require.Len(t, items, 2)
	for _, it := range items {
		assert.Empty(t, it.Error)
		require.NotNil(t, it.Result)
		assert.Len(t, it.Result.TaskIDs, 1)
	}
	tasks, err := r.svc.ListTasks(ctx, remediationapp.ListTasksInput{TenantID: r.tenant}, pagination.New(1, 50))
	require.NoError(t, err)
	assert.Len(t, tasks.Data, 2)
}

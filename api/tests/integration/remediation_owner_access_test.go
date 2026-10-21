package integration

// The task owner picker and the owner access rule (research 217 D25): the
// picker reports, per candidate, how many open findings (on how many assets)
// they cannot see, counts only; naming an owner with a gap needs
// findings:assign and an explicit confirmation; nobody else's findings or
// tenant is reachable through it.

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/internal/app/datascope"
	remediationapp "github.com/openctemio/openctem/api/internal/app/remediation"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	auditdom "github.com/openctemio/openctem/api/pkg/domain/audit"
	"github.com/openctemio/openctem/api/pkg/domain/remediation"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

type auditRecorder struct{ events []auditapp.AuditEvent }

func (a *auditRecorder) LogEvent(_ context.Context, _ auditapp.AuditContext, ev auditapp.AuditEvent) error {
	a.events = append(a.events, ev)
	return nil
}

func (a *auditRecorder) extended() []auditapp.AuditEvent {
	var out []auditapp.AuditEvent
	for _, e := range a.events {
		if e.Action == auditdom.ActionRemediationTaskOwnerAccessExtended {
			out = append(out, e)
		}
	}
	return out
}

type ownerRig struct {
	*rtRig
	audit *auditRecorder
	svc   *remediationapp.TaskService
	fA    shared.ID // finding on assetA (member sees it)
	fB1   shared.ID // findings on assetB (member does not)
	fB2   shared.ID
}

func newOwnerRig(t *testing.T) *ownerRig {
	r := newRTRig(t)
	pdb := &postgres.DB{DB: r.db}
	svc := remediationapp.NewTaskService(r.repo, logger.NewNop())
	svc.SetAssigneeChecker(postgres.NewAccessControlRepository(pdb))
	enf := datascope.New(postgres.NewDataScopeRepository(pdb), func(ctx context.Context) datascope.Caller {
		c, _ := ctx.Value(rtCallerKey{}).(datascope.Caller)
		return c
	}, logger.NewNop())
	// Only r.admin is an administrator (unrestricted); the member is scoped.
	enf.SetAdminLookup(func(_ context.Context, _, userID shared.ID) (bool, error) { return userID == r.admin, nil })
	svc.SetDataScope(enf)
	svc.SetOwnerAccess(postgres.NewRemediationOwnerAccessRepository(pdb))
	rec := &auditRecorder{}
	svc.SetAuditLogger(rec)
	return &ownerRig{rtRig: r, svc: svc, audit: rec,
		fA: r.finding(r.assetA, "new", nil), fB1: r.finding(r.assetB, "new", nil), fB2: r.finding(r.assetB, "in_progress", nil)}
}

func (r *ownerRig) create(owner *shared.ID, group *shared.ID, canExtend, confirm bool, ids ...shared.ID) (*remediation.Task, error) {
	return r.svc.CreateTask(r.adminCtx(), remediationapp.CreateTaskInput{
		TenantID: r.tenant, ActorID: &r.admin, Title: "owner access", FindingIDs: ids, AssigneeUserID: owner, AssigneeGroupID: group,
		CanExtendOwnerAccess: canExtend, ConfirmOwnerAccess: confirm,
	}, auditapp.AuditContext{})
}

func TestOwnerCandidates_CountsOnlyAgainstEachCandidatesScope(t *testing.T) {
	r := newOwnerRig(t)
	res, err := r.svc.OwnerCandidates(r.adminCtx(), remediationapp.OwnerCandidatesInput{
		TenantID: r.tenant, FindingIDs: []shared.ID{r.fA, r.fB1, r.fB2}})
	require.NoError(t, err)
	assert.Equal(t, 3, res.Findings)
	byID := map[shared.ID]remediationapp.OwnerCandidate{}
	for _, c := range res.Candidates {
		byID[c.ID] = c
	}
	// The administrator sees everything; the member lacks the two assetB findings (one asset).
	assert.Zero(t, byID[r.admin].Findings)
	m := byID[r.member]
	assert.Equal(t, 2, m.Findings)
	assert.Equal(t, 1, m.Assets)
	// Entitled candidates come first.
	require.NotEmpty(t, res.Candidates)
	assert.Zero(t, res.Candidates[0].Findings)
	// A team with no member lacks nothing.
	g := byID[r.group]
	assert.True(t, g.Team)
	assert.Zero(t, g.Findings)

	// A team whose member lacks access reports the member count.
	r.exec(`INSERT INTO group_members (group_id, user_id, role) VALUES ($1, $2, 'member')`, r.group.String(), r.member.String())
	res, err = r.svc.OwnerCandidates(r.adminCtx(), remediationapp.OwnerCandidatesInput{
		TenantID: r.tenant, FindingIDs: []shared.ID{r.fA, r.fB1, r.fB2}, Query: "rt team"})
	require.NoError(t, err)
	require.Len(t, res.Candidates, 1)
	assert.Equal(t, 2, res.Candidates[0].Findings)
	assert.Equal(t, 1, res.Candidates[0].MembersMissing)
	assert.Equal(t, 1, res.Candidates[0].Members)
}

func TestOwnerCandidates_AssigneeExceptionAndClosedFindings(t *testing.T) {
	r := newOwnerRig(t)
	// A finding assigned to the member is visible to them; a closed one is not counted.
	r.exec(`UPDATE findings SET assigned_to = $1 WHERE id = $2`, r.member.String(), r.fB1.String())
	r.setStatus(r.fB2, "resolved", "")
	res, err := r.svc.OwnerCandidates(r.adminCtx(), remediationapp.OwnerCandidatesInput{
		TenantID: r.tenant, FindingIDs: []shared.ID{r.fA, r.fB1, r.fB2}, Query: r.member.String()})
	require.NoError(t, err)
	require.Len(t, res.Candidates, 1)
	assert.Zero(t, res.Candidates[0].Findings)
	assert.Equal(t, 2, res.Findings) // the resolved one is not a finding to fix
}

func TestOwnerCandidates_NegativesTenantAndScope(t *testing.T) {
	r := newOwnerRig(t)
	// A finding of another tenant is the one not-found answer.
	_, err := r.svc.OwnerCandidates(r.adminCtx(), remediationapp.OwnerCandidatesInput{TenantID: r.tenant, FindingIDs: []shared.ID{r.otherF}})
	assert.ErrorIs(t, err, shared.ErrNotFound)
	// The other tenant's users and teams are never listed.
	otherUser := shared.NewID()
	r.exec(`INSERT INTO users (id, email, name) VALUES ($1, $2, 'rt other')`, otherUser.String(), otherUser.String()+"@rt.test")
	r.exec(`INSERT INTO tenant_members (user_id, tenant_id, role) VALUES ($1, $2, 'member')`, otherUser.String(), r.other.String())
	t.Cleanup(func() { _, _ = r.db.Exec(`DELETE FROM users WHERE id = $1`, otherUser.String()) })
	res, err := r.svc.OwnerCandidates(r.adminCtx(), remediationapp.OwnerCandidatesInput{TenantID: r.tenant, FindingIDs: []shared.ID{r.fA}})
	require.NoError(t, err)
	for _, c := range res.Candidates {
		assert.NotEqual(t, otherUser, c.ID)
	}
	// A restricted caller cannot probe findings outside their scope.
	_, err = r.svc.OwnerCandidates(rtAs(context.Background(), datascope.Caller{UserID: r.member.String()}),
		remediationapp.OwnerCandidatesInput{TenantID: r.tenant, FindingIDs: []shared.ID{r.fB1}})
	assert.ErrorIs(t, err, shared.ErrNotFound)
	// Nor ask for the candidates of a task they cannot change.
	task, err := r.create(nil, nil, false, false, r.fA, r.fB1)
	require.NoError(t, err)
	_, err = r.svc.OwnerCandidates(rtAs(context.Background(), datascope.Caller{UserID: r.member.String()}),
		remediationapp.OwnerCandidatesInput{TenantID: r.tenant, TaskID: &task.ID})
	require.Error(t, err)
}

func TestOwnerAccessRule_CreateAndUpdate(t *testing.T) {
	r := newOwnerRig(t)
	member := r.member

	// An owner who sees everything needs nothing.
	_, err := r.create(&member, nil, false, false, r.finding(r.assetA, "new", nil))
	require.NoError(t, err)

	// A gap without findings:assign: refused with the counts.
	_, err = r.create(&member, nil, false, true, r.fA, r.fB1, r.fB2)
	oe, ok := remediationapp.AsOwnerAccessError(err)
	require.True(t, ok, "%v", err)
	assert.True(t, oe.NeedsPermission)
	assert.Equal(t, 2, oe.MissingFindings)
	assert.Equal(t, 1, oe.MissingAssets)

	// With the permission but no confirmation: asks for it.
	_, err = r.create(&member, nil, true, false, r.fA, r.fB1)
	oe, ok = remediationapp.AsOwnerAccessError(err)
	require.True(t, ok)
	assert.False(t, oe.NeedsPermission)
	assert.Equal(t, 1, oe.MissingFindings)

	// Confirmed with the permission: created, and audited with the counts.
	task, err := r.create(&member, nil, true, true, r.fA, r.fB1)
	require.NoError(t, err)
	ev := r.audit.extended()
	require.Len(t, ev, 1, "refused attempts write no access entry")
	assert.Equal(t, task.ID.String(), ev[0].ResourceID)
	assert.Equal(t, 1, ev[0].Metadata["findings"])
	assert.Equal(t, 1, ev[0].Metadata["assets"])
	assert.Equal(t, member.String(), ev[0].Metadata["owner_user_id"])

	// Changing the owner of that task to the administrator is fine; back to
	// the member needs the same consent.
	admin := r.admin
	var adm **shared.ID = new(*shared.ID)
	*adm = &admin
	_, err = r.svc.UpdateTask(r.adminCtx(), remediationapp.UpdateTaskInput{TenantID: r.tenant, TaskID: task.ID, Version: task.Version,
		AssigneeUserID: adm}, auditapp.AuditContext{})
	require.NoError(t, err)
	cur, err := r.svc.GetTask(r.adminCtx(), r.tenant, task.ID)
	require.NoError(t, err)
	mp := &member
	mm := &mp
	_, err = r.svc.UpdateTask(r.adminCtx(), remediationapp.UpdateTaskInput{TenantID: r.tenant, TaskID: task.ID, Version: cur.Version,
		AssigneeUserID: mm}, auditapp.AuditContext{})
	_, ok = remediationapp.AsOwnerAccessError(err)
	require.True(t, ok, "%v", err)
	_, err = r.svc.UpdateTask(r.adminCtx(), remediationapp.UpdateTaskInput{TenantID: r.tenant, TaskID: task.ID, Version: cur.Version,
		AssigneeUserID: mm, CanExtendOwnerAccess: true, ConfirmOwnerAccess: true}, auditapp.AuditContext{})
	require.NoError(t, err)

	// An unchanged owner is not re-judged on an unrelated edit.
	cur, err = r.svc.GetTask(r.adminCtx(), r.tenant, task.ID)
	require.NoError(t, err)
	title := "renamed"
	_, err = r.svc.UpdateTask(r.adminCtx(), remediationapp.UpdateTaskInput{TenantID: r.tenant, TaskID: task.ID, Version: cur.Version,
		Title: &title, AssigneeUserID: mm}, auditapp.AuditContext{})
	require.NoError(t, err)

	// Adding findings the owner cannot see follows the same rule.
	cur, err = r.svc.GetTask(r.adminCtx(), r.tenant, task.ID)
	require.NoError(t, err)
	_, err = r.svc.AddMembers(r.adminCtx(), remediationapp.AddMembersInput{TenantID: r.tenant, TaskID: task.ID, Version: cur.Version,
		FindingIDs: []shared.ID{r.fB2}}, auditapp.AuditContext{})
	_, ok = remediationapp.AsOwnerAccessError(err)
	require.True(t, ok, "%v", err)
	_, err = r.svc.AddMembers(r.adminCtx(), remediationapp.AddMembersInput{TenantID: r.tenant, TaskID: task.ID, Version: cur.Version,
		FindingIDs: []shared.ID{r.fB2}, CanExtendOwnerAccess: true, ConfirmOwnerAccess: true}, auditapp.AuditContext{})
	require.NoError(t, err)
}

func TestOwnerAccessRule_TeamOwnerWithMemberGap(t *testing.T) {
	r := newOwnerRig(t)
	r.exec(`INSERT INTO group_members (group_id, user_id, role) VALUES ($1, $2, 'member')`, r.group.String(), r.member.String())
	g := r.group
	_, err := r.create(nil, &g, false, false, r.fA, r.fB1)
	oe, ok := remediationapp.AsOwnerAccessError(err)
	require.True(t, ok, "%v", err)
	assert.Equal(t, 1, oe.MissingFindings)
	// An expired membership does not count.
	r.exec(`UPDATE group_members SET expires_at = now() - interval '1 day' WHERE group_id = $1`, r.group.String())
	_, err = r.create(nil, &g, false, false, r.fA, r.fB1)
	require.NoError(t, err)
}

package integration

// Remediation tasks (docs/rfcs/RFC-098-remediation-tasks.md) on a migrated
// database: a person creates a task from findings; a finding has one primary
// task; the state, the deadline and the counters are derived from the
// members; done needs a verified fix; a restricted member sees and changes
// tasks through their data scope only; another tenant sees nothing.

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/internal/app/datascope"
	remediationapp "github.com/openctemio/openctem/api/internal/app/remediation"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/internal/testdb"
	"github.com/openctemio/openctem/api/pkg/domain/remediation"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/pagination"
)

type rtCallerKey struct{}

func rtAs(ctx context.Context, c datascope.Caller) context.Context {
	return context.WithValue(ctx, rtCallerKey{}, c)
}

type rtRig struct {
	t      *testing.T
	db     *sql.DB
	svc    *remediationapp.TaskService
	repo   *postgres.RemediationTaskRepository
	tenant shared.ID
	admin  shared.ID
	member shared.ID // restricted to assetA
	assetA shared.ID
	assetB shared.ID
	group  shared.ID
	other  shared.ID // another tenant
	otherF shared.ID // a finding of the other tenant
	seq    int
}

func newRTRig(t *testing.T) *rtRig {
	t.Helper()
	dsn := testdb.URL()
	if dsn == "" {
		t.Skip("DATABASE_URL not set; skipping DB-backed test")
	}
	db, err := sql.Open("postgres", dsn)
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })

	r := &rtRig{t: t, db: db, tenant: shared.NewID(), admin: shared.NewID(), member: shared.NewID(),
		assetA: shared.NewID(), assetB: shared.NewID(), group: shared.NewID(), other: shared.NewID()}
	for _, tn := range []shared.ID{r.tenant, r.other} {
		r.exec(`INSERT INTO tenants (id, name, slug) VALUES ($1, $2, $2)`, tn.String(), "rt-"+tn.String())
	}
	t.Cleanup(func() {
		_, _ = db.Exec(`DELETE FROM tenants WHERE id = ANY($1::uuid[])`, "{"+r.tenant.String()+","+r.other.String()+"}")
		_, _ = db.Exec(`DELETE FROM users WHERE id = ANY($1::uuid[])`, "{"+r.admin.String()+","+r.member.String()+"}")
	})
	for _, u := range []shared.ID{r.admin, r.member} {
		r.exec(`INSERT INTO users (id, email, name) VALUES ($1, $2, 'rt')`, u.String(), u.String()+"@rt.test")
		r.exec(`INSERT INTO tenant_members (user_id, tenant_id, role) VALUES ($1, $2, 'member')`, u.String(), r.tenant.String())
	}
	for _, a := range []shared.ID{r.assetA, r.assetB} {
		r.exec(`INSERT INTO assets (id, tenant_id, name, asset_type, exposure, criticality) VALUES ($1, $2, $3, 'domain', 'public', 'high')`,
			a.String(), r.tenant.String(), "rt-"+a.String()+".example.com")
	}
	r.exec(`INSERT INTO user_accessible_assets (user_id, tenant_id, asset_id) VALUES ($1, $2, $3)`,
		r.member.String(), r.tenant.String(), r.assetA.String())
	r.exec(`INSERT INTO groups (id, tenant_id, name, slug) VALUES ($1, $2, 'rt team', $3)`,
		r.group.String(), r.tenant.String(), "rt-"+r.group.String())
	otherAsset := shared.NewID()
	r.exec(`INSERT INTO assets (id, tenant_id, name, asset_type, exposure, criticality) VALUES ($1, $2, 'rt-other.example.com', 'domain', 'public', 'high')`,
		otherAsset.String(), r.other.String())
	r.otherF = r.findingIn(r.other, otherAsset, "new", "high", nil)

	pdb := &postgres.DB{DB: db}
	r.repo = postgres.NewRemediationTaskRepository(pdb)
	r.svc = remediationapp.NewTaskService(r.repo, logger.NewNop())
	r.svc.SetAssigneeChecker(postgres.NewAccessControlRepository(pdb))
	r.svc.SetDataScope(datascope.New(postgres.NewDataScopeRepository(pdb), func(ctx context.Context) datascope.Caller {
		c, _ := ctx.Value(rtCallerKey{}).(datascope.Caller)
		return c
	}, logger.NewNop()))
	return r
}

func (r *rtRig) exec(q string, args ...any) {
	r.t.Helper()
	_, err := r.db.Exec(q, args...)
	require.NoError(r.t, err, q)
}

func (r *rtRig) findingIn(tenant, asset shared.ID, status, severity string, sla *time.Time) shared.ID {
	r.t.Helper()
	r.seq++
	id := shared.NewID()
	r.exec(`INSERT INTO findings (id, tenant_id, asset_id, source, tool_name, message, title, severity, fingerprint, status, sla_deadline)
		VALUES ($1::uuid, $2, $3, 'sca', 'rt-tool', 'rt finding', $4, $5, $1::text, $6, $7)`,
		id.String(), tenant.String(), asset.String(), "rt finding", severity, status, sla)
	return id
}

func (r *rtRig) finding(asset shared.ID, status string, sla *time.Time) shared.ID {
	return r.findingIn(r.tenant, asset, status, "high", sla)
}

// setStatus moves a finding; for a closed status, verification is how the
// closure was proven ("" = none).
func (r *rtRig) setStatus(id shared.ID, status, verification string) {
	r.t.Helper()
	var reason, verif any
	switch status {
	case "resolved":
		reason = "fixed"
		verif = "none"
		if verification != "" {
			verif = verification
		}
	case "accepted":
		reason = "risk_accepted"
	}
	r.exec(`UPDATE findings SET status = $3, closure_reason = $4, verification = $5, updated_at = now() + interval '1 second'
		WHERE tenant_id = $1 AND id = $2`, r.tenant.String(), id.String(), status, reason, verif)
}

func (r *rtRig) adminCtx() context.Context {
	return rtAs(context.Background(), datascope.Caller{UserID: r.admin.String(), IsAdmin: true})
}

func (r *rtRig) memberCtx() context.Context {
	return rtAs(context.Background(), datascope.Caller{UserID: r.member.String()})
}

func TestRemediationTasks_CreateDeriveAndOnePrimaryTask(t *testing.T) {
	r := newRTRig(t)
	ctx := r.adminCtx()
	now := time.Now().UTC().Truncate(time.Second)
	early, late := now.Add(48*time.Hour), now.Add(240*time.Hour)
	f1 := r.finding(r.assetA, "new", &late)
	f2 := r.finding(r.assetB, "confirmed", &early)
	f3 := r.finding(r.assetA, "new", nil)

	task, err := r.svc.CreateTask(ctx, remediationapp.CreateTaskInput{
		TenantID: r.tenant, ActorID: &r.admin, Title: "  Upgrade django to 4.2.30 ",
		FindingIDs: []shared.ID{f1, f2, f1}, RelatedIDs: []shared.ID{f3},
		AssigneeUserID: &r.admin, AssigneeGroupID: &r.group,
	}, auditapp.AuditContext{})
	require.NoError(t, err)
	assert.Equal(t, "Upgrade django to 4.2.30", task.Title)
	assert.Equal(t, remediation.ActionKindManual, task.ActionKind)
	assert.Equal(t, remediation.TaskStateOpen, task.State)
	assert.Equal(t, 2, task.Counts.Total, "duplicates collapse")
	assert.Equal(t, 1, task.Counts.Related)
	assert.Equal(t, 4, task.Counts.RiskPoints, "two open high findings")
	require.NotNil(t, task.Deadline)
	assert.WithinDuration(t, early, *task.Deadline, time.Second, "deadline = earliest open member SLA")
	assert.Equal(t, remediation.DeadlineSourceMember, *task.DeadlineSource)
	assert.Equal(t, 1, task.Version)

	// A finding has one primary task: a second task naming f2 is refused
	// with the finding listed.
	_, err = r.svc.CreateTask(ctx, remediationapp.CreateTaskInput{TenantID: r.tenant, ActorID: &r.admin, Title: "Other",
		FindingIDs: []shared.ID{f2}}, auditapp.AuditContext{})
	e, ok := remediation.AsFindingsInOtherTask(err)
	require.True(t, ok, "got %v", err)
	assert.Equal(t, []shared.ID{f2}, e.FindingIDs)
	// ... but it may be a related member of another task.
	other, err := r.svc.CreateTask(ctx, remediationapp.CreateTaskInput{TenantID: r.tenant, ActorID: &r.admin, Title: "Other",
		FindingIDs: []shared.ID{f3}, RelatedIDs: []shared.ID{f2}}, auditapp.AuditContext{})
	require.NoError(t, err)
	assert.Equal(t, 1, other.Counts.Related)

	// The finding's timeline names the task.
	var n int
	require.NoError(t, r.db.QueryRow(`SELECT COUNT(*) FROM finding_activities WHERE tenant_id = $1 AND finding_id = $2
		AND activity_type = 'remediation_task_changed' AND changes->>'task_id' = $3`,
		r.tenant.String(), f1.String(), task.ID.String()).Scan(&n))
	assert.Equal(t, 1, n)

	// A tighter manual deadline wins; a later one never extends the member SLA.
	tighter := now.Add(24 * time.Hour)
	dl := &tighter
	task, err = r.svc.UpdateTask(ctx, remediationapp.UpdateTaskInput{TenantID: r.tenant, TaskID: task.ID, ActorID: &r.admin,
		Version: task.Version, Deadline: &dl}, auditapp.AuditContext{})
	require.NoError(t, err)
	assert.WithinDuration(t, tighter, *task.Deadline, time.Second)
	assert.Equal(t, remediation.DeadlineSourceManual, *task.DeadlineSource)
	later := now.Add(2400 * time.Hour)
	dl = &later
	task, err = r.svc.UpdateTask(ctx, remediationapp.UpdateTaskInput{TenantID: r.tenant, TaskID: task.ID, ActorID: &r.admin,
		Version: task.Version, Deadline: &dl}, auditapp.AuditContext{})
	require.NoError(t, err)
	assert.WithinDuration(t, early, *task.Deadline, time.Second, "a later manual deadline does not extend")

	// A stale version is refused.
	title := "Renamed"
	_, err = r.svc.UpdateTask(ctx, remediationapp.UpdateTaskInput{TenantID: r.tenant, TaskID: task.ID, ActorID: &r.admin,
		Version: 1, Title: &title}, auditapp.AuditContext{})
	assert.ErrorIs(t, err, remediation.ErrTaskVersionConflict)

	// Derived state follows the members (the reconcile picks up changes).
	r.setStatus(f1, "in_progress", "")
	_, err = r.svc.Reconcile(context.Background())
	require.NoError(t, err)
	task, err = r.svc.GetTask(ctx, r.tenant, task.ID)
	require.NoError(t, err)
	assert.Equal(t, remediation.TaskStateInProgress, task.State)

	r.setStatus(f1, "fix_applied", "")
	r.setStatus(f2, "fix_applied", "")
	_, err = r.svc.Reconcile(context.Background())
	require.NoError(t, err)
	task, _ = r.svc.GetTask(ctx, r.tenant, task.ID)
	assert.Equal(t, remediation.TaskStateVerifying, task.State)

	// Every member closed but nothing verified: not done.
	r.setStatus(f1, "accepted", "")
	r.setStatus(f2, "resolved", "attested")
	_, err = r.svc.Reconcile(context.Background())
	require.NoError(t, err)
	task, _ = r.svc.GetTask(ctx, r.tenant, task.ID)
	assert.Equal(t, remediation.TaskStateClosedUnverified, task.State)
	assert.Nil(t, task.Deadline, "no open member, no deadline")

	// One member verified by a scan: done.
	r.setStatus(f2, "resolved", "covered_scan")
	_, err = r.svc.Reconcile(context.Background())
	require.NoError(t, err)
	task, _ = r.svc.GetTask(ctx, r.tenant, task.ID)
	assert.Equal(t, remediation.TaskStateDone, task.State)
	assert.Equal(t, 1, task.Counts.Verified)
	assert.NotNil(t, task.ClosedAt)

	// A done task takes no new members and no edits.
	_, err = r.svc.UpdateTask(ctx, remediationapp.UpdateTaskInput{TenantID: r.tenant, TaskID: task.ID, ActorID: &r.admin,
		Version: task.Version, Title: &title}, auditapp.AuditContext{})
	assert.ErrorIs(t, err, remediation.ErrTaskTerminal)

	// The timeline records the creation, the edits and the state changes.
	ev, err := r.svc.ListEvents(ctx, r.tenant, task.ID, pagination.New(1, 50))
	require.NoError(t, err)
	kinds := map[string]int{}
	for _, e := range ev.Data {
		kinds[e.Kind]++
	}
	assert.Equal(t, 1, kinds[remediation.TaskEventCreated])
	assert.GreaterOrEqual(t, kinds[remediation.TaskEventStateChanged], 4)
}

func TestRemediationTasks_RefusesBadInput(t *testing.T) {
	r := newRTRig(t)
	ctx := r.adminCtx()
	open := r.finding(r.assetA, "new", nil)
	closed := r.finding(r.assetA, "new", nil)
	r.setStatus(closed, "resolved", "")
	create := func(in remediationapp.CreateTaskInput) error {
		in.TenantID, in.ActorID = r.tenant, &r.admin
		if in.Title == "" {
			in.Title = "t"
		}
		_, err := r.svc.CreateTask(ctx, in, auditapp.AuditContext{})
		return err
	}
	assert.ErrorIs(t, create(remediationapp.CreateTaskInput{}), remediationapp.ErrTaskNoFindings)
	assert.ErrorIs(t, create(remediationapp.CreateTaskInput{FindingIDs: []shared.ID{closed}}), remediationapp.ErrTaskFindingClosed)
	// Another tenant's finding is not found (never "forbidden").
	assert.ErrorIs(t, create(remediationapp.CreateTaskInput{FindingIDs: []shared.ID{r.otherF}}), remediationapp.ErrTaskFindingNotFound)
	// An owner who is not a member, a group of no tenant.
	stranger, strangerGroup := shared.NewID(), shared.NewID()
	assert.ErrorIs(t, create(remediationapp.CreateTaskInput{FindingIDs: []shared.ID{open}, AssigneeUserID: &stranger}), remediationapp.ErrInvalidTaskAssignee)
	assert.ErrorIs(t, create(remediationapp.CreateTaskInput{FindingIDs: []shared.ID{open}, AssigneeGroupID: &strangerGroup}), remediationapp.ErrInvalidTaskGroup)
	// A campaign of another tenant.
	camp := shared.NewID()
	r.exec(`INSERT INTO remediation_campaigns (id, tenant_id, name) VALUES ($1, $2, 'rt other')`, camp.String(), r.other.String())
	assert.ErrorIs(t, create(remediationapp.CreateTaskInput{FindingIDs: []shared.ID{open}, CampaignID: &camp}), remediationapp.ErrTaskCampaignNotFound)
	// A blank title.
	err := create(remediationapp.CreateTaskInput{Title: "   ", FindingIDs: []shared.ID{open}})
	assert.ErrorIs(t, err, shared.ErrValidation)
}

func TestRemediationTasks_CampaignDeadlineOnlyTightens(t *testing.T) {
	r := newRTRig(t)
	ctx := r.adminCtx()
	sla := time.Now().UTC().Add(30 * 24 * time.Hour).Truncate(time.Second)
	f := r.finding(r.assetA, "new", &sla)
	camp := shared.NewID()
	due := time.Now().UTC().Add(5 * 24 * time.Hour)
	r.exec(`INSERT INTO remediation_campaigns (id, tenant_id, name, due_date) VALUES ($1, $2, 'rt camp', $3::date)`,
		camp.String(), r.tenant.String(), due.Format(time.DateOnly))
	task, err := r.svc.CreateTask(ctx, remediationapp.CreateTaskInput{TenantID: r.tenant, ActorID: &r.admin, Title: "KEV",
		FindingIDs: []shared.ID{f}, CampaignID: &camp}, auditapp.AuditContext{})
	require.NoError(t, err)
	require.NotNil(t, task.Deadline)
	assert.Equal(t, remediation.DeadlineSourceCampaign, *task.DeadlineSource)
	assert.True(t, task.Deadline.Before(sla))

	// A campaign due after the member SLA does not extend it.
	r.exec(`UPDATE remediation_campaigns SET due_date = $2::date WHERE id = $1`, camp.String(),
		time.Now().UTC().Add(90*24*time.Hour).Format(time.DateOnly))
	require.NoError(t, r.repo.Recompute(context.Background(), r.tenant, []shared.ID{task.ID}, nil))
	task, _ = r.svc.GetTask(ctx, r.tenant, task.ID)
	assert.Equal(t, remediation.DeadlineSourceMember, *task.DeadlineSource)
	assert.WithinDuration(t, sla, *task.Deadline, time.Second)
}

func TestRemediationTasks_TenantIsolationAndDataScope(t *testing.T) {
	r := newRTRig(t)
	admin, member := r.adminCtx(), r.memberCtx()
	inA := r.finding(r.assetA, "new", nil)
	inB := r.finding(r.assetB, "new", nil)
	mixed, err := r.svc.CreateTask(admin, remediationapp.CreateTaskInput{TenantID: r.tenant, ActorID: &r.admin, Title: "Mixed",
		FindingIDs: []shared.ID{inA, inB}}, auditapp.AuditContext{})
	require.NoError(t, err)
	onlyB, err := r.svc.CreateTask(admin, remediationapp.CreateTaskInput{TenantID: r.tenant, ActorID: &r.admin, Title: "Only B",
		FindingIDs: []shared.ID{r.finding(r.assetB, "new", nil)}}, auditapp.AuditContext{})
	require.NoError(t, err)

	// Another tenant: not found, and not listed.
	_, err = r.svc.GetTask(admin, r.other, mixed.ID)
	assert.ErrorIs(t, err, shared.ErrNotFound)
	list, err := r.svc.ListTasks(admin, remediationapp.ListTasksInput{TenantID: r.other}, pagination.New(1, 50))
	require.NoError(t, err)
	assert.Empty(t, list.Data)
	_, err = r.svc.AddMembers(admin, remediationapp.AddMembersInput{TenantID: r.other, TaskID: mixed.ID, Version: mixed.Version,
		FindingIDs: []shared.ID{r.otherF}}, auditapp.AuditContext{})
	assert.ErrorIs(t, err, shared.ErrNotFound)

	// The restricted member sees the mixed task through its in-scope finding
	// only, and not the task whose findings are all out of scope.
	got, err := r.svc.GetTask(member, r.tenant, mixed.ID)
	require.NoError(t, err)
	assert.Equal(t, 1, got.Counts.Total)
	assert.Equal(t, 1, got.HiddenMembers)
	_, err = r.svc.GetTask(member, r.tenant, onlyB.ID)
	assert.ErrorIs(t, err, shared.ErrNotFound)
	list, err = r.svc.ListTasks(member, remediationapp.ListTasksInput{TenantID: r.tenant}, pagination.New(1, 50))
	require.NoError(t, err)
	require.Len(t, list.Data, 1)
	assert.Equal(t, mixed.ID, list.Data[0].ID)
	members, err := r.svc.ListMembers(member, r.tenant, mixed.ID, remediation.MemberFilter{}, pagination.New(1, 50))
	require.NoError(t, err)
	require.Len(t, members.Data, 1)
	assert.Equal(t, inA, members.Data[0].FindingID)
	_, err = r.svc.ListEvents(member, r.tenant, onlyB.ID, pagination.New(1, 50))
	assert.ErrorIs(t, err, shared.ErrNotFound)

	// ... and may not change a task with findings outside their scope.
	title := "x"
	_, err = r.svc.UpdateTask(member, remediationapp.UpdateTaskInput{TenantID: r.tenant, TaskID: mixed.ID, ActorID: &r.member,
		Version: mixed.Version, Title: &title}, auditapp.AuditContext{})
	assert.ErrorIs(t, err, remediation.ErrTaskHiddenMembers)

	// They may create a task from their own findings, never from others'.
	_, err = r.svc.CreateTask(member, remediationapp.CreateTaskInput{TenantID: r.tenant, ActorID: &r.member, Title: "Mine",
		FindingIDs: []shared.ID{r.finding(r.assetB, "new", nil)}}, auditapp.AuditContext{})
	assert.ErrorIs(t, err, remediationapp.ErrTaskFindingNotFound)
	mine, err := r.svc.CreateTask(member, remediationapp.CreateTaskInput{TenantID: r.tenant, ActorID: &r.member, Title: "Mine",
		FindingIDs: []shared.ID{r.finding(r.assetA, "new", nil)}, AssigneeGroupID: &r.group}, auditapp.AuditContext{})
	require.NoError(t, err)
	_, err = r.svc.AddMembers(member, remediationapp.AddMembersInput{TenantID: r.tenant, TaskID: mine.ID, ActorID: &r.member,
		Version: mine.Version, FindingIDs: []shared.ID{inB}, Role: remediation.MemberRoleRelated}, auditapp.AuditContext{})
	assert.ErrorIs(t, err, remediationapp.ErrTaskFindingNotFound)

	// The schema itself refuses a link to another tenant's finding or group
	// (composite tenant foreign keys), whatever the code does.
	_, err = r.db.Exec(`INSERT INTO remediation_task_members (tenant_id, task_id, finding_id, join_source)
		VALUES ($1, $2, $3, 'manual')`, r.tenant.String(), mixed.ID.String(), r.otherF.String())
	assert.Error(t, err, "a member row cannot name another tenant's finding")
	otherGroup := shared.NewID()
	r.exec(`INSERT INTO groups (id, tenant_id, name, slug) VALUES ($1, $2, 'rt other', $3)`,
		otherGroup.String(), r.other.String(), "rt-"+otherGroup.String())
	_, err = r.db.Exec(`UPDATE remediation_tasks SET assignee_group_id = $3 WHERE tenant_id = $1 AND id = $2`,
		r.tenant.String(), mixed.ID.String(), otherGroup.String())
	assert.Error(t, err, "a task cannot be assigned another tenant's group")

	// "My tasks" lists tasks assigned to the caller's groups.
	r.exec(`INSERT INTO group_members (group_id, user_id) VALUES ($1, $2)`, r.group.String(), r.member.String())
	list, err = r.svc.ListTasks(member, remediationapp.ListTasksInput{TenantID: r.tenant, CallerID: &r.member, Mine: true}, pagination.New(1, 50))
	require.NoError(t, err)
	require.Len(t, list.Data, 1)
	assert.Equal(t, mine.ID, list.Data[0].ID)
}

func TestRemediationTasks_HoldResumeCancel(t *testing.T) {
	r := newRTRig(t)
	ctx := r.adminCtx()
	held := r.finding(r.assetA, "new", nil)
	task, err := r.svc.CreateTask(ctx, remediationapp.CreateTaskInput{TenantID: r.tenant, ActorID: &r.admin, Title: "Hold me",
		FindingIDs: []shared.ID{held}}, auditapp.AuditContext{})
	require.NoError(t, err)
	hold := true
	task, err = r.svc.UpdateTask(ctx, remediationapp.UpdateTaskInput{TenantID: r.tenant, TaskID: task.ID, ActorID: &r.admin,
		Version: task.Version, Hold: &hold, StateNote: "no window"}, auditapp.AuditContext{})
	require.NoError(t, err)
	assert.Equal(t, remediation.TaskStateOnHold, task.State)
	hold = false
	task, err = r.svc.UpdateTask(ctx, remediationapp.UpdateTaskInput{TenantID: r.tenant, TaskID: task.ID, ActorID: &r.admin,
		Version: task.Version, Hold: &hold}, auditapp.AuditContext{})
	require.NoError(t, err)
	assert.Equal(t, remediation.TaskStateOpen, task.State)
	_, err = r.svc.UpdateTask(ctx, remediationapp.UpdateTaskInput{TenantID: r.tenant, TaskID: task.ID, ActorID: &r.admin,
		Version: task.Version, Cancel: true}, auditapp.AuditContext{})
	assert.True(t, errors.Is(err, shared.ErrValidation), "cancel needs a reason")
	task, err = r.svc.UpdateTask(ctx, remediationapp.UpdateTaskInput{TenantID: r.tenant, TaskID: task.ID, ActorID: &r.admin,
		Version: task.Version, Cancel: true, StateNote: "duplicate effort"}, auditapp.AuditContext{})
	require.NoError(t, err)
	assert.Equal(t, remediation.TaskStateCanceled, task.State)
	// A canceled task lets its findings go (they may join another task) and
	// takes no new members.
	_, err = r.svc.CreateTask(ctx, remediationapp.CreateTaskInput{TenantID: r.tenant, ActorID: &r.admin, Title: "Next try",
		FindingIDs: []shared.ID{held}}, auditapp.AuditContext{})
	require.NoError(t, err)
	_, err = r.svc.AddMembers(ctx, remediationapp.AddMembersInput{TenantID: r.tenant, TaskID: task.ID, ActorID: &r.admin,
		Version: task.Version, FindingIDs: []shared.ID{r.finding(r.assetA, "new", nil)}}, auditapp.AuditContext{})
	assert.ErrorIs(t, err, remediation.ErrTaskTerminal)
}

// overdue=true counts every open task past its deadline, not just the ones
// on a page; a task without a deadline or with a future one is never
// overdue, another tenant's tasks never count, and a restricted member's
// count covers only the tasks they can see.
func TestRemediationTasks_OverdueFilter(t *testing.T) {
	r := newRTRig(t)
	admin, member := r.adminCtx(), r.memberCtx()
	mk := func(asset shared.ID, title string, deadline *string) remediation.Task {
		task, err := r.svc.CreateTask(admin, remediationapp.CreateTaskInput{TenantID: r.tenant, ActorID: &r.admin, Title: title,
			FindingIDs: []shared.ID{r.finding(asset, "new", nil)}}, auditapp.AuditContext{})
		require.NoError(t, err)
		if deadline == nil {
			r.exec(`UPDATE remediation_tasks SET deadline = NULL WHERE id = $1`, task.ID.String())
		} else {
			r.exec(`UPDATE remediation_tasks SET deadline = NOW() + $2::interval WHERE id = $1`, task.ID.String(), *deadline)
		}
		return *task
	}
	past, future := "-2 days", "3 days"
	late := mk(r.assetA, "late", &past)
	lateB := mk(r.assetB, "late out of scope", &past)
	mk(r.assetA, "future", &future)
	mk(r.assetA, "no deadline", nil)
	canceled := mk(r.assetA, "late but canceled", &past)
	r.exec(`UPDATE remediation_tasks SET state = 'canceled' WHERE id = $1`, canceled.ID.String())

	open := []remediation.TaskState{remediation.TaskStateOpen, remediation.TaskStateInProgress,
		remediation.TaskStateVerifying, remediation.TaskStateOnHold}
	count := func(ctx context.Context, tenant shared.ID, f remediation.TaskFilter) int64 {
		res, err := r.svc.ListTasks(ctx, remediationapp.ListTasksInput{TenantID: tenant, Filter: f}, pagination.New(1, 1))
		require.NoError(t, err)
		return res.Total
	}
	assert.EqualValues(t, 2, count(admin, r.tenant, remediation.TaskFilter{States: open, Overdue: true}))
	assert.EqualValues(t, 3, count(admin, r.tenant, remediation.TaskFilter{Overdue: true}), "without a state filter canceled counts too")
	assert.EqualValues(t, 4, count(admin, r.tenant, remediation.TaskFilter{States: open}))
	assert.EqualValues(t, 0, count(admin, r.other, remediation.TaskFilter{States: open, Overdue: true}), "another tenant sees none")

	res, err := r.svc.ListTasks(member, remediationapp.ListTasksInput{TenantID: r.tenant,
		Filter: remediation.TaskFilter{States: open, Overdue: true}}, pagination.New(1, 50))
	require.NoError(t, err)
	require.EqualValues(t, 1, res.Total, "a restricted member counts only tasks they can see")
	assert.Equal(t, late.ID, res.Data[0].ID)
	assert.NotEqual(t, lateB.ID, res.Data[0].ID)
}

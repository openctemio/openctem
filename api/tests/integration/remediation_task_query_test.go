package integration

// Remediation tasks created from a custom query
// (docs/rfcs/RFC-098-remediation-tasks.md, "Tasks from a query") on a
// migrated database: the query runs in the creator's scope (tenant, data
// scope, pentest and closed findings left out); conflicts answer 409 unless
// skipped; the cap holds; auto mode runs as the owner with their current
// access, never takes a finding another active task holds, and suspends
// when the owner leaves, loses access or the account is deleted; every
// step is audited.

import (
	"context"
	"fmt"
	"slices"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/internal/app/datascope"
	queryapp "github.com/openctemio/openctem/api/internal/app/query"
	remediationapp "github.com/openctemio/openctem/api/internal/app/remediation"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	auditdom "github.com/openctemio/openctem/api/pkg/domain/audit"
	notificationdom "github.com/openctemio/openctem/api/pkg/domain/notification"
	"github.com/openctemio/openctem/api/pkg/domain/permission"
	"github.com/openctemio/openctem/api/pkg/domain/remediation"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	tenantdom "github.com/openctemio/openctem/api/pkg/domain/tenant"
	"github.com/openctemio/openctem/api/pkg/logger"
)

type qtAudit struct {
	mu     sync.Mutex
	events []auditapp.AuditEvent
}

func (a *qtAudit) LogEvent(_ context.Context, _ auditapp.AuditContext, ev auditapp.AuditEvent) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.events = append(a.events, ev)
	return nil
}

func (a *qtAudit) count(action auditdom.Action) int {
	a.mu.Lock()
	defer a.mu.Unlock()
	n := 0
	for _, e := range a.events {
		if e.Action == action {
			n++
		}
	}
	return n
}

func (a *qtAudit) last(action auditdom.Action) *auditapp.AuditEvent {
	a.mu.Lock()
	defer a.mu.Unlock()
	for i := len(a.events) - 1; i >= 0; i-- {
		if a.events[i].Action == action {
			e := a.events[i]
			return &e
		}
	}
	return nil
}

// qtOwners is the owner directory: who is an active member, with which
// role and permissions.
type qtOwners struct {
	mu     sync.Mutex
	tenant shared.ID
	roles  map[shared.ID]tenantdom.Role
	perms  map[shared.ID][]string
}

func (o *qtOwners) IsActiveTenantMember(_ context.Context, tenantID, userID shared.ID) (bool, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	_, ok := o.roles[userID]
	return ok && tenantID == o.tenant, nil
}

func (o *qtOwners) GetMembership(_ context.Context, userID, tenantID shared.ID) (*tenantdom.Membership, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	role, ok := o.roles[userID]
	if !ok {
		return nil, shared.ErrNotFound
	}
	return tenantdom.NewMembership(userID, tenantID, role, nil)
}

func (o *qtOwners) GetUserPermissions(_ context.Context, _, userID string) ([]string, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	id, _ := shared.IDFromString(userID)
	return o.perms[id], nil
}

type qtNotifier struct {
	mu   sync.Mutex
	sent []notificationdom.NotificationParams
}

func (n *qtNotifier) Notify(_ context.Context, p notificationdom.NotificationParams) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.sent = append(n.sent, p)
	return nil
}

type qtRig struct {
	*rtRig
	audit    *qtAudit
	owners   *qtOwners
	notifier *qtNotifier
}

var memberPerms = []string{permission.FindingsRead.String(), permission.RemediationRead.String(), permission.RemediationWrite.String()}

func newQTRig(t *testing.T) *qtRig {
	r := newRTRig(t)
	pdb := &postgres.DB{DB: r.db}
	enf := datascope.New(postgres.NewDataScopeRepository(pdb), func(ctx context.Context) datascope.Caller {
		c, _ := ctx.Value(rtCallerKey{}).(datascope.Caller)
		return c
	}, logger.NewNop())
	q := queryapp.NewService(postgres.NewQueryExecutor(pdb, 0), enf, logger.NewNop())
	qr := &qtRig{rtRig: r, audit: &qtAudit{}, notifier: &qtNotifier{},
		owners: &qtOwners{tenant: r.tenant, roles: map[shared.ID]tenantdom.Role{r.admin: tenantdom.RoleAdmin, r.member: tenantdom.RoleMember},
			perms: map[shared.ID][]string{r.member: memberPerms}}}
	r.svc.SetAuditLogger(qr.audit)
	r.svc.SetQueryTasks(r.repo, q, qr.owners, qr.notifier)
	return qr
}

func (r *qtRig) adminCaller() queryapp.Caller {
	return queryapp.Caller{TenantID: r.tenant.String(), UserID: r.admin.String(), IsAdmin: true, Has: func(string) bool { return true }}
}

func (r *qtRig) memberCaller() queryapp.Caller {
	return queryapp.Caller{TenantID: r.tenant.String(), UserID: r.member.String(),
		Has: func(p string) bool { return slices.Contains(memberPerms, p) }}
}

// pentestFinding adds an open pentest finding on asset.
func (r *qtRig) pentestFinding(asset shared.ID) shared.ID {
	r.t.Helper()
	id := shared.NewID()
	r.exec(`INSERT INTO findings (id, tenant_id, asset_id, source, tool_name, message, title, severity, fingerprint, status)
		VALUES ($1::uuid, $2, $3, 'pentest', 'rt-tool', 'rt finding', 'pentest finding', 'high', $1::text, 'confirmed')`,
		id.String(), r.tenant.String(), asset.String())
	return id
}

// makeDue moves an auto task's last run into the past.
func (r *qtRig) makeDue(taskID shared.ID) {
	r.exec(`UPDATE remediation_task_queries SET last_run_at = now() - interval '1 day' WHERE task_id = $1`, taskID.String())
}

func (r *qtRig) createQueryTask(ctx context.Context, c queryapp.Caller, actor shared.ID, query string, mode remediation.QueryMode, capN int, res remediation.ConflictResolution) (*remediationapp.CreateQueryTaskResult, error) {
	return r.svc.CreateQueryTask(ctx, remediationapp.CreateQueryTaskInput{TenantID: r.tenant, Caller: c, ActorID: &actor,
		Title: "From a query", Query: query, Mode: mode, Cap: capN, Conflicts: res}, auditapp.AuditContext{})
}

func memberIDs(t *testing.T, r *qtRig, taskID shared.ID) []shared.ID {
	t.Helper()
	rows, err := r.db.Query(`SELECT finding_id FROM remediation_task_members WHERE tenant_id = $1 AND task_id = $2
		AND left_at IS NULL AND role = 'primary' ORDER BY finding_id`, r.tenant.String(), taskID.String())
	require.NoError(t, err)
	defer func() { _ = rows.Close() }()
	var out []shared.ID
	for rows.Next() {
		var id shared.ID
		require.NoError(t, rows.Scan(&id))
		out = append(out, id)
	}
	require.NoError(t, rows.Err())
	return out
}

const qtHigh = `findings where severity = high`

func TestRemediationTaskQuery_ScopeIsolationAndExclusions(t *testing.T) {
	r := newQTRig(t)
	inA := r.finding(r.assetA, "new", nil)
	inB := r.finding(r.assetB, "confirmed", nil)
	_ = r.finding(r.assetA, "resolved", nil) // closed: never matches
	pen := r.pentestFinding(r.assetA)        // pentest: never matches

	// The administrator sees both assets, never the other tenant's finding,
	// a closed one or a pentest one.
	p, err := r.svc.PreviewQueryTask(r.adminCtx(), r.tenant, r.adminCaller(), qtHigh)
	require.NoError(t, err)
	assert.Equal(t, 2, p.Total)
	assert.Equal(t, 2, p.Claimable)
	assert.Equal(t, "organization", p.Scope.Kind)
	sample := map[shared.ID]bool{}
	for _, s := range p.Stats.Sample {
		sample[s.FindingID] = true
	}
	assert.True(t, sample[inA] && sample[inB])
	assert.False(t, sample[pen], "pentest finding left out")
	assert.False(t, sample[r.otherF], "other tenant's finding left out")

	// The restricted member previews only their scope (assetA).
	p, err = r.svc.PreviewQueryTask(r.memberCtx(), r.tenant, r.memberCaller(), qtHigh)
	require.NoError(t, err)
	assert.Equal(t, 1, p.Total)
	assert.Equal(t, "data_scope", p.Scope.Kind)
	require.Len(t, p.Stats.Sample, 1)
	assert.Equal(t, inA, p.Stats.Sample[0].FindingID)

	// ... and creates a task with only that finding.
	res, err := r.createQueryTask(r.memberCtx(), r.memberCaller(), r.member, qtHigh, remediation.QueryModeSnapshot, 0, remediation.ConflictResolution{})
	require.NoError(t, err)
	assert.Equal(t, []shared.ID{inA}, memberIDs(t, r, res.Task.ID))
	assert.Equal(t, remediation.QueryModeSnapshot, res.Query.Mode)
	assert.Equal(t, 1000, res.Query.Cap)

	// The stored query is canonical and versioned; the join source is query.
	got, err := r.svc.GetTaskQuery(r.memberCtx(), r.tenant, res.Task.ID)
	require.NoError(t, err)
	assert.Equal(t, queryapp.LanguageVersion(), got.Version)
	assert.Equal(t, r.member, *got.OwnerUserID)
	var src string
	require.NoError(t, r.db.QueryRow(`SELECT join_source FROM remediation_task_members WHERE task_id = $1`, res.Task.ID.String()).Scan(&src))
	assert.Equal(t, "query", src)

	// Audited with the query text.
	ev := r.audit.last(auditdom.ActionRemediationTaskCreatedFromQuery)
	require.NotNil(t, ev)
	assert.Equal(t, got.Text, ev.Metadata["query"])

	// A caller can never name another tenant.
	bad := r.memberCaller()
	bad.TenantID = r.other.String()
	_, err = r.svc.PreviewQueryTask(r.memberCtx(), r.tenant, bad, qtHigh)
	assert.ErrorIs(t, err, shared.ErrForbidden)

	// Another tenant cannot read the task's query.
	_, err = r.svc.GetTaskQuery(rtAs(context.Background(), datascope.Caller{UserID: r.admin.String(), IsAdmin: true}), r.other, res.Task.ID)
	assert.Error(t, err)

	// An aggregate query selects no findings.
	_, err = r.svc.PreviewQueryTask(r.adminCtx(), r.tenant, r.adminCaller(), `findings | count by severity`)
	assert.ErrorIs(t, err, queryapp.ErrNotFindingFilter)
}

func TestRemediationTaskQuery_ConflictsSkipAndCap(t *testing.T) {
	r := newQTRig(t)
	ctx := r.adminCtx()
	f1 := r.finding(r.assetA, "new", nil)
	f2 := r.finding(r.assetA, "new", nil)
	held := r.finding(r.assetB, "new", nil)
	other, err := r.svc.CreateTask(ctx, remediationapp.CreateTaskInput{TenantID: r.tenant, ActorID: &r.admin, Title: "Held elsewhere",
		FindingIDs: []shared.ID{held}}, auditapp.AuditContext{})
	require.NoError(t, err)

	// The preview lists the conflict with the task (the admin may read and
	// change it).
	p, err := r.svc.PreviewQueryTask(ctx, r.tenant, r.adminCaller(), qtHigh)
	require.NoError(t, err)
	require.Len(t, p.Conflicts, 1)
	assert.Equal(t, held, p.Conflicts[0].FindingID)
	require.NotNil(t, p.Conflicts[0].TaskTitle)
	assert.Equal(t, "Held elsewhere", *p.Conflicts[0].TaskTitle)
	assert.True(t, p.Conflicts[0].CanMove)
	assert.Equal(t, 2, p.Claimable)

	// No resolution: 409 with the conflicts.
	_, err = r.createQueryTask(ctx, r.adminCaller(), r.admin, qtHigh, remediation.QueryModeSnapshot, 0, remediation.ConflictResolution{})
	ce, ok := remediation.AsFindingsInOtherTask(err)
	require.True(t, ok, "got %v", err)
	assert.ErrorIs(t, err, shared.ErrConflict)
	require.Len(t, ce.Conflicts, 1)
	assert.Equal(t, other.ID, ce.Conflicts[0].TaskID)

	// The cap: three matches do not fit an auto task capped at two.
	_, err = r.createQueryTask(ctx, r.adminCaller(), r.admin, qtHigh, remediation.QueryModeAuto, 2, remediation.ConflictResolution{Skip: true})
	assert.ErrorIs(t, err, remediation.ErrTooManyMatches)
	_, err = r.createQueryTask(ctx, r.adminCaller(), r.admin, qtHigh, remediation.QueryModeSnapshot, 1001, remediation.ConflictResolution{})
	assert.ErrorIs(t, err, shared.ErrValidation)

	// Skip: the held finding stays where it is.
	res, err := r.createQueryTask(ctx, r.adminCaller(), r.admin, qtHigh, remediation.QueryModeSnapshot, 0, remediation.ConflictResolution{Skip: true})
	require.NoError(t, err)
	assert.Equal(t, 2, res.Added)
	assert.Equal(t, 1, res.Skipped)
	assert.ElementsMatch(t, []shared.ID{f1, f2}, memberIDs(t, r, res.Task.ID))
	assert.Equal(t, []shared.ID{held}, memberIDs(t, r, other.ID))
}

func TestRemediationTaskQuery_ConflictCountOnlyForRestrictedCaller(t *testing.T) {
	r := newQTRig(t)
	inA := r.finding(r.assetA, "new", nil)
	onB := r.finding(r.assetB, "new", nil)
	// A task the member cannot read (its only finding is on assetB) holds
	// nothing the member can match; one with findings on both assets is
	// visible but not changeable.
	mixed, err := r.svc.CreateTask(r.adminCtx(), remediationapp.CreateTaskInput{TenantID: r.tenant, ActorID: &r.admin, Title: "Mixed",
		FindingIDs: []shared.ID{inA, onB}}, auditapp.AuditContext{})
	require.NoError(t, err)
	p, err := r.svc.PreviewQueryTask(r.memberCtx(), r.tenant, r.memberCaller(), qtHigh)
	require.NoError(t, err)
	require.Len(t, p.Conflicts, 1)
	assert.Equal(t, mixed.ID, p.Conflicts[0].TaskID)
	assert.False(t, p.Conflicts[0].CanMove, "the member may not change a task with findings outside their scope")

	// Moving it is refused.
	_, err = r.createQueryTask(r.memberCtx(), r.memberCaller(), r.member, qtHigh, remediation.QueryModeSnapshot, 0,
		remediation.ConflictResolution{Move: []shared.ID{inA}, MoveReason: "mine now"})
	assert.ErrorIs(t, err, remediation.ErrMoveNotAllowed)
}

func TestRemediationTaskQuery_AutoIncludeInvariantCapAndAudit(t *testing.T) {
	r := newQTRig(t)
	ctx := r.adminCtx()
	_ = r.finding(r.assetA, "new", nil)
	res, err := r.createQueryTask(ctx, r.adminCaller(), r.admin, qtHigh, remediation.QueryModeAuto, 3, remediation.ConflictResolution{})
	require.NoError(t, err)
	require.NotNil(t, res.Query.AutoState)
	assert.Equal(t, remediation.AutoStateActive, *res.Query.AutoState)

	// New matches: one free, one held by another active task, one closed.
	free := r.finding(r.assetB, "new", nil)
	held := r.finding(r.assetA, "new", nil)
	other, err := r.svc.CreateTask(ctx, remediationapp.CreateTaskInput{TenantID: r.tenant, ActorID: &r.admin, Title: "Other",
		FindingIDs: []shared.ID{held}}, auditapp.AuditContext{})
	require.NoError(t, err)
	_ = r.finding(r.assetA, "resolved", nil)

	// Not due yet: nothing runs.
	n, err := r.svc.AutoInclude(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 0, n)

	r.makeDue(res.Task.ID)
	n, err = r.svc.AutoInclude(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 1, n)
	ids := memberIDs(t, r, res.Task.ID)
	assert.Contains(t, ids, free)
	assert.NotContains(t, ids, held, "never takes a finding another active task holds")
	assert.Equal(t, []shared.ID{held}, memberIDs(t, r, other.ID))
	assert.Equal(t, 1, r.audit.count(auditdom.ActionRemediationTaskQueryAutoAdded))
	require.Len(t, r.notifier.sent, 1, "the owner is told of additions")
	assert.Equal(t, r.admin, *r.notifier.sent[0].AudienceID)

	// The cap (3): two more matches, room for one.
	_ = r.finding(r.assetA, "new", nil)
	_ = r.finding(r.assetB, "new", nil)
	r.makeDue(res.Task.ID)
	n, err = r.svc.AutoInclude(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 1, n)
	assert.Len(t, memberIDs(t, r, res.Task.ID), 3)

	// Paused: nothing runs; resumed: runs again.
	_, err = r.svc.SetQueryAutoState(ctx, remediationapp.SetQueryAutoStateInput{TenantID: r.tenant, TaskID: res.Task.ID, ActorID: &r.admin, Paused: true}, auditapp.AuditContext{})
	require.NoError(t, err)
	r.makeDue(res.Task.ID)
	n, err = r.svc.AutoInclude(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 0, n)
	q, err := r.svc.SetQueryAutoState(ctx, remediationapp.SetQueryAutoStateInput{TenantID: r.tenant, TaskID: res.Task.ID, ActorID: &r.admin}, auditapp.AuditContext{})
	require.NoError(t, err)
	assert.Equal(t, remediation.AutoStateActive, *q.AutoState)
	assert.Equal(t, 2, r.audit.count(auditdom.ActionRemediationTaskQueryAutoStateChanged))
}

func TestRemediationTaskQuery_AutoUsesOwnersCurrentScope(t *testing.T) {
	r := newQTRig(t)
	_ = r.finding(r.assetA, "new", nil)
	res, err := r.createQueryTask(r.memberCtx(), r.memberCaller(), r.member, qtHigh, remediation.QueryModeAuto, 0, remediation.ConflictResolution{})
	require.NoError(t, err)
	inA := r.finding(r.assetA, "new", nil)
	onB := r.finding(r.assetB, "new", nil)
	r.makeDue(res.Task.ID)
	_, err = r.svc.AutoInclude(context.Background())
	require.NoError(t, err)
	ids := memberIDs(t, r, res.Task.ID)
	assert.Contains(t, ids, inA)
	assert.NotContains(t, ids, onB, "a restricted owner's auto run stays in their scope")
}

func TestRemediationTaskQuery_AutoSuspendsWhenOwnerLosesAccess(t *testing.T) {
	cases := []struct {
		name   string
		change func(r *qtRig)
		reason remediation.AutoReason
	}{
		{"left the organization", func(r *qtRig) {
			r.owners.mu.Lock()
			delete(r.owners.roles, r.member)
			r.owners.mu.Unlock()
		}, remediation.AutoReasonOwnerRemoved},
		{"lost remediation write", func(r *qtRig) {
			r.owners.mu.Lock()
			r.owners.perms[r.member] = []string{permission.FindingsRead.String()}
			r.owners.mu.Unlock()
		}, remediation.AutoReasonOwnerLostAccess},
		{"account deleted", func(r *qtRig) {
			r.exec(`UPDATE remediation_task_members SET joined_by = NULL WHERE joined_by = $1`, r.member.String())
			r.exec(`UPDATE remediation_tasks SET created_by = NULL WHERE created_by = $1`, r.member.String())
			r.exec(`DELETE FROM users WHERE id = $1`, r.member.String())
		}, remediation.AutoReasonOwnerRemoved},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := newQTRig(t)
			_ = r.finding(r.assetA, "new", nil)
			res, err := r.createQueryTask(r.memberCtx(), r.memberCaller(), r.member, qtHigh, remediation.QueryModeAuto, 0, remediation.ConflictResolution{})
			require.NoError(t, err)
			tc.change(r)
			newF := r.finding(r.assetA, "new", nil)
			r.makeDue(res.Task.ID)
			n, err := r.svc.AutoInclude(context.Background())
			require.NoError(t, err)
			assert.Equal(t, 0, n, "never runs ownerless")
			assert.NotContains(t, memberIDs(t, r, res.Task.ID), newF)
			q, err := r.repo.GetTaskQuery(context.Background(), r.tenant, res.Task.ID)
			require.NoError(t, err)
			assert.Equal(t, remediation.AutoStateSuspended, *q.AutoState)
			assert.Equal(t, tc.reason, *q.AutoReason)
			ev := r.audit.last(auditdom.ActionRemediationTaskQueryAutoStateChanged)
			require.NotNil(t, ev)
			assert.Equal(t, string(tc.reason), ev.Metadata["reason"])

			// Resuming while the cause remains is refused.
			_, err = r.svc.SetQueryAutoState(r.adminCtx(), remediationapp.SetQueryAutoStateInput{TenantID: r.tenant, TaskID: res.Task.ID, ActorID: &r.admin}, auditapp.AuditContext{})
			assert.ErrorIs(t, err, remediation.ErrAutoSuspended)
		})
	}
}

func TestRemediationTaskQuery_RerunAddsOnConfirmation(t *testing.T) {
	r := newQTRig(t)
	ctx := r.adminCtx()
	_ = r.finding(r.assetA, "new", nil)
	res, err := r.createQueryTask(ctx, r.adminCaller(), r.admin, qtHigh, remediation.QueryModeSnapshot, 0, remediation.ConflictResolution{})
	require.NoError(t, err)
	newF := r.finding(r.assetB, "new", nil)

	// Snapshot mode never adds by itself.
	r.makeDue(res.Task.ID)
	n, err := r.svc.AutoInclude(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 0, n)

	p, err := r.svc.PreviewQueryRerun(ctx, r.tenant, res.Task.ID, r.adminCaller())
	require.NoError(t, err)
	assert.Equal(t, 1, p.New)
	assert.NotContains(t, memberIDs(t, r, res.Task.ID), newF, "a preview claims nothing")

	out, task, err := r.svc.RerunQuery(ctx, remediationapp.RerunQueryInput{TenantID: r.tenant, TaskID: res.Task.ID,
		Caller: r.adminCaller(), ActorID: &r.admin}, auditapp.AuditContext{})
	require.NoError(t, err)
	assert.Equal(t, []shared.ID{newF}, out.Added)
	assert.Equal(t, 2, task.Counts.Total)
	assert.Equal(t, 1, r.audit.count(auditdom.ActionRemediationTaskQueryRerun))

	// A restricted member may not re-run a task with findings outside
	// their scope.
	_, err = r.svc.PreviewQueryRerun(r.memberCtx(), r.tenant, res.Task.ID, r.memberCaller())
	assert.ErrorIs(t, err, remediation.ErrTaskHiddenMembers)
}

func TestRemediationTaskQuery_ConcurrentClaimsOneWinner(t *testing.T) {
	r := newQTRig(t)
	ctx := r.adminCtx()
	seed1 := r.finding(r.assetA, "new", nil)
	seed2 := r.finding(r.assetB, "new", nil)
	t1, err := r.svc.CreateTask(ctx, remediationapp.CreateTaskInput{TenantID: r.tenant, ActorID: &r.admin, Title: "A", FindingIDs: []shared.ID{seed1}}, auditapp.AuditContext{})
	require.NoError(t, err)
	t2, err := r.svc.CreateTask(ctx, remediationapp.CreateTaskInput{TenantID: r.tenant, ActorID: &r.admin, Title: "B", FindingIDs: []shared.ID{seed2}}, auditapp.AuditContext{})
	require.NoError(t, err)
	contested := make([]shared.ID, 5)
	for i := range contested {
		contested[i] = r.finding(r.assetA, "new", nil)
	}
	var wg sync.WaitGroup
	results := make([]*remediation.QueryClaimResult, 2)
	errs := make([]error, 2)
	for i, task := range []shared.ID{t1.ID, t2.ID} {
		wg.Add(1)
		go func(i int, task shared.ID) {
			defer wg.Done()
			results[i], errs[i] = r.repo.ClaimQueryFindings(context.Background(), remediation.QueryClaim{TenantID: r.tenant,
				TaskID: task, IDs: contested, Cap: 1000, ActorID: &r.admin, Auto: true})
		}(i, task)
	}
	wg.Wait()
	require.NoError(t, errs[0])
	require.NoError(t, errs[1])
	assert.Equal(t, len(contested), len(results[0].Added)+len(results[1].Added), "each finding claimed exactly once")
	for _, id := range contested {
		var n int
		require.NoError(t, r.db.QueryRow(`SELECT count(*) FROM remediation_task_members WHERE tenant_id = $1 AND finding_id = $2
			AND left_at IS NULL AND role = 'primary'`, r.tenant.String(), id.String()).Scan(&n))
		assert.Equal(t, 1, n, fmt.Sprintf("finding %s has one primary task", id))
	}
}

func TestRemediationTaskQuery_MoveConflictIsAudited(t *testing.T) {
	r := newQTRig(t)
	ctx := r.adminCtx()
	free := r.finding(r.assetA, "new", nil)
	held := r.finding(r.assetB, "new", nil)
	keep := r.finding(r.assetB, "new", nil)
	other, err := r.svc.CreateTask(ctx, remediationapp.CreateTaskInput{TenantID: r.tenant, ActorID: &r.admin, Title: "Source",
		FindingIDs: []shared.ID{held, keep}}, auditapp.AuditContext{})
	require.NoError(t, err)
	// A move needs a reason.
	_, err = r.createQueryTask(ctx, r.adminCaller(), r.admin, qtHigh, remediation.QueryModeSnapshot, 0,
		remediation.ConflictResolution{Move: []shared.ID{held}})
	assert.ErrorIs(t, err, shared.ErrValidation)
	res, err := r.createQueryTask(ctx, r.adminCaller(), r.admin, qtHigh, remediation.QueryModeSnapshot, 0,
		remediation.ConflictResolution{Move: []shared.ID{held}, MoveReason: "one owner for the batch"})
	require.NoError(t, err)
	assert.Equal(t, 1, res.Moved)
	assert.Equal(t, 1, res.Skipped)
	assert.ElementsMatch(t, []shared.ID{free, held}, memberIDs(t, r, res.Task.ID))
	assert.Equal(t, []shared.ID{keep}, memberIDs(t, r, other.ID))
	assert.Equal(t, 1, r.audit.count(auditdom.ActionRemediationTaskFindingsMoved))
}

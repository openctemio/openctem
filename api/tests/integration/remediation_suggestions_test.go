package integration

// Remediation suggestions (docs/rfcs/RFC-098-remediation-tasks.md §5) on a
// migrated database: the generator proposes groups from the remediation
// keys, partitioned by the asset's primary owner; it never creates a task;
// a dismissal holds until a material change; snoozes wake; suggestions
// expire when their findings close; a key with an accepted action yields
// join and task_route proposals; the daily cap holds the rest back; a
// restricted member sees only their findings; another tenant sees nothing.

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/internal/app/datascope"
	"github.com/openctemio/openctem/api/internal/app/outbox"
	remediationapp "github.com/openctemio/openctem/api/internal/app/remediation"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/remediation"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/pagination"
)

type fakeDigest struct {
	mu   sync.Mutex
	sent []outbox.EnqueueParams
}

func (f *fakeDigest) Enqueue(_ context.Context, p outbox.EnqueueParams) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sent = append(f.sent, p)
	return nil
}

type rsRig struct {
	*rtRig
	sug    *remediationapp.SuggestionService
	digest *fakeDigest
	owner  shared.ID // primary user owner of assetA
}

func newRSRig(t *testing.T) *rsRig {
	r := &rsRig{rtRig: newRTRig(t), digest: &fakeDigest{}}
	r.owner = r.admin
	r.exec(`INSERT INTO asset_owners (asset_id, user_id, ownership_type, assignment_source) VALUES ($1, $2, 'primary', 'manual')`,
		r.assetA.String(), r.owner.String())
	r.exec(`INSERT INTO asset_owners (asset_id, group_id, ownership_type, assignment_source) VALUES ($1, $2, 'primary', 'manual')`,
		r.assetB.String(), r.group.String())
	pdb := &postgres.DB{DB: r.db}
	r.sug = remediationapp.NewSuggestionService(postgres.NewRemediationSuggestionRepository(pdb), logger.NewNop())
	r.sug.SetNotifier(r.digest)
	r.sug.SetDataScope(datascope.New(postgres.NewDataScopeRepository(pdb), func(ctx context.Context) datascope.Caller {
		c, _ := ctx.Value(rtCallerKey{}).(datascope.Caller)
		return c
	}, logger.NewNop()))
	return r
}

// keyed adds an open finding with a remediation key on an asset.
func (r *rsRig) keyed(asset shared.ID, key, class string) shared.ID {
	r.t.Helper()
	id := r.finding(asset, "new", nil)
	if class != "" {
		r.exec(`UPDATE findings SET priority_class = $2 WHERE id = $1`, id.String(), class)
	}
	r.exec(`INSERT INTO finding_remediation_keys (finding_id, tenant_id, remediation_key, title) VALUES ($1, $2, $3, $4)`,
		id.String(), r.tenant.String(), key, "Upgrade django to 4.2.30")
	return id
}

func (r *rsRig) run() remediation.RunStats {
	r.t.Helper()
	st, err := r.sug.RunTenant(context.Background(), r.tenant)
	require.NoError(r.t, err)
	return st
}

func (r *rsRig) list(ctx context.Context, states ...remediation.SuggestionState) []*remediation.Suggestion {
	r.t.Helper()
	res, err := r.sug.List(ctx, r.tenant, remediation.SuggestionFilter{States: states}, pagination.New(1, 100))
	require.NoError(r.t, err)
	return res.Data
}

const djangoKey = "upgrade:pypi:django:4.2.30"

func TestRemediationSuggestions_ProposeNeverCreate(t *testing.T) {
	r := newRSRig(t)
	ctx := r.adminCtx()
	a1 := r.keyed(r.assetA, djangoKey, "P1")
	a2 := r.keyed(r.assetA, djangoKey, "P2")
	b1 := r.keyed(r.assetB, djangoKey, "P0")
	r.keyed(r.assetA, "upgrade:npm:lodash:4.17.21", "P3") // a lone, non-urgent finding: no group
	inTask := r.keyed(r.assetB, djangoKey, "P1")
	_, err := r.svc.CreateTask(ctx, remediationapp.CreateTaskInput{TenantID: r.tenant, ActorID: &r.admin, Title: "Manual",
		FindingIDs: []shared.ID{inTask}}, auditapp.AuditContext{})
	require.NoError(t, err)

	st := r.run()
	assert.Equal(t, 1, st.Created)
	assert.Equal(t, 1, st.Surfaced)
	ss := r.list(ctx)
	require.Len(t, ss, 1)
	s := ss[0]
	assert.Equal(t, remediation.SuggestionNewGroup, s.Kind)
	assert.Equal(t, 3, s.MemberCount, "a finding already in a task is not proposed again")
	assert.ElementsMatch(t, []shared.ID{a1, a2, b1}, s.FindingIDs)
	assert.Equal(t, 14, s.RiskPoints)
	assert.True(t, s.HasUrgent)
	require.Len(t, s.Partitions, 2, "one partition per primary owner")
	assert.Equal(t, r.group.String(), s.Partitions[0].OwnerGroup, "highest risk first")
	assert.Equal(t, r.owner.String(), s.Partitions[1].OwnerUser)

	// Nothing was created: one task (the manual one), one action.
	var tasks, actions int
	require.NoError(t, r.db.QueryRow(`SELECT COUNT(*) FROM remediation_tasks WHERE tenant_id = $1`, r.tenant.String()).Scan(&tasks))
	require.NoError(t, r.db.QueryRow(`SELECT COUNT(*) FROM remediation_actions WHERE tenant_id = $1`, r.tenant.String()).Scan(&actions))
	assert.Equal(t, 1, tasks)
	assert.Equal(t, 1, actions)

	// A rerun updates in place.
	r.keyed(r.assetA, djangoKey, "P3")
	st = r.run()
	assert.Equal(t, 0, st.Created)
	assert.Equal(t, 1, st.Updated)
	got, err := r.sug.Get(ctx, r.tenant, s.ID)
	require.NoError(t, err)
	assert.Equal(t, 4, got.MemberCount)
	assert.Greater(t, got.Version, s.Version)

	// The findings close: the suggestion expires.
	r.exec(`UPDATE findings SET status = 'resolved' WHERE tenant_id = $1`, r.tenant.String())
	st = r.run()
	assert.Equal(t, 1, st.Expired)
	assert.Empty(t, r.list(ctx))
	assert.Len(t, r.list(ctx, remediation.SuggestionExpired), 1)
}

func TestRemediationSuggestions_DismissHoldsUntilMaterialChange(t *testing.T) {
	r := newRSRig(t)
	ctx := r.adminCtx()
	for i := 0; i < 4; i++ {
		r.keyed(r.assetA, djangoKey, "P2")
	}
	r.run()
	s := r.list(ctx)[0]

	_, err := r.sug.Dismiss(ctx, remediationapp.DismissInput{TenantID: r.tenant, ID: s.ID, Version: s.Version,
		Reason: remediation.DismissOther, ActorID: &r.admin}, auditapp.AuditContext{})
	assert.ErrorIs(t, err, shared.ErrValidation, "other needs a note")
	_, err = r.sug.Dismiss(ctx, remediationapp.DismissInput{TenantID: r.tenant, ID: s.ID, Version: s.Version + 5,
		Reason: remediation.DismissWrongGrouping, ActorID: &r.admin}, auditapp.AuditContext{})
	assert.ErrorIs(t, err, remediation.ErrSuggestionDecided, "stale version")
	d, err := r.sug.Dismiss(ctx, remediationapp.DismissInput{TenantID: r.tenant, ID: s.ID, Version: s.Version,
		Reason: remediation.DismissWrongGrouping, Note: "different services", ActorID: &r.admin}, auditapp.AuditContext{})
	require.NoError(t, err)
	assert.Equal(t, remediation.SuggestionDismissed, d.State)

	// One more finding: the dismissal holds.
	r.keyed(r.assetA, djangoKey, "P2")
	st := r.run()
	assert.Equal(t, 1, st.Held)
	assert.Empty(t, r.list(ctx))

	// A P0 member is material: proposed again, as a new suggestion.
	r.keyed(r.assetA, djangoKey, "P0")
	st = r.run()
	assert.Equal(t, 1, st.Created)
	again := r.list(ctx)
	require.Len(t, again, 1)
	assert.NotEqual(t, s.ID, again[0].ID)

	// Reopen of the old dismissal is refused: the fix is already proposed.
	_, err = r.sug.Reopen(ctx, r.tenant, s.ID, d.Version, &r.admin, auditapp.AuditContext{})
	assert.ErrorIs(t, err, remediation.ErrSuggestionDecided)
}

func TestRemediationSuggestions_SnoozeWakes(t *testing.T) {
	r := newRSRig(t)
	ctx := r.adminCtx()
	r.keyed(r.assetA, djangoKey, "P1")
	r.keyed(r.assetA, djangoKey, "P1")
	r.run()
	s := r.list(ctx)[0]
	_, err := r.sug.Snooze(ctx, remediationapp.SnoozeInput{TenantID: r.tenant, ID: s.ID, Version: s.Version,
		Until: time.Now().Add(400 * 24 * time.Hour)}, auditapp.AuditContext{})
	assert.ErrorIs(t, err, shared.ErrValidation, "at most 180 days")
	sn, err := r.sug.Snooze(ctx, remediationapp.SnoozeInput{TenantID: r.tenant, ID: s.ID, Version: s.Version,
		Until: time.Now().Add(48 * time.Hour), ActorID: &r.admin}, auditapp.AuditContext{})
	require.NoError(t, err)
	assert.Equal(t, remediation.SuggestionSnoozed, sn.State)
	r.run()
	assert.Empty(t, r.list(ctx), "still snoozed")
	r.exec(`UPDATE remediation_suggestions SET snoozed_until = now() - interval '1 minute' WHERE id = $1`, s.ID.String())
	st := r.run()
	assert.Equal(t, 1, st.Woken)
	assert.Len(t, r.list(ctx), 1)
}

func TestRemediationSuggestions_AcceptedActionJoinAndRoute(t *testing.T) {
	r := newRSRig(t)
	ctx := r.adminCtx()
	first := r.keyed(r.assetA, djangoKey, "P1")
	action := shared.NewID()
	r.exec(`INSERT INTO remediation_actions (id, tenant_id, action_key, kind, title, origin) VALUES ($1, $2, $3, 'upgrade', 'Upgrade django', 'suggestion')`,
		action.String(), r.tenant.String(), djangoKey)
	task, err := r.svc.CreateTask(ctx, remediationapp.CreateTaskInput{TenantID: r.tenant, ActorID: &r.admin, Title: "Upgrade django",
		ActionID: &action, FindingIDs: []shared.ID{first}, AssigneeUserID: &r.owner}, auditapp.AuditContext{})
	require.NoError(t, err)

	r.keyed(r.assetA, djangoKey, "P2") // owner = user: joins the task
	r.keyed(r.assetB, djangoKey, "P2") // owner = group: no task yet
	excluded := r.keyed(r.assetA, djangoKey, "P1")
	r.exec(`INSERT INTO remediation_key_exclusions (tenant_id, action_key, finding_id, reason) VALUES ($1, $2, $3, 'removed')`,
		r.tenant.String(), djangoKey, excluded.String())
	r.run()
	ss := r.list(ctx)
	require.Len(t, ss, 2)
	byKind := map[remediation.SuggestionKind]*remediation.Suggestion{}
	for _, s := range ss {
		byKind[s.Kind] = s
		assert.NotContains(t, s.FindingIDs, excluded, "a finding a person took out is not proposed again")
	}
	require.NotNil(t, byKind[remediation.SuggestionJoin])
	assert.Equal(t, task.ID, *byKind[remediation.SuggestionJoin].TargetTaskID)
	require.NotNil(t, byKind[remediation.SuggestionTaskRoute])
	assert.Equal(t, action, *byKind[remediation.SuggestionTaskRoute].TargetActionID)
	assert.Nil(t, byKind[remediation.SuggestionNewGroup])
}

func TestRemediationSuggestions_DailyCapAndDigest(t *testing.T) {
	r := newRSRig(t)
	ctx := r.adminCtx()
	for i := 0; i < remediation.DailySurfaceCap+5; i++ {
		key := fmt.Sprintf("upgrade:npm:pkg-%03d:1.0.%d", i, i)
		r.keyed(r.assetA, key, "P3")
		r.keyed(r.assetA, key, "P3")
	}
	st := r.run()
	assert.Equal(t, remediation.DailySurfaceCap+5, st.Created)
	assert.Equal(t, remediation.DailySurfaceCap, st.Surfaced)
	counts, err := r.sug.Counts(ctx, r.tenant)
	require.NoError(t, err)
	assert.Equal(t, remediation.DailySurfaceCap, counts.Proposed)
	assert.Equal(t, 5, counts.Queued)

	// The background job sends one digest a day.
	_, err = r.sug.RunAll(context.Background())
	require.NoError(t, err)
	_, err = r.sug.RunAll(context.Background())
	require.NoError(t, err)
	r.digest.mu.Lock()
	var mine []outbox.EnqueueParams
	for _, p := range r.digest.sent {
		if p.TenantID == r.tenant {
			mine = append(mine, p)
		}
	}
	r.digest.mu.Unlock()
	require.Len(t, mine, 1)
	assert.Equal(t, "remediation_suggestions_digest", mine[0].EventType)

	// A person's refresh is throttled.
	_, err = r.sug.Refresh(ctx, r.tenant, auditapp.AuditContext{})
	assert.ErrorIs(t, err, remediation.ErrRunTooSoon)
}

func TestRemediationSuggestions_TenantIsolationAndDataScope(t *testing.T) {
	r := newRSRig(t)
	admin, member := r.adminCtx(), r.memberCtx()
	inA := r.keyed(r.assetA, djangoKey, "P1")
	inB := r.keyed(r.assetB, djangoKey, "P1")
	r.keyed(r.assetB, "rotate:secret:00aa11bb22cc33dd", "P0") // all out of the member's scope
	r.run()

	// Another tenant: nothing.
	res, err := r.sug.List(admin, r.other, remediation.SuggestionFilter{}, pagination.New(1, 50))
	require.NoError(t, err)
	assert.Empty(t, res.Data)
	s := r.list(admin)
	require.Len(t, s, 2)
	var django *remediation.Suggestion
	for _, x := range s {
		if x.Key == djangoKey {
			django = x
		}
	}
	require.NotNil(t, django)
	_, err = r.sug.Get(admin, r.other, django.ID)
	assert.ErrorIs(t, err, shared.ErrNotFound)

	// The restricted member sees the django suggestion through their one
	// finding, never the id of the other, and not the secret suggestion.
	ms := r.list(member)
	require.Len(t, ms, 1)
	assert.Equal(t, 1, ms[0].MemberCount)
	assert.Equal(t, 1, ms[0].HiddenMembers)
	assert.Empty(t, ms[0].FindingIDs)
	assert.Empty(t, ms[0].Partitions)
	members, err := r.sug.Members(member, r.tenant, django.ID, pagination.New(1, 50))
	require.NoError(t, err)
	require.Len(t, members.Data, 1)
	assert.Equal(t, inA, members.Data[0].FindingID)
	assert.NotEqual(t, inB, members.Data[0].FindingID)
	// ... and may not decide on it.
	_, err = r.sug.Dismiss(member, remediationapp.DismissInput{TenantID: r.tenant, ID: django.ID, Version: django.Version,
		Reason: remediation.DismissTooSmall, ActorID: &r.member}, auditapp.AuditContext{})
	assert.ErrorIs(t, err, remediation.ErrSuggestionHiddenMembers)
	counts, err := r.sug.Counts(member, r.tenant)
	require.NoError(t, err)
	assert.Equal(t, 1, counts.Proposed)
}

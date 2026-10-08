package entitlement

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/admin"
	"github.com/openctemio/openctem/api/pkg/domain/plan"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

type fakeRepo struct {
	defaults   plan.Defaults
	version    int
	plans      map[shared.ID]plan.Plan
	overrides  map[shared.ID][]plan.Override
	usage      map[plan.Key]int
	ownedFree  int
	failUsage  bool
	failPlan   bool
	saveErr    error
	savedPlans []plan.Plan
}

func (f *fakeRepo) GetDefaults(context.Context) (plan.Defaults, int, error) {
	if f.defaults == nil {
		return nil, 0, shared.ErrNotFound
	}
	return f.defaults, f.version, nil
}

func (f *fakeRepo) SaveDefaults(_ context.Context, d plan.Defaults, expected int, _ shared.ID, _ time.Time) (int, error) {
	if f.saveErr != nil {
		return 0, f.saveErr
	}
	if expected != f.version {
		return 0, shared.ErrConflict
	}
	f.defaults, f.version = d, f.version+1
	return f.version, nil
}

func (f *fakeRepo) TenantPlan(_ context.Context, id shared.ID) (plan.Plan, bool, error) {
	if f.failPlan {
		return "", false, errors.New("db down")
	}
	p, ok := f.plans[id]
	return p, ok, nil
}

func (f *fakeRepo) SetTenantPlan(_ context.Context, id shared.ID, p plan.Plan, _ *shared.ID, _ time.Time) error {
	if f.plans == nil {
		f.plans = map[shared.ID]plan.Plan{}
	}
	f.plans[id] = p
	f.savedPlans = append(f.savedPlans, p)
	return nil
}

func (f *fakeRepo) ListOverrides(_ context.Context, id shared.ID) ([]plan.Override, error) {
	return f.overrides[id], nil
}

func (f *fakeRepo) SetOverride(_ context.Context, o plan.Override) error {
	if f.overrides == nil {
		f.overrides = map[shared.ID][]plan.Override{}
	}
	f.overrides[o.TenantID] = append(f.overrides[o.TenantID], o)
	return nil
}

func (f *fakeRepo) DeleteOverride(_ context.Context, id shared.ID, k plan.Key) error {
	for i, o := range f.overrides[id] {
		if o.Key == k {
			f.overrides[id] = append(f.overrides[id][:i], f.overrides[id][i+1:]...)
			return nil
		}
	}
	return shared.ErrNotFound
}

func (f *fakeRepo) Usage(context.Context, shared.ID) (map[plan.Key]int, error) {
	if f.failUsage {
		return nil, errors.New("db down")
	}
	return f.usage, nil
}

func (f *fakeRepo) CountOwnedFreeTenants(context.Context, shared.ID) (int, error) {
	return f.ownedFree, nil
}

type fakeAudit struct{ rows []*admin.AuditLog }

func (a *fakeAudit) Create(_ context.Context, l *admin.AuditLog) error {
	a.rows = append(a.rows, l)
	return nil
}

type fakeAdmins struct{ list []*admin.AdminUser }

func (a fakeAdmins) ListActive(context.Context) ([]*admin.AdminUser, error) { return a.list, nil }

type fakeNotifier struct {
	by         string
	recipients []string
}

func (n *fakeNotifier) NotifyPlanDefaultsChanged(_ context.Context, by string, to []string) error {
	n.by, n.recipients = by, to
	return nil
}

func newAdmin(t *testing.T, email string, role admin.AdminRole) *admin.AdminUser {
	t.Helper()
	a, err := admin.NewAdminUser(email, "Admin", role, nil)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func freeTenant(repo *fakeRepo) shared.ID {
	id := shared.NewID()
	if repo.plans == nil {
		repo.plans = map[shared.ID]plan.Plan{}
	}
	repo.plans[id] = plan.Free
	return id
}

func limitErr(t *testing.T, err error) *plan.ErrLimitReached {
	t.Helper()
	var lim *plan.ErrLimitReached
	if !errors.As(err, &lim) {
		t.Fatalf("want ErrLimitReached, got %v", err)
	}
	if !errors.Is(err, shared.ErrForbidden) {
		t.Fatal("ErrLimitReached must unwrap to ErrForbidden")
	}
	return lim
}

func TestCheck_FreeLimitRefusesTheAdditionOverTheLimit(t *testing.T) {
	repo := &fakeRepo{usage: map[plan.Key]int{plan.Seats: 5, plan.Assets: 499}}
	svc := NewService(repo, nil, nil, nil, nil)
	id := freeTenant(repo)

	lim := limitErr(t, svc.Check(context.Background(), id, plan.Seats, 1))
	if lim.Limit != 5 || lim.Used != 5 || lim.Unavailable {
		t.Fatalf("got %+v", lim)
	}
	if err := svc.Check(context.Background(), id, plan.Assets, 1); err != nil {
		t.Fatalf("500th asset must pass: %v", err)
	}
	limitErr(t, svc.Check(context.Background(), id, plan.Assets, 2))
}

func TestCheck_OrganizationWithoutPlanIsUnlimited(t *testing.T) {
	repo := &fakeRepo{usage: map[plan.Key]int{plan.Seats: 1000}}
	svc := NewService(repo, nil, nil, nil, nil)
	if err := svc.Check(context.Background(), shared.NewID(), plan.Seats, 1); err != nil {
		t.Fatalf("an organization created before plans must stay unlimited: %v", err)
	}
}

func TestCheck_OverrideWinsUntilItExpires(t *testing.T) {
	repo := &fakeRepo{usage: map[plan.Key]int{plan.Seats: 7}}
	svc := NewService(repo, nil, nil, nil, nil)
	now := time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC)
	svc.now = func() time.Time { return now }
	id := freeTenant(repo)
	future := now.Add(time.Hour)
	repo.overrides = map[shared.ID][]plan.Override{id: {{TenantID: id, Key: plan.Seats, Value: 10, Reason: "pilot", ExpiresAt: &future}}}

	if err := svc.Check(context.Background(), id, plan.Seats, 1); err != nil {
		t.Fatalf("override of 10 must allow the 8th seat: %v", err)
	}
	now = now.Add(2 * time.Hour)
	limitErr(t, svc.Check(context.Background(), id, plan.Seats, 1))
}

func TestCheck_OverrideCanLowerAndUnlimitedNeverRefuses(t *testing.T) {
	repo := &fakeRepo{usage: map[plan.Key]int{plan.APIKeys: 0, plan.Sensors: 50}}
	svc := NewService(repo, nil, nil, nil, nil)
	id := freeTenant(repo)
	repo.overrides = map[shared.ID][]plan.Override{id: {
		{TenantID: id, Key: plan.APIKeys, Value: 0, Reason: "abuse"},
		{TenantID: id, Key: plan.Sensors, Value: plan.Unlimited, Reason: "partner"},
	}}
	lim := limitErr(t, svc.Check(context.Background(), id, plan.APIKeys, 1))
	if lim.Unavailable || lim.Limit != 0 {
		t.Fatalf("a limit of 0 is a real limit, got %+v", lim)
	}
	if err := svc.Check(context.Background(), id, plan.Sensors, 1); err != nil {
		t.Fatalf("unlimited override: %v", err)
	}
}

func TestCheck_FailsClosed(t *testing.T) {
	repo := &fakeRepo{failUsage: true}
	svc := NewService(repo, nil, nil, nil, nil)
	id := freeTenant(repo)
	if lim := limitErr(t, svc.Check(context.Background(), id, plan.Seats, 1)); !lim.Unavailable {
		t.Fatal("a read failure must refuse as Unavailable")
	}
	repo2 := &fakeRepo{failPlan: true}
	if lim := limitErr(t, NewService(repo2, nil, nil, nil, nil).Check(context.Background(), shared.NewID(), plan.Seats, 1)); !lim.Unavailable {
		t.Fatal("a plan read failure must refuse")
	}
}

func TestCheck_UnknownKeyRefused(t *testing.T) {
	svc := NewService(&fakeRepo{}, nil, nil, nil, nil)
	if err := svc.Check(context.Background(), shared.NewID(), plan.Key("bogus"), 1); !errors.Is(err, plan.ErrInvalid) {
		t.Fatalf("got %v", err)
	}
}

func TestEffective_LoweringNeverRemovesAndFlagsOverLimit(t *testing.T) {
	repo := &fakeRepo{usage: map[plan.Key]int{plan.Seats: 7}}
	svc := NewService(repo, nil, nil, nil, nil)
	id := freeTenant(repo)
	sum, err := svc.Effective(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	if !sum.OverLimit {
		t.Fatal("7 seats on a 5-seat plan must be flagged over limit")
	}
	for _, e := range sum.Limits {
		if e.Key == plan.Seats && (e.Used != 7 || !e.OverLimit || e.Source != plan.SourcePlan) {
			t.Fatalf("seats: %+v", e)
		}
	}
	if repo.usage[plan.Seats] != 7 {
		t.Fatal("usage must be untouched")
	}
}

func TestCheckFreeTeam(t *testing.T) {
	repo := &fakeRepo{}
	svc := NewService(repo, nil, nil, nil, nil)
	if err := svc.CheckFreeTeam(context.Background(), shared.NewID()); err != nil {
		t.Fatalf("first Free organization: %v", err)
	}
	repo.ownedFree = 1
	lim := limitErr(t, svc.CheckFreeTeam(context.Background(), shared.NewID()))
	if lim.Key != plan.FreeTeamsPerUser || lim.Limit != 1 || lim.Used != 1 {
		t.Fatalf("got %+v", lim)
	}
}

func TestAssignFree(t *testing.T) {
	repo := &fakeRepo{}
	svc := NewService(repo, nil, nil, nil, nil)
	id := shared.NewID()
	if err := svc.AssignFree(context.Background(), id); err != nil {
		t.Fatal(err)
	}
	if repo.plans[id] != plan.Free {
		t.Fatalf("got %q", repo.plans[id])
	}
}

func TestUpdateDefaults_AuditsCriticalAndNotifiesOthers(t *testing.T) {
	repo := &fakeRepo{}
	audit := &fakeAudit{}
	actor := newAdmin(t, "root@example.test", admin.AdminRoleSuperAdmin)
	other := newAdmin(t, "ops@example.test", admin.AdminRoleOpsAdmin)
	notifier := &fakeNotifier{}
	svc := NewService(repo, audit, fakeAdmins{list: []*admin.AdminUser{actor, other}}, notifier, nil)

	d := plan.BuiltinDefaults()
	d[plan.Free][plan.Seats] = 3
	v, err := svc.UpdateDefaults(context.Background(), actor, d, 0, "203.0.113.9", "test")
	if err != nil || v != 1 {
		t.Fatalf("v=%d err=%v", v, err)
	}
	if len(audit.rows) != 1 || audit.rows[0].Action != ActionDefaultsChanged || audit.rows[0].Severity != admin.SeverityCritical {
		t.Fatalf("audit rows: %+v", audit.rows)
	}
	if len(notifier.recipients) != 1 || notifier.recipients[0] != "ops@example.test" {
		t.Fatalf("notified %v; the actor must not be told about their own change", notifier.recipients)
	}
	got, _, _ := svc.Defaults(context.Background())
	if got.For(plan.Free).Get(plan.Seats) != 3 {
		t.Fatal("cache not refreshed")
	}
}

func TestUpdateDefaults_Refusals(t *testing.T) {
	actor := newAdmin(t, "root@example.test", admin.AdminRoleSuperAdmin)
	svc := NewService(&fakeRepo{}, &fakeAudit{}, nil, nil, nil)
	if _, err := svc.UpdateDefaults(context.Background(), nil, plan.BuiltinDefaults(), 0, "", ""); err == nil {
		t.Fatal("nil actor must be refused")
	}
	bad := plan.Defaults{plan.Free: {plan.Seats: -2}}
	if _, err := svc.UpdateDefaults(context.Background(), actor, bad, 0, "", ""); !errors.Is(err, plan.ErrInvalid) {
		t.Fatalf("below -1: %v", err)
	}
	unknown := plan.Defaults{plan.Plan("gold"): {}}
	if _, err := svc.UpdateDefaults(context.Background(), actor, unknown, 0, "", ""); !errors.Is(err, plan.ErrInvalid) {
		t.Fatalf("unknown plan: %v", err)
	}
	if _, err := svc.UpdateDefaults(context.Background(), actor, plan.BuiltinDefaults(), 4, "", ""); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("stale version: %v", err)
	}
}

func TestPutOverride_Refusals(t *testing.T) {
	actor := newAdmin(t, "ops@example.test", admin.AdminRoleOpsAdmin)
	audit := &fakeAudit{}
	svc := NewService(&fakeRepo{}, audit, nil, nil, nil)
	now := time.Now()
	past := now.Add(-time.Minute)
	long := make([]rune, 501)
	for i := range long {
		long[i] = 'x'
	}
	cases := map[string]OverrideInput{
		"unknown key": {Key: "bogus", Value: 1, Reason: "r"},
		"below -1":    {Key: plan.Seats, Value: -2, Reason: "r"},
		"no reason":   {Key: plan.Seats, Value: 1, Reason: "  "},
		"long reason": {Key: plan.Seats, Value: 1, Reason: string(long)},
		"past expiry": {Key: plan.Seats, Value: 1, Reason: "r", ExpiresAt: &past},
	}
	for name, in := range cases {
		if err := svc.PutOverride(context.Background(), actor, shared.NewID(), in, "", ""); !errors.Is(err, plan.ErrInvalid) {
			t.Errorf("%s: got %v", name, err)
		}
	}
	if len(audit.rows) != 0 {
		t.Fatal("refused overrides must not be audited as set")
	}
	if err := svc.PutOverride(context.Background(), actor, shared.NewID(), OverrideInput{Key: plan.Seats, Value: 9, Reason: "pilot"}, "", ""); err != nil {
		t.Fatal(err)
	}
	if len(audit.rows) != 1 || audit.rows[0].Action != ActionOverrideSet || audit.rows[0].Severity != admin.SeverityHigh {
		t.Fatalf("audit: %+v", audit.rows)
	}
}

func TestDeleteOverride(t *testing.T) {
	actor := newAdmin(t, "ops@example.test", admin.AdminRoleOpsAdmin)
	svc := NewService(&fakeRepo{}, &fakeAudit{}, nil, nil, nil)
	if err := svc.DeleteOverride(context.Background(), actor, shared.NewID(), "bogus", "", ""); !errors.Is(err, plan.ErrInvalid) {
		t.Fatalf("unknown key: %v", err)
	}
	if err := svc.DeleteOverride(context.Background(), actor, shared.NewID(), plan.Seats, "", ""); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("missing: %v", err)
	}
}

func TestChangeTenantPlan_RefusesUnknownPlan(t *testing.T) {
	actor := newAdmin(t, "ops@example.test", admin.AdminRoleOpsAdmin)
	svc := NewService(&fakeRepo{}, &fakeAudit{}, nil, nil, nil)
	if err := svc.ChangeTenantPlan(context.Background(), actor, shared.NewID(), "gold", "", ""); !errors.Is(err, plan.ErrInvalid) {
		t.Fatalf("got %v", err)
	}
}

package entitlement

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/admin"
	"github.com/openctemio/openctem/api/pkg/domain/limits"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

type memRepo struct {
	defaults        limits.Limits
	defaultsVersion int
	lims            []limits.Limit
	denies          []limits.FeatureDeny
	grace           map[shared.ID]map[string]time.Time
	usage           map[limits.Key]int
	owned           int
	err             error
	usageCalls      int
}

func (m *memRepo) GetSelfServiceDefaults(context.Context) (limits.Limits, int, error) {
	if m.err != nil {
		return nil, 0, m.err
	}
	if m.defaults == nil {
		return nil, 0, shared.ErrNotFound
	}
	return m.defaults, m.defaultsVersion, nil
}
func (m *memRepo) SaveSelfServiceDefaults(_ context.Context, l limits.Limits, v int, _ shared.ID, _ time.Time) (int, error) {
	if v != m.defaultsVersion {
		return 0, shared.ErrConflict
	}
	m.defaults, m.defaultsVersion = l, v+1
	return m.defaultsVersion, nil
}
func (m *memRepo) ListLimits(_ context.Context, t shared.ID, o limits.Origin) ([]limits.Limit, error) {
	if m.err != nil {
		return nil, m.err
	}
	out := []limits.Limit{}
	for _, l := range m.lims {
		if l.TenantID == t && l.Origin == o {
			out = append(out, l)
		}
	}
	return out, nil
}
func (m *memRepo) SetLimit(_ context.Context, l limits.Limit) error {
	_ = m.DeleteLimit(context.Background(), l.TenantID, l.Key, l.Origin)
	m.lims = append(m.lims, l)
	return nil
}
func (m *memRepo) DeleteLimit(_ context.Context, t shared.ID, k limits.Key, o limits.Origin) error {
	for i, l := range m.lims {
		if l.TenantID == t && l.Key == k && l.Origin == o {
			m.lims = append(m.lims[:i], m.lims[i+1:]...)
			return nil
		}
	}
	return shared.ErrNotFound
}
func (m *memRepo) ListDenies(_ context.Context, t shared.ID, o limits.Origin) ([]limits.FeatureDeny, error) {
	if m.err != nil {
		return nil, m.err
	}
	out := []limits.FeatureDeny{}
	for _, d := range m.denies {
		if d.TenantID == t && d.Origin == o {
			out = append(out, d)
		}
	}
	return out, nil
}
func (m *memRepo) SetDeny(_ context.Context, d limits.FeatureDeny) error {
	_ = m.DeleteDeny(context.Background(), d.TenantID, d.Feature, d.Origin)
	m.denies = append(m.denies, d)
	return nil
}
func (m *memRepo) DeleteDeny(_ context.Context, t shared.ID, f string, o limits.Origin) error {
	for i, d := range m.denies {
		if d.TenantID == t && d.Feature == f && d.Origin == o {
			m.denies = append(m.denies[:i], m.denies[i+1:]...)
			return nil
		}
	}
	return shared.ErrNotFound
}
func (m *memRepo) ReplaceOrigin(_ context.Context, t shared.ID, o limits.Origin, ls []limits.Limit, ds []limits.FeatureDeny) error {
	keepL := []limits.Limit{}
	for _, l := range m.lims {
		if l.TenantID != t || l.Origin != o {
			keepL = append(keepL, l)
		}
	}
	keepD := []limits.FeatureDeny{}
	for _, d := range m.denies {
		if d.TenantID != t || d.Origin != o {
			keepD = append(keepD, d)
		}
	}
	m.lims, m.denies = append(keepL, ls...), append(keepD, ds...)
	return nil
}
func (m *memRepo) Usage(context.Context, shared.ID, bool) (map[limits.Key]int, error) {
	m.usageCalls++
	if m.err != nil {
		return nil, m.err
	}
	return m.usage, nil
}
func (m *memRepo) CountOwnedTenants(context.Context, shared.ID) (int, error) { return m.owned, m.err }
func (m *memRepo) ListGrace(_ context.Context, t shared.ID) (map[string]time.Time, error) {
	return m.grace[t], nil
}
func (m *memRepo) StartGrace(_ context.Context, t shared.ID, fs []string, until time.Time) error {
	if m.grace == nil {
		m.grace = map[shared.ID]map[string]time.Time{}
	}
	if m.grace[t] == nil {
		m.grace[t] = map[string]time.Time{}
	}
	for _, f := range fs {
		if _, ok := m.grace[t][f]; !ok {
			m.grace[t][f] = until
		}
	}
	return nil
}
func (m *memRepo) EndGrace(_ context.Context, t shared.ID, fs []string) error {
	for _, f := range fs {
		delete(m.grace[t], f)
	}
	return nil
}

type memAudit struct{ actions []string }

func (a *memAudit) Create(_ context.Context, l *admin.AuditLog) error {
	a.actions = append(a.actions, l.Action)
	return nil
}

func operator(t *testing.T) *admin.AdminUser {
	t.Helper()
	a, err := admin.NewAdminUser("ops@platform.test", "Ops", admin.AdminRoleOpsAdmin, nil)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

// A self-hosted install with no limits set: every organization is unlimited,
// Check never counts usage and nothing applies.
func TestNoLimitsByDefault(t *testing.T) {
	repo := &memRepo{usage: map[limits.Key]int{limits.Seats: 10000}}
	svc := NewService(repo, nil, nil)
	tid := shared.NewID()
	for _, k := range limits.Keys {
		if !k.PerOrganization() {
			continue
		}
		if err := svc.Check(context.Background(), tid, k, 1); err != nil {
			t.Fatalf("%s: %v", k, err)
		}
		if room, err := svc.Headroom(context.Background(), tid, k); err != nil || room != limits.Unlimited {
			t.Fatalf("%s headroom: %d %v", k, room, err)
		}
	}
	if repo.usageCalls != 0 {
		t.Fatal("an unlimited key must not count usage")
	}
	sum, err := svc.Effective(context.Background(), tid)
	if err != nil || sum.Applies || sum.OverLimit || len(sum.Denied) != 0 {
		t.Fatalf("nothing applies: %+v %v", sum, err)
	}
	if err := svc.CheckOrgsPerUser(context.Background(), shared.NewID()); err != nil {
		t.Fatalf("no per-person cap by default: %v", err)
	}
	if names := svc.SourceNames(); len(names) != 1 || names[0] != "none" {
		t.Fatalf("sources: %v", names)
	}
}

// The operator's limit wins over a source's for the same key; a source's
// limit applies where the operator set none; another organization's rows
// never leak in, even when a source returns them.
func TestSourcesAndPrecedence(t *testing.T) {
	a, b := shared.NewID(), shared.NewID()
	repo := &memRepo{usage: map[limits.Key]int{limits.Seats: 5, limits.Assets: 99}}
	repo.lims = []limits.Limit{
		{TenantID: a, Key: limits.Seats, Value: 50, Origin: limits.OriginOperator, Reason: "sales"},
		{TenantID: a, Key: limits.Seats, Value: 5, Origin: limits.OriginControlPlane, Reason: "cp"},
		{TenantID: a, Key: limits.Assets, Value: 100, Origin: limits.OriginControlPlane, Reason: "cp"},
		{TenantID: b, Key: limits.Assets, Value: 1, Origin: limits.OriginControlPlane, Reason: "cp"},
	}
	svc := NewService(repo, nil, nil)
	svc.SetSources(NewControlPlaneSource(repo), leakySource{other: b})
	ctx := context.Background()

	if err := svc.Check(ctx, a, limits.Seats, 1); err != nil {
		t.Fatalf("operator 50 wins over control plane 5: %v", err)
	}
	if err := svc.Check(ctx, a, limits.Assets, 1); err != nil {
		t.Fatalf("99+1 <= 100: %v", err)
	}
	var lim *limits.ErrLimitReached
	if err := svc.Check(ctx, a, limits.Assets, 2); !errors.As(err, &lim) || lim.Limit != 100 || lim.Used != 99 {
		t.Fatalf("99+2 > 100: %v", err)
	}
	sum, err := svc.Effective(ctx, a)
	if err != nil || !sum.Applies {
		t.Fatalf("applies: %+v %v", sum, err)
	}
	for _, e := range sum.Limits {
		switch e.Key {
		case limits.Seats:
			if e.Limit != 50 || e.Origin != limits.OriginOperator {
				t.Fatalf("seats: %+v", e)
			}
		case limits.Assets:
			if e.Limit != 100 || e.Origin != limits.OriginControlPlane {
				t.Fatalf("assets: %+v", e)
			}
		case limits.Sensors:
			if e.Limit != limits.Unlimited || e.Origin != "" {
				t.Fatalf("sensors: %+v", e)
			}
		}
	}
}

// leakySource returns another organization's row: the service must drop it.
type leakySource struct{ other shared.ID }

func (leakySource) Name() string { return "leaky" }
func (l leakySource) Limits(context.Context, shared.ID) ([]limits.Limit, error) {
	return []limits.Limit{{TenantID: l.other, Key: limits.Sensors, Value: 0, Origin: limits.OriginControlPlane}}, nil
}
func (l leakySource) Denies(context.Context, shared.ID) ([]limits.FeatureDeny, error) {
	return []limits.FeatureDeny{{TenantID: l.other, Feature: "pentest", Origin: limits.OriginControlPlane}}, nil
}

func TestCrossTenantSourceRowsIgnored(t *testing.T) {
	a, b := shared.NewID(), shared.NewID()
	repo := &memRepo{usage: map[limits.Key]int{}}
	svc := NewService(repo, nil, nil)
	svc.SetSources(leakySource{other: b})
	if err := svc.Check(context.Background(), a, limits.Sensors, 1); err != nil {
		t.Fatalf("another organization's limit applied: %v", err)
	}
	if ok, err := svc.Allowed(context.Background(), a, "pentest"); err != nil || !ok {
		t.Fatalf("another organization's deny applied: %v %v", ok, err)
	}
	off, err := svc.NotEntitled(context.Background(), a.String())
	if err != nil || len(off) != 0 {
		t.Fatalf("another organization's deny applied: %v %v", off, err)
	}
}

// Fail-closed: a read error refuses the addition and reports Unavailable.
func TestCheckFailsClosed(t *testing.T) {
	repo := &memRepo{err: errors.New("db down")}
	svc := NewService(repo, nil, nil)
	var lim *limits.ErrLimitReached
	if err := svc.Check(context.Background(), shared.NewID(), limits.Assets, 1); !errors.As(err, &lim) || !lim.Unavailable {
		t.Fatalf("want unavailable refusal, got %v", err)
	}
	if _, err := svc.Headroom(context.Background(), shared.NewID(), limits.Assets); !errors.As(err, &lim) || !lim.Unavailable {
		t.Fatalf("headroom: %v", err)
	}
	if err := svc.CheckOrgsPerUser(context.Background(), shared.NewID()); !errors.As(err, &lim) || !lim.Unavailable {
		t.Fatalf("orgs per user: %v", err)
	}
	if _, err := svc.NotEntitled(context.Background(), shared.NewID().String()); err == nil {
		t.Fatal("an unreadable deny list must be reported, never read as allowed")
	}
}

func TestOrgsPerUser(t *testing.T) {
	repo := &memRepo{defaults: limits.Limits{limits.OrgsPerUser: 1}, defaultsVersion: 1, owned: 1}
	svc := NewService(repo, nil, nil)
	var lim *limits.ErrLimitReached
	if err := svc.CheckOrgsPerUser(context.Background(), shared.NewID()); !errors.As(err, &lim) || lim.Key != limits.OrgsPerUser || lim.Limit != 1 || lim.Used != 1 {
		t.Fatalf("want refusal, got %v", err)
	}
	if err := svc.Check(context.Background(), shared.NewID(), limits.OrgsPerUser, 1); !errors.Is(err, limits.ErrInvalid) {
		t.Fatalf("orgs_per_user is not a per-organization key: %v", err)
	}
}

func TestSelfServiceDefaults(t *testing.T) {
	repo := &memRepo{}
	audit := &memAudit{}
	svc := NewService(repo, audit, nil)
	ctx := context.Background()
	d, v, err := svc.SelfServiceDefaults(ctx)
	if err != nil || len(d) != 0 || v != 0 {
		t.Fatalf("empty by default: %v %d %v", d, v, err)
	}
	tid := shared.NewID()
	if rows := limits.SelfServiceRows(tid, d, time.Now()); len(rows) != 0 {
		t.Fatalf("no rows for empty defaults: %v", rows)
	}
	if _, err := svc.UpdateSelfServiceDefaults(ctx, operator(t), limits.Limits{"bogus": 1}, 0, "", ""); !errors.Is(err, limits.ErrInvalid) {
		t.Fatalf("unknown key: %v", err)
	}
	if _, err := svc.UpdateSelfServiceDefaults(ctx, nil, limits.Limits{}, 0, "", ""); err == nil {
		t.Fatal("nil actor")
	}
	v, err = svc.UpdateSelfServiceDefaults(ctx, operator(t), limits.Limits{limits.Seats: 5, limits.OrgsPerUser: 1, limits.Assets: limits.Unlimited}, 0, "", "")
	if err != nil || v != 1 {
		t.Fatalf("save: %d %v", v, err)
	}
	if len(audit.actions) != 1 || audit.actions[0] != ActionSelfServiceDefaultsChanged {
		t.Fatalf("audit: %v", audit.actions)
	}
	d, _, _ = svc.SelfServiceDefaults(ctx)
	rows := limits.SelfServiceRows(tid, d, time.Now())
	if len(rows) != 1 || rows[0].Key != limits.Seats || rows[0].Value != 5 || rows[0].Origin != limits.OriginOperator || rows[0].TenantID != tid {
		t.Fatalf("rows: only per-organization, non-unlimited keys: %+v", rows)
	}
	if _, err := svc.UpdateSelfServiceDefaults(ctx, operator(t), limits.Limits{}, 0, "", ""); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("stale version: %v", err)
	}
}

func TestPutAndDeleteLimit(t *testing.T) {
	repo := &memRepo{usage: map[limits.Key]int{limits.Seats: 4}}
	audit := &memAudit{}
	svc := NewService(repo, audit, nil)
	ctx := context.Background()
	tid := shared.NewID()
	past := time.Now().Add(-time.Hour)
	for _, in := range []LimitInput{
		{Key: "bogus", Value: 1, Reason: "x"},
		{Key: limits.OrgsPerUser, Value: 1, Reason: "x"},
		{Key: limits.Seats, Value: -2, Reason: "x"},
		{Key: limits.Seats, Value: 1, Reason: "  "},
		{Key: limits.Seats, Value: 1, Reason: "x", ExpiresAt: &past},
	} {
		if err := svc.PutLimit(ctx, operator(t), tid, in, "", ""); !errors.Is(err, limits.ErrInvalid) {
			t.Fatalf("%+v: %v", in, err)
		}
	}
	if err := svc.PutLimit(ctx, nil, tid, LimitInput{Key: limits.Seats, Value: 1, Reason: "x"}, "", ""); !errors.Is(err, limits.ErrInvalid) {
		t.Fatal("nil actor")
	}
	if err := svc.PutLimit(ctx, operator(t), tid, LimitInput{Key: limits.Seats, Value: 3, Reason: "pilot"}, "", ""); err != nil {
		t.Fatal(err)
	}
	// Lowered below usage: nothing is removed, additions are refused.
	sum, _ := svc.Effective(ctx, tid)
	if !sum.OverLimit || !sum.Applies {
		t.Fatalf("over limit: %+v", sum)
	}
	if err := svc.Check(ctx, tid, limits.Seats, 1); err == nil {
		t.Fatal("an addition over the limit must be refused")
	}
	if err := svc.Check(ctx, tid, limits.Seats, 0); err != nil {
		t.Fatalf("no addition, no refusal: %v", err)
	}
	if err := svc.DeleteLimit(ctx, operator(t), tid, limits.Seats, "", ""); err != nil {
		t.Fatal(err)
	}
	if err := svc.DeleteLimit(ctx, operator(t), tid, limits.Seats, "", ""); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("delete twice: %v", err)
	}
	if len(audit.actions) != 2 || audit.actions[0] != ActionLimitSet || audit.actions[1] != ActionLimitRemoved {
		t.Fatalf("audit: %v", audit.actions)
	}
	// An expired limit no longer applies.
	repo.lims = append(repo.lims, limits.Limit{TenantID: tid, Key: limits.Seats, Value: 1, Origin: limits.OriginOperator, Reason: "x", ExpiresAt: &past})
	if err := svc.Check(ctx, tid, limits.Seats, 1); err != nil {
		t.Fatalf("expired limit applied: %v", err)
	}
}

func TestAllowAddition(t *testing.T) {
	for _, c := range []struct {
		limit, used, delta int
		want               bool
	}{
		{limits.Unlimited, 1e6, 1, true}, {5, 4, 1, true}, {5, 5, 1, false}, {5, 9, 0, true}, {0, 0, 1, false}, {5, 9, -1, true},
	} {
		if got := limits.AllowAddition(c.limit, c.used, c.delta); got != c.want {
			t.Fatalf("%+v: got %v", c, got)
		}
	}
}

func TestStartLimits(t *testing.T) {
	ctx := context.Background()
	repo := &memRepo{}
	svc := NewService(repo, nil, nil)
	if ok, err := svc.StartLimitsConfigured(ctx); err != nil || ok {
		t.Fatalf("nothing configured: %v %v", ok, err)
	}
	if err := svc.SetStartLimits(`{"gold":1}`); err == nil {
		t.Fatal("unknown key must be refused")
	}
	if err := svc.SetStartLimits(`not json`); err == nil {
		t.Fatal("garbage must be refused")
	}
	if err := svc.SetStartLimits("unlimited"); err != nil {
		t.Fatal(err)
	}
	if ok, _ := svc.StartLimitsConfigured(ctx); !ok {
		t.Fatal("explicit unlimited is configured")
	}
	if d, _, _ := svc.SelfServiceDefaults(ctx); len(d) != 0 {
		t.Fatalf("unlimited: %v", d)
	}
	svc2 := NewService(repo, nil, nil)
	if err := svc2.SetStartLimits(`{"seats":5,"orgs_per_user":1}`); err != nil {
		t.Fatal(err)
	}
	if d, _, _ := svc2.SelfServiceDefaults(ctx); d.Get(limits.Seats) != 5 || d.Get(limits.OrgsPerUser) != 1 {
		t.Fatalf("environment defaults: %v", d)
	}
	// A console setting wins over the environment and counts as configured.
	svc3 := NewService(&memRepo{defaults: limits.Limits{limits.Seats: 9}, defaultsVersion: 1}, nil, nil)
	_ = svc3.SetStartLimits(`{"seats":5}`)
	if d, _, _ := svc3.SelfServiceDefaults(ctx); d.Get(limits.Seats) != 9 {
		t.Fatalf("console wins: %v", d)
	}
	svc4 := NewService(&memRepo{defaults: limits.Limits{}, defaultsVersion: 1}, nil, nil)
	if ok, _ := svc4.StartLimitsConfigured(ctx); !ok {
		t.Fatal("a saved console setting (even empty) is configured")
	}
	svc5 := NewService(repo, nil, nil)
	svc5.SetSources(NewControlPlaneSource(repo))
	if ok, _ := svc5.StartLimitsConfigured(ctx); !ok {
		t.Fatal("a control-plane source is configured")
	}
	svc6 := NewService(&memRepo{err: errors.New("down")}, nil, nil)
	if _, err := svc6.StartLimitsConfigured(ctx); err == nil {
		t.Fatal("a read error is reported")
	}
}

func TestApplies(t *testing.T) {
	a, b := shared.NewID(), shared.NewID()
	repo := &memRepo{lims: []limits.Limit{
		{TenantID: a, Key: limits.Seats, Value: 5, Origin: limits.OriginOperator, Reason: "x"},
		{TenantID: b, Key: limits.Seats, Value: limits.Unlimited, Origin: limits.OriginOperator, Reason: "x"},
	}}
	svc := NewService(repo, nil, nil)
	if ok, err := svc.Applies(context.Background(), a); err != nil || !ok {
		t.Fatalf("a: %v %v", ok, err)
	}
	if ok, _ := svc.Applies(context.Background(), b); ok {
		t.Fatal("an unlimited row is not a limit")
	}
	if repo.usageCalls != 0 {
		t.Fatal("Applies must not count usage")
	}
	repo.denies = []limits.FeatureDeny{{TenantID: b, Feature: "pentest", Origin: limits.OriginOperator}}
	if ok, _ := svc.Applies(context.Background(), b); !ok {
		t.Fatal("a deny applies")
	}
}

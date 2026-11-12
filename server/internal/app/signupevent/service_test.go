package signupevent

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/admin"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	dom "github.com/openctemio/openctem/api/pkg/domain/signupevent"
	"github.com/openctemio/openctem/api/pkg/httpsec"
)

type memRepo struct {
	mu      sync.Mutex
	records []dom.Record
	err     error
}

func (m *memRepo) Insert(_ context.Context, r dom.Record) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.err != nil {
		return m.err
	}
	m.records = append(m.records, r)
	return nil
}
func (m *memRepo) List(context.Context, dom.Filter) ([]dom.Record, int64, error) {
	return m.records, 0, nil
}
func (m *memRepo) Daily(context.Context, time.Time) ([]dom.DailyCount, error) { return nil, nil }
func (m *memRepo) Purge(context.Context, time.Time) (int64, error)            { return 0, nil }

type memSettings struct {
	t   *dom.BurstThresholds
	ver int
	err error
}

func (m *memSettings) GetBurstThresholds(context.Context) (dom.BurstThresholds, int, error) {
	if m.err != nil {
		return dom.BurstThresholds{}, 0, m.err
	}
	if m.t == nil {
		return dom.BurstThresholds{}, 0, dom.ErrThresholdsNotFound
	}
	return *m.t, m.ver, nil
}

func (m *memSettings) SetBurstThresholds(_ context.Context, t dom.BurstThresholds, expected int, _ string, _ time.Time) (int, error) {
	if expected != m.ver {
		return 0, dom.ErrVersionConflict
	}
	m.t, m.ver = &t, m.ver+1
	return m.ver, nil
}

type memCounter struct {
	counts map[string]int64
	once   map[string]bool
	err    error
}

func newCounter() *memCounter {
	return &memCounter{counts: map[string]int64{}, once: map[string]bool{}}
}

func (c *memCounter) Incr(_ context.Context, key string, n int64, _ time.Duration) (int64, error) {
	if c.err != nil {
		return 0, c.err
	}
	c.counts[key] += n
	return c.counts[key], nil
}

func (c *memCounter) Once(_ context.Context, key string, _ time.Duration) (bool, error) {
	if c.once[key] {
		return false, nil
	}
	c.once[key] = true
	return true, nil
}

type memMetrics struct{ bursts []string }

func (m *memMetrics) ObserveSignupEvent(string, string) {}
func (m *memMetrics) ObserveSignupBurst(dimension, kind string) {
	m.bursts = append(m.bursts, dimension+"/"+kind)
}

type memNotifier struct{ subjects, bodies []string }

func (n *memNotifier) NotifyAdmins(_ context.Context, subject, body string) error {
	n.subjects, n.bodies = append(n.subjects, subject), append(n.bodies, body)
	return nil
}

type memAudit struct {
	admin.AuditLogRepository
	logs []*admin.AuditLog
}

func (a *memAudit) Create(_ context.Context, l *admin.AuditLog) error {
	a.logs = append(a.logs, l)
	return nil
}

type fixture struct {
	svc      *Service
	repo     *memRepo
	settings *memSettings
	counter  *memCounter
	metrics  *memMetrics
	notifier *memNotifier
	audit    *memAudit
}

func newFixture(t dom.BurstThresholds) *fixture {
	f := &fixture{repo: &memRepo{}, settings: &memSettings{t: &t, ver: 1}, counter: newCounter(),
		metrics: &memMetrics{}, notifier: &memNotifier{}, audit: &memAudit{}}
	f.svc = NewService(f.repo, f.settings, f.audit, nil)
	f.svc.SetBurstCounter(f.counter, f.metrics)
	f.svc.SetNotifier(f.notifier)
	now := time.Date(2026, 10, 18, 10, 5, 0, 0, time.UTC)
	f.svc.SetClock(func() time.Time { return now })
	return f
}

func ctxFrom(ip string) context.Context {
	return httpsec.WithClientIP(context.Background(), ip)
}

func TestRecordKeepsOnlyDomainAndPrefix(t *testing.T) {
	f := newFixture(dom.DefaultBurstThresholds())
	uid, tid := shared.NewID(), shared.NewID()
	f.svc.Record(ctxFrom("203.0.113.45"), dom.Event{Kind: dom.KindAccountCreated, Source: dom.SourcePassword,
		Email: "alice.smith@mail.example.com", UserID: uid, TenantID: tid})
	if len(f.repo.records) != 1 {
		t.Fatalf("records = %d", len(f.repo.records))
	}
	r := f.repo.records[0]
	if r.EmailDomain != "example.com" || r.IPPrefix != "203.0.113.0/24" {
		t.Fatalf("stored %q %q", r.EmailDomain, r.IPPrefix)
	}
	if r.UserID == nil || *r.UserID != uid || r.TenantID == nil || *r.TenantID != tid {
		t.Fatal("ids not kept")
	}
}

func TestOperatorEventsRecordNoAddressAndNeverCount(t *testing.T) {
	f := newFixture(dom.BurstThresholds{PerIPPrefix: 1, PerEmailDomain: 1, WindowMinutes: 60})
	for _, src := range []dom.Source{dom.SourceConsole, dom.SourceAccessRequest, dom.SourceControlPlane} {
		f.svc.Record(ctxFrom("192.0.2.10"), dom.Event{Kind: dom.KindOrganizationCreated, Source: src, Email: "o@example.com"})
	}
	for _, r := range f.repo.records {
		if r.IPPrefix != "" {
			t.Fatalf("operator event %s recorded the operator network %q", r.Source, r.IPPrefix)
		}
	}
	if len(f.counter.counts) != 0 || len(f.notifier.subjects) != 0 {
		t.Fatal("operator events must not count toward the burst alerts")
	}
}

func TestUnknownKindIsDropped(t *testing.T) {
	f := newFixture(dom.DefaultBurstThresholds())
	f.svc.Record(context.Background(), dom.Event{Kind: "bogus", Source: dom.SourcePassword, Email: "a@example.com"})
	if len(f.repo.records) != 0 {
		t.Fatal("an unknown kind must not be stored")
	}
}

func TestBurstPerPrefixAlertsOncePerWindow(t *testing.T) {
	f := newFixture(dom.BurstThresholds{PerIPPrefix: 3, WindowMinutes: 60})
	for i, ip := range []string{"198.51.100.1", "198.51.100.2", "198.51.100.3", "198.51.100.4", "198.51.100.5"} {
		f.svc.Record(ctxFrom(ip), dom.Event{Kind: dom.KindAccountCreated, Source: dom.SourcePassword,
			Email: "bot" + string(rune('a'+i)) + "@d" + string(rune('a'+i)) + ".example"})
	}
	if len(f.metrics.bursts) != 1 || f.metrics.bursts[0] != DimensionIPPrefix+"/account_created" {
		t.Fatalf("bursts = %v", f.metrics.bursts)
	}
	if len(f.notifier.subjects) != 1 || len(f.audit.logs) != 1 {
		t.Fatalf("one email and one audit row expected: %d %d", len(f.notifier.subjects), len(f.audit.logs))
	}
	if f.audit.logs[0].Severity != admin.SeverityHigh || f.audit.logs[0].Action != ActionBurst {
		t.Fatalf("audit = %+v", f.audit.logs[0])
	}
	body := f.notifier.bodies[0]
	if !strings.Contains(body, "198.51.100.0/24") || strings.Contains(body, "bota") || strings.Contains(body, "198.51.100.1") {
		t.Fatalf("the alert names the network, never a person or a full address: %s", body)
	}
}

func TestBurstCountsKindsSeparately(t *testing.T) {
	f := newFixture(dom.BurstThresholds{PerIPPrefix: 2, WindowMinutes: 60})
	f.svc.Record(ctxFrom("198.51.100.1"), dom.Event{Kind: dom.KindAccountCreated, Source: dom.SourcePassword})
	f.svc.Record(ctxFrom("198.51.100.1"), dom.Event{Kind: dom.KindOrganizationCreated, Source: dom.SourceSelfService})
	if len(f.metrics.bursts) != 0 {
		t.Fatalf("different kinds must not add up: %v", f.metrics.bursts)
	}
}

func TestBurstPerDomainSkipsIgnoredDomains(t *testing.T) {
	f := newFixture(dom.BurstThresholds{PerEmailDomain: 2, WindowMinutes: 60, IgnoredDomains: []string{"gmail.com"}})
	for i := 0; i < 3; i++ {
		f.svc.Record(ctxFrom(""), dom.Event{Kind: dom.KindAccessRequested, Source: dom.SourcePublic, Email: "x@gmail.com"})
	}
	if len(f.metrics.bursts) != 0 {
		t.Fatalf("an ignored domain must not alert: %v", f.metrics.bursts)
	}
	for i := 0; i < 2; i++ {
		f.svc.Record(ctxFrom(""), dom.Event{Kind: dom.KindAccessRequested, Source: dom.SourcePublic, Email: "x@spam.example"})
	}
	if len(f.metrics.bursts) != 1 || f.metrics.bursts[0] != DimensionEmailDomain+"/access_requested" {
		t.Fatalf("bursts = %v", f.metrics.bursts)
	}
}

func TestZeroThresholdTurnsADimensionOff(t *testing.T) {
	f := newFixture(dom.BurstThresholds{PerIPPrefix: 0, PerEmailDomain: 0, WindowMinutes: 60})
	for i := 0; i < 20; i++ {
		f.svc.Record(ctxFrom("198.51.100.1"), dom.Event{Kind: dom.KindAccountCreated, Source: dom.SourcePassword, Email: "a@x.example"})
	}
	if len(f.metrics.bursts) != 0 || len(f.counter.counts) != 0 {
		t.Fatal("0 must turn the dimension off")
	}
}

func TestFailuresNeverFailTheSignup(t *testing.T) {
	f := newFixture(dom.BurstThresholds{PerIPPrefix: 1, WindowMinutes: 60})
	f.repo.err = errors.New("db down")
	f.counter.err = errors.New("redis down")
	f.svc.Record(ctxFrom("198.51.100.1"), dom.Event{Kind: dom.KindAccountCreated, Source: dom.SourcePassword})
	if len(f.metrics.bursts) != 0 {
		t.Fatal("a counter failure loses the signal, nothing else")
	}
	// No counter store wired: events are still stored.
	g := newFixture(dom.DefaultBurstThresholds())
	g.svc.SetBurstCounter(nil, nil)
	g.svc.Record(ctxFrom("198.51.100.1"), dom.Event{Kind: dom.KindAccountCreated, Source: dom.SourcePassword})
	if len(g.repo.records) != 1 {
		t.Fatal("events are recorded without Redis")
	}
	var nilSvc *Service
	nilSvc.Record(context.Background(), dom.Event{Kind: dom.KindAccountCreated})
}

func TestUnreadableThresholdsFallBackToDefaults(t *testing.T) {
	f := newFixture(dom.DefaultBurstThresholds())
	f.settings.err = errors.New("db down")
	for i := 0; i < dom.DefaultBurstThresholds().PerIPPrefix; i++ {
		f.svc.Record(ctxFrom("198.51.100.1"), dom.Event{Kind: dom.KindAccountCreated, Source: dom.SourcePassword})
	}
	if len(f.metrics.bursts) != 1 {
		t.Fatalf("the alerts must stay on with the defaults: %v", f.metrics.bursts)
	}
}

func testAdmin() *admin.AdminUser {
	now := time.Now()
	return admin.Reconstitute(shared.NewID(), "root@example.com", "Root", admin.AdminRoleSuperAdmin, true,
		nil, nil, "", 0, nil, nil, "", now, nil, now)
}

func TestUpdateThresholds(t *testing.T) {
	f := newFixture(dom.DefaultBurstThresholds())
	next := dom.BurstThresholds{PerIPPrefix: 5, PerEmailDomain: 0, WindowMinutes: 30}
	if _, _, err := f.svc.UpdateThresholds(context.Background(), next, 1, Change{Reason: "x"}); !errors.Is(err, shared.ErrForbidden) {
		t.Fatalf("no actor: %v", err)
	}
	if _, _, err := f.svc.UpdateThresholds(context.Background(), next, 1, Change{Actor: testAdmin(), Reason: "  "}); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("no reason: %v", err)
	}
	if _, _, err := f.svc.UpdateThresholds(context.Background(), dom.BurstThresholds{WindowMinutes: 1}, 1,
		Change{Actor: testAdmin(), Reason: "r"}); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("invalid: %v", err)
	}
	if _, _, err := f.svc.UpdateThresholds(context.Background(), next, 7, Change{Actor: testAdmin(), Reason: "r"}); !errors.Is(err, dom.ErrVersionConflict) {
		t.Fatalf("stale version: %v", err)
	}
	got, v, err := f.svc.UpdateThresholds(context.Background(), next, 1, Change{Actor: testAdmin(), Reason: "tighten"})
	if err != nil || v != 2 || got.PerIPPrefix != 5 {
		t.Fatalf("update: %+v %d %v", got, v, err)
	}
	if len(f.audit.logs) != 1 || f.audit.logs[0].Action != ActionThresholdsChanged || f.audit.logs[0].Severity != admin.SeverityCritical {
		t.Fatalf("audit: %+v", f.audit.logs)
	}
	if len(f.notifier.subjects) != 1 {
		t.Fatal("administrators must be emailed")
	}
	// The new value is in force at once on this replica.
	for i := 0; i < 5; i++ {
		f.svc.Record(ctxFrom("198.51.100.1"), dom.Event{Kind: dom.KindAccountCreated, Source: dom.SourcePassword})
	}
	if len(f.metrics.bursts) != 1 {
		t.Fatalf("new threshold not applied: %v", f.metrics.bursts)
	}
}

func TestThresholdsDefaultWhenNothingStored(t *testing.T) {
	svc := NewService(&memRepo{}, &memSettings{}, nil, nil)
	got, v, err := svc.Thresholds(context.Background())
	if err != nil || v != 0 || got.PerIPPrefix != dom.DefaultBurstThresholds().PerIPPrefix {
		t.Fatalf("%+v %d %v", got, v, err)
	}
}

func TestListRefusesUnknownKind(t *testing.T) {
	svc := NewService(&memRepo{}, nil, nil, nil)
	if _, _, err := svc.List(context.Background(), dom.Filter{Kind: "x"}); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("%v", err)
	}
}

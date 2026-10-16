package scanpolicy

import (
	"context"
	"errors"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/admin"
	"github.com/openctemio/openctem/api/pkg/domain/scangov"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// memDefaults is a Repository with the proof, internal zones and anomaly
// threshold stores.
type memDefaults struct {
	proof, zones       *bool
	failProof, failZon bool
	thresholds         *AnomalyThresholds
	failThresholds     bool
	versions           map[string]int
}

func (m *memDefaults) GetDefault(context.Context) (scangov.PlatformPolicy, int, error) {
	return "", 0, ErrNotFound
}
func (m *memDefaults) SetDefault(context.Context, scangov.PlatformPolicy, int, shared.ID, time.Time) (int, error) {
	return 0, nil
}
func (m *memDefaults) GetOverride(context.Context, shared.ID) (*scangov.PlatformPolicy, error) {
	return nil, nil
}
func (m *memDefaults) SetOverride(context.Context, shared.ID, *scangov.PlatformPolicy) error {
	return nil
}
func (m *memDefaults) ListFollowingDefault(context.Context) ([]shared.ID, error) { return nil, nil }

func (m *memDefaults) bump(key string, expected int) (int, error) {
	if m.versions == nil {
		m.versions = map[string]int{}
	}
	if m.versions[key] != expected {
		return 0, ErrVersionConflict
	}
	m.versions[key]++
	return m.versions[key], nil
}

func (m *memDefaults) GetProofRequired(context.Context) (bool, int, error) {
	if m.failProof {
		return false, 0, errors.New("db down")
	}
	if m.proof == nil {
		return false, 0, ErrNotFound
	}
	return *m.proof, m.versions[ProofSettingKey], nil
}
func (m *memDefaults) SetProofRequired(_ context.Context, v bool, expected int, _ string, _ time.Time) (int, error) {
	ver, err := m.bump(ProofSettingKey, expected)
	if err == nil {
		m.proof = &v
	}
	return ver, err
}
func (m *memDefaults) GetInternalZones(context.Context) (bool, int, error) {
	if m.failZon {
		return false, 0, errors.New("db down")
	}
	if m.zones == nil {
		return false, 0, ErrNotFound
	}
	return *m.zones, m.versions[InternalZonesSettingKey], nil
}
func (m *memDefaults) SetInternalZones(_ context.Context, v bool, expected int, _ string, _ time.Time) (int, error) {
	ver, err := m.bump(InternalZonesSettingKey, expected)
	if err == nil {
		m.zones = &v
	}
	return ver, err
}
func (m *memDefaults) GetAnomalyThresholds(context.Context) (AnomalyThresholds, int, error) {
	if m.failThresholds {
		return AnomalyThresholds{}, 0, errors.New("db down")
	}
	if m.thresholds == nil {
		return AnomalyThresholds{}, 0, ErrNotFound
	}
	return *m.thresholds, m.versions[AnomalyThresholdsSettingKey], nil
}
func (m *memDefaults) SetAnomalyThresholds(_ context.Context, t AnomalyThresholds, expected int, _ string, _ time.Time) (int, error) {
	ver, err := m.bump(AnomalyThresholdsSettingKey, expected)
	if err == nil {
		m.thresholds = &t
	}
	return ver, err
}

func newDefaults(repo *memDefaults, managed bool) *Service {
	s := NewService(repo, nil, nil, nil, nil, logger.NewNop())
	s.SetManagedService(managed)
	return s
}

func TestProofDefaultFollowsManagedService(t *testing.T) {
	ctx := context.Background()
	if newDefaults(&memDefaults{}, false).PlatformProofRequired(ctx) {
		t.Fatal("self-hosted default must be off")
	}
	if !newDefaults(&memDefaults{}, true).PlatformProofRequired(ctx) {
		t.Fatal("MANAGED_SERVICE default must be on")
	}
	// A stored console value always wins.
	if newDefaults(&memDefaults{proof: boolp(false)}, true).PlatformProofRequired(ctx) {
		t.Fatal("stored off must win over the hosted default")
	}
	if !newDefaults(&memDefaults{proof: boolp(true)}, false).PlatformProofRequired(ctx) {
		t.Fatal("stored on must win over the self-hosted default")
	}
	// Unreadable: on (fail closed), whatever the deployment.
	if !newDefaults(&memDefaults{failProof: true}, false).PlatformProofRequired(ctx) {
		t.Fatal("an unreadable setting must require proof")
	}
	_, ver, _ := newDefaults(&memDefaults{}, true).ProofSetting(ctx)
	if ver != 0 {
		t.Fatalf("version = %d, want 0 while nothing is stored", ver)
	}
}

func TestInternalZonesDefaultOffEverywhere(t *testing.T) {
	ctx := context.Background()
	if newDefaults(&memDefaults{}, false).SharedSensorsInternalZonesAllowed(ctx) {
		t.Fatal("self-hosted default must be off until zones are enforced")
	}
	if newDefaults(&memDefaults{}, true).SharedSensorsInternalZonesAllowed(ctx) {
		t.Fatal("MANAGED_SERVICE default must be off")
	}
	if InternalZonesEnforced() {
		t.Fatal("the setting is not enforced until signed zone ranges land")
	}
	if !newDefaults(&memDefaults{zones: boolp(true)}, true).SharedSensorsInternalZonesAllowed(ctx) {
		t.Fatal("stored on must win over the hosted default")
	}
	if newDefaults(&memDefaults{zones: boolp(false)}, false).SharedSensorsInternalZonesAllowed(ctx) {
		t.Fatal("stored off must win over the self-hosted default")
	}
	if newDefaults(&memDefaults{failZon: true}, false).SharedSensorsInternalZonesAllowed(ctx) {
		t.Fatal("an unreadable setting must refuse internal zones")
	}
}

func TestUpdateInternalZonesNeedsActorAndReason(t *testing.T) {
	ctx := context.Background()
	repo := &memDefaults{}
	s := newDefaults(repo, true)
	if _, err := s.UpdateInternalZones(ctx, true, 0, Change{Reason: "x"}); !errors.Is(err, shared.ErrForbidden) {
		t.Fatalf("no actor: err = %v", err)
	}
	actor := testAdmin(t)
	if _, err := s.UpdateInternalZones(ctx, true, 0, Change{Actor: actor}); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("no reason: err = %v", err)
	}
	audit := &memAudit{}
	s.audit = audit
	v, err := s.UpdateInternalZones(ctx, true, 0, Change{Actor: actor, Reason: "central scanners"})
	if err != nil || v != 1 {
		t.Fatalf("update: v=%d err=%v", v, err)
	}
	if !s.SharedSensorsInternalZonesAllowed(ctx) {
		t.Fatal("stored on must apply on a hosted service")
	}
	if len(audit.rows) != 1 || audit.rows[0].Action != ActionInternalZonesChanged || audit.rows[0].Severity != admin.SeverityCritical {
		t.Fatalf("audit rows = %+v", audit.rows)
	}
	if _, err := s.UpdateInternalZones(ctx, false, 0, Change{Actor: actor, Reason: "stale"}); !errors.Is(err, ErrVersionConflict) {
		t.Fatalf("stale version: err = %v", err)
	}
}

// memCounter is an AnomalyCounter in memory.
type memCounter struct {
	mu       sync.Mutex
	sets     map[string]map[string]struct{}
	counts   map[string]int64
	once     map[string]bool
	fail     bool
	keysSeen []string
}

func newCounter() *memCounter {
	return &memCounter{sets: map[string]map[string]struct{}{}, counts: map[string]int64{}, once: map[string]bool{}}
}

func (c *memCounter) AddDistinct(_ context.Context, key string, members []string, _ time.Duration) (int64, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.fail {
		return 0, errors.New("redis down")
	}
	c.keysSeen = append(c.keysSeen, key)
	if c.sets[key] == nil {
		c.sets[key] = map[string]struct{}{}
	}
	for _, m := range members {
		c.sets[key][m] = struct{}{}
	}
	return int64(len(c.sets[key])), nil
}
func (c *memCounter) Incr(_ context.Context, key string, n int64, _ time.Duration) (int64, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.fail {
		return 0, errors.New("redis down")
	}
	c.keysSeen = append(c.keysSeen, key)
	c.counts[key] += n
	return c.counts[key], nil
}
func (c *memCounter) Once(_ context.Context, key string, _ time.Duration) (bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.once[key] {
		return false, nil
	}
	c.once[key] = true
	return true, nil
}

type memMetrics struct {
	signals   map[string]int
	anomalies map[string]int
}

func (m *memMetrics) ObserveSharedSensorSignal(signal string, n int) { m.signals[signal] += n }
func (m *memMetrics) ObserveSharedSensorAnomaly(signal string)       { m.anomalies[signal]++ }

type memAudit struct{ rows []*admin.AuditLog }

func (a *memAudit) Create(_ context.Context, l *admin.AuditLog) error {
	a.rows = append(a.rows, l)
	return nil
}

func testAdmin(t *testing.T) *admin.AdminUser {
	t.Helper()
	a, err := admin.NewAdminUser("ops@example.com", "Ops", admin.AdminRoleSuperAdmin, nil)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func TestAnomalyDistinctDomainsAlertsOncePerOrganization(t *testing.T) {
	ctx := context.Background()
	repo := &memDefaults{thresholds: &AnomalyThresholds{DistinctDomainsPerDay: 3, FailuresPerDay: 2, DenyListHitsPerDay: 1}}
	s := newDefaults(repo, true)
	audit := &memAudit{}
	s.audit = audit
	counter := newCounter()
	metrics := &memMetrics{signals: map[string]int{}, anomalies: map[string]int{}}
	s.SetAnomalyCounter(counter, metrics)
	orgA, orgB := shared.NewID(), shared.NewID()

	// Two names of one registrable domain count once; an address is not a
	// domain.
	s.ObserveSharedTargets(ctx, orgA, []string{"a.example.com", "https://b.example.com:8443/x", "203.0.113.7"})
	s.ObserveSharedTargets(ctx, orgA, []string{"victim-one.org"})
	if len(audit.rows) != 0 {
		t.Fatalf("alert below the threshold: %+v", audit.rows)
	}
	// Organization B's domains never add to A's count.
	s.ObserveSharedTargets(ctx, orgB, []string{"b1.net", "b2.net"})
	if len(audit.rows) != 0 {
		t.Fatal("another organization's domains must not count for A")
	}
	s.ObserveSharedTargets(ctx, orgA, []string{"victim-two.co.uk"})
	if len(audit.rows) != 1 {
		t.Fatalf("want one alert at the threshold, got %d", len(audit.rows))
	}
	row := audit.rows[0]
	if row.Action != ActionSharedSensorAnomaly || row.ResourceID == nil || *row.ResourceID != orgA || row.Severity != admin.SeverityHigh {
		t.Fatalf("alert row = %+v", row)
	}
	// Aggregate only: the alert never names a target.
	for k, v := range row.RequestBody {
		if s, ok := v.(string); ok && (strings.Contains(s, "victim") || strings.Contains(s, "example")) {
			t.Fatalf("alert body %s names a target: %v", k, v)
		}
	}
	// Once per organization, signal and day.
	s.ObserveSharedTargets(ctx, orgA, []string{"victim-three.io"})
	if len(audit.rows) != 1 || metrics.anomalies[SignalDistinctDomains] != 1 {
		t.Fatalf("alert repeated: rows=%d metric=%d", len(audit.rows), metrics.anomalies[SignalDistinctDomains])
	}
	for _, k := range counter.keysSeen {
		if !strings.Contains(k, orgA.String()) && !strings.Contains(k, orgB.String()) {
			t.Fatalf("counter key %q carries no organization", k)
		}
	}
}

func TestAnomalyFailuresAndDenyHits(t *testing.T) {
	ctx := context.Background()
	repo := &memDefaults{thresholds: &AnomalyThresholds{DistinctDomainsPerDay: 0, FailuresPerDay: 2, DenyListHitsPerDay: 3}}
	s := newDefaults(repo, false)
	audit := &memAudit{}
	s.audit = audit
	s.SetAnomalyCounter(newCounter(), nil)
	org := shared.NewID()

	s.ObserveSharedFailure(ctx, org)
	s.ObserveDenyListHits(ctx, org, 2)
	if len(audit.rows) != 0 {
		t.Fatal("alert below the thresholds")
	}
	s.ObserveSharedFailure(ctx, org)
	s.ObserveDenyListHits(ctx, org, 1)
	if len(audit.rows) != 2 {
		t.Fatalf("want two alerts, got %d", len(audit.rows))
	}
	got := []string{audit.rows[0].ResourceName, audit.rows[1].ResourceName}
	sort.Strings(got)
	if got[0] != SignalDenyListHits || got[1] != SignalFailures {
		t.Fatalf("signals = %v", got)
	}
	// Threshold 0 turns a signal off.
	for i := 0; i < 10; i++ {
		s.ObserveSharedTargets(ctx, org, []string{"x" + string(rune('a'+i)) + ".com"})
	}
	if len(audit.rows) != 2 {
		t.Fatal("a signal with threshold 0 must never alert")
	}
}

func TestAnomalyNeverBlocks(t *testing.T) {
	ctx := context.Background()
	// No counter: nothing happens.
	s := newDefaults(&memDefaults{}, false)
	s.ObserveSharedFailure(ctx, shared.NewID())
	// A failing counter is logged, never panics or blocks.
	c := newCounter()
	c.fail = true
	s.SetAnomalyCounter(c, nil)
	s.ObserveSharedTargets(ctx, shared.NewID(), []string{"example.com"})
	s.ObserveDenyListHits(ctx, shared.NewID(), 1)
	// Unreadable thresholds: the defaults apply.
	s2 := newDefaults(&memDefaults{failThresholds: true}, false)
	if got := s2.thresholds(ctx); got != DefaultAnomalyThresholds() {
		t.Fatalf("thresholds = %+v", got)
	}
}

func TestAnomalyThresholdsValidateAndUpdate(t *testing.T) {
	ctx := context.Background()
	for _, bad := range []AnomalyThresholds{{DistinctDomainsPerDay: -1}, {FailuresPerDay: MaxAnomalyThreshold + 1}} {
		if err := bad.Validate(); !errors.Is(err, shared.ErrValidation) {
			t.Fatalf("Validate(%+v) = %v", bad, err)
		}
	}
	s := newDefaults(&memDefaults{}, false)
	got, ver, err := s.AnomalyThresholdsSetting(ctx)
	if err != nil || ver != 0 || got != DefaultAnomalyThresholds() {
		t.Fatalf("defaults: %+v %d %v", got, ver, err)
	}
	if _, err := s.UpdateAnomalyThresholds(ctx, AnomalyThresholds{FailuresPerDay: 3}, 0, Change{Reason: "x"}); !errors.Is(err, shared.ErrForbidden) {
		t.Fatalf("no actor: %v", err)
	}
	if _, err := s.UpdateAnomalyThresholds(ctx, AnomalyThresholds{FailuresPerDay: -3}, 0, Change{Actor: testAdmin(t), Reason: "x"}); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("negative: %v", err)
	}
	want := AnomalyThresholds{DistinctDomainsPerDay: 10, FailuresPerDay: 3, DenyListHitsPerDay: 1}
	if v, err := s.UpdateAnomalyThresholds(ctx, want, 0, Change{Actor: testAdmin(t), Reason: "tighter"}); err != nil || v != 1 {
		t.Fatalf("update: %d %v", v, err)
	}
	if got := s.thresholds(ctx); got != want {
		t.Fatalf("thresholds after update = %+v", got)
	}
}

func TestRegistrableDomains(t *testing.T) {
	got := registrableDomains([]string{
		"www.example.com", "api.example.com:443", "https://shop.example.co.uk/path",
		"*.wild.example.org", "10.0.0.0/24", "192.0.2.1", "[2001:db8::1]:80", "example.com.", "", "com",
	})
	sort.Strings(got)
	want := []string{"example.co.uk", "example.com", "example.org"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("registrableDomains = %v, want %v", got, want)
	}
}

package integration

// Integration coverage for invariant B6 — runtime telemetry that hits
// a known IOC auto-reopens the source finding.
//
// The wire is:
//   agent POST /telemetry-events
//     → runtime_telemetry_events row inserted
//       → Correlator.Correlate(tenantID, event)
//         → FindActiveByValues(tenantID, candidates)
//           → per hit: RecordMatch + (if source_finding linked) Reopen
//
// This file drives the correlator with fakes for both the IOC repo
// and the FindingReopener, then asserts the before/after shape the
// B6 contract promises.

import (
	"context"
	"strings"
	"sync/atomic"
	"testing"

	iocapp "github.com/openctemio/api/internal/app/ioc"
	iocdom "github.com/openctemio/api/pkg/domain/ioc"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/domain/telemetry"
	"github.com/openctemio/api/pkg/domain/vulnerability"
	"github.com/openctemio/api/pkg/logger"
)

// memIOCRepo is a tiny in-memory implementation of iocdom.Repository.
// It satisfies the hot path used by the correlator and nothing else.
type memIOCRepo struct {
	inds    []*iocdom.Indicator
	matches []iocdom.Match
}

func (r *memIOCRepo) Create(_ context.Context, ind *iocdom.Indicator) error {
	r.inds = append(r.inds, ind)
	return nil
}

func (r *memIOCRepo) GetByID(_ context.Context, tenantID, id shared.ID) (*iocdom.Indicator, error) {
	for _, ind := range r.inds {
		if ind.ID == id && ind.TenantID == tenantID {
			return ind, nil
		}
	}
	return nil, shared.ErrNotFound
}

func (r *memIOCRepo) FindActiveByValues(_ context.Context, tenantID shared.ID, cands []iocdom.Candidate) ([]*iocdom.Indicator, error) {
	want := make(map[string]bool, len(cands))
	for _, c := range cands {
		want[string(c.Type)+":"+c.Normalised] = true
	}
	var hits []*iocdom.Indicator
	for _, ind := range r.inds {
		if !ind.Active || ind.TenantID != tenantID {
			continue
		}
		if want[string(ind.Type)+":"+ind.Normalised] {
			hits = append(hits, ind)
		}
	}
	return hits, nil
}

func (r *memIOCRepo) RecordMatch(_ context.Context, m iocdom.Match) error {
	r.matches = append(r.matches, m)
	return nil
}

func (r *memIOCRepo) ListByTenant(_ context.Context, _ shared.ID, _, _ int) ([]*iocdom.Indicator, error) {
	return nil, nil
}

func (r *memIOCRepo) Deactivate(_ context.Context, _, _ shared.ID) error { return nil }

// reopenerSpy is the adapter seam — emulates what reopen_adapter.go
// does at the app layer without depending on a full finding repo.
type reopenerSpy struct {
	finding  *vulnerability.Finding
	calls    int32
	lastArgs struct {
		findingID shared.ID
		reason    string
	}
}

func (s *reopenerSpy) ReopenForIOCMatch(_ context.Context, _, findingID shared.ID, reason string) (bool, error) {
	atomic.AddInt32(&s.calls, 1)
	s.lastArgs.findingID = findingID
	s.lastArgs.reason = reason
	if s.finding == nil {
		return false, nil
	}
	if !s.finding.Status().IsClosed() {
		return false, nil
	}
	// Matches the real reopen_adapter: closed → confirmed, the only
	// edge the domain workflow allows out of a closed state.
	if err := s.finding.TransitionStatus(vulnerability.FindingStatusConfirmed, reason, nil); err != nil {
		return false, err
	}
	return true, nil
}

// buildResolvedFinding walks a finding to resolved — the state the
// correlator must reopen from.
func buildResolvedFinding(t *testing.T, tenantID shared.ID) *vulnerability.Finding {
	t.Helper()
	f, err := vulnerability.NewFinding(
		tenantID, shared.NewID(),
		vulnerability.FindingSourceManual, "T-1",
		vulnerability.SeverityHigh, "IOC source finding",
	)
	if err != nil {
		t.Fatalf("new finding: %v", err)
	}
	for _, st := range []vulnerability.FindingStatus{
		vulnerability.FindingStatusConfirmed,
		vulnerability.FindingStatusInProgress,
		vulnerability.FindingStatusFixApplied,
		vulnerability.FindingStatusResolved,
	} {
		if err := f.TransitionStatus(st, "", nil); err != nil {
			t.Fatalf("walk to %s: %v", st, err)
		}
	}
	if !f.Status().IsClosed() {
		t.Fatalf("precondition: finding must be closed, got %s", f.Status())
	}
	return f
}

// TestCTEM_B6_RuntimeMatchReopensClosedFinding — the headline B6
// scenario: resolved finding has a known-bad IP attached as IOC;
// runtime telemetry reports a connection to that IP; correlator fires
// → finding reopens → audit trail (match row) recorded.
func TestCTEM_B6_RuntimeMatchReopensClosedFinding(t *testing.T) {
	tenantID := shared.NewID()
	finding := buildResolvedFinding(t, tenantID)

	// Seed an IOC tied to the resolved finding.
	fid := finding.ID()
	ind := &iocdom.Indicator{
		ID:              shared.NewID(),
		TenantID:        tenantID,
		Type:            iocdom.TypeIP,
		Value:           "185.220.101.42",
		Normalised:      "185.220.101.42",
		SourceFindingID: &fid,
		Active:          true,
	}
	repo := &memIOCRepo{inds: []*iocdom.Indicator{ind}}
	reop := &reopenerSpy{finding: finding}
	correlator := iocapp.NewCorrelator(repo, reop, logger.NewNop())

	// Simulate a runtime event matching the IOC.
	event := iocapp.TelemetryEvent{
		ID:        shared.NewID(),
		EventType: "network_connect",
		Properties: map[string]any{
			telemetry.PropRemoteIP: "185.220.101.42",
		},
	}
	hits, err := correlator.Correlate(context.Background(), tenantID, event)
	if err != nil {
		t.Fatalf("correlate: %v", err)
	}
	if len(hits) != 1 {
		t.Fatalf("want 1 hit, got %d", len(hits))
	}

	// B6 contract: finding reopened (closed → confirmed, per domain
	// workflow rules).
	if finding.Status() != vulnerability.FindingStatusConfirmed {
		t.Fatalf("finding must reopen to confirmed, got %s", finding.Status())
	}
	if atomic.LoadInt32(&reop.calls) != 1 {
		t.Fatalf("reopener should fire exactly once, got %d", reop.calls)
	}
	if !strings.Contains(reop.lastArgs.reason, "ioc") {
		t.Fatalf("reason must mention ioc: %q", reop.lastArgs.reason)
	}

	// Audit trail: exactly one match row, flagged reopened + linked
	// back to the telemetry event.
	if len(repo.matches) != 1 {
		t.Fatalf("want 1 match row, got %d", len(repo.matches))
	}
	m := repo.matches[0]
	if !m.Reopened {
		t.Fatal("match row must flag reopened=true")
	}
	if m.FindingID == nil || *m.FindingID != fid {
		t.Fatal("match row must link the source finding")
	}
	if m.TelemetryEventID == nil || *m.TelemetryEventID != event.ID {
		t.Fatal("match row must link the telemetry event")
	}
	if m.IOCID != ind.ID {
		t.Fatal("match row must link the triggering IOC")
	}
}

// TestCTEM_B6_NoReopenWhenFindingAlreadyOpen — a second runtime match
// on the same IOC while the finding is already in_progress MUST NOT
// transition the finding again (idempotent). The match row is still
// recorded because the agent observed the activity.
func TestCTEM_B6_NoReopenWhenFindingAlreadyOpen(t *testing.T) {
	tenantID := shared.NewID()
	// Build a finding that is NOT closed.
	f, _ := vulnerability.NewFinding(
		tenantID, shared.NewID(),
		vulnerability.FindingSourceManual, "T-1",
		vulnerability.SeverityHigh, "already open",
	)
	_ = f.TransitionStatus(vulnerability.FindingStatusConfirmed, "", nil)
	_ = f.TransitionStatus(vulnerability.FindingStatusInProgress, "", nil)

	fid := f.ID()
	ind := &iocdom.Indicator{
		ID:              shared.NewID(),
		TenantID:        tenantID,
		Type:            iocdom.TypeDomain,
		Value:           "evil.example.com",
		Normalised:      "evil.example.com",
		SourceFindingID: &fid,
		Active:          true,
	}
	repo := &memIOCRepo{inds: []*iocdom.Indicator{ind}}
	reop := &reopenerSpy{finding: f}
	c := iocapp.NewCorrelator(repo, reop, logger.NewNop())

	_, err := c.Correlate(context.Background(), tenantID, iocapp.TelemetryEvent{
		ID:         shared.NewID(),
		Properties: map[string]any{telemetry.PropQueryName: "evil.example.com"},
	})
	if err != nil {
		t.Fatalf("%v", err)
	}

	if f.Status() != vulnerability.FindingStatusInProgress {
		t.Fatalf("open finding must not change status, got %s", f.Status())
	}
	if len(repo.matches) != 1 {
		t.Fatalf("match row still recorded for the hit, got %d", len(repo.matches))
	}
	if repo.matches[0].Reopened {
		t.Fatal("reopened must be false when finding was already open")
	}
}

// TestCTEM_B6_ThreatFeedIOCRecordsMatchWithoutReopen — IOC sourced
// from a threat feed has no linked finding. The correlator still
// records the match so the SOC dashboard can surface the hit, but
// there is nothing to reopen.
func TestCTEM_B6_ThreatFeedIOCRecordsMatchWithoutReopen(t *testing.T) {
	tenantID := shared.NewID()
	ind := &iocdom.Indicator{
		ID:         shared.NewID(),
		TenantID:   tenantID,
		Type:       iocdom.TypeFileHash,
		Value:      "DEADBEEFCAFE",
		Normalised: "deadbeefcafe",
		Active:     true,
		// SourceFindingID intentionally nil
	}
	repo := &memIOCRepo{inds: []*iocdom.Indicator{ind}}
	reop := &reopenerSpy{}
	c := iocapp.NewCorrelator(repo, reop, logger.NewNop())

	_, err := c.Correlate(context.Background(), tenantID, iocapp.TelemetryEvent{
		ID:         shared.NewID(),
		Properties: map[string]any{telemetry.PropFileHash: "deadbeefcafe"},
	})
	if err != nil {
		t.Fatalf("%v", err)
	}
	if atomic.LoadInt32(&reop.calls) != 0 {
		t.Fatal("no reopen when IOC has no source finding")
	}
	if len(repo.matches) != 1 || repo.matches[0].FindingID != nil {
		t.Fatalf("match row must have no finding link: %+v", repo.matches)
	}
}

// TestCTEM_B6_InactiveIOCIsIgnored — soft-deleted IOCs (active=false)
// must not fire. This is the escape hatch for stale indicators.
func TestCTEM_B6_InactiveIOCIsIgnored(t *testing.T) {
	tenantID := shared.NewID()
	fid := shared.NewID()
	ind := &iocdom.Indicator{
		ID:              shared.NewID(),
		TenantID:        tenantID,
		Type:            iocdom.TypeIP,
		Value:           "1.2.3.4",
		Normalised:      "1.2.3.4",
		SourceFindingID: &fid,
		Active:          false, // soft-deleted
	}
	repo := &memIOCRepo{inds: []*iocdom.Indicator{ind}}
	c := iocapp.NewCorrelator(repo, &reopenerSpy{}, logger.NewNop())

	hits, err := c.Correlate(context.Background(), tenantID, iocapp.TelemetryEvent{
		Properties: map[string]any{telemetry.PropRemoteIP: "1.2.3.4"},
	})
	if err != nil {
		t.Fatalf("%v", err)
	}
	if len(hits) != 0 {
		t.Fatalf("inactive IOC must not match, got %d hits", len(hits))
	}
	if len(repo.matches) != 0 {
		t.Fatalf("no match row for inactive IOC, got %d", len(repo.matches))
	}
}

// TestCTEM_B6_CrossTenantIOCIsolated — IOCs from tenant A must not
// match events from tenant B even if value is identical. Otherwise
// tenants poison each other's dashboards.
func TestCTEM_B6_CrossTenantIOCIsolated(t *testing.T) {
	tenantA := shared.NewID()
	tenantB := shared.NewID()
	fid := shared.NewID()
	ind := &iocdom.Indicator{
		ID:              shared.NewID(),
		TenantID:        tenantA,
		Type:            iocdom.TypeIP,
		Value:           "1.2.3.4",
		Normalised:      "1.2.3.4",
		SourceFindingID: &fid,
		Active:          true,
	}
	repo := &memIOCRepo{inds: []*iocdom.Indicator{ind}}
	c := iocapp.NewCorrelator(repo, &reopenerSpy{}, logger.NewNop())

	// Tenant B sees the same IP; must not match.
	hits, err := c.Correlate(context.Background(), tenantB, iocapp.TelemetryEvent{
		Properties: map[string]any{telemetry.PropRemoteIP: "1.2.3.4"},
	})
	if err != nil {
		t.Fatalf("%v", err)
	}
	if len(hits) != 0 {
		t.Fatalf("cross-tenant IOC leaked, got %d hits", len(hits))
	}
}

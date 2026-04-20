package ioc

import (
	"context"
	"sync/atomic"
	"testing"

	iocdom "github.com/openctemio/api/pkg/domain/ioc"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/domain/telemetry"
	"github.com/openctemio/api/pkg/logger"
)

// -----------------------------------------------------------------------------
// ExtractCandidates
// -----------------------------------------------------------------------------

func TestExtractCandidates_EmptyProperties(t *testing.T) {
	got := ExtractCandidates(TelemetryEvent{})
	if len(got) != 0 {
		t.Fatalf("empty properties must yield no candidates, got %d", len(got))
	}
}

func TestExtractCandidates_NetworkConnectExtractsIPAndDomain(t *testing.T) {
	ev := TelemetryEvent{
		EventType: "network_connect",
		Properties: map[string]any{
			telemetry.PropRemoteIP:     "185.220.101.42",
			telemetry.PropRemoteDomain: "Evil.Example.com",
		},
	}
	cs := ExtractCandidates(ev)
	if len(cs) != 2 {
		t.Fatalf("want 2 candidates, got %d", len(cs))
	}
	// Domain must be lowercased by Normalise.
	found := map[string]bool{}
	for _, c := range cs {
		found[string(c.Type)+":"+c.Normalized] = true
	}
	if !found["ip:185.220.101.42"] {
		t.Fatalf("missing IP candidate: %+v", cs)
	}
	if !found["domain:evil.example.com"] {
		t.Fatalf("domain not normalized to lowercase: %+v", cs)
	}
}

func TestExtractCandidates_IgnoresEmptyStrings(t *testing.T) {
	ev := TelemetryEvent{
		Properties: map[string]any{
			telemetry.PropRemoteIP:   "",
			telemetry.PropFileHash:   "abc123",
			telemetry.PropUserAgent:  "   ",
		},
	}
	cs := ExtractCandidates(ev)
	if len(cs) != 1 {
		t.Fatalf("want only the file_hash candidate, got %+v", cs)
	}
	if cs[0].Type != iocdom.TypeFileHash {
		t.Fatalf("wrong type: %v", cs[0].Type)
	}
}

func TestExtractCandidates_UnknownKeysIgnored(t *testing.T) {
	ev := TelemetryEvent{
		Properties: map[string]any{
			"some_random_field": "value",
			"foo":               "bar",
		},
	}
	cs := ExtractCandidates(ev)
	if len(cs) != 0 {
		t.Fatalf("whitelist violated: %+v", cs)
	}
}

func TestExtractCandidates_NonStringValuesIgnored(t *testing.T) {
	ev := TelemetryEvent{
		Properties: map[string]any{
			telemetry.PropRemoteIP: 12345, // int, not string
		},
	}
	cs := ExtractCandidates(ev)
	if len(cs) != 0 {
		t.Fatalf("non-string must be ignored, got %+v", cs)
	}
}

// -----------------------------------------------------------------------------
// Correlator
// -----------------------------------------------------------------------------

type fakeIOCRepo struct {
	indicators []*iocdom.Indicator
	matches    []iocdom.Match
	lookupErr  error
	recordErr  error
}

func (f *fakeIOCRepo) Create(_ context.Context, _ *iocdom.Indicator) error { return nil }
func (f *fakeIOCRepo) GetByID(_ context.Context, _, _ shared.ID) (*iocdom.Indicator, error) {
	return nil, nil
}
func (f *fakeIOCRepo) FindActiveByValues(_ context.Context, _ shared.ID, cands []iocdom.Candidate) ([]*iocdom.Indicator, error) {
	if f.lookupErr != nil {
		return nil, f.lookupErr
	}
	// Return any indicator whose (type, normalized) appears in candidates.
	want := make(map[string]bool, len(cands))
	for _, c := range cands {
		want[string(c.Type)+":"+c.Normalized] = true
	}
	var hits []*iocdom.Indicator
	for _, ind := range f.indicators {
		if want[string(ind.Type)+":"+ind.Normalized] {
			hits = append(hits, ind)
		}
	}
	return hits, nil
}
func (f *fakeIOCRepo) RecordMatch(_ context.Context, m iocdom.Match) error {
	if f.recordErr != nil {
		return f.recordErr
	}
	f.matches = append(f.matches, m)
	return nil
}
func (f *fakeIOCRepo) ListByTenant(_ context.Context, _ shared.ID, _, _ int) ([]*iocdom.Indicator, error) {
	return nil, nil
}
func (f *fakeIOCRepo) Deactivate(_ context.Context, _, _ shared.ID) error { return nil }

type fakeReopener struct {
	calls       int32
	lastReason  string
	lastFinding shared.ID
	reopened    bool // return value
	err         error
}

func (r *fakeReopener) ReopenForIOCMatch(_ context.Context, _, findingID shared.ID, reason string) (bool, error) {
	atomic.AddInt32(&r.calls, 1)
	r.lastReason = reason
	r.lastFinding = findingID
	return r.reopened, r.err
}

func makeIOC(t iocdom.Type, normalized string, source *shared.ID) *iocdom.Indicator {
	return &iocdom.Indicator{
		ID:              shared.NewID(),
		Type:            t,
		Value:           normalized,
		Normalized:      normalized,
		SourceFindingID: source,
		Active:          true,
	}
}

func TestCorrelator_NoCandidates_NoHits_NoRecord(t *testing.T) {
	repo := &fakeIOCRepo{}
	c := NewCorrelator(repo, &fakeReopener{}, logger.NewNop())

	hits, err := c.Correlate(context.Background(), shared.NewID(), TelemetryEvent{})
	if err != nil {
		t.Fatalf("%v", err)
	}
	if len(hits) != 0 {
		t.Fatal("should yield no hits")
	}
	if len(repo.matches) != 0 {
		t.Fatal("no matches should be recorded")
	}
}

func TestCorrelator_HitWithSourceFinding_ReopensAndRecords(t *testing.T) {
	fid := shared.NewID()
	ind := makeIOC(iocdom.TypeIP, "1.2.3.4", &fid)
	repo := &fakeIOCRepo{indicators: []*iocdom.Indicator{ind}}
	reop := &fakeReopener{reopened: true}
	c := NewCorrelator(repo, reop, logger.NewNop())

	tenantID := shared.NewID()
	ev := TelemetryEvent{
		ID:         shared.NewID(),
		Properties: map[string]any{telemetry.PropRemoteIP: "1.2.3.4"},
	}
	hits, err := c.Correlate(context.Background(), tenantID, ev)
	if err != nil {
		t.Fatalf("%v", err)
	}
	if len(hits) != 1 {
		t.Fatalf("want 1 hit, got %d", len(hits))
	}
	if atomic.LoadInt32(&reop.calls) != 1 {
		t.Fatalf("reopener should fire once, got %d", reop.calls)
	}
	if reop.lastFinding != fid {
		t.Fatalf("wrong finding: %s vs %s", reop.lastFinding, fid)
	}
	if len(repo.matches) != 1 {
		t.Fatalf("want 1 match row, got %d", len(repo.matches))
	}
	if !repo.matches[0].Reopened {
		t.Fatal("match row should flag reopened=true")
	}
	if repo.matches[0].TelemetryEventID == nil || *repo.matches[0].TelemetryEventID != ev.ID {
		t.Fatal("match row should link telemetry event id")
	}
}

func TestCorrelator_HitWithoutSourceFinding_RecordsOnlyNoReopen(t *testing.T) {
	// Threat-feed IOC with no linked finding — match is recorded for
	// visibility but there's nothing to reopen.
	ind := makeIOC(iocdom.TypeDomain, "evil.example.com", nil)
	repo := &fakeIOCRepo{indicators: []*iocdom.Indicator{ind}}
	reop := &fakeReopener{}
	c := NewCorrelator(repo, reop, logger.NewNop())

	hits, err := c.Correlate(context.Background(), shared.NewID(), TelemetryEvent{
		Properties: map[string]any{telemetry.PropRemoteDomain: "Evil.Example.com"},
	})
	if err != nil {
		t.Fatalf("%v", err)
	}
	if len(hits) != 1 {
		t.Fatalf("want 1 hit, got %d", len(hits))
	}
	if atomic.LoadInt32(&reop.calls) != 0 {
		t.Fatal("no reopen when IOC has no source finding")
	}
	if len(repo.matches) != 1 {
		t.Fatal("match row still recorded")
	}
	if repo.matches[0].Reopened {
		t.Fatal("reopened must be false when no finding linked")
	}
}

func TestCorrelator_ReopenFailure_DoesNotBlockMatchRecord(t *testing.T) {
	// If the reopen errors, the match row MUST still land so the
	// auditor has evidence the hit occurred.
	fid := shared.NewID()
	ind := makeIOC(iocdom.TypeFileHash, "deadbeef", &fid)
	repo := &fakeIOCRepo{indicators: []*iocdom.Indicator{ind}}
	reop := &fakeReopener{err: context.DeadlineExceeded}
	c := NewCorrelator(repo, reop, logger.NewNop())

	_, err := c.Correlate(context.Background(), shared.NewID(), TelemetryEvent{
		Properties: map[string]any{telemetry.PropFileHash: "DEADBEEF"},
	})
	if err != nil {
		t.Fatalf("per-hit errors must not bubble: %v", err)
	}
	if len(repo.matches) != 1 {
		t.Fatal("match row should be recorded even when reopen errors")
	}
	if repo.matches[0].Reopened {
		t.Fatal("reopened must be false on reopen failure")
	}
}

func TestCorrelator_MultipleHitsEachRecorded(t *testing.T) {
	fid := shared.NewID()
	indIP := makeIOC(iocdom.TypeIP, "1.2.3.4", &fid)
	indDomain := makeIOC(iocdom.TypeDomain, "evil.example.com", &fid)
	repo := &fakeIOCRepo{indicators: []*iocdom.Indicator{indIP, indDomain}}
	reop := &fakeReopener{reopened: true}
	c := NewCorrelator(repo, reop, logger.NewNop())

	_, err := c.Correlate(context.Background(), shared.NewID(), TelemetryEvent{
		Properties: map[string]any{
			telemetry.PropRemoteIP:     "1.2.3.4",
			telemetry.PropRemoteDomain: "evil.example.com",
		},
	})
	if err != nil {
		t.Fatalf("%v", err)
	}
	if len(repo.matches) != 2 {
		t.Fatalf("want 2 match rows, got %d", len(repo.matches))
	}
	if atomic.LoadInt32(&reop.calls) != 2 {
		t.Fatalf("reopener called %d, want 2 (once per hit; adapter no-ops the second)", reop.calls)
	}
}

func TestCorrelator_LookupErrorReturned(t *testing.T) {
	// A lookup failure is fatal — the caller needs to know ingest
	// didn't surface any correlation results.
	repo := &fakeIOCRepo{lookupErr: context.DeadlineExceeded}
	c := NewCorrelator(repo, &fakeReopener{}, logger.NewNop())

	_, err := c.Correlate(context.Background(), shared.NewID(), TelemetryEvent{
		Properties: map[string]any{telemetry.PropRemoteIP: "1.2.3.4"},
	})
	if err == nil {
		t.Fatal("lookup failure should propagate")
	}
}

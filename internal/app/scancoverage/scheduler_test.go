package scancoverage

import (
	"context"
	"errors"
	"testing"

	"github.com/openctemio/api/pkg/domain/shared"
)

// --- fakes ---------------------------------------------------------------

type fakeSource struct {
	configs    []CoverageConfig
	candidates map[string][]Candidate // keyed by tenant id string
	activeIPs  map[string]int
	listErr    error
	candErr    error
	activeErr  error
}

func (f *fakeSource) ListActiveCoverage(_ context.Context) ([]CoverageConfig, error) {
	return f.configs, f.listErr
}

func (f *fakeSource) ListCandidates(_ context.Context, tenantID shared.ID, _ int) ([]Candidate, error) {
	if f.candErr != nil {
		return nil, f.candErr
	}
	return f.candidates[tenantID.String()], nil
}

func (f *fakeSource) ActiveIPs(_ context.Context, tenantID shared.ID) (int, error) {
	if f.activeErr != nil {
		return 0, f.activeErr
	}
	return f.activeIPs[tenantID.String()], nil
}

type recordingDispatcher struct {
	calls []DispatchTenableInput
	err   error
	seq   int
}

func (d *recordingDispatcher) DispatchTenableScan(_ context.Context, in DispatchTenableInput) (shared.ID, string, error) {
	if d.err != nil {
		return shared.ID{}, "", d.err
	}
	d.calls = append(d.calls, in)
	d.seq++
	session := in.SessionID
	if session == "" {
		session = "sess-" + shared.NewID().String()
	}
	return shared.NewID(), session, nil
}

type recordingStore struct {
	records []DispatchRecord
	err     error
}

func (s *recordingStore) MarkDispatched(_ context.Context, rec DispatchRecord) error {
	if s.err != nil {
		return s.err
	}
	s.records = append(s.records, rec)
	return nil
}

// --- tests ---------------------------------------------------------------

func TestScheduler_DispatchesUnlimitedBatch(t *testing.T) {
	tenant := shared.NewID()
	src := &fakeSource{
		configs: []CoverageConfig{{
			TenantID:     tenant,
			Engine:       "nessus_pro",
			Policy:       LicensePolicy{Mode: LicenseUnlimited},
			DefaultBatch: 2,
		}},
		candidates: map[string][]Candidate{
			tenant.String(): {
				{AssetID: "a1", Target: "10.0.0.1", Criticality: "high"},
				{AssetID: "a2", Target: "10.0.0.2", Criticality: "critical"},
				{AssetID: "a3", Target: "10.0.0.3", Criticality: "low"},
			},
		},
	}
	disp := &recordingDispatcher{}
	store := &recordingStore{}
	s := NewScheduler(src, disp, store, nil)

	n, err := s.RunOnce(context.Background())
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if n != 1 {
		t.Fatalf("expected 1 dispatch, got %d", n)
	}
	if len(disp.calls) != 1 {
		t.Fatalf("dispatcher called %d times", len(disp.calls))
	}
	// Unlimited engine: batch = DefaultBatch (2), highest criticality first.
	got := disp.calls[0].Targets
	if len(got) != 2 {
		t.Fatalf("expected 2 targets, got %v", got)
	}
	if got[0] != "10.0.0.2" {
		t.Fatalf("critical asset should sort first, got %v", got)
	}
	if disp.calls[0].TenantID != tenant || disp.calls[0].Engine != "nessus_pro" {
		t.Fatalf("dispatch input wrong: %+v", disp.calls[0])
	}
	// Cursor recorded for the dispatched assets.
	if len(store.records) != 1 || len(store.records[0].AssetIDs) != 2 {
		t.Fatalf("store record wrong: %+v", store.records)
	}
	if store.records[0].SessionID == "" {
		t.Fatal("session id should be recorded")
	}
}

func TestScheduler_CapHeadroomLimitsBatch(t *testing.T) {
	tenant := shared.NewID()
	src := &fakeSource{
		configs: []CoverageConfig{{
			TenantID:     tenant,
			Engine:       "tenable_sc",
			Policy:       LicensePolicy{Mode: LicenseActiveIPCap, Cap: 500, SafetyMargin: 10},
			DefaultBatch: 1000, // larger than headroom, so the cap is the binding limit
		}},
		candidates: map[string][]Candidate{
			tenant.String(): {
				{AssetID: "a1", Target: "10.0.0.0/24", Criticality: "high"}, // 256
				{AssetID: "a2", Target: "10.0.1.0/24", Criticality: "high"}, // 256 -> 512 > 490
				{AssetID: "a3", Target: "10.0.2.5", Criticality: "high"},    // 1
			},
		},
		activeIPs: map[string]int{tenant.String(): 0},
	}
	disp := &recordingDispatcher{}
	store := &recordingStore{}
	s := NewScheduler(src, disp, store, nil)

	if _, err := s.RunOnce(context.Background()); err != nil {
		t.Fatalf("run: %v", err)
	}
	if len(disp.calls) != 1 {
		t.Fatalf("expected 1 dispatch, got %d", len(disp.calls))
	}
	// Headroom = 500 - 10 - 0 = 490. First /24 (256) fits; second /24 would make
	// 512 > 490 so it is skipped; the single IP (1) still fits → 257 total.
	if store.records[0].IPCount != 257 {
		t.Fatalf("expected 257 ips, got %d", store.records[0].IPCount)
	}
	if len(disp.calls[0].Targets) != 2 {
		t.Fatalf("expected 2 targets (256-block + single ip), got %v", disp.calls[0].Targets)
	}
}

func TestScheduler_CapFullPausesUntilReclaim(t *testing.T) {
	tenant := shared.NewID()
	src := &fakeSource{
		configs: []CoverageConfig{{
			TenantID:     tenant,
			Engine:       "tenable_sc",
			Policy:       LicensePolicy{Mode: LicenseActiveIPCap, Cap: 500, SafetyMargin: 10},
			DefaultBatch: 500,
		}},
		candidates: map[string][]Candidate{
			tenant.String(): {{AssetID: "a1", Target: "10.0.0.1", Criticality: "high"}},
		},
		activeIPs: map[string]int{tenant.String(): 495}, // > cap-margin → no room
	}
	disp := &recordingDispatcher{}
	store := &recordingStore{}
	s := NewScheduler(src, disp, store, nil)

	n, err := s.RunOnce(context.Background())
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if n != 0 || len(disp.calls) != 0 {
		t.Fatalf("should pause when cap is full: dispatched=%d calls=%d", n, len(disp.calls))
	}
}

func TestScheduler_OversizedTargetSkippedForCap(t *testing.T) {
	tenant := shared.NewID()
	src := &fakeSource{
		configs: []CoverageConfig{{
			TenantID:     tenant,
			Engine:       "tenable_sc",
			Policy:       LicensePolicy{Mode: LicenseActiveIPCap, Cap: 500, SafetyMargin: 10},
			DefaultBatch: 500,
		}},
		candidates: map[string][]Candidate{
			// /23 = 512 > headroom (490); the only candidate. Must be refused, not
			// dispatched (would blow the license).
			tenant.String(): {{AssetID: "a1", Target: "10.0.0.0/23", Criticality: "critical"}},
		},
		activeIPs: map[string]int{tenant.String(): 0},
	}
	disp := &recordingDispatcher{}
	store := &recordingStore{}
	s := NewScheduler(src, disp, store, nil)

	n, err := s.RunOnce(context.Background())
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if n != 0 || len(disp.calls) != 0 {
		t.Fatalf("oversized target must not be dispatched for capped engine: dispatched=%d", n)
	}
}

func TestScheduler_OversizedTargetAllowedForUnlimited(t *testing.T) {
	tenant := shared.NewID()
	src := &fakeSource{
		configs: []CoverageConfig{{
			TenantID:     tenant,
			Engine:       "nessus_pro",
			Policy:       LicensePolicy{Mode: LicenseUnlimited},
			DefaultBatch: 100,
		}},
		candidates: map[string][]Candidate{
			tenant.String(): {{AssetID: "a1", Target: "10.0.0.0/23", Criticality: "high"}}, // 512 > 100
		},
	}
	disp := &recordingDispatcher{}
	store := &recordingStore{}
	s := NewScheduler(src, disp, store, nil)

	n, err := s.RunOnce(context.Background())
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	// No cap to violate → top candidate is dispatched even though it exceeds the
	// perf batch size.
	if n != 1 || len(disp.calls) != 1 {
		t.Fatalf("unlimited engine should dispatch oversized top target: dispatched=%d", n)
	}
}

func TestScheduler_PinnedAgentForwarded(t *testing.T) {
	tenant := shared.NewID()
	agent := shared.NewID()
	src := &fakeSource{
		configs: []CoverageConfig{{
			TenantID:     tenant,
			AgentID:      &agent,
			Engine:       "nessus_pro",
			Policy:       LicensePolicy{Mode: LicenseUnlimited},
			DefaultBatch: 1,
		}},
		candidates: map[string][]Candidate{
			tenant.String(): {{AssetID: "a1", Target: "10.0.0.1", Criticality: "high"}},
		},
	}
	disp := &recordingDispatcher{}
	s := NewScheduler(src, disp, &recordingStore{}, nil)

	if _, err := s.RunOnce(context.Background()); err != nil {
		t.Fatalf("run: %v", err)
	}
	if disp.calls[0].AgentID == nil || *disp.calls[0].AgentID != agent {
		t.Fatal("pinned agent id must be forwarded to the dispatcher (C3)")
	}
}

func TestScheduler_NoCandidatesNoDispatch(t *testing.T) {
	tenant := shared.NewID()
	src := &fakeSource{
		configs: []CoverageConfig{{
			TenantID:     tenant,
			Engine:       "nessus_pro",
			Policy:       LicensePolicy{Mode: LicenseUnlimited},
			DefaultBatch: 100,
		}},
		candidates: map[string][]Candidate{},
	}
	disp := &recordingDispatcher{}
	s := NewScheduler(src, disp, &recordingStore{}, nil)

	n, err := s.RunOnce(context.Background())
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if n != 0 || len(disp.calls) != 0 {
		t.Fatalf("no candidates → no dispatch, got %d", n)
	}
}

func TestScheduler_OneTenantFailureDoesNotAbortPass(t *testing.T) {
	good := shared.NewID()
	bad := shared.NewID()
	src := &fakeSource{
		configs: []CoverageConfig{
			{TenantID: bad, Engine: "tenable_sc", Policy: LicensePolicy{Mode: LicenseActiveIPCap, Cap: 500}, DefaultBatch: 100},
			{TenantID: good, Engine: "nessus_pro", Policy: LicensePolicy{Mode: LicenseUnlimited}, DefaultBatch: 1},
		},
		candidates: map[string][]Candidate{
			good.String(): {{AssetID: "a1", Target: "10.0.0.1", Criticality: "high"}},
		},
		// ActiveIPs fails for every tenant, but only the capped (bad) tenant calls
		// it — the unlimited tenant skips the active-IP lookup — so just the bad
		// tenant errors and the good tenant must still dispatch.
		activeErr: errors.New("active ip lookup down"),
	}
	disp := &recordingDispatcher{}
	s := NewScheduler(src, disp, &recordingStore{}, nil)

	n, err := s.RunOnce(context.Background())
	if err != nil {
		t.Fatalf("pass must not abort on one tenant error: %v", err)
	}
	if n != 1 {
		t.Fatalf("good tenant should still dispatch, got %d", n)
	}
}

func TestScheduler_ListErrorAborts(t *testing.T) {
	src := &fakeSource{listErr: errors.New("db down")}
	s := NewScheduler(src, &recordingDispatcher{}, &recordingStore{}, nil)
	if _, err := s.RunOnce(context.Background()); err == nil {
		t.Fatal("list error must propagate")
	}
}

func TestScheduler_DispatchErrorSurfacedPerTenant(t *testing.T) {
	tenant := shared.NewID()
	src := &fakeSource{
		configs: []CoverageConfig{{
			TenantID:     tenant,
			Engine:       "nessus_pro",
			Policy:       LicensePolicy{Mode: LicenseUnlimited},
			DefaultBatch: 1,
		}},
		candidates: map[string][]Candidate{
			tenant.String(): {{AssetID: "a1", Target: "10.0.0.1", Criticality: "high"}},
		},
	}
	disp := &recordingDispatcher{err: errors.New("command create failed")}
	store := &recordingStore{}
	s := NewScheduler(src, disp, store, nil)

	n, err := s.RunOnce(context.Background())
	if err != nil {
		t.Fatalf("dispatch error for one tenant must not abort the pass: %v", err)
	}
	if n != 0 {
		t.Fatalf("failed dispatch must not count, got %d", n)
	}
	if len(store.records) != 0 {
		t.Fatal("cursor must not advance when dispatch failed")
	}
}

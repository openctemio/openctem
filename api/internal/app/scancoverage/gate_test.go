package scancoverage

// The coverage dispatcher sends a batch only after the target gate a scan
// trigger uses (RFC-042 F16): excluded and refused targets are skipped, a
// batch stays in one scan zone, and without a gate nothing is dispatched.

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	scanapp "github.com/openctemio/openctem/api/internal/app/scan"
	"github.com/openctemio/openctem/api/pkg/domain/scanzone"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// allowAllGate lets every target through, unzoned (the gate's decision when
// the tenant has no exclusions and no zones and every target is valid).
type allowAllGate struct{}

func (allowAllGate) ResolveDispatchTargets(_ context.Context, in scanapp.DispatchTargetsInput) (*scanapp.DispatchTargets, error) {
	return &scanapp.DispatchTargets{Allowed: slices.Clone(in.Targets)}, nil
}

// scriptedGate excludes, refuses and zones targets by name.
type scriptedGate struct {
	excluded map[string]bool
	refused  map[string]string
	zones    map[string]*scanzone.Zone
	err      error
	calls    []scanapp.DispatchTargetsInput
}

func (g *scriptedGate) ResolveDispatchTargets(_ context.Context, in scanapp.DispatchTargetsInput) (*scanapp.DispatchTargets, error) {
	g.calls = append(g.calls, in)
	if g.err != nil {
		return nil, g.err
	}
	out := &scanapp.DispatchTargets{ZoneOf: map[string]*scanzone.Zone{}}
	for _, t := range in.Targets {
		switch {
		case g.excluded[t]:
			out.Excluded = append(out.Excluded, t)
		case g.refused[t] != "":
			out.Refused = append(out.Refused, scanapp.RefusedTarget{Target: t, Reason: g.refused[t]})
		default:
			out.Allowed = append(out.Allowed, t)
			out.ZoneOf[t] = g.zones[t]
		}
	}
	return out, nil
}

// claimingStore records what was claimed.
type claimingStore struct {
	recordingStore
	claimed []string
}

func (s *claimingStore) ClaimBatch(ctx context.Context, tenantID shared.ID, batch []Candidate, at time.Time) ([]string, error) {
	ids, err := s.recordingStore.ClaimBatch(ctx, tenantID, batch, at)
	s.claimed = append(s.claimed, ids...)
	return ids, err
}

func gateTestSource(tenant shared.ID, cands ...Candidate) *fakeSource {
	return &fakeSource{
		configs: []CoverageConfig{{
			TenantID:     tenant,
			Engine:       "nessus_pro",
			Policy:       LicensePolicy{Mode: LicenseUnlimited},
			DefaultBatch: 10,
		}},
		candidates: map[string][]Candidate{tenant.String(): cands},
	}
}

func TestScheduler_GateSkipsExcludedAndRefusedTargets(t *testing.T) {
	tenant := shared.NewID()
	src := gateTestSource(tenant,
		Candidate{AssetID: "ok", Target: "203.0.113.10", Criticality: "critical"},
		Candidate{AssetID: "excl", Target: "203.0.113.20", Criticality: "critical"},
		Candidate{AssetID: "priv", Target: "10.0.0.5", Criticality: "critical"},
	)
	gate := &scriptedGate{
		excluded: map[string]bool{"203.0.113.20": true},
		refused:  map[string]string{"10.0.0.5": "10.0.0.5 is a private address outside every scan zone"},
	}
	disp := &recordingDispatcher{}
	store := &claimingStore{}

	n, err := NewScheduler(src, disp, store, &SchedulerConfig{Gate: gate}).RunOnce(context.Background())
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if n != 1 || len(disp.calls) != 1 {
		t.Fatalf("dispatched %d batches (%d calls), want 1", n, len(disp.calls))
	}
	if got := disp.calls[0].Targets; !slices.Equal(got, []string{"203.0.113.10"}) {
		t.Fatalf("dispatched targets %v, want only the allowed one (excluded and private targets must not reach the runner)", got)
	}
	if len(store.records) != 1 || !slices.Equal(store.records[0].AssetIDs, []string{"ok"}) {
		t.Fatalf("marked dispatched %+v, want only asset ok", store.records)
	}
	// Skipped assets are claimed (their cursor moves) so they do not hold
	// the top of every later batch.
	slices.Sort(store.claimed)
	if !slices.Equal(store.claimed, []string{"excl", "ok", "priv"}) {
		t.Fatalf("claimed %v, want all three", store.claimed)
	}
}

func TestScheduler_OnlyExcludedTargetsDispatchNothing(t *testing.T) {
	tenant := shared.NewID()
	src := gateTestSource(tenant, Candidate{AssetID: "excl", Target: "203.0.113.20", Criticality: "high"})
	gate := &scriptedGate{excluded: map[string]bool{"203.0.113.20": true}}
	disp := &recordingDispatcher{}

	n, err := NewScheduler(src, disp, &claimingStore{}, &SchedulerConfig{Gate: gate}).RunOnce(context.Background())
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if n != 0 || len(disp.calls) != 0 {
		t.Fatalf("an excluded target was dispatched: %+v", disp.calls)
	}
}

func TestScheduler_GateFailureOrMissingGateDispatchesNothing(t *testing.T) {
	cases := map[string]*SchedulerConfig{
		"no gate":        {},
		"nil config":     nil,
		"lookup failure": {Gate: &scriptedGate{err: errors.New("db down")}},
	}
	for name, cfg := range cases {
		t.Run(name, func(t *testing.T) {
			tenant := shared.NewID()
			src := gateTestSource(tenant, Candidate{AssetID: "a", Target: "203.0.113.10", Criticality: "high"})
			disp := &recordingDispatcher{}
			store := &claimingStore{}
			n, _ := NewScheduler(src, disp, store, cfg).RunOnce(context.Background())
			if n != 0 || len(disp.calls) != 0 {
				t.Fatalf("dispatched without a working gate: %+v", disp.calls)
			}
			if len(store.claimed) != 0 {
				t.Fatalf("claimed %v without a working gate; nothing may move", store.claimed)
			}
		})
	}
}

func TestScheduler_BatchStaysInOneZoneAndIsStamped(t *testing.T) {
	tenant := shared.NewID()
	sensor := shared.NewID()
	zoneA := &scanzone.Zone{ID: shared.NewID(), Name: "dc-a", SensorIDs: []shared.ID{sensor}}
	zoneB := &scanzone.Zone{ID: shared.NewID(), Name: "dc-b", SensorIDs: []shared.ID{shared.NewID()}}
	src := gateTestSource(tenant,
		Candidate{AssetID: "a1", Target: "10.1.0.1", Criticality: "critical"},
		Candidate{AssetID: "b1", Target: "10.2.0.1", Criticality: "high"},
		Candidate{AssetID: "a2", Target: "10.1.0.2", Criticality: "medium"},
	)
	src.configs[0].SensorID = &sensor
	gate := &scriptedGate{zones: map[string]*scanzone.Zone{"10.1.0.1": zoneA, "10.1.0.2": zoneA, "10.2.0.1": zoneB}}
	disp := &recordingDispatcher{}
	store := &claimingStore{}

	if _, err := NewScheduler(src, disp, store, &SchedulerConfig{Gate: gate}).RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if len(gate.calls) != 1 || gate.calls[0].SensorID == nil || !gate.calls[0].SensorID.Equals(sensor) {
		t.Fatalf("the pinned sensor must reach the gate: %+v", gate.calls)
	}
	if len(disp.calls) != 1 {
		t.Fatalf("calls = %d, want 1", len(disp.calls))
	}
	got := disp.calls[0]
	if strings.Join(got.Targets, ",") != "10.1.0.1,10.1.0.2" {
		t.Fatalf("targets %v, want the zone of the top candidate only", got.Targets)
	}
	if got.ScanZoneID == nil || !got.ScanZoneID.Equals(zoneA.ID) {
		t.Fatalf("command zone %v, want %s", got.ScanZoneID, zoneA.ID)
	}
	if slices.Contains(store.claimed, "b1") {
		t.Fatal("a candidate of another zone was claimed; it must stay for a later cycle")
	}
}

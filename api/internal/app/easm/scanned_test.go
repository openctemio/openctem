package easm

import (
	"context"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/internal/app/ingest"
	"github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/domain/attribution"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// fakeScanStore keeps evidence per asset and evaluates what was recorded.
type fakeScanStore struct {
	evidence map[string][]attribution.Evidence
	records  map[string]attribution.Record
	saved    map[string]attribution.Decision
}

func newFakeScanStore() *fakeScanStore {
	return &fakeScanStore{evidence: map[string][]attribution.Evidence{}, records: map[string]attribution.Record{}, saved: map[string]attribution.Decision{}}
}

func (f *fakeScanStore) UpsertEvidenceBulk(_ context.Context, _ shared.ID, ids []string, ev attribution.Evidence) error {
	for _, id := range ids {
		f.evidence[id] = append(f.evidence[id], ev)
	}
	return nil
}

func (f *fakeScanStore) FiredRules(_ context.Context, _ shared.ID, ids []string) (map[string][]attribution.Rule, error) {
	out := map[string][]attribution.Rule{}
	for _, id := range ids {
		for _, ev := range f.evidence[id] {
			out[id] = append(out[id], ev.Rule)
		}
	}
	return out, nil
}

func (f *fakeScanStore) Records(_ context.Context, _ shared.ID, ids []string) (map[string]attribution.Record, error) {
	out := map[string]attribution.Record{}
	for _, id := range ids {
		if r, ok := f.records[id]; ok {
			out[id] = r
		}
	}
	return out, nil
}

func (f *fakeScanStore) SaveAutomatic(_ context.Context, _ shared.ID, id string, d attribution.Decision) error {
	f.saved[id] = d
	return nil
}

func (f *fakeScanStore) ScanRunOf(context.Context, shared.ID, shared.ID) (string, string, error) {
	return "run-1", "scan-1", nil
}

type verified []string

func (v verified) VerifiedDomainNames(context.Context, shared.ID) ([]string, error) { return v, nil }

func scanned(name string, typ asset.AssetType, typed, created bool) ingest.ScannedAsset {
	return ingest.ScannedAsset{ID: shared.NewID(), Name: name, Type: asset.TypeRef{Type: typ}, Typed: typed, Created: created}
}

func rulesOf(evs []attribution.Evidence) map[attribution.Rule]bool {
	out := map[attribution.Rule]bool{}
	for _, e := range evs {
		out[e.Rule] = true
	}
	return out
}

// research/22 E7: a scan confirms only targets the tenant typed; names it
// discovers go to review unless under a verified domain; a scan never takes
// a name past review, and never overrides a person.
func TestScanStamper_E7(t *testing.T) {
	store := newFakeScanStore()
	typedLegacy := scanned("www.example.com", asset.AssetTypeSubdomain, true, false)
	typedCandidate := scanned("cand.example.com", asset.AssetTypeSubdomain, true, false)
	store.records[typedCandidate.ID.String()] = attribution.Record{State: attribution.StateCandidate, Confidence: 40}
	typedReview := scanned("review.example.com", asset.AssetTypeSubdomain, true, false)
	store.records[typedReview.ID.String()] = attribution.Record{State: attribution.StateNeedsReview, Confidence: 85}
	typedRejected := scanned("rejected.example.com", asset.AssetTypeSubdomain, true, false)
	store.records[typedRejected.ID.String()] = attribution.Record{State: attribution.StateRejected, HumanDecided: true}
	foundNew := scanned("api.example.com", asset.AssetTypeSubdomain, false, true)
	foundVerified := scanned("api.proven.org", asset.AssetTypeSubdomain, false, true)
	foundIP := scanned("203.0.113.9", asset.AssetTypeIPAddress, false, true)
	foundHost := scanned("db01.example.com", asset.AssetTypeHost, false, true)
	foundExistingLegacy := scanned("old.example.com", asset.AssetTypeSubdomain, false, false)
	foundExistingReview := scanned("ct.example.com", asset.AssetTypeSubdomain, false, false)
	store.records[foundExistingReview.ID.String()] = attribution.Record{State: attribution.StateNeedsReview, Confidence: 85}
	store.evidence[foundExistingReview.ID.String()] = []attribution.Evidence{{Rule: attribution.RuleAssertedRoot}}

	sensorID, cmd, step := shared.NewID(), shared.NewID(), shared.NewID()
	all := []ingest.ScannedAsset{typedLegacy, typedCandidate, typedReview, typedRejected, foundNew, foundVerified, foundIP, foundHost, foundExistingLegacy, foundExistingReview}
	err := NewScanStamper(store, verified{"proven.org"}).StampScanned(context.Background(), shared.NewID(), all,
		ingest.ScanProvenance{SensorID: sensorID, CommandID: &cmd, StepRunID: &step, Tool: "subfinder", ReportID: "r1", ObservedAt: time.Now()})
	if err != nil {
		t.Fatal(err)
	}

	// Evidence: typed targets tenant_scanned, discovered names
	// tenant_scan_discovered, with the provenance.
	if r := rulesOf(store.evidence[typedLegacy.ID.String()]); !r[attribution.RuleTenantScanned] || r[attribution.RuleScanDiscovered] {
		t.Fatalf("typed target evidence = %v", r)
	}
	if r := rulesOf(store.evidence[foundNew.ID.String()]); r[attribution.RuleTenantScanned] || !r[attribution.RuleScanDiscovered] {
		t.Fatalf("discovered name evidence = %v", r)
	}
	ev := store.evidence[typedLegacy.ID.String()][0]
	for k, want := range map[string]string{"scan_id": "scan-1", "scan_run_id": "run-1", "command_id": cmd.String(), "sensor_id": sensorID.String(), "tool": "subfinder"} {
		if ev.Observed[k] != want {
			t.Errorf("observed[%s] = %v, want %s", k, ev.Observed[k], want)
		}
	}

	want := map[string]attribution.State{
		typedCandidate.ID.String(): attribution.StateConfirmed,   // typed, not under review: the scan confirms it
		foundNew.ID.String():       attribution.StateNeedsReview, // discovered: review
		foundVerified.ID.String():  attribution.StateConfirmed,   // discovered under a verified domain
		foundIP.ID.String():        attribution.StateNeedsReview, // discovered address: review
	}
	for id, st := range want {
		if got := store.saved[id]; got.State != st {
			t.Errorf("%s: saved %+v, want %s", id, got, st)
		}
	}
	// Never written: a legacy typed target (the gate decides by scope), a
	// typed name under review, a person's rejection, a discovered host (not
	// governed by EASM attribution) and an existing legacy asset.
	for _, a := range []ingest.ScannedAsset{typedLegacy, typedReview, typedRejected, foundHost, foundExistingLegacy} {
		if d, ok := store.saved[a.ID.String()]; ok {
			t.Errorf("%s got a record: %+v", a.Name, d)
		}
	}
	// An existing needs_review name the scan saw again stays in review.
	if d := store.saved[foundExistingReview.ID.String()]; d.State != attribution.StateNeedsReview {
		t.Errorf("existing review name = %+v, want needs_review", d)
	}
}

// An unsolicited report gives a new internet-facing asset a candidate
// record and no evidence; a synthetic sensor (server-side ingest) records
// nothing.
func TestScanStamper_UnsolicitedAndSynthetic(t *testing.T) {
	store := newFakeScanStore()
	newName := scanned("x.example.net", asset.AssetTypeDomain, false, true)
	repo := scanned("github.com/acme/app", asset.AssetTypeRepository, false, true)
	err := NewScanStamper(store, nil).StampScanned(context.Background(), shared.NewID(), []ingest.ScannedAsset{newName, repo},
		ingest.ScanProvenance{SensorID: shared.NewID(), Unsolicited: true})
	if err != nil {
		t.Fatal(err)
	}
	if d := store.saved[newName.ID.String()]; d.State != attribution.StateCandidate {
		t.Fatalf("unsolicited new name = %+v, want candidate", d)
	}
	if _, ok := store.saved[repo.ID.String()]; ok || len(store.evidence) != 0 {
		t.Fatalf("unsolicited: repo record %v, evidence %v", ok, store.evidence)
	}

	store = newFakeScanStore()
	if err := NewScanStamper(store, nil).StampScanned(context.Background(), shared.NewID(), []ingest.ScannedAsset{newName}, ingest.ScanProvenance{}); err != nil ||
		len(store.saved) != 0 || len(store.evidence) != 0 {
		t.Fatalf("zero sensor recorded: %v %v %v", store.saved, store.evidence, err)
	}
}

// A platform sensor scan is evidence from "the platform": one shared source,
// and the observation carries no platform sensor id.
func TestScanStamper_PlatformSensorIsNeverNamed(t *testing.T) {
	store := newFakeScanStore()
	typed := scanned("www.example.com", asset.AssetTypeSubdomain, true, false)
	sensorID, cmd := shared.NewID(), shared.NewID()
	err := NewScanStamper(store, verified{}).StampScanned(context.Background(), shared.NewID(), []ingest.ScannedAsset{typed},
		ingest.ScanProvenance{SensorID: sensorID, CommandID: &cmd, Tool: "nuclei", ObservedAt: time.Now(), Platform: true})
	if err != nil {
		t.Fatal(err)
	}
	evs := store.evidence[typed.ID.String()]
	if len(evs) != 1 {
		t.Fatalf("evidence %+v", evs)
	}
	ev := evs[0]
	if ev.Source != PlatformSensorSource || ev.Observed["sensor_id"] != nil || ev.Observed["platform"] != true {
		t.Fatalf("platform evidence names the sensor: source %q observed %v", ev.Source, ev.Observed)
	}
	for _, v := range ev.Observed {
		if s, ok := v.(string); ok && s == sensorID.String() {
			t.Fatalf("platform sensor id in the observation: %v", ev.Observed)
		}
	}
}

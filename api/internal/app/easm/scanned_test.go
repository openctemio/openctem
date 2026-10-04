package easm

import (
	"context"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/internal/app/ingest"
	"github.com/openctemio/openctem/api/pkg/domain/attribution"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

type fakeScanStore struct {
	ev      attribution.Evidence
	ids     []string
	records map[string]attribution.Record
	saved   map[string]attribution.Decision
}

func (f *fakeScanStore) UpsertEvidenceBulk(_ context.Context, _ shared.ID, ids []string, ev attribution.Evidence) error {
	f.ids, f.ev = ids, ev
	return nil
}

func (f *fakeScanStore) FiredRules(_ context.Context, _ shared.ID, ids []string) (map[string][]attribution.Rule, error) {
	out := map[string][]attribution.Rule{}
	for _, id := range ids {
		out[id] = []attribution.Rule{attribution.RuleAssertedRoot, attribution.RuleTenantScanned}
	}
	return out, nil
}

func (f *fakeScanStore) Records(context.Context, shared.ID, []string) (map[string]attribution.Record, error) {
	return f.records, nil
}

func (f *fakeScanStore) SaveAutomatic(_ context.Context, _ shared.ID, id string, d attribution.Decision) error {
	f.saved[id] = d
	return nil
}

func (f *fakeScanStore) ScanRunOf(context.Context, shared.ID, shared.ID) (string, string, error) {
	return "run-1", "scan-1", nil
}

func TestScanStamper(t *testing.T) {
	review, rejected, legacy := shared.NewID(), shared.NewID(), shared.NewID()
	store := &fakeScanStore{
		records: map[string]attribution.Record{
			review.String():   {State: attribution.StateNeedsReview, Confidence: 85},
			rejected.String(): {State: attribution.StateRejected, HumanDecided: true},
		},
		saved: map[string]attribution.Decision{},
	}
	sensorID, cmd, step := shared.NewID(), shared.NewID(), shared.NewID()
	err := NewScanStamper(store).StampScanned(context.Background(), shared.NewID(), []shared.ID{review, rejected, legacy},
		ingest.ScanProvenance{SensorID: sensorID, CommandID: &cmd, StepRunID: &step, Tool: "subfinder", ReportID: "r1", ObservedAt: time.Now()})
	if err != nil {
		t.Fatal(err)
	}
	if len(store.ids) != 3 || store.ev.Rule != attribution.RuleTenantScanned || store.ev.Source != "sensor:"+sensorID.String() || store.ev.Technique != "subfinder" {
		t.Fatalf("evidence = %+v on %v", store.ev, store.ids)
	}
	for k, want := range map[string]string{"scan_id": "scan-1", "pipeline_run_id": "run-1", "command_id": cmd.String(), "sensor_id": sensorID.String(), "tool": "subfinder"} {
		if store.ev.Observed[k] != want {
			t.Errorf("observed[%s] = %v, want %s", k, store.ev.Observed[k], want)
		}
	}
	if d := store.saved[review.String()]; d.State != attribution.StateConfirmed {
		t.Errorf("needs_review asset = %+v, want confirmed", d)
	}
	if _, ok := store.saved[rejected.String()]; ok {
		t.Error("a human decision was rewritten")
	}
	if _, ok := store.saved[legacy.String()]; ok {
		t.Error("a legacy asset got a record; it is confirmed by construction")
	}

	// A synthetic sensor (server-side ingest) never stamps.
	store.ids = nil
	if err := NewScanStamper(store).StampScanned(context.Background(), shared.NewID(), []shared.ID{review}, ingest.ScanProvenance{}); err != nil || store.ids != nil {
		t.Fatalf("zero sensor stamped: %v %v", store.ids, err)
	}
}

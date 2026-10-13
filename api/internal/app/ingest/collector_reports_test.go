package ingest

import (
	"strings"
	"testing"

	"github.com/openctemio/ctis"

	"github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/domain/ingestreport"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

func TestCompleteCoverage(t *testing.T) {
	for cov, want := range map[string]bool{"full": true, " FULL ": true, "partial": false, "incremental": false, "": false} {
		if got := completeCoverage(ctis.ReportMetadata{CoverageType: cov}); got != want {
			t.Errorf("completeCoverage(%q) = %v, want %v", cov, got, want)
		}
	}
}

// The collector source is the sensor, the tool and the bounded instance
// name; a report without a tool has none.
func TestCollectorSourceOf(t *testing.T) {
	tenant, sensorID := shared.NewID(), shared.NewID()
	if collectorSourceOf(tenant, sensorID, nil, ctis.ReportMetadata{}) != nil {
		t.Fatal("a report without a tool got a collector source")
	}
	src := collectorSourceOf(tenant, sensorID, &ctis.Tool{Name: " vCenter "}, ctis.ReportMetadata{SourceRef: strings.Repeat("x", 400)})
	if src == nil || src.Tool != "vcenter" || len(src.SourceRef) != maxCollectorSourceRef || src.TenantID != tenant || src.SensorID != sensorID {
		t.Fatalf("source = %+v", src)
	}
}

// Ownership counts only for a complete report, and a lookup failure is
// "not owned" (fail closed); answers are cached.
func TestCollectorScopeOwns(t *testing.T) {
	owned, other := shared.NewID(), shared.NewID()
	calls := 0
	lookup := func(ids []shared.ID) map[shared.ID]bool {
		calls++
		return map[shared.ID]bool{owned: true}
	}
	c := &collectorScope{complete: true, owned: map[shared.ID]bool{}, lookup: lookup}
	if !c.owns(owned) || c.owns(other) || !c.owns(owned) {
		t.Fatal("ownership answers wrong")
	}
	if calls != 2 {
		t.Fatalf("lookups = %d, want 2 (cached)", calls)
	}
	partial := &collectorScope{complete: false, owned: map[shared.ID]bool{}, lookup: lookup}
	if partial.owns(owned) {
		t.Fatal("a partial report owns an asset")
	}
	failing := &collectorScope{complete: true, owned: map[shared.ID]bool{}, lookup: func([]shared.ID) map[shared.ID]bool { return nil }}
	if failing.owns(owned) {
		t.Fatal("a failed lookup granted ownership")
	}
	var none *collectorScope
	if none.owns(owned) {
		t.Fatal("no collector scope owns an asset")
	}
}

// A collector source may change its own asset, but a finding a person
// resolved there stays resolved.
func TestAlterScope_CollectorOwnedNeverReopens(t *testing.T) {
	a := relTestAssetForScope(t)
	s := newAlterScope(Binding{})
	s.collector = &collectorScope{complete: true, owned: map[shared.ID]bool{a.ID(): true}}
	if !s.mayAlter(a) {
		t.Fatal("the collector source may change its own asset")
	}
	s.allow(a.ID())
	if s.mayReopen(a.ID()) {
		t.Fatal("a collector source reopened a finding a person resolved")
	}
	plain := newAlterScope(Binding{})
	if plain.mayAlter(a) {
		t.Fatal("an unsolicited report may change an existing asset")
	}
}

func TestReportLostAssets(t *testing.T) {
	ok := &ingestreport.Report{SegmentsReceived: 2, Outcomes: map[int]ingestreport.SegmentOutcome{0: {AcceptedAssets: 3}, 1: {AcceptedAssets: 1}}}
	if reportLostAssets(ok) {
		t.Fatal("a clean report lost assets")
	}
	for name, rep := range map[string]*ingestreport.Report{
		"rejected":        {SegmentsReceived: 1, Outcomes: map[int]ingestreport.SegmentOutcome{0: {RejectedAssets: 1}}},
		"quarantined":     {SegmentsReceived: 1, Outcomes: map[int]ingestreport.SegmentOutcome{0: {QuarantinedAssets: 1}}},
		"missing outcome": {SegmentsReceived: 2, Outcomes: map[int]ingestreport.SegmentOutcome{0: {}}},
		"nil":             nil,
	} {
		if !reportLostAssets(rep) {
			t.Errorf("%s: not counted as lost", name)
		}
	}
}

func relTestAssetForScope(t *testing.T) *asset.Asset {
	t.Helper()
	a, err := asset.NewAsset("vm01.example.com", asset.AssetTypeHost, asset.CriticalityLow)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

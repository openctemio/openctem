package ingest

import (
	"testing"
	"time"

	"github.com/openctemio/ctis"

	protov2 "github.com/openctemio/openctem/api/pkg/sensorproto/v2"
)

func TestV2Options(t *testing.T) {
	o := V2Options()
	if !o.RequireAssetForFindings || !o.NoCatalogWrites || !o.DeferAutoResolve || !o.DeferSensorStats {
		t.Fatalf("v2 options %+v", o)
	}
	if (Options{}) != (Options{RequireAssetForFindings: false}) {
		t.Fatal("zero options must be v1")
	}
}

func TestSensorDeclaresTool(t *testing.T) {
	cases := []struct {
		tools []string
		tool  string
		want  bool
	}{
		{[]string{"semgrep", "trivy"}, "semgrep", true},
		{[]string{"Semgrep"}, " semgrep ", true},
		{[]string{"trivy"}, "semgrep", false},
		{nil, "semgrep", false}, // no allow-all for a sensor that declared nothing
		{[]string{}, "semgrep", false},
		{[]string{"semgrep"}, "", false},
		{[]string{"pentest"}, "pentest", false}, // reserved for non-sensor sources
		{[]string{"defectdojo"}, "DefectDojo", false},
	}
	for _, c := range cases {
		if got := SensorDeclaresTool(c.tools, c.tool); got != c.want {
			t.Errorf("%v %q: got %v", c.tools, c.tool, got)
		}
	}
}

func TestBlindingGuard(t *testing.T) {
	g := DefaultBlindingGuard()
	cases := []struct {
		stale, open int
		hold        bool
	}{
		{100, 150, false}, // not more than 100
		{101, 150, true},  // > 100 and > 50 %
		{101, 300, false}, // > 100 but not > 50 %
		{150, 300, false}, // exactly 50 % is not more
		{151, 300, true},
		{0, 0, false},
	}
	for _, c := range cases {
		if got := g.Holds(c.stale, c.open); got != c.hold {
			t.Errorf("stale %d open %d: got %v", c.stale, c.open, got)
		}
	}
}

func TestResolveV2Assets(t *testing.T) {
	r := &ctis.Report{
		Assets: []ctis.Asset{{ID: "a"}, {}, {ID: "_server_asset_1"}},
		Findings: []ctis.Finding{
			{AssetRef: "a"},
			{AssetRef: "missing"},
			{},                            // no ref, three assets: ambiguous
			{AssetRef: "_server_asset_1"}, // the sensor's own id, not the generated one
		},
	}
	kept, keptIdx, _, errs := resolveV2Assets(r)
	if len(kept) != 2 || keptIdx[0] != 0 || keptIdx[1] != 3 {
		t.Fatalf("kept %v idx %v", kept, keptIdx)
	}
	if r.Assets[1].ID == "" || r.Assets[1].ID == "_server_asset_1" {
		t.Fatalf("generated id collides: %q", r.Assets[1].ID)
	}
	if len(errs) != 2 || errs[0].Pointer != "/findings/1/asset_ref" || errs[1].Detail != protov2.DetailAssetAmbiguous {
		t.Fatalf("errs %+v", errs)
	}

	single := &ctis.Report{Assets: []ctis.Asset{{ID: "only"}}, Findings: []ctis.Finding{{}}}
	kept, _, _, errs = resolveV2Assets(single)
	if len(kept) != 1 || kept[0].AssetRef != "only" || len(errs) != 0 {
		t.Fatalf("single asset binding: %v %v", kept, errs)
	}

	none := &ctis.Report{Findings: []ctis.Finding{{}, {AssetRef: "x"}}}
	kept, _, _, errs = resolveV2Assets(none)
	if len(kept) != 0 || len(errs) != 2 {
		t.Fatalf("no assets: %v %v", kept, errs)
	}
}

func TestV2HeaderOf(t *testing.T) {
	r := &ctis.Report{
		Metadata: ctis.ReportMetadata{ID: "x", Timestamp: time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)},
		Tool:     &ctis.Tool{Name: "semgrep"},
		Findings: []ctis.Finding{{Title: "a"}},
	}
	_, d1, err := V2HeaderOf(r)
	if err != nil {
		t.Fatal(err)
	}
	// metadata.id and the findings are not part of the header.
	r.Metadata.ID = ""
	r.Findings = nil
	_, d2, _ := V2HeaderOf(r)
	if d1 != d2 {
		t.Fatal("header digest depends on metadata.id or findings")
	}
	r.Tool.Name = "trivy"
	if _, d3, _ := V2HeaderOf(r); d3 == d1 {
		t.Fatal("header digest ignores the tool")
	}
}

package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/stage"
)

// GET /scans/stages serves the whole catalog with JSON arrays (never
// null) and the tier labels.
func TestListStages_ServesTheCatalog(t *testing.T) {
	rec := httptest.NewRecorder()
	(&ScanHandler{}).ListStages(rec, httptest.NewRequest(http.MethodGet, "/api/v1/scans/stages", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
	var raw struct {
		Stages []map[string]any `json:"stages"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &raw); err != nil {
		t.Fatal(err)
	}
	if len(raw.Stages) != len(stage.Taxonomy()) {
		t.Fatalf("%d stages, want %d", len(raw.Stages), len(stage.Taxonomy()))
	}
	for _, s := range raw.Stages {
		for _, k := range []string{"inputs", "outputs", "relations", "implementations", "in_ports", "out_ports", "params", "required_output_fields"} {
			if _, ok := s[k].([]any); !ok {
				t.Errorf("%v: %s is not an array", s["key"], k)
			}
		}
	}
	var resp ScanStageListResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.MaxHops != stage.MaxHops {
		t.Errorf("max_hops = %d", resp.MaxHops)
	}
	byKey := map[string]ScanStageResponse{}
	for _, s := range resp.Stages {
		byKey[s.Key] = s
	}
	if byKey["resolve.dns"].Tier != "T0" || byKey["scan.ports"].Tier != "T1" {
		t.Errorf("tiers: dns %s ports %s", byKey["resolve.dns"].Tier, byKey["scan.ports"].Tier)
	}
}

// The contract the workflow editor wires with: typed ports, the port type
// set, adapters, params with per-tool mappings, and planned capabilities
// marked unavailable.
func TestListStages_ServesContracts(t *testing.T) {
	rec := httptest.NewRecorder()
	(&ScanHandler{}).ListStages(rec, httptest.NewRequest(http.MethodGet, "/api/v1/scans/stages", nil))
	var resp ScanStageListResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if len(resp.PortTypes) != 11 || len(resp.Adapters) == 0 {
		t.Fatalf("port types %d adapters %d", len(resp.PortTypes), len(resp.Adapters))
	}
	byKey := map[string]ScanStageResponse{}
	for _, s := range resp.Stages {
		byKey[s.Key] = s
	}
	ports := byKey["scan.ports"]
	if ports.ID != "scan.ports@1" || !ports.Available || len(ports.InPorts) == 0 || ports.OutPorts[0] != "service" {
		t.Fatalf("scan.ports contract: %+v", ports)
	}
	naabu := ports.Implementations[0]
	if naabu.Tool != "naabu" || !naabu.Batch || naabu.Params["top_n"] != "top_ports" {
		t.Fatalf("naabu implementation: %+v", naabu)
	}
	if tls, ok := byKey["check.tls"]; !ok || tls.Available || len(tls.Implementations) != 0 {
		t.Fatalf("planned check.tls: %+v", tls)
	}
	if v := byKey["verify.finding"]; !v.CrossCutting {
		t.Fatal("verify.finding must be cross-cutting")
	}
	for _, a := range resp.Adapters {
		if _, ok := byKey[a.Capability]; !ok {
			t.Fatalf("adapter names unknown capability %s", a.Capability)
		}
	}
}

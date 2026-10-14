package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/stage/stagetest"

	"github.com/openctemio/openctem/api/pkg/domain/stage"
)

// GET /scans/stages serves the whole catalog with JSON arrays (never
// null) and the tier labels.
func TestListStages_ServesTheCatalog(t *testing.T) {
	rec := httptest.NewRecorder()
	(&ScanHandler{stages: builtinStages}).ListStages(rec, stagesRequest(shared.NewID()))
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
	(&ScanHandler{stages: builtinStages}).ListStages(rec, stagesRequest(shared.NewID()))
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

// builtinStages hands every organization the built-in tools' catalog.
var builtinStages = stagetest.Source{Cat: stagetest.Catalog()}

// stagesRequest is GET /scans/stages by a member of tenant.
func stagesRequest(tenant shared.ID) *http.Request {
	req := httptest.NewRequest(http.MethodGet, "/api/v1/scans/stages", nil)
	return req.WithContext(context.WithValue(req.Context(), middleware.TenantIDKey, tenant.String()))
}

// perTenantStages is a catalog source with one catalog per organization.
type perTenantStages map[shared.ID]stage.Catalog

func (p perTenantStages) Catalog(_ context.Context, tenantID shared.ID) (stage.Catalog, error) {
	return p[tenantID], nil
}

// SECURITY: the implementations are the caller's organization's (from the
// authenticated tenant, never the request): a tool only tenant A's sensor
// reports is offered to A and never to B; without a tenant the request is
// refused.
func TestListStages_ImplementationsAreTheCallersOrganizations(t *testing.T) {
	a, b := shared.NewID(), shared.NewID()
	toyweb := stage.ToolFacts{Name: "toyweb", Implements: []stage.Key{stage.DASTWeb},
		Params: map[stage.Key]map[string]string{stage.DASTWeb: {"max_duration_minutes": "max_minutes"}}}
	h := &ScanHandler{stages: perTenantStages{a: stagetest.Catalog(toyweb), b: stagetest.Catalog()}}
	dast := func(tenant shared.ID) ScanStageResponse {
		rec := httptest.NewRecorder()
		h.ListStages(rec, stagesRequest(tenant))
		var resp ScanStageListResponse
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatal(err)
		}
		for _, s := range resp.Stages {
			if s.Key == "dast.web" {
				return s
			}
		}
		t.Fatal("no dast.web")
		return ScanStageResponse{}
	}
	if got := dast(a); !got.Available || len(got.Implementations) != 1 || got.Implementations[0].Tool != "toyweb" ||
		got.Implementations[0].Params["max_duration_minutes"] != "max_minutes" {
		t.Fatalf("tenant A dast.web: %+v", got)
	}
	if got := dast(b); got.Available || len(got.Implementations) != 0 {
		t.Fatalf("tenant B sees tenant A's tool: %+v", got)
	}
	rec := httptest.NewRecorder()
	h.ListStages(rec, httptest.NewRequest(http.MethodGet, "/api/v1/scans/stages?tenant_id="+a.String(), nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("no tenant in the principal: status %d", rec.Code)
	}
}

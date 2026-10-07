package ingest

import (
	"strings"
	"testing"

	"github.com/openctemio/ctis"

	"github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/stage"
)

func countType(r *ctis.Report, t ctis.AssetType) int {
	n := 0
	for _, a := range r.Assets {
		if a.Type == t {
			n++
		}
	}
	return n
}

func TestPlanEndpoints_FoldsDiscoveredURLsIntoEndpointsUnderOneOrigin(t *testing.T) {
	s := &Service{}
	in := &ctis.Report{
		Assets: []ctis.Asset{
			{ID: "u1", Type: ctis.AssetTypeDiscoveredURL, Value: "https://shop.example.com/orders/42?token=SECRET-TOKEN&sig=abc",
				Properties: map[string]any{"method": "GET", "status_code": float64(200)}},
			{ID: "u2", Type: ctis.AssetTypeDiscoveredURL, Value: "https://shop.example.com/orders/43"},
			{ID: "d", Type: ctis.AssetTypeDomain, Value: "shop.example.com"},
		},
		Findings: []ctis.Finding{{Title: "x", AssetRef: "u1"}},
	}
	out := &Output{}
	r, plan := s.planEndpoints(in, TrustedBinding(), out)

	if countType(r, ctis.AssetTypeDiscoveredURL) != 0 {
		t.Fatal("a discovered_url asset is still created")
	}
	if countType(r, ctis.AssetTypeHTTPService) != 1 || countType(in, ctis.AssetTypeDiscoveredURL) != 2 {
		t.Fatalf("want one origin asset added (and the input report untouched): %+v", r.Assets)
	}
	if out.LegacyURLAssetsFolded != 2 || len(plan.byOrigin) != 1 {
		t.Fatalf("folded %d, origins %d", out.LegacyURLAssetsFolded, len(plan.byOrigin))
	}
	for ref, obs := range plan.byOrigin {
		if len(obs) != 2 || obs[0].PathTemplate != "/orders/{int}" {
			t.Fatalf("observations %+v", obs)
		}
		if r.Findings[0].AssetRef != ref {
			t.Fatalf("finding on the folded URL points at %q, want the origin %q", r.Findings[0].AssetRef, ref)
		}
		names := []string{}
		for _, p := range obs[0].Params {
			names = append(names, p.Name)
		}
		if strings.Join(names, ",") != "sig,token" {
			t.Fatalf("query names = %v", names)
		}
		for _, o := range obs {
			if strings.Contains(o.ExamplePath+o.PathTemplate, "SECRET") {
				t.Fatal("a query value reached an observation")
			}
		}
	}
	if len(r.Endpoints) != 0 {
		t.Fatal("endpoints must reach storage only through the plan")
	}
}

func TestPlanEndpoints_ReusesTheReportOriginAsset(t *testing.T) {
	s := &Service{}
	in := &ctis.Report{
		Assets:    []ctis.Asset{{Type: ctis.AssetTypeHTTPService, Value: "https://API.example.com:443"}},
		Endpoints: []ctis.Endpoint{{Origin: "https://api.example.com", Method: "GET", Path: "/v1/users/7"}},
	}
	r, plan := s.planEndpoints(in, TrustedBinding(), &Output{})
	if countType(r, ctis.AssetTypeHTTPService) != 1 {
		t.Fatalf("origin asset duplicated: %+v", r.Assets)
	}
	ref := r.Assets[0].ID
	if ref == "" || len(plan.byOrigin[ref]) != 1 {
		t.Fatalf("endpoint not planned under the report origin asset %q: %+v", ref, plan.byOrigin)
	}
}

func TestPlanEndpoints_CommandWritesOnlyUnderOriginsItsTargetsCover(t *testing.T) {
	s := &Service{}
	in := &ctis.Report{Endpoints: []ctis.Endpoint{
		{Origin: "https://app.example.com", Method: "GET", Path: "/a"},
		{Origin: "https://victim.other.test", Method: "GET", Path: "/b"},
		{Origin: "https://sub.app.example.com", Method: "GET", Path: "/c"},
	}}
	out := &Output{}
	b := Binding{Kind: BindingCommand, Targets: []string{"https://app.example.com"}, Tool: "katana"}
	r, plan := s.planEndpoints(in, b, out)
	if out.EndpointsRefused != 1 {
		t.Fatalf("refused %d, want the uncovered origin refused", out.EndpointsRefused)
	}
	for _, a := range r.Assets {
		if strings.Contains(a.Value, "victim") {
			t.Fatal("an origin outside the command's targets was added as an asset")
		}
	}
	if len(plan.byOrigin) != 2 {
		t.Fatalf("origins planned = %d, want 2 (the target and its subdomain)", len(plan.byOrigin))
	}

	// A command without targets writes no endpoint at all.
	out = &Output{}
	_, plan = s.planEndpoints(in, Binding{Kind: BindingCommand, Tool: "katana"}, out)
	if len(plan.byOrigin) != 0 || out.EndpointsRefused != 3 {
		t.Fatalf("no-target command planned %d origins, refused %d", len(plan.byOrigin), out.EndpointsRefused)
	}
}

func TestPlanEndpoints_StaticFilesCountedNotStored(t *testing.T) {
	s := &Service{}
	out := &Output{}
	_, plan := s.planEndpoints(&ctis.Report{Endpoints: []ctis.Endpoint{
		{Origin: "https://a.example.com", Path: "/logo.png", Kind: ctis.EndpointKindStatic},
		{Origin: "https://a.example.com", Path: "/", Kind: ctis.EndpointKindPage},
	}}, TrustedBinding(), out)
	if out.EndpointsStatic != 1 {
		t.Fatalf("static = %d", out.EndpointsStatic)
	}
	n := 0
	for _, obs := range plan.byOrigin {
		n += len(obs)
	}
	if n != 1 {
		t.Fatalf("planned %d endpoints, want 1", n)
	}
}

func TestSplitByContract_EndpointsOnlyFromToolsThatReportThem(t *testing.T) {
	report := &ctis.Report{Endpoints: []ctis.Endpoint{{Origin: "https://a.example.com", Path: "/"}}}

	nuclei := outputRules{stages: stage.ForTool("nuclei")}
	if nuclei.endpointsAllowed() {
		t.Fatal("a template scanner may not write the endpoint inventory")
	}
	sp := splitByContract(report, nuclei)
	if !sp.anyHeld() || len(sp.kept.Endpoints) != 0 || len(sp.held.Endpoints) != 1 {
		t.Fatal("endpoints of a tool that does not report them must be held")
	}

	katana := outputRules{stages: stage.ForTool("katana")}
	if !katana.endpointsAllowed() {
		t.Fatal("the crawler reports endpoints")
	}
	if sp := splitByContract(report, katana); sp.anyHeld() {
		t.Fatal("the crawler's endpoints were held")
	}

	// A declared contract narrows: a crawler that does not declare
	// endpoints may not report them.
	declared := outputRules{stages: stage.ForTool("katana"), declared: &sensor.ToolContract{Produces: []string{"asset:http_service"}}}
	if declared.endpointsAllowed() {
		t.Fatal("an undeclared endpoint output was allowed")
	}
	declared.declared.Produces = append(declared.declared.Produces, sensor.ProduceEndpoint)
	if !declared.endpointsAllowed() {
		t.Fatal("a declared endpoint output was refused")
	}
}

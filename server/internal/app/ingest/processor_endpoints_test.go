package ingest

import (
	"strings"
	"testing"

	"github.com/openctemio/ctis/v2"

	"github.com/openctemio/openctem/server/pkg/domain/command"
	"github.com/openctemio/openctem/server/pkg/domain/sensor"
	"github.com/openctemio/openctem/server/pkg/domain/stage"
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

// Endpoints of one origin are planned under one origin asset the plan adds
// when the report has none; the input report is not touched. (The folding of
// discovered_url assets is gone with the asset type: producers send endpoints.)
func TestPlanEndpoints_EndpointsUnderOneOrigin(t *testing.T) {
	s := &Service{}
	in := &ctis.Report{
		Assets: []ctis.Asset{{ID: "d", Type: ctis.AssetTypeDomainName, Value: "shop.example.com"}},
		Endpoints: []ctis.Endpoint{
			{Origin: "https://shop.example.com", Method: "GET", Path: "/orders/42"},
			{Origin: "https://shop.example.com", Method: "GET", Path: "/orders/43"},
		},
		Findings: []ctis.Finding{{Title: "x", AssetRef: "d"}},
	}
	r, plan := s.planEndpoints(in, TrustedBinding(), &Output{})

	if countType(r, ctis.AssetTypeWebOrigin) != 1 || countType(in, ctis.AssetTypeWebOrigin) != 0 {
		t.Fatalf("want one origin asset added (and the input report untouched): %+v", r.Assets)
	}
	if len(plan.byOrigin) != 1 {
		t.Fatalf("origins %d", len(plan.byOrigin))
	}
	for _, obs := range plan.byOrigin {
		if len(obs) != 2 || obs[0].PathTemplate != "/orders/{int}" {
			t.Fatalf("observations %+v", obs)
		}
	}
	if len(r.Endpoints) != 0 {
		t.Fatal("endpoints must reach storage only through the plan")
	}
}

func TestPlanEndpoints_ReusesTheReportOriginAsset(t *testing.T) {
	s := &Service{}
	in := &ctis.Report{
		Assets:    []ctis.Asset{{Type: ctis.AssetTypeWebOrigin, Value: "https://API.example.com:443"}},
		Endpoints: []ctis.Endpoint{{Origin: "https://api.example.com", Method: "GET", Path: "/v1/users/7"}},
	}
	r, plan := s.planEndpoints(in, TrustedBinding(), &Output{})
	if countType(r, ctis.AssetTypeWebOrigin) != 1 {
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
	declared := outputRules{stages: stage.ForTool("katana"), declared: &sensor.ToolContract{Produces: []string{"asset:web_origin"}}}
	if declared.endpointsAllowed() {
		t.Fatal("an undeclared endpoint output was allowed")
	}
	declared.declared.Produces = append(declared.declared.Produces, sensor.ProduceEndpoint)
	if !declared.endpointsAllowed() {
		t.Fatal("a declared endpoint output was refused")
	}
}

// The source of a report's endpoints comes from the bound command's
// capability: a path discovery job's endpoints are guess and are refused
// without evidence; a crawl job claiming guess is stored as crawl.
func TestPlanEndpoints_SourceFromTheBoundCapability(t *testing.T) {
	s := &Service{}
	ev := ctis.Extensions{}
	ev.Set("io.openctem", "response", map[string]any{"size": float64(512), "hash": "00ff00ff00ff00ff"})
	in := &ctis.Report{Endpoints: []ctis.Endpoint{
		{Origin: "https://app.example.com", Method: "GET", Path: "/backup.zip", Source: "probe", Extensions: ev},
		{Origin: "https://app.example.com", Method: "GET", Path: "/db.sql", Source: "probe"},
	}}
	cmd := &command.Command{Type: command.CommandTypeScan,
		Payload: []byte(`{"capability":"enumerate.web_paths@1","targets":["https://app.example.com"]}`)}
	b := CommandBinding(cmd)
	if b.Capability != "enumerate.web_paths@1" {
		t.Fatalf("binding capability %q", b.Capability)
	}
	out := &Output{}
	_, plan := s.planEndpoints(in, b, out)
	if out.EndpointsRefused != 1 || out.EndpointsNoEvidence != 1 {
		t.Fatalf("refused %d (no evidence %d), want the endpoint without evidence refused", out.EndpointsRefused, out.EndpointsNoEvidence)
	}
	var got []string
	for _, obs := range plan.byOrigin {
		for _, o := range obs {
			got = append(got, o.PathTemplate+"="+strings.Join(o.Sources, ","))
			if o.Evidence == nil || o.Evidence.Size != 512 {
				t.Fatalf("evidence not kept: %+v", o.Evidence)
			}
		}
	}
	if len(got) != 1 || got[0] != "/backup.zip=guess" {
		t.Fatalf("planned %v, want [/backup.zip=guess]", got)
	}

	// A crawl job's report claiming guess, with evidence, is a crawl.
	in.Endpoints[1].Source = "guess"
	in.Endpoints[1].Extensions = ev
	crawl := Binding{Kind: BindingCommand, Targets: []string{"https://app.example.com"}, Tool: "katana", Capability: "crawl.web@1"}
	out = &Output{}
	_, plan = s.planEndpoints(in, crawl, out)
	for _, obs := range plan.byOrigin {
		for _, o := range obs {
			if strings.Join(o.Sources, ",") == "guess" || o.Evidence != nil {
				t.Fatalf("a crawl produced %v with evidence %v", o.Sources, o.Evidence)
			}
		}
	}
	if out.EndpointsRefused != 0 {
		t.Fatalf("crawl endpoints refused: %d", out.EndpointsRefused)
	}
}

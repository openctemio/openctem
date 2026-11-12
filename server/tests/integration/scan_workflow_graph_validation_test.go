package integration

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/openctemio/openctem/api/internal/app/scanrun"

	"github.com/go-chi/chi/v5"

	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/stage"
)

// A scan workflow save validates the graph against the capability contracts.
//
// Before: a save checked each step's key and tool only. "subfinder → katana"
// (hostnames into a URL crawler) was stored, and the run silently fed katana
// the scan's seeds instead of subfinder's output; a cycle or a dependency on
// a missing step was stored too.

func TestPipelineSave_RefusesAnIncompatibleEdge(t *testing.T) {
	p := newScanWorkflowSaveHarness(t, "pipeline-graph-refuse")
	id, steps := p.create()

	rec := p.do(p.tenant, http.MethodPut, id, map[string]any{
		"steps": []map[string]any{
			{"id": steps["discover"].ID, "step_key": "discover", "name": "Discover", "tool": "subfinder"},
			{"step_key": "crawl", "name": "Crawl", "tool": "katana", "depends_on": []string{"discover"}},
		},
	}, p.h.UpdateTemplate)
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("subfinder → katana: %d %s, want 422", rec.Code, rec.Body.String())
	}
	var body struct {
		Details stage.GraphReport `json:"details"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if len(body.Details.Errors) != 1 {
		t.Fatalf("issues: %+v", body.Details.Errors)
	}
	e := body.Details.Errors[0]
	if e.Code != stage.IssueIncompatible || e.From != "discover" || e.To != "crawl" || e.Adapter != stage.ProbeHTTP {
		t.Fatalf("issue: %+v", e)
	}
	// Nothing changed.
	if n := p.count(`SELECT count(*) FROM scan_workflow_steps WHERE scan_workflow_id=$1 AND step_key='crawl'`, id); n != 0 {
		t.Fatal("a refused save stored a step")
	}

	// A cycle and a missing dependency are refused too.
	for name, body := range map[string][]map[string]any{
		"cycle": {
			{"step_key": "a", "name": "A", "tool": "httpx", "depends_on": []string{"b"}},
			{"step_key": "b", "name": "B", "tool": "katana", "depends_on": []string{"a"}},
		},
		"missing dependency": {
			{"step_key": "a", "name": "A", "tool": "httpx", "depends_on": []string{"ghost"}},
		},
	} {
		rec := p.do(p.tenant, http.MethodPut, id, map[string]any{"steps": body}, p.h.UpdateTemplate)
		if rec.Code != http.StatusUnprocessableEntity {
			t.Errorf("%s: %d %s, want 422", name, rec.Code, rec.Body.String())
		}
	}
}

func TestPipelineValidate_ReportsWithoutSaving(t *testing.T) {
	p := newScanWorkflowSaveHarness(t, "pipeline-graph-validate")
	rec := p.do(p.tenant, http.MethodPost, "", map[string]any{
		"steps": []map[string]any{
			{"step_key": "subs", "name": "Subs", "tool": "subfinder"},
			{"step_key": "crawl", "name": "Crawl", "tool": "katana", "depends_on": []string{"subs"}},
			{"step_key": "custom", "name": "Custom", "tool": "my-scanner", "capabilities": []string{"scan"}, "depends_on": []string{"subs"}},
		},
	}, p.h.ValidateScanWorkflow)
	if rec.Code != http.StatusOK {
		t.Fatalf("validate: %d %s", rec.Code, rec.Body.String())
	}
	var out struct {
		Valid    bool               `json:"valid"`
		Errors   []stage.GraphIssue `json:"errors"`
		Warnings []stage.GraphIssue `json:"warnings"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out.Valid || len(out.Errors) != 1 || out.Errors[0].Adapter != stage.ProbeHTTP {
		t.Fatalf("errors: %+v", out.Errors)
	}
	if len(out.Warnings) != 1 || out.Warnings[0].Code != stage.IssueOpaqueEdge || out.Warnings[0].To != "custom" {
		t.Fatalf("warnings: %+v", out.Warnings)
	}
	if n := p.count(`SELECT count(*) FROM scan_workflows WHERE tenant_id=$1`, p.tenant.String()); n != 0 {
		t.Fatal("validate stored a pipeline")
	}
}

// Deleting a step others depend on drops the dependency instead of leaving
// a dangling edge the graph check would refuse.
func TestPipelineDeleteStep_DropsDependencies(t *testing.T) {
	p := newScanWorkflowSaveHarness(t, "pipeline-graph-delete")
	id, steps := p.create()
	rec := p.do(p.tenant, http.MethodDelete, id, nil, func(w http.ResponseWriter, r *http.Request) {
		r = withURLParam(r, "stepId", steps["discover"].ID)
		p.h.DeleteStep(w, r)
	})
	if rec.Code != http.StatusNoContent {
		t.Fatalf("delete: %d %s", rec.Code, rec.Body.String())
	}
	if n := p.count(`SELECT count(*) FROM scan_workflow_steps WHERE scan_workflow_id=$1 AND step_key='probe' AND depends_on = '{}'`, id); n != 1 {
		t.Fatal("probe still depends on the deleted step")
	}
}

// Every seeded system template still validates: the graph check refuses
// nothing that was valid before.
func TestSystemTemplates_PassTheGraphCheck(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()
	pg := &postgres.DB{DB: db}
	templates := postgres.NewScanWorkflowRepository(pg)
	rows, err := db.Query(`SELECT id, name FROM scan_workflows WHERE is_system_template`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	n := 0
	for rows.Next() {
		var idStr, name string
		if err := rows.Scan(&idStr, &name); err != nil {
			t.Fatal(err)
		}
		id, _ := shared.IDFromString(idStr)
		tpl, err := templates.GetWithSteps(context.Background(), id)
		if err != nil {
			t.Fatal(err)
		}
		rep := stage.ValidateGraph(scanrun.StepsGraph(tpl.Steps))
		if !rep.Valid() {
			t.Errorf("system template %q fails the graph check: %+v", name, rep.Errors)
		}
		n++
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if n == 0 {
		t.Fatal("no system templates seeded")
	}
}

// withURLParam adds a chi URL param to a request built by the harness.
func withURLParam(r *http.Request, key, value string) *http.Request {
	chi.RouteContext(r.Context()).URLParams.Add(key, value)
	return r
}

// A capability step picks its tool by auto, prefer or pin, and its settings
// follow the capability contract.
func TestPipelineSave_ToolSelectionAndSettings(t *testing.T) {
	p := newScanWorkflowSaveHarness(t, "pipeline-tool-selection")
	id, _ := p.create()

	ok := p.do(p.tenant, http.MethodPut, id, map[string]any{
		"steps": []map[string]any{
			{"step_key": "secrets", "name": "Secrets", "capabilities": []string{"secrets.code"}, "prefer_tools": []string{"gitleaks", "betterleaks"}},
			{"step_key": "ports", "name": "Ports", "capabilities": []string{"scan.ports"}, "config": map[string]any{"top_n": 100, "rate": 500}},
		},
	}, p.h.UpdateTemplate)
	if ok.Code != http.StatusOK {
		t.Fatalf("save: %d %s", ok.Code, ok.Body.String())
	}
	var out struct {
		Steps []struct {
			StepKey       string   `json:"step_key"`
			PreferTools   []string `json:"prefer_tools"`
			ToolSelection string   `json:"tool_selection"`
		} `json:"steps"`
	}
	if err := json.Unmarshal(ok.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	modes := map[string]string{}
	for _, s := range out.Steps {
		modes[s.StepKey] = s.ToolSelection
	}
	if modes["secrets"] != "prefer" || modes["ports"] != "auto" {
		t.Fatalf("selection modes: %v", modes)
	}

	for name, steps := range map[string][]map[string]any{
		"prefer a tool that does not implement the capability": {
			{"step_key": "s", "name": "S", "capabilities": []string{"secrets.code"}, "prefer_tools": []string{"nuclei"}},
		},
		"pin and prefer": {
			{"step_key": "s", "name": "S", "tool": "gitleaks", "capabilities": []string{"secrets.code"}, "prefer_tools": []string{"betterleaks"}},
		},
		"out of contract value": {
			{"step_key": "p", "name": "P", "capabilities": []string{"scan.ports"}, "config": map[string]any{"rate": 10000000}},
		},
		"tool setting without a pin": {
			{"step_key": "p", "name": "P", "capabilities": []string{"scan.ports"}, "config": map[string]any{"exclude_cdn": true}},
		},
	} {
		rec := p.do(p.tenant, http.MethodPut, id, map[string]any{"steps": steps}, p.h.UpdateTemplate)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("%s: %d %s, want 400", name, rec.Code, rec.Body.String())
		}
	}
}

// A draft whose steps have problems is still checked whole: 200 with every
// issue anchored to its step, never a 400 at the first problem (the builder
// checks the draft while the user edits it).
func TestPipelineValidate_StepProblemsAreIssuesNotErrors(t *testing.T) {
	p := newScanWorkflowSaveHarness(t, "pipeline-graph-issues")
	rec := p.do(p.tenant, http.MethodPost, "", map[string]any{
		"steps": []map[string]any{
			{"step_key": "ports", "name": "Ports", "capabilities": []string{"scan.ports"}, "config": map[string]any{"top_n": "lots"}},
			{"step_key": "both", "name": "Both", "tool": "naabu", "prefer_tools": []string{"naabu"}, "capabilities": []string{"scan.ports"}},
			{"step_key": "http", "name": "HTTP", "capabilities": []string{"probe.http"}, "depends_on": []string{"ports"}},
		},
	}, p.h.ValidateScanWorkflow)
	if rec.Code != http.StatusOK {
		t.Fatalf("validate: %d %s, want 200", rec.Code, rec.Body.String())
	}
	var out struct {
		Valid  bool               `json:"valid"`
		Errors []stage.GraphIssue `json:"errors"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	nodes := map[string]bool{}
	for _, e := range out.Errors {
		nodes[e.Node] = true
		if e.Message == "" {
			t.Errorf("issue without a message: %+v", e)
		}
	}
	if out.Valid || !nodes["ports"] || !nodes["both"] || nodes["http"] {
		t.Fatalf("issues: %+v", out.Errors)
	}
	if n := p.count(`SELECT count(*) FROM scan_workflows WHERE tenant_id=$1`, p.tenant.String()); n != 0 {
		t.Fatal("validate stored a workflow")
	}
}

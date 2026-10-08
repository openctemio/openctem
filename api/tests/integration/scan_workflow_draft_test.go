package integration

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/openctemio/openctem/api/internal/app/scanrun"
	"github.com/openctemio/openctem/api/internal/infra/http/handler"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/validator"
)

// draftValidator refuses the tool gowitness ("not installed"), as the real
// validator does for a tool the organization does not have.
type draftValidator struct{ acceptingStepValidator }

func (draftValidator) ValidateStepConfig(_ context.Context, _ shared.ID, tool string, _ []string, _ map[string]any) *scanrun.ValidationResult {
	if tool == "gowitness" {
		return &scanrun.ValidationResult{Errors: []scanrun.ValidationError{{
			Field: "tool", Code: "INVALID_TOOL", Message: `tool "gowitness" is not installed in this organization`,
		}}}
	}
	return &scanrun.ValidationResult{Valid: true}
}

func newDraftHarness(t *testing.T, name string) *scanWorkflowSaveHarness {
	p := newScanWorkflowSaveHarness(t, name)
	pg := &postgres.DB{DB: p.db}
	svc := scanrun.NewService(
		postgres.NewScanWorkflowRepository(pg),
		postgres.NewScanWorkflowStepRepository(pg),
		postgres.NewScanRunRepository(pg),
		postgres.NewStepRunRepository(pg),
		nil,
		postgres.NewCommandRepository(pg),
		draftValidator{},
		logger.New(logger.Config{Level: "error"}),
		scanrun.WithDraftStore(postgres.NewScanWorkflowRepository(pg)),
	)
	p.h = handler.NewScanWorkflowHandler(svc, validator.New(), logger.NewNop())
	return p
}

type draftOut struct {
	Steps []struct {
		StepKey    string `json:"step_key"`
		Tool       string `json:"tool"`
		UIPosition *struct {
			X float64 `json:"x"`
			Y float64 `json:"y"`
		} `json:"ui_position"`
	} `json:"steps"`
	UIStartPosition *struct {
		X float64 `json:"x"`
	} `json:"ui_start_position"`
	Issues struct {
		Valid  bool `json:"valid"`
		Errors []struct {
			Code string `json:"code"`
			Node string `json:"node"`
			Fix  string `json:"fix"`
		} `json:"errors"`
	} `json:"issues"`
}

// The owner's case: rearranging "Full Reconnaissance" (which pinned a tool
// the organization lacks) and saving lost the layout because the save was
// refused. A draft saves whatever its state, with its issues; publishing
// refuses it until the blocking issue is fixed; the fixed draft publishes.
func TestScanWorkflowDraft_SaveAlwaysPublishWhenClean(t *testing.T) {
	p := newDraftHarness(t, "wf-draft")
	id, steps := p.create()

	broken := map[string]any{
		"steps": []map[string]any{
			{"id": steps["discover"].ID, "step_key": "discover", "name": "Discover", "tool": "subfinder", "ui_position": map[string]any{"x": -307.42, "y": 88.6}},
			{"id": steps["probe"].ID, "step_key": "probe", "name": "Probe", "tool": "httpx", "depends_on": []string{"discover"}},
			{"step_key": "shots", "name": "Screenshots", "tool": "gowitness", "capabilities": []string{"scan"}, "depends_on": []string{"probe"}},
		},
		"ui_start_position": map[string]any{"x": 12.5, "y": 40},
	}
	rec := p.do(p.tenant, http.MethodPut, id, broken, withID(p.h.SaveDraft))
	if rec.Code != http.StatusOK {
		t.Fatalf("save draft with a blocking issue: %d %s, want 200", rec.Code, rec.Body.String())
	}
	var saved draftOut
	if err := json.Unmarshal(rec.Body.Bytes(), &saved); err != nil {
		t.Fatal(err)
	}
	if saved.Issues.Valid || len(saved.Issues.Errors) == 0 || saved.Issues.Errors[0].Node != "shots" || saved.Issues.Errors[0].Fix == "" {
		t.Fatalf("draft issues: %+v", saved.Issues)
	}
	// The published steps are untouched; the layout round-trips in the draft.
	if n := p.count(`SELECT count(*) FROM scan_workflow_steps WHERE scan_workflow_id=$1`, id); n != 2 {
		t.Fatalf("published steps after a draft save: %d, want 2", n)
	}
	rec = p.do(p.tenant, http.MethodGet, id, nil, withID(p.h.GetDraft))
	var got draftOut
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil || rec.Code != http.StatusOK {
		t.Fatalf("get draft: %d %s", rec.Code, rec.Body.String())
	}
	if len(got.Steps) != 3 || got.Steps[0].UIPosition == nil || got.Steps[0].UIPosition.X != -307.42 || got.UIStartPosition == nil || got.UIStartPosition.X != 12.5 {
		t.Fatalf("draft layout did not round-trip: %s", rec.Body.String())
	}

	// Publish is refused while the draft has a blocking issue; the draft stays.
	rec = p.do(p.tenant, http.MethodPost, id, nil, withID(p.h.PublishDraft))
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("publish a broken draft: %d %s, want 422", rec.Code, rec.Body.String())
	}
	if n := p.count(`SELECT count(*) FROM scan_workflows WHERE id=$1 AND draft IS NOT NULL`, id); n != 1 {
		t.Fatal("a refused publish dropped the draft")
	}

	// The user picks Any tool for the screenshot step: here, removes it.
	fixed := map[string]any{
		"steps": []map[string]any{
			{"id": steps["discover"].ID, "step_key": "discover", "name": "Discover", "tool": "subfinder", "ui_position": map[string]any{"x": -307.42, "y": 88.6}},
			{"id": steps["probe"].ID, "step_key": "probe", "name": "Probe", "tool": "httpx", "depends_on": []string{"discover"}},
		},
		"ui_start_position": map[string]any{"x": 12.5, "y": 40},
	}
	if rec = p.do(p.tenant, http.MethodPut, id, fixed, withID(p.h.SaveDraft)); rec.Code != http.StatusOK {
		t.Fatalf("save fixed draft: %d %s", rec.Code, rec.Body.String())
	}
	rec = p.do(p.tenant, http.MethodPost, id, nil, withID(p.h.PublishDraft))
	if rec.Code != http.StatusOK {
		t.Fatalf("publish: %d %s", rec.Code, rec.Body.String())
	}
	var pub struct {
		Version int `json:"version"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &pub)
	if pub.Version != 2 {
		t.Fatalf("version after publish: %d, want 2", pub.Version)
	}
	// Steps kept their ids (run history), the position is stored rounded,
	// and the draft is gone.
	if n := p.count(`SELECT count(*) FROM scan_workflow_steps WHERE scan_workflow_id=$1 AND id=$2 AND ui_position_x=-307`, id, steps["discover"].ID); n != 1 {
		t.Fatal("published step lost its id or position")
	}
	if rec = p.do(p.tenant, http.MethodGet, id, nil, withID(p.h.GetDraft)); rec.Code != http.StatusNotFound {
		t.Fatalf("draft after publish: %d, want 404", rec.Code)
	}
	if rec = p.do(p.tenant, http.MethodPost, id, nil, withID(p.h.PublishDraft)); rec.Code != http.StatusConflict {
		t.Fatalf("publish without a draft: %d, want 409", rec.Code)
	}
}

// Another tenant can neither read, write, publish nor discard the draft.
func TestScanWorkflowDraft_OtherTenantGets404(t *testing.T) {
	p := newDraftHarness(t, "wf-draft-iso")
	id, _ := p.create()
	body := map[string]any{"steps": []map[string]any{{"step_key": "a", "name": "A", "tool": "subfinder"}}}
	if rec := p.do(p.tenant, http.MethodPut, id, body, withID(p.h.SaveDraft)); rec.Code != http.StatusOK {
		t.Fatalf("own save: %d %s", rec.Code, rec.Body.String())
	}
	other := createTestTenant(t, p.db, "wf-draft-other")
	t.Cleanup(func() { _, _ = p.db.Exec(`DELETE FROM tenants WHERE id=$1`, other.String()) })
	for name, fn := range map[string]func(http.ResponseWriter, *http.Request){
		"get": p.h.GetDraft, "save": p.h.SaveDraft, "publish": p.h.PublishDraft, "discard": p.h.DiscardDraft,
	} {
		method := map[string]string{"get": http.MethodGet, "save": http.MethodPut, "publish": http.MethodPost, "discard": http.MethodDelete}[name]
		if rec := p.do(other, method, id, body, withID(fn)); rec.Code != http.StatusNotFound {
			t.Errorf("%s by another tenant: %d %s, want 404", name, rec.Code, rec.Body.String())
		}
	}
	if n := p.count(`SELECT count(*) FROM scan_workflows WHERE id=$1 AND draft IS NOT NULL`, id); n != 1 {
		t.Fatal("another tenant changed the draft")
	}
	// A system template has no draft and takes none.
	if rec := p.do(p.tenant, http.MethodPut, "a0000002-0000-0000-0000-000000000001", body, withID(p.h.SaveDraft)); rec.Code == http.StatusOK {
		t.Fatalf("draft saved on a system template: %d", rec.Code)
	}
}

// withID is the handler itself: the harness puts {id} in the route context.
func withID(fn func(http.ResponseWriter, *http.Request)) func(http.ResponseWriter, *http.Request) {
	return fn
}

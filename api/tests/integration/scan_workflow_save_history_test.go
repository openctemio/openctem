package integration

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/openctemio/openctem/api/internal/app/scanrun"
	scanrundom "github.com/openctemio/openctem/api/pkg/domain/scanrun"
	"github.com/openctemio/openctem/api/pkg/domain/scanworkflow"

	"github.com/go-chi/chi/v5"

	"github.com/openctemio/openctem/api/internal/infra/http/handler"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/validator"
)

// Saving a scan workflow from the builder (PUT with every step) keeps the run
// history of the scan workflow, end to end through the handler.
//
// Before: the save deleted every step and added them again; step runs
// cascaded with their step and chaining inputs with their step run, so one
// save erased the step history of every past and running run.

type scanWorkflowSaveHarness struct {
	t      *testing.T
	db     *sql.DB
	h      *handler.ScanWorkflowHandler
	tenant shared.ID
}

func newScanWorkflowSaveHarness(t *testing.T, name string) *scanWorkflowSaveHarness {
	t.Helper()
	db := setupTestDB(t)
	t.Cleanup(func() { db.Close() })
	tenant := createTestTenant(t, db, name)
	t.Cleanup(func() {
		_, _ = db.Exec(`DELETE FROM scan_runs WHERE tenant_id=$1`, tenant.String())
		_, _ = db.Exec(`DELETE FROM scan_workflow_steps WHERE scan_workflow_id IN (SELECT id FROM scan_workflows WHERE tenant_id=$1)`, tenant.String())
		_, _ = db.Exec(`DELETE FROM scan_workflows WHERE tenant_id=$1`, tenant.String())
		_, _ = db.Exec(`DELETE FROM assets WHERE tenant_id=$1`, tenant.String())
		_, _ = db.Exec(`DELETE FROM tenants WHERE id=$1`, tenant.String())
	})
	pg := &postgres.DB{DB: db}
	svc := scanrun.NewService(
		postgres.NewScanWorkflowRepository(pg),
		postgres.NewScanWorkflowStepRepository(pg),
		postgres.NewScanRunRepository(pg),
		postgres.NewStepRunRepository(pg),
		nil,
		postgres.NewCommandRepository(pg),
		acceptingStepValidator{},
		logger.New(logger.Config{Level: "error"}),
	)
	return &scanWorkflowSaveHarness{t: t, db: db, h: handler.NewScanWorkflowHandler(svc, validator.New(), logger.NewNop()), tenant: tenant}
}

func (p *scanWorkflowSaveHarness) do(tenant shared.ID, method, id string, body any, fn func(http.ResponseWriter, *http.Request)) *httptest.ResponseRecorder {
	p.t.Helper()
	var buf bytes.Buffer
	_ = json.NewEncoder(&buf).Encode(body)
	req := httptest.NewRequest(method, "/api/v1/scan-workflows/"+id, &buf)
	rctx := chi.NewRouteContext()
	if id != "" {
		rctx.URLParams.Add("id", id)
	}
	ctx := context.WithValue(req.Context(), chi.RouteCtxKey, rctx)
	ctx = context.WithValue(ctx, middleware.TenantIDKey, tenant.String())
	rec := httptest.NewRecorder()
	fn(rec, req.WithContext(ctx))
	return rec
}

type savedStep struct {
	ID      string `json:"id"`
	StepKey string `json:"step_key"`
	Tool    string `json:"tool"`
}

func (p *scanWorkflowSaveHarness) create() (string, map[string]savedStep) {
	p.t.Helper()
	rec := p.do(p.tenant, http.MethodPost, "", map[string]any{
		"name": "save-history",
		"steps": []map[string]any{
			{"step_key": "discover", "name": "Discover", "tool": "subfinder"},
			{"step_key": "probe", "name": "Probe", "tool": "httpx", "depends_on": []string{"discover"}},
		},
	}, p.h.CreateTemplate)
	if rec.Code != http.StatusCreated {
		p.t.Fatalf("create: %d %s", rec.Code, rec.Body.String())
	}
	var out struct {
		ID    string      `json:"id"`
		Steps []savedStep `json:"steps"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		p.t.Fatal(err)
	}
	byKey := map[string]savedStep{}
	for _, s := range out.Steps {
		byKey[s.StepKey] = s
	}
	return out.ID, byKey
}

// seedRun records a run of the scan workflow with one step run per step and a
// chaining input on each.
func (p *scanWorkflowSaveHarness) seedRun(templateID string, steps map[string]savedStep, finished bool) shared.ID {
	p.t.Helper()
	ctx := context.Background()
	pg := &postgres.DB{DB: p.db}
	tid, _ := shared.IDFromString(templateID)
	run, err := scanrundom.NewRun(tid, p.tenant, nil, scanworkflow.TriggerTypeManual, "", map[string]any{})
	if err != nil {
		p.t.Fatal(err)
	}
	run.Start()
	runs := postgres.NewScanRunRepository(pg)
	if err := runs.Create(ctx, run); err != nil {
		p.t.Fatal(err)
	}
	asset := shared.NewID()
	if _, err := p.db.Exec(`INSERT INTO assets (id, tenant_id, name, asset_type) VALUES ($1, $2, $3, 'domain')`,
		asset.String(), p.tenant.String(), "history-"+asset.String()[:8]+".example.com"); err != nil {
		p.t.Fatalf("seed asset: %v", err)
	}
	stepRuns := postgres.NewStepRunRepository(pg)
	for key, s := range steps {
		sid, _ := shared.IDFromString(s.ID)
		sr := scanrundom.NewStepRunForStep(run.ID, &scanworkflow.Step{ID: sid, StepKey: key, Name: key, Tool: s.Tool})
		if err := stepRuns.Create(ctx, sr); err != nil {
			p.t.Fatal(err)
		}
		if _, err := p.db.Exec(`INSERT INTO scan_step_outputs (tenant_id, run_id, scan_run_step_id, asset_id) VALUES ($1, $2, $3, $4)`,
			p.tenant.String(), run.ID.String(), sr.ID.String(), asset.String()); err != nil {
			p.t.Fatal(err)
		}
	}
	if finished {
		if err := runs.UpdateStatus(ctx, run.ID, scanrundom.RunStatusCompleted, ""); err != nil {
			p.t.Fatal(err)
		}
	}
	return run.ID
}

func (p *scanWorkflowSaveHarness) count(q string, args ...any) int {
	p.t.Helper()
	var n int
	if err := p.db.QueryRow(q, args...).Scan(&n); err != nil {
		p.t.Fatalf("%s: %v", q, err)
	}
	return n
}

func TestPipelineSave_KeepsRunHistory(t *testing.T) {
	p := newScanWorkflowSaveHarness(t, "pipeline-save-history")
	id, steps := p.create()
	runID := p.seedRun(id, steps, true)

	// The builder's save: discover edited (by id), probe removed, a new step
	// with a client-side temporary id.
	rec := p.do(p.tenant, http.MethodPut, id, map[string]any{
		"steps": []map[string]any{
			{"id": steps["discover"].ID, "step_key": "discover", "name": "Discover v2", "tool": "subfinder"},
			{"id": "temp-AbC123xyz", "step_key": "vuln", "name": "Vuln", "tool": "nuclei", "depends_on": []string{"discover"}},
		},
	}, p.h.UpdateTemplate)
	if rec.Code != http.StatusOK {
		t.Fatalf("save: %d %s", rec.Code, rec.Body.String())
	}

	if n := p.count(`SELECT count(*) FROM scan_workflow_steps WHERE id=$1 AND name='Discover v2'`, steps["discover"].ID); n != 1 {
		t.Fatal("the edited step did not keep its id")
	}
	if n := p.count(`SELECT count(*) FROM scan_run_steps WHERE scan_run_id=$1`, runID.String()); n != 2 {
		t.Fatalf("step runs after save: %d, want 2", n)
	}
	if n := p.count(`SELECT count(*) FROM scan_run_steps WHERE scan_run_id=$1 AND step_id IS NULL AND step_key='probe' AND tool='httpx'`, runID.String()); n != 1 {
		t.Fatal("the removed step's run lost its history")
	}
	if n := p.count(`SELECT count(*) FROM scan_step_outputs WHERE run_id=$1`, runID.String()); n != 2 {
		t.Fatalf("chaining inputs after save: %d, want 2", n)
	}
	if n := p.count(`SELECT count(*) FROM scan_workflow_steps WHERE id::text = 'temp-AbC123xyz'`); n != 0 {
		t.Fatal("a client id was stored")
	}
}

func TestPipelineSave_RefusedWhileARunIsActive(t *testing.T) {
	p := newScanWorkflowSaveHarness(t, "pipeline-save-active")
	id, steps := p.create()
	runID := p.seedRun(id, steps, false)

	rec := p.do(p.tenant, http.MethodPut, id, map[string]any{
		"name":  "renamed while running",
		"steps": []map[string]any{{"step_key": "other", "name": "Other", "tool": "nuclei"}},
	}, p.h.UpdateTemplate)
	if rec.Code != http.StatusConflict || !bytes.Contains(rec.Body.Bytes(), []byte("PIPELINE_RUN_ACTIVE")) {
		t.Fatalf("save during a run: %d %s, want 409 PIPELINE_RUN_ACTIVE", rec.Code, rec.Body.String())
	}
	if n := p.count(`SELECT count(*) FROM scan_run_steps WHERE scan_run_id=$1 AND step_id IS NOT NULL`, runID.String()); n != 2 {
		t.Fatalf("running run's step runs: %d attached, want 2", n)
	}
	if n := p.count(`SELECT count(*) FROM scan_workflows WHERE id=$1 AND name='save-history'`, id); n != 1 {
		t.Fatal("a refused save renamed the pipeline")
	}
}

func TestPipelineSave_OtherTenantGets404(t *testing.T) {
	p := newScanWorkflowSaveHarness(t, "pipeline-save-xtenant")
	id, steps := p.create()
	other := createTestTenant(t, p.db, "pipeline-save-xtenant-other")
	t.Cleanup(func() { _, _ = p.db.Exec(`DELETE FROM tenants WHERE id=$1`, other.String()) })

	rec := p.do(other, http.MethodPut, id, map[string]any{
		"steps": []map[string]any{{"id": steps["discover"].ID, "step_key": "x", "name": "x", "tool": "nuclei"}},
	}, p.h.UpdateTemplate)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("other tenant's save: %d %s, want 404", rec.Code, rec.Body.String())
	}
	if n := p.count(`SELECT count(*) FROM scan_workflow_steps WHERE scan_workflow_id=$1`, id); n != 2 {
		t.Fatalf("other tenant changed the steps: %d", n)
	}
}

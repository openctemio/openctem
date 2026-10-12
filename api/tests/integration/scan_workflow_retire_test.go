package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/openctemio/openctem/api/internal/app/scanrun"
	"github.com/openctemio/openctem/api/internal/infra/http/handler"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/scanworkflow"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/validator"
)

// Deleting a scan workflow that has runs retires it (research/62 SW4): the
// delete answers 204, the runs stay, the workflow is still readable by id
// with retired_at (the run page draws its graph from it), it cannot be
// changed or run, and another tenant can do none of this.
func TestScanWorkflowDelete_RetiresAndKeepsRuns(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	tenant := createTestTenant(t, db, "workflow-retire")
	other := createTestTenant(t, db, "workflow-retire-other")
	t.Cleanup(func() {
		for _, id := range []shared.ID{tenant, other} {
			_, _ = db.Exec(`DELETE FROM tenants WHERE id=$1`, id.String())
		}
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
	h := handler.NewScanWorkflowHandler(svc, validator.New(), logger.NewNop())
	call := func(fn http.HandlerFunc, method, target string, as shared.ID, body any, id string) *httptest.ResponseRecorder {
		var buf bytes.Buffer
		if body != nil {
			_ = json.NewEncoder(&buf).Encode(body)
		}
		req := httptest.NewRequest(method, target, &buf)
		rctx := chi.NewRouteContext()
		if id != "" {
			rctx.URLParams.Add("id", id)
		}
		ctx := context.WithValue(req.Context(), chi.RouteCtxKey, rctx)
		ctx = context.WithValue(ctx, middleware.TenantIDKey, as.String())
		w := httptest.NewRecorder()
		fn(w, req.WithContext(ctx))
		return w
	}

	w := call(h.CreateTemplate, http.MethodPost, "/api/v1/scan-workflows/", tenant, map[string]any{
		"name":  "retire-me",
		"steps": []map[string]any{{"step_key": "s1", "name": "nuclei", "tool": "nuclei", "capabilities": []string{"dast"}}},
	}, "")
	if w.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", w.Code, w.Body.String())
	}
	var created struct {
		ID string `json:"id"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &created)
	run := shared.NewID().String()
	if _, err := db.Exec(`INSERT INTO scan_runs (id, tenant_id, scan_workflow_id, trigger_type, status) VALUES ($1, $2, $3, 'manual', 'completed')`,
		run, tenant.String(), created.ID); err != nil {
		t.Fatal(err)
	}

	// Another tenant: not found, nothing changes.
	if w := call(h.DeleteTemplate, http.MethodDelete, "/", other, nil, created.ID); w.Code != http.StatusNotFound {
		t.Fatalf("delete from another tenant: %d %s", w.Code, w.Body.String())
	}

	if w := call(h.DeleteTemplate, http.MethodDelete, "/", tenant, nil, created.ID); w.Code != http.StatusNoContent {
		t.Fatalf("delete: %d %s", w.Code, w.Body.String())
	}
	var runs int
	if err := db.QueryRow(`SELECT count(*) FROM scan_runs WHERE id = $1`, run).Scan(&runs); err != nil || runs != 1 {
		t.Fatalf("the run is gone after delete (%d, %v)", runs, err)
	}

	w = call(h.GetTemplate, http.MethodGet, "/", tenant, nil, created.ID)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"retired_at"`) {
		t.Fatalf("get retired workflow: %d %s", w.Code, w.Body.String())
	}

	w = call(h.UpdateTemplate, http.MethodPut, "/", tenant, map[string]any{"name": "back"}, created.ID)
	if w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), "WORKFLOW_RETIRED") {
		t.Fatalf("update retired workflow: %d %s", w.Code, w.Body.String())
	}

	_, err := svc.TriggerPipeline(context.Background(), scanrun.TriggerRunInput{TenantID: tenant.String(), TemplateID: created.ID, TriggerType: "manual"})
	if !errors.Is(err, scanworkflow.ErrScanWorkflowRetired) {
		t.Fatalf("trigger retired workflow: %v, want ErrScanWorkflowRetired", err)
	}
}

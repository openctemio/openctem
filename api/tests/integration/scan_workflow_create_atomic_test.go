package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/openctemio/openctem/api/internal/app/scanrun"

	"github.com/openctemio/openctem/api/internal/infra/http/handler"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/validator"
)

// rejectingStepValidator accepts identifiers but rejects every step config,
// the way the real validator rejects a capability the tool does not support.
type rejectingStepValidator struct{}

func (rejectingStepValidator) ValidateIdentifier(string, int, string) *scanrun.ValidationResult {
	return &scanrun.ValidationResult{Valid: true}
}

func (rejectingStepValidator) ValidateIdentifiers([]string, int, string) *scanrun.ValidationResult {
	return &scanrun.ValidationResult{Valid: true}
}

func (rejectingStepValidator) ValidateStepConfig(context.Context, shared.ID, string, []string, map[string]any) *scanrun.ValidationResult {
	return &scanrun.ValidationResult{Errors: []scanrun.ValidationError{{
		Field: "capabilities", Message: "capability 'vulnerability' is not supported by tool 'nuclei'", Code: "CAPABILITY_TOOL_MISMATCH",
	}}}
}

func (rejectingStepValidator) ValidateCommandPayload(context.Context, shared.ID, map[string]any) *scanrun.ValidationResult {
	return &scanrun.ValidationResult{Valid: true}
}

// POST /api/v1/scan-workflows created the template, then added its steps one by
// one. A step that failed validation returned 400 — but the template was
// already committed, with no steps, so the client saw an error, the template
// list showed an empty scan workflow, and retrying the same request hit 409
// "Scan workflow already exists".
func TestCreatePipelineWithInvalidStepPersistsNothing(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	tenant := createTestTenant(t, db, "pipeline-atomic")
	t.Cleanup(func() {
		_, _ = db.Exec(`DELETE FROM scan_workflows WHERE tenant_id=$1`, tenant.String())
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
		rejectingStepValidator{},
		logger.New(logger.Config{Level: "error"}),
	)
	h := handler.NewScanWorkflowHandler(svc, validator.New(), logger.NewNop())

	create := func() *httptest.ResponseRecorder {
		body, _ := json.Marshal(map[string]any{
			"name": "atomic-create",
			"steps": []map[string]any{{
				"step_key": "s1", "name": "nuclei", "tool": "nuclei", "capabilities": []string{"vulnerability"},
			}},
		})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/scan-workflows/", bytes.NewReader(body))
		ctx := context.WithValue(req.Context(), middleware.TenantIDKey, tenant.String())
		rec := httptest.NewRecorder()
		h.CreateTemplate(rec, req.WithContext(ctx))
		return rec
	}

	if rec := create(); rec.Code != http.StatusBadRequest {
		t.Fatalf("invalid step: want 400, got %d: %s", rec.Code, rec.Body.String())
	}
	var n int
	if err := db.QueryRow(`SELECT count(*) FROM scan_workflows WHERE tenant_id=$1`, tenant.String()).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("a rejected create left %d pipeline template(s) behind", n)
	}
	// The same request must fail the same way, not as a duplicate.
	if rec := create(); rec.Code != http.StatusBadRequest {
		t.Fatalf("retry: want 400 again, got %d: %s", rec.Code, rec.Body.String())
	}
}

// acceptingStepValidator accepts everything, so a step can only fail at insert.
type acceptingStepValidator struct{ rejectingStepValidator }

func (acceptingStepValidator) ValidateStepConfig(context.Context, shared.ID, string, []string, map[string]any) *scanrun.ValidationResult {
	return &scanrun.ValidationResult{Valid: true}
}

// A step that passes validation but fails to insert (two steps sharing a
// step_key) must not leave the template behind either.
func TestCreatePipelineWithDuplicateStepKeyPersistsNothing(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	tenant := createTestTenant(t, db, "pipeline-atomic-dup")
	t.Cleanup(func() {
		_, _ = db.Exec(`DELETE FROM scan_workflow_steps WHERE scan_workflow_id IN (SELECT id FROM scan_workflows WHERE tenant_id=$1)`, tenant.String())
		_, _ = db.Exec(`DELETE FROM scan_workflows WHERE tenant_id=$1`, tenant.String())
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
	h := handler.NewScanWorkflowHandler(svc, validator.New(), logger.NewNop())

	step := map[string]any{"step_key": "s1", "name": "nuclei", "tool": "nuclei", "capabilities": []string{"dast"}}
	body, _ := json.Marshal(map[string]any{"name": "atomic-dup", "steps": []map[string]any{step, step}})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/scan-workflows/", bytes.NewReader(body))
	ctx := context.WithValue(req.Context(), middleware.TenantIDKey, tenant.String())
	rec := httptest.NewRecorder()
	h.CreateTemplate(rec, req.WithContext(ctx))

	if rec.Code < 400 || rec.Code >= 500 {
		t.Fatalf("duplicate step_key: want a 4xx, got %d: %s", rec.Code, rec.Body.String())
	}
	var n int
	if err := db.QueryRow(`SELECT count(*) FROM scan_workflows WHERE tenant_id=$1`, tenant.String()).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("a rejected create left %d pipeline template(s) behind", n)
	}
}

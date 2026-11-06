package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/openctemio/openctem/api/internal/app/scanrun"

	"github.com/go-chi/chi/v5"

	"github.com/openctemio/openctem/api/internal/infra/http/handler"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/audit"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/validator"
)

type recordedAudit struct {
	action audit.Action
	actor  string
}

type recordingAuditService struct {
	mu     sync.Mutex
	events []recordedAudit
}

func (r *recordingAuditService) LogEvent(_ context.Context, actx scanrun.AuditContext, ev scanrun.AuditEvent) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, recordedAudit{action: ev.Action, actor: actx.ActorID})
	return nil
}

// A scan workflow decides which tools a sensor runs against the tenant's
// network, yet adding, changing or deleting its steps, and updating or
// deleting the template, wrote audit entries with no actor: the service
// methods take none and the handler passed the bare request context. Found in
// the scan-scan workflow e2e run, where every pipeline_step.created row had an
// empty actor_id. The handler now carries the caller to every entry.
func TestPipelineHandler_AuditEntriesNameTheCaller(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	tenant := createTestTenant(t, db, "pipeline-audit-actor")
	t.Cleanup(func() {
		_, _ = db.Exec(`DELETE FROM scan_workflow_steps WHERE scan_workflow_id IN (SELECT id FROM scan_workflows WHERE tenant_id=$1)`, tenant.String())
		_, _ = db.Exec(`DELETE FROM scan_workflows WHERE tenant_id=$1`, tenant.String())
		_, _ = db.Exec(`DELETE FROM tenants WHERE id=$1`, tenant.String())
	})

	rec := &recordingAuditService{}
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
		scanrun.WithAuditService(rec),
	)
	h := handler.NewScanWorkflowHandler(svc, validator.New(), logger.NewNop())
	userID := shared.NewID().String()
	if _, err := db.Exec(`INSERT INTO users (id, email, name) VALUES ($1, $2, 'pipeline audit')`, userID, "pipe-"+userID+"@example.test"); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	t.Cleanup(func() { _, _ = db.Exec(`DELETE FROM users WHERE id=$1`, userID) })

	request := func(method, target string, body any, params map[string]string) *http.Request {
		var buf bytes.Buffer
		if body != nil {
			_ = json.NewEncoder(&buf).Encode(body)
		}
		req := httptest.NewRequest(method, target, &buf)
		rctx := chi.NewRouteContext()
		for k, v := range params {
			rctx.URLParams.Add(k, v)
		}
		ctx := context.WithValue(req.Context(), chi.RouteCtxKey, rctx)
		ctx = context.WithValue(ctx, middleware.TenantIDKey, tenant.String())
		ctx = context.WithValue(ctx, middleware.UserIDKey, userID)
		return req.WithContext(ctx)
	}

	w := httptest.NewRecorder()
	h.CreateTemplate(w, request(http.MethodPost, "/api/v1/scan-workflows/", map[string]any{
		"name":  "audit-actor",
		"steps": []map[string]any{{"step_key": "s1", "name": "nuclei", "tool": "nuclei", "capabilities": []string{"dast"}}},
	}, nil))
	if w.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", w.Code, w.Body.String())
	}
	var created struct {
		ID string `json:"id"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &created)

	w = httptest.NewRecorder()
	h.DeleteTemplate(w, request(http.MethodDelete, "/api/v1/scan-workflows/"+created.ID, nil, map[string]string{"id": created.ID}))
	if w.Code >= 300 {
		t.Fatalf("delete: %d %s", w.Code, w.Body.String())
	}

	seen := map[audit.Action]bool{}
	for _, ev := range rec.events {
		seen[ev.action] = true
		if ev.actor != userID {
			t.Errorf("%s: actor %q, want the caller %q", ev.action, ev.actor, userID)
		}
	}
	for _, want := range []audit.Action{audit.ActionScanWorkflowCreated, audit.ActionScanWorkflowStepCreated, audit.ActionScanWorkflowDeleted} {
		if !seen[want] {
			t.Errorf("no %s audit entry (got %v)", want, rec.events)
		}
	}
}

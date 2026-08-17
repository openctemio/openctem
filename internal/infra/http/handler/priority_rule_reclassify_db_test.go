package handler

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"testing"

	"github.com/go-chi/chi/v5"
	_ "github.com/lib/pq"
	"github.com/openctemio/api/internal/infra/controller"
	"github.com/openctemio/api/internal/infra/http/middleware"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/logger"
)

// captureReclassifyQueue records enqueued reclassify requests.
type captureReclassifyQueue struct {
	mu   sync.Mutex
	reqs []controller.ReclassifyRequest
}

func (c *captureReclassifyQueue) Enqueue(_ context.Context, r controller.ReclassifyRequest) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.reqs = append(c.reqs, r)
	return nil
}

func (c *captureReclassifyQueue) DequeueBatch(_ context.Context, _ int) ([]controller.ReclassifyRequest, error) {
	return nil, nil
}

func (c *captureReclassifyQueue) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.reqs)
}

// TestPriorityRuleHandler_MutationsEnqueueReclassify proves rule create / update
// / delete each drive a whole-tenant reclassify sweep (fake enqueuer), so a rule
// change reflects in priority promptly instead of lagging up to 12h.
//
// DB-gated: needs DATABASE_URL pointing at app_test (never the live DB).
func TestPriorityRuleHandler_MutationsEnqueueReclassify(t *testing.T) {
	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		t.Skip("DATABASE_URL not set; skipping DB-backed test")
	}
	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer func() { _ = db.Close() }()
	if err := db.Ping(); err != nil {
		t.Skipf("cannot reach test DB: %v", err)
	}
	ctx := context.Background()

	// Seed a tenant + user to satisfy FK / uuid columns.
	tenantID := shared.NewID()
	userID := shared.NewID()
	if _, err := db.ExecContext(ctx,
		`INSERT INTO tenants (id, name, slug) VALUES ($1, $2, $3)`,
		tenantID.String(), "reclassify-test", "reclassify-test-"+tenantID.String()[:8]); err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	t.Cleanup(func() {
		_, _ = db.ExecContext(ctx, `DELETE FROM priority_override_rules WHERE tenant_id = $1`, tenantID.String())
		_, _ = db.ExecContext(ctx, `DELETE FROM tenants WHERE id = $1`, tenantID.String())
	})

	queue := &captureReclassifyQueue{}
	h := NewPriorityRuleHandler(db, logger.NewNop())
	h.SetChangePublisher(controller.NewControlChangePublisher(queue, nil))

	withCtx := func(r *http.Request) *http.Request {
		c := context.WithValue(r.Context(), middleware.TenantIDKey, tenantID.String())
		c = context.WithValue(c, middleware.UserIDKey, userID.String())
		return r.WithContext(c)
	}

	// --- Create ---
	body, _ := json.Marshal(map[string]any{
		"name": "esc P0", "priority_class": "P0", "conditions": json.RawMessage("[]"),
	})
	rec := httptest.NewRecorder()
	h.Create(rec, withCtx(httptest.NewRequest(http.MethodPost, "/priority-rules", bytes.NewReader(body))))
	if rec.Code != http.StatusCreated {
		t.Fatalf("Create status = %d, body=%s", rec.Code, rec.Body.String())
	}
	var created struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil || created.ID == "" {
		t.Fatalf("decode create response: %v (%s)", err, rec.Body.String())
	}
	if queue.count() != 1 {
		t.Fatalf("Create should enqueue 1 reclassify, got %d", queue.count())
	}

	// --- Update ---
	upBody, _ := json.Marshal(map[string]any{"priority_class": "P1"})
	rec = httptest.NewRecorder()
	req := withCtx(httptest.NewRequest(http.MethodPut, "/priority-rules/"+created.ID, bytes.NewReader(upBody)))
	req = withURLParam(req, "id", created.ID)
	h.Update(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("Update status = %d, body=%s", rec.Code, rec.Body.String())
	}
	if queue.count() != 2 {
		t.Fatalf("Update should enqueue a reclassify (total 2), got %d", queue.count())
	}

	// --- Delete ---
	rec = httptest.NewRecorder()
	req = withCtx(httptest.NewRequest(http.MethodDelete, "/priority-rules/"+created.ID, nil))
	req = withURLParam(req, "id", created.ID)
	h.Delete(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("Delete status = %d, body=%s", rec.Code, rec.Body.String())
	}
	if queue.count() != 3 {
		t.Fatalf("Delete should enqueue a reclassify (total 3), got %d", queue.count())
	}

	// Every enqueued request must be a whole-tenant, rule-changed sweep.
	queue.mu.Lock()
	defer queue.mu.Unlock()
	for i, r := range queue.reqs {
		if r.TenantID != tenantID {
			t.Fatalf("req %d: tenant = %s, want %s", i, r.TenantID, tenantID)
		}
		if r.Reason != controller.ReasonRuleChanged {
			t.Fatalf("req %d: reason = %s, want %s", i, r.Reason, controller.ReasonRuleChanged)
		}
		if len(r.AssetIDs) != 0 {
			t.Fatalf("req %d: expected whole-tenant sweep (no AssetIDs), got %d", i, len(r.AssetIDs))
		}
	}
}

// withURLParam injects a chi URL param into the request's route context.
func withURLParam(r *http.Request, key, val string) *http.Request {
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add(key, val)
	return r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, rctx))
}

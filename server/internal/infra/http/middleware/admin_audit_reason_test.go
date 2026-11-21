package middleware_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/openctemio/openctem/server/internal/infra/http/middleware"
	"github.com/openctemio/openctem/server/pkg/domain/admin"
	"github.com/openctemio/openctem/server/pkg/logger"
)

// auditPatch sends body through the admin-update audit middleware to h and
// returns the row.
func auditPatch(t *testing.T, body string, h http.HandlerFunc) *admin.AuditLog {
	t.Helper()
	repo := newFakeAuditRepo()
	am := middleware.NewAuditMiddleware(repo, logger.NewNop())
	r := chi.NewRouter()
	r.With(am.AuditAdminUpdate()).Patch("/admin/users/{id}", h)
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPatch, "/admin/users/x", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(httptest.NewRecorder(), req)
	return waitForAudit(t, repo.created)
}

// The row keeps the reason the handler accepted (trimmed), not the raw field;
// a refused reason is not kept; a handler that checks no reason leaves the
// body as it was.
func TestAuditReason_HandlerDecides(t *testing.T) {
	t.Run("accepted reason is kept trimmed", func(t *testing.T) {
		log := auditPatch(t, `{"is_active":false,"reason":"  left the team  "}`, func(w http.ResponseWriter, r *http.Request) {
			middleware.SetAuditReason(r.Context(), "left the team")
			w.WriteHeader(http.StatusOK)
		})
		if log.RequestBody["reason"] != "left the team" || log.RequestBody["is_active"] != false {
			t.Fatalf("body = %v", log.RequestBody)
		}
	})
	t.Run("refused reason is dropped", func(t *testing.T) {
		long := strings.Repeat("a", 1001)
		log := auditPatch(t, `{"role":"super_admin","reason":"`+long+`"}`, func(w http.ResponseWriter, r *http.Request) {
			middleware.SetAuditReason(r.Context(), "")
			w.WriteHeader(http.StatusBadRequest)
		})
		if _, ok := log.RequestBody["reason"]; ok || log.RequestBody["role"] != "super_admin" || log.ResponseStatus != http.StatusBadRequest {
			t.Fatalf("row = %d %v", log.ResponseStatus, log.RequestBody)
		}
	})
	t.Run("no body, a reason set by the handler", func(t *testing.T) {
		log := auditPatch(t, ``, func(w http.ResponseWriter, r *http.Request) {
			middleware.SetAuditReason(r.Context(), "drill")
			w.WriteHeader(http.StatusOK)
		})
		if log.RequestBody["reason"] != "drill" {
			t.Fatalf("body = %v", log.RequestBody)
		}
	})
	t.Run("handler without a reason check keeps the body", func(t *testing.T) {
		log := auditPatch(t, `{"reason":" raw "}`, func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		})
		if log.RequestBody["reason"] != " raw " {
			t.Fatalf("body = %v", log.RequestBody)
		}
	})
}

// Outside an audited request SetAuditReason does nothing (no panic).
func TestSetAuditReason_NoAuditContext(t *testing.T) {
	middleware.SetAuditReason(context.Background(), "x")
}

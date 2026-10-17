package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// A handler without a data-scope enforcer must fail closed: only owners and
// administrators read the organization audit log, never everyone.
func TestAuditHandler_NoEnforcerFailsClosed(t *testing.T) {
	tenantID := shared.NewID().String()
	for _, tc := range []struct {
		name  string
		admin bool
		want  int
	}{
		{"member without enforcer", false, http.StatusForbidden},
		{"admin without enforcer", true, http.StatusOK},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := NewAuditHandler(audit.NewAuditService(&pagingAuditRepo{}, logger.NewNop()), nil, logger.NewNop())
			req := httptest.NewRequest(http.MethodGet, "/api/v1/audit-logs", nil)
			ctx := context.WithValue(req.Context(), middleware.TenantIDKey, tenantID)
			ctx = context.WithValue(ctx, middleware.IsAdminKey, tc.admin)
			rec := httptest.NewRecorder()
			h.List(rec, req.WithContext(ctx))
			if rec.Code != tc.want {
				t.Fatalf("status = %d, want %d (%s)", rec.Code, tc.want, rec.Body.String())
			}
		})
	}
}

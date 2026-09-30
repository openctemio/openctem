package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/openctemio/api/internal/infra/http/middleware"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/logger"
	"github.com/openctemio/api/pkg/validator"
)

// Organization-level decisions that belong to the platform administrator
// (RFC-022) must be refused by the tenant-facing handlers before any service
// call, so these tests need no service.

func TestTenantCreateRefusedInAdminOnlyMode(t *testing.T) {
	h := NewTenantHandler(nil, validator.New(), logger.NewNop())
	h.SetAdminOnlyTenantCreation(true)
	rec := httptest.NewRecorder()
	h.Create(rec, httptest.NewRequest(http.MethodPost, "/api/v1/tenants", strings.NewReader(`{"name":"X","slug":"x-org"}`)))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status %d, want 403", rec.Code)
	}
}

func TestTenantSecurityPatchRefusesSSOEnforced(t *testing.T) {
	h := NewTenantHandler(nil, validator.New(), logger.NewNop())
	req := httptest.NewRequest(http.MethodPatch, "/api/v1/tenants/acme/settings/security",
		strings.NewReader(`{"sso_enforced":false}`))
	req = req.WithContext(context.WithValue(req.Context(), middleware.TeamIDKey, shared.NewID()))
	rec := httptest.NewRecorder()
	h.UpdateSecuritySettings(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status %d, want 403", rec.Code)
	}
}

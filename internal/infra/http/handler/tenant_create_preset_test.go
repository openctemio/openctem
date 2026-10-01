package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/openctemio/api/internal/infra/http/middleware"
	userdom "github.com/openctemio/api/pkg/domain/user"
	"github.com/openctemio/api/pkg/logger"
	"github.com/openctemio/api/pkg/validator"
)

// Creating an organization with an unknown module preset succeeded and the
// preset was ignored. It is refused before anything is created (the zero
// handler has no service: reaching it would panic).
func TestTenantCreate_UnknownPresetRefused(t *testing.T) {
	h := &TenantHandler{validator: validator.New(), logger: logger.NewNop()}
	u, err := userdom.NewProvisionedLocalUser("o@acme.test", "Owner")
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/tenants",
		strings.NewReader(`{"name":"Acme","slug":"acme-co","module_preset_id":"no_such_preset"}`))
	req = req.WithContext(context.WithValue(req.Context(), middleware.LocalUserKey, u))
	rec := httptest.NewRecorder()
	h.Create(rec, req)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "no_such_preset") {
		t.Fatalf("got %d %s, want 400 naming the preset", rec.Code, rec.Body.String())
	}
}

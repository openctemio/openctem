package handler

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// A lost claim / already-finished command is a 409, not a 500.
func TestCommandHandler_ConflictMapsTo409(t *testing.T) {
	h := &CommandHandler{logger: logger.NewNop()}
	rec := httptest.NewRecorder()
	h.handleServiceError(rec, shared.NewDomainError("CONFLICT", "command already claimed by another sensor", shared.ErrConflict))
	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "already claimed") {
		t.Errorf("expected the domain message, got %s", rec.Body.String())
	}
}

// A request without a tenant reaching the credential import gets a clean
// 403 instead of a MustGetTenantID panic (recovered as a 500).
func TestCredentialImport_NoTenantIs403NotPanic(t *testing.T) {
	h := &CredentialImportHandler{logger: logger.NewNop()}
	r := httptest.NewRequest(http.MethodPost, "/api/v1/credentials/import", strings.NewReader(`{}`))
	rec := httptest.NewRecorder()

	defer func() {
		if p := recover(); p != nil {
			t.Fatalf("handler panicked: %v", p)
		}
	}()
	h.Import(rec, r)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
}

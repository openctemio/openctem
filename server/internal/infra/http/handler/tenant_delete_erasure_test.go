package handler

import (
	"net/http"
	"net/http/httptest"
	"testing"

	tenantapp "github.com/openctemio/openctem/api/internal/app/tenant"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// An organization deletion refused because its stored files could not be
// erased is a retryable 503, not a 500, and says nothing about the storage.
func TestTenantHandler_DeleteRefusedForStoredFilesIs503(t *testing.T) {
	h := &TenantHandler{logger: logger.NewNop()}
	rec := httptest.NewRecorder()
	h.handleServiceError(rec, tenantapp.ErrStoredFilesNotErased)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503 (body %s)", rec.Code, rec.Body.String())
	}
}

package handler

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/internal/app/platformlegal"
	"github.com/openctemio/openctem/api/pkg/domain/admin"
	"github.com/openctemio/openctem/api/pkg/domain/platformsetting"
	"github.com/openctemio/openctem/api/pkg/logger"
)

func TestAdminLegalHandler(t *testing.T) {
	const path = "/api/v1/admin/settings/legal"
	newH := func(stepErr error) *AdminLegalHandler {
		svc := platformlegal.NewService(&settingMemRepo{rows: map[string]platformsetting.State{}}, nil, logger.NewNop())
		return NewAdminLegalHandler(svc, fakeStepUp{err: stepErr}, logger.NewNop())
	}

	h := newH(nil)
	rec := httptest.NewRecorder()
	h.Update(rec, emailRequest(t, http.MethodPut, path, map[string]any{"terms_url": "https://example.com/t", "version": 0}))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("no code: %d", rec.Code)
	}
	rec = httptest.NewRecorder()
	newH(admin.ErrInvalidMFACode).Update(rec, emailRequest(t, http.MethodPut, path, map[string]any{"terms_url": "https://example.com/t", "totp_code": "1"}))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("bad code: %d", rec.Code)
	}
	rec = httptest.NewRecorder()
	h.Update(rec, emailRequest(t, http.MethodPut, path, map[string]any{"terms_url": "javascript:alert(1)", "totp_code": "123456"}))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("javascript link: %d", rec.Code)
	}
	rec = httptest.NewRecorder()
	h.Update(rec, emailRequest(t, http.MethodPut, path, `{"terms_url":"https://example.com/t","tenant_id":"x","totp_code":"123456"}`))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("unknown field: %d", rec.Code)
	}
	rec = httptest.NewRecorder()
	h.Update(rec, emailRequest(t, http.MethodPut, path, map[string]any{"terms_url": "https://example.com/t", "security_contact": "sec@example.com", "totp_code": "123456"}))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"version":1`) {
		t.Fatalf("save: %d %s", rec.Code, rec.Body.String())
	}

	// The public read serves the values, not the version or who changed it.
	rec = httptest.NewRecorder()
	h.Public(rec, httptest.NewRequest(http.MethodGet, "/api/v1/legal", nil))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"terms_url":"https://example.com/t"`) ||
		strings.Contains(rec.Body.String(), "version") || rec.Header().Get("Cache-Control") == "" {
		t.Fatalf("public: %d %s", rec.Code, rec.Body.String())
	}
}

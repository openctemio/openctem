package handler

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/internal/app/orgdeletion"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// The cancel refuses before any lookup: unwired, a bad body, a missing
// organization id, and no session token.
func TestCancelOrganizationDeletion_Refusals(t *testing.T) {
	serve := func(h *LocalAuthHandler, body string) int {
		rec := httptest.NewRecorder()
		h.CancelOrganizationDeletion(rec, httptest.NewRequest(http.MethodPost, "/api/v1/auth/organization-deletion/cancel", strings.NewReader(body)))
		return rec.Code
	}
	if code := serve(&LocalAuthHandler{logger: logger.NewNop()}, `{}`); code != http.StatusServiceUnavailable {
		t.Fatalf("unwired: %d", code)
	}
	h := &LocalAuthHandler{logger: logger.NewNop(), deletions: &orgdeletion.Service{}}
	for body, want := range map[string]int{
		`not json`:          http.StatusBadRequest,
		`{"tenant_id":"x"}`: http.StatusBadRequest,
		`{"tenant_id":"0190a7a1-6f3e-7c4b-9a2d-1b2c3d4e5f60"}`: http.StatusUnauthorized,
	} {
		if code := serve(h, body); code != want {
			t.Errorf("%s: %d, want %d", body, code, want)
		}
	}
}

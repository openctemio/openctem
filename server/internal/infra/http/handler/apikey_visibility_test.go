package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	apikeydom "github.com/openctemio/openctem/api/pkg/domain/apikey"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// The last-used IP of a key is shown to owners and administrators only.
func TestAPIKeyResponseHidesLastUsedIPFromNonAdmins(t *testing.T) {
	now := time.Now()
	k := apikeydom.Reconstruct(shared.NewID(), shared.NewID(), nil, "k", "", "h", "oct_abcd",
		nil, 10, apikeydom.StatusActive, nil, &now, "203.0.113.7", 1, nil, now, now, nil, nil)

	member := context.WithValue(context.Background(), middleware.IsAdminKey, false)
	if got := toAPIKeyResponse(member, k).LastUsedIP; got != "" {
		t.Errorf("non-admin sees the last-used IP %q", got)
	}
	if got := toAPIKeyResponse(context.Background(), k).LastUsedIP; got != "" {
		t.Errorf("a context without an admin flag sees the last-used IP %q", got)
	}
	admin := context.WithValue(context.Background(), middleware.IsAdminKey, true)
	if got := toAPIKeyResponse(admin, k).LastUsedIP; got != "203.0.113.7" {
		t.Errorf("admin: want the IP, got %q", got)
	}
}

// A service account's key list is refused for anyone who is not an owner or
// administrator, before any lookup happens.
func TestServiceAccountListKeysAdminOnly(t *testing.T) {
	h := &ServiceAccountHandler{}
	for _, admin := range []bool{false} {
		req := httptest.NewRequest(http.MethodGet, "/x/api-keys", nil)
		req = req.WithContext(context.WithValue(req.Context(), middleware.IsAdminKey, admin))
		w := httptest.NewRecorder()
		h.ListKeys(w, req)
		if w.Code != http.StatusForbidden {
			t.Errorf("admin=%v: want 403, got %d", admin, w.Code)
		}
	}
}

package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/domain/admin"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// A second-factor sign-in (security key, recovery code) hands the CSRF token to
// the client in the body, matching the cookie, like the password sign-in.
func TestWriteSignedInReturnsCSRFToken(t *testing.T) {
	h := NewAdminConsoleHandler(nil, false, logger.NewNop())
	a, err := admin.NewAdminUser("a@example.com", "A", admin.AdminRoleOpsAdmin, nil)
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	h.writeSignedIn(rec, "session-token", a)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
	var body ValidateResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	var cookie string
	for _, c := range rec.Result().Cookies() {
		if c.Name == middleware.AdminCSRFCookie && c.Path == "/api/v1/admin" {
			cookie = c.Value
		}
	}
	if body.CSRFToken == "" || body.CSRFToken != cookie {
		t.Fatalf("csrf_token %q must equal the cookie %q", body.CSRFToken, cookie)
	}
}

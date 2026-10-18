package handler

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/internal/app/auth"
	"github.com/openctemio/openctem/api/internal/app/orgdeletion"
	"github.com/openctemio/openctem/api/internal/config"
	"github.com/openctemio/openctem/api/pkg/jwt"
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

// The cancel is authorised by a refresh token, and a refresh token exists
// only after the second factor succeeded: until then the sign-in holds just
// an opaque two-factor challenge token. Presenting that challenge token (or
// an access token) as the refresh token is refused before any lookup, and the
// cancel never reaches the deletion service.
func TestCancelOrganizationDeletion_RequiresCompletedSignIn(t *testing.T) {
	cfg := config.AuthConfig{
		JWTSecret:            strings.Repeat("s", 48),
		JWTIssuer:            "test",
		AccessTokenDuration:  time.Minute,
		RefreshTokenDuration: time.Hour,
	}
	svc := auth.NewAuthService(nil, nil, nil, nil, nil, cfg, logger.NewNop())
	h := &LocalAuthHandler{logger: logger.NewNop(), authService: svc, deletions: &orgdeletion.Service{}}

	access, _, err := jwt.NewGenerator(jwt.TokenConfig{
		Secret: cfg.JWTSecret, Issuer: cfg.JWTIssuer,
		AccessTokenDuration: cfg.AccessTokenDuration, RefreshTokenDuration: cfg.RefreshTokenDuration,
	}).GenerateAccessToken("0190a7a1-6f3e-7c4b-9a2d-1b2c3d4e5f61", "0190a7a1-6f3e-7c4b-9a2d-1b2c3d4e5f62", "owner")
	if err != nil {
		t.Fatal(err)
	}
	for name, token := range map[string]string{
		"two-factor challenge token": "Zm9vYmFyYmF6cXV4MTIzNDU2Nzg5MGFiY2RlZmdoaWo",
		"access token":               access,
	} {
		body := `{"tenant_id":"0190a7a1-6f3e-7c4b-9a2d-1b2c3d4e5f60","refresh_token":"` + token + `"}`
		rec := httptest.NewRecorder()
		h.CancelOrganizationDeletion(rec, httptest.NewRequest(http.MethodPost, "/api/v1/auth/organization-deletion/cancel", strings.NewReader(body)))
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("%s: %d, want 401", name, rec.Code)
		}
	}
}

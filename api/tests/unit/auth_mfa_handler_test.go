package unit

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/internal/app/auth"
	"github.com/openctemio/openctem/api/internal/config"
	"github.com/openctemio/openctem/api/internal/infra/http/handler"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/domain/tenant"
	"github.com/openctemio/openctem/api/pkg/jwt"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/totp"
)

func newMFAHandler(h *mfaHarness) *handler.LocalAuthHandler {
	sess := auth.NewSessionService(h.sessions, newMockAuthRefreshTokenRepo(), logger.NewNop())
	return handler.NewLocalAuthHandler(h.svc, sess, nil, nil, defaultAuthTestConfig(), logger.NewNop())
}

func postJSON(t *testing.T, fn http.HandlerFunc, body any) *httptest.ResponseRecorder {
	t.Helper()
	b, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	fn(rec, req)
	return rec
}

func hasRefreshCookie(rec *httptest.ResponseRecorder) bool {
	for _, c := range rec.Result().Cookies() {
		if strings.Contains(c.Name, "refresh") && c.Value != "" {
			return true
		}
	}
	return false
}

func TestMFAHandler_LoginReturnsChallengeWithoutSessionCookie(t *testing.T) {
	h := newMFAHarness(t)
	uid := h.seedUser(t, "hl@example.com")
	secret, _ := h.enroll(t, uid)
	h.forgetLastStep(uid)
	lh := newMFAHandler(h)

	rec := postJSON(t, lh.Login, map[string]string{"email": "hl@example.com", "password": mfaTestPassword})
	if rec.Code != http.StatusOK {
		t.Fatalf("login status %d: %s", rec.Code, rec.Body.String())
	}
	if hasRefreshCookie(rec) {
		t.Fatal("refresh cookie set before the second factor")
	}
	var ch handler.MFAChallengeResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &ch); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !ch.MFARequired || ch.MFAToken == "" || ch.MFAPurpose != "verify" || ch.ExpiresIn <= 0 {
		t.Fatalf("unexpected challenge response %+v", ch)
	}
	if strings.Contains(rec.Body.String(), "refresh_token") || strings.Contains(rec.Body.String(), "tenants") {
		t.Fatalf("challenge response leaks session data: %s", rec.Body.String())
	}

	// Wrong code → 401, still no cookie.
	bad := postJSON(t, lh.VerifyMFA, map[string]string{"mfa_token": ch.MFAToken, "code": wrongCode(currentCode(t, secret))})
	if bad.Code != http.StatusUnauthorized || hasRefreshCookie(bad) {
		t.Fatalf("wrong code: status %d, cookie=%v", bad.Code, hasRefreshCookie(bad))
	}

	// Right code → normal login response with the session cookie.
	code, _ := totp.Code(secret, time.Now())
	ok := postJSON(t, lh.VerifyMFA, map[string]string{"mfa_token": ch.MFAToken, "code": code})
	if ok.Code != http.StatusOK || !hasRefreshCookie(ok) {
		t.Fatalf("verify: status %d, cookie=%v body=%s", ok.Code, hasRefreshCookie(ok), ok.Body.String())
	}
	var lr handler.LoginResponse
	_ = json.Unmarshal(ok.Body.Bytes(), &lr)
	if lr.User.Email != "hl@example.com" {
		t.Fatalf("verify response user = %+v", lr.User)
	}

	// Missing code → 400.
	if rec := postJSON(t, lh.VerifyMFA, map[string]string{"mfa_token": "x"}); rec.Code != http.StatusBadRequest {
		t.Fatalf("missing code: status %d", rec.Code)
	}
}

func TestMFAHandler_ForcedEnrollmentReturnsRecoveryCodesOnce(t *testing.T) {
	h := newMFAHarness(t)
	tn := newPolicyTenant(t, h.tenants, "forced-tenant", true)
	h.tenants.userMemberships = []tenant.UserMembership{{TenantID: tn.ID().String(), TenantSlug: tn.Slug(), TenantName: "Acme", Role: "member"}}
	h.seedUser(t, "fe@example.com")
	lh := newMFAHandler(h)

	rec := postJSON(t, lh.Login, map[string]string{"email": "fe@example.com", "password": mfaTestPassword})
	var ch handler.MFAChallengeResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &ch)
	if ch.MFAPurpose != "enroll" {
		t.Fatalf("purpose = %q, want enroll", ch.MFAPurpose)
	}
	start := postJSON(t, lh.StartMFAEnrollment, map[string]string{"mfa_token": ch.MFAToken})
	if start.Code != http.StatusOK || start.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("start: %d cache=%q", start.Code, start.Header().Get("Cache-Control"))
	}
	var setup handler.MFASetupResponse
	_ = json.Unmarshal(start.Body.Bytes(), &setup)
	if !strings.HasPrefix(setup.OTPAuthURI, "otpauth://totp/") || setup.Secret == "" {
		t.Fatalf("setup = %+v", setup)
	}
	code, _ := totp.Code(setup.Secret, time.Now())
	done := postJSON(t, lh.ConfirmMFAEnrollment, map[string]string{"mfa_token": ch.MFAToken, "code": code})
	if done.Code != http.StatusOK || !hasRefreshCookie(done) {
		t.Fatalf("confirm: %d %s", done.Code, done.Body.String())
	}
	var lr handler.LoginResponse
	_ = json.Unmarshal(done.Body.Bytes(), &lr)
	if len(lr.RecoveryCodes) != 10 {
		t.Fatalf("recovery codes = %d, want 10", len(lr.RecoveryCodes))
	}
}

func TestMFAHandler_MappedErrors(t *testing.T) {
	h := newMFAHarness(t)
	lh := newMFAHandler(h)
	rec := postJSON(t, lh.VerifyMFA, map[string]string{"mfa_token": "unknown", "code": "123456"})
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("unknown challenge: %d", rec.Code)
	}
	if strings.Contains(strings.ToLower(rec.Body.String()), "not found") {
		t.Fatalf("error leaks internal state: %s", rec.Body.String())
	}
}

// =============================================================================
// Middleware: immediate revocation and challenge tokens
// =============================================================================

type staticRevoked map[string]bool

func (s staticRevoked) IsSessionRevoked(_ context.Context, id string) (bool, error) {
	return s[id], nil
}

func TestUnifiedAuth_RejectsRevokedSessionAndChallengeTokens(t *testing.T) {
	cfg := defaultAuthTestConfig()
	gen := jwt.NewGenerator(jwt.TokenConfig{
		Secret: cfg.JWTSecret, Issuer: cfg.JWTIssuer,
		AccessTokenDuration: cfg.AccessTokenDuration, RefreshTokenDuration: cfg.RefreshTokenDuration,
	})
	live, _, err := gen.GenerateAccessToken("11111111-1111-1111-1111-111111111111", "sess-live", "member")
	if err != nil {
		t.Fatalf("token: %v", err)
	}
	dead, _, _ := gen.GenerateAccessToken("11111111-1111-1111-1111-111111111111", "sess-dead", "member")

	mw := middleware.UnifiedAuth(middleware.UnifiedAuthConfig{
		Provider:        config.AuthProviderLocal,
		LocalValidator:  gen,
		Logger:          logger.NewNop(),
		RevokedSessions: staticRevoked{"sess-dead": true},
	})
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
	call := func(token string) int {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/users/me", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		rec := httptest.NewRecorder()
		mw(next).ServeHTTP(rec, req)
		return rec.Code
	}

	if got := call(live); got != http.StatusNoContent {
		t.Fatalf("live session: %d", got)
	}
	if got := call(dead); got != http.StatusUnauthorized {
		t.Fatalf("revoked session must be rejected immediately, got %d", got)
	}

	// An MFA challenge token is opaque, not a JWT: never an access token.
	h := newMFAHarness(t)
	uid := h.seedUser(t, "mw@example.com")
	h.enroll(t, uid)
	ch := h.login(t, "mw@example.com").MFAChallenge
	if got := call(ch.Token); got != http.StatusUnauthorized {
		t.Fatalf("MFA challenge accepted as bearer token: %d", got)
	}
}

func TestLocalAuthHandler_MalformedRefreshTokenIs401(t *testing.T) {
	h := newMFAHarness(t)
	lh := newMFAHandler(h)
	for _, fn := range []http.HandlerFunc{lh.ExchangeToken, lh.RefreshToken} {
		rec := postJSON(t, fn, map[string]string{"refresh_token": "not-a-jwt", "tenant_id": "00000000-0000-0000-0000-000000000001"})
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("malformed refresh token: status %d, want 401 (%s)", rec.Code, rec.Body.String())
		}
	}
}

// A wrong code or password on the signed-in /users/me endpoints must be a 400:
// the UI treats any 401 as an expired session and signs the user out.
func TestMFAHandler_SelfServiceErrorsAreNot401(t *testing.T) {
	h := newMFAHarness(t)
	uid := h.seedUser(t, "self@example.com")
	lh := newMFAHandler(h)
	authed := func(fn http.HandlerFunc, body any) *httptest.ResponseRecorder {
		b, _ := json.Marshal(body)
		req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(b))
		req = req.WithContext(context.WithValue(req.Context(), middleware.UserIDKey, uid.String()))
		rec := httptest.NewRecorder()
		fn(rec, req)
		return rec
	}

	if rec := authed(lh.SetupMFA, map[string]string{}); rec.Code != http.StatusOK {
		t.Fatalf("setup: %d %s", rec.Code, rec.Body.String())
	}
	if rec := authed(lh.EnableMFA, map[string]string{"password": mfaTestPassword, "code": "000000"}); rec.Code != http.StatusBadRequest {
		t.Fatalf("enable with wrong code: %d, want 400", rec.Code)
	}
	// Enabling 2FA needs the current password (settings audit A-M1).
	if rec := authed(lh.EnableMFA, map[string]string{"code": "000000"}); rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("enable without a password: %d, want 422", rec.Code)
	}
	if rec := authed(lh.EnableMFA, map[string]string{"password": "wrong", "code": "000000"}); rec.Code != http.StatusBadRequest {
		t.Fatalf("enable with a wrong password: %d, want 400", rec.Code)
	}
	secret, _ := h.enroll(t, uid)
	if rec := authed(lh.DisableMFA, map[string]string{"password": "wrong", "code": currentCode(t, secret)}); rec.Code != http.StatusBadRequest {
		t.Fatalf("disable with wrong password: %d, want 400", rec.Code)
	}
	if rec := authed(lh.RegenerateRecoveryCodes, map[string]string{"code": wrongCode(currentCode(t, secret))}); rec.Code != http.StatusBadRequest {
		t.Fatalf("regenerate with wrong code: %d, want 400", rec.Code)
	}
	if rec := authed(lh.ChangePassword, map[string]string{"current_password": "wrong", "new_password": "AnotherPassword1"}); rec.Code != http.StatusBadRequest {
		t.Fatalf("change password with wrong current password: %d, want 400", rec.Code)
	}
}

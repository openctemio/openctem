package routes

// Step-up re-authentication end to end over the real routes, the auth
// service and a migrated database (docs/architecture/step-up-reauth.md):
// POST /api/v1/auth/step-up opens a window on the calling session only;
// sensitive routes refuse a session outside its window with 403
// STEP_UP_REQUIRED; a wrong or replayed proof opens nothing, is audited and
// counts towards the lockout; the window is not extended without a new proof.
// The probe route is DELETE /api/v1/api-keys/{unknown id}: 404 once the
// step-up gate lets the request through, 403 STEP_UP_REQUIRED before.

import (
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	_ "github.com/lib/pq"

	"github.com/openctemio/openctem/api/internal/app/apikey"
	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	authapp "github.com/openctemio/openctem/api/internal/app/auth"
	tenantapp "github.com/openctemio/openctem/api/internal/app/tenant"
	"github.com/openctemio/openctem/api/internal/config"
	infrahttp "github.com/openctemio/openctem/api/internal/infra/http"
	"github.com/openctemio/openctem/api/internal/infra/http/handler"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/internal/testdb"
	"github.com/openctemio/openctem/api/pkg/crypto"
	"github.com/openctemio/openctem/api/pkg/domain/session"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/jwt"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/password"
	"github.com/openctemio/openctem/api/pkg/totp"
	"github.com/openctemio/openctem/api/pkg/validator"
)

const stepUpTestPassword = "Step-up-test-Passw0rd!"

type stepUpHarness struct {
	t      *testing.T
	db     *sql.DB
	srv    *httptest.Server
	gen    *jwt.Generator
	cipher crypto.Encryptor
	tenant string
}

type stepUpUser struct {
	id, email string
}

func newStepUpHarness(t *testing.T) *stepUpHarness {
	t.Helper()
	dbURL := testdb.URL()
	if dbURL == "" {
		t.Skip("DATABASE_URL not set; skipping step-up route test")
	}
	sqldb, err := sql.Open("postgres", dbURL)
	if err != nil {
		t.Skipf("open db: %v", err)
	}
	t.Cleanup(func() { _ = sqldb.Close() })
	if err := sqldb.PingContext(context.Background()); err != nil {
		t.Skipf("cannot reach DATABASE_URL: %v", err)
	}
	saved := []Middleware{csrfProtectionMiddleware, readRateLimitMiddleware, activeMembershipFromJWTMiddleware,
		permissionSyncMiddleware, ssoEnforcementMiddleware, ipAllowlistMiddleware}
	savedKeyAuth, savedChecker := apiKeyOrJWT, stepUpChecker
	t.Cleanup(func() {
		apiKeyOrJWT, stepUpChecker = savedKeyAuth, savedChecker
		csrfProtectionMiddleware, readRateLimitMiddleware, activeMembershipFromJWTMiddleware = saved[0], saved[1], saved[2]
		permissionSyncMiddleware, ssoEnforcementMiddleware, ipAllowlistMiddleware = saved[3], saved[4], saved[5]
	})

	db := &postgres.DB{DB: sqldb}
	log := logger.NewNop()
	tenantRepo := postgres.NewTenantRepository(db)
	userRepo := postgres.NewUserRepository(db)
	auditSvc := auditapp.NewAuditService(postgres.NewAuditRepository(db), log)
	authCfgApp := config.AuthConfig{
		JWTSecret: "step-up-db-test-secret-0123456789abcdef", JWTIssuer: "test",
		AccessTokenDuration: time.Hour, RefreshTokenDuration: time.Hour, SessionDuration: time.Hour,
		MaxLoginAttempts: 3, LockoutDuration: 15 * time.Minute,
	}
	authSvc := authapp.NewAuthService(userRepo, postgres.NewSessionRepository(sqldb), postgres.NewRefreshTokenRepository(sqldb),
		tenantRepo, auditSvc, authCfgApp, log)
	cipher, err := crypto.NewCipher([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	authSvc.SetMFA(postgres.NewUserMFARepository(db), cipher, "OpenCTEM")

	gen := jwt.NewGenerator(jwt.TokenConfig{Secret: "step-up-db-route-test-secret-0123456789abcdef", Issuer: "test",
		AccessTokenDuration: time.Hour, RefreshTokenDuration: time.Hour})
	cfg := &config.Config{}
	cfg.Auth.Provider = config.AuthProviderLocal
	v := validator.New()
	router := infrahttp.NewChiRouter()
	Register(router, Handlers{
		LocalAuth: handler.NewLocalAuthHandler(authSvc, nil, nil, nil, authCfgApp, log),
		APIKey:    handler.NewAPIKeyHandler(apikey.NewService(postgres.NewAPIKeyRepository(db), "step-up-pepper", log), v, log),
	}, cfg, log, AuthConfig{Provider: config.AuthProviderLocal, LocalValidator: gen}, tenantRepo, tenantapp.NewUserService(userRepo, log), nil, nil, nil)
	srv := httptest.NewServer(router.(interface{ Handler() http.Handler }).Handler())
	t.Cleanup(srv.Close)

	h := &stepUpHarness{t: t, db: sqldb, srv: srv, gen: gen, cipher: cipher}
	h.tenant = uuid.NewString()
	h.exec(`INSERT INTO tenants (id, name, slug) VALUES ($1, 'Step-up IT', $2)`,
		h.tenant, "stepup-"+strings.ReplaceAll(h.tenant[:13], "-", ""))
	t.Cleanup(func() {
		ctx := context.Background()
		for _, q := range []string{
			`DELETE FROM audit_log_chain WHERE tenant_id = $1`,
			`DELETE FROM audit_logs WHERE tenant_id = $1`,
			`DELETE FROM user_roles WHERE tenant_id = $1`,
			`DELETE FROM tenant_members WHERE tenant_id = $1`,
			`DELETE FROM tenants WHERE id = $1`,
		} {
			_, _ = sqldb.ExecContext(ctx, q, h.tenant)
		}
	})
	return h
}

func (h *stepUpHarness) exec(q string, args ...any) {
	h.t.Helper()
	if _, err := h.db.ExecContext(context.Background(), q, args...); err != nil {
		h.t.Fatalf("%s: %v", q, err)
	}
}

// owner creates an owner of the harness organization. withPassword gives the
// account a local password; without it the account is SSO-only.
func (h *stepUpHarness) owner(withPassword bool) stepUpUser {
	h.t.Helper()
	u := stepUpUser{id: uuid.NewString()}
	u.email = "stepup-" + u.id[:8] + "@it.test"
	h.exec(`INSERT INTO users (id, email, name, auth_provider) VALUES ($1, $2, 'Step-up IT', $3)`,
		u.id, u.email, map[bool]string{true: "local", false: "oidc"}[withPassword])
	h.t.Cleanup(func() { _, _ = h.db.ExecContext(context.Background(), `DELETE FROM users WHERE id = $1`, u.id) })
	if withPassword {
		hash, err := password.New().Hash(stepUpTestPassword)
		if err != nil {
			h.t.Fatal(err)
		}
		h.exec(`UPDATE users SET password_hash = $2 WHERE id = $1`, u.id, hash)
	}
	h.exec(`INSERT INTO tenant_members (id, user_id, tenant_id, role) VALUES ($1, $2, $3, 'owner')`,
		uuid.NewString(), u.id, h.tenant)
	return u
}

// enrollTOTP turns on an authenticator for u and returns its secret.
func (h *stepUpHarness) enrollTOTP(u stepUpUser) string {
	h.t.Helper()
	secret, err := totp.GenerateSecret()
	if err != nil {
		h.t.Fatal(err)
	}
	enc, err := h.cipher.EncryptString(secret)
	if err != nil {
		h.t.Fatal(err)
	}
	h.exec(`INSERT INTO user_mfa (user_id, secret_encrypted, enabled, enabled_at) VALUES ($1, $2, TRUE, NOW())`, u.id, enc)
	return secret
}

// signIn creates a session for u that signed in `ago` ago and returns an
// access token bound to it.
func (h *stepUpHarness) signIn(u stepUpUser, ago time.Duration) (sessionID, token string) {
	h.t.Helper()
	s, err := session.New(shared.MustIDFromString(u.id), "tok-"+uuid.NewString(), "10.0.0.1", "Browser", time.Hour)
	if err != nil {
		h.t.Fatal(err)
	}
	if err := postgres.NewSessionRepository(h.db).Create(context.Background(), s); err != nil {
		h.t.Fatal(err)
	}
	h.exec(`UPDATE sessions SET created_at = NOW() - $2::interval WHERE id = $1`, s.ID().String(), ago.String())
	return s.ID().String(), h.token(u, s.ID().String())
}

func (h *stepUpHarness) token(u stepUpUser, sessionID string) string {
	h.t.Helper()
	tok, err := h.gen.GenerateTenantScopedAccessToken(u.id, u.email, "Step-up IT", sessionID,
		jwt.TenantMembership{TenantID: h.tenant, Role: "owner"}, true, 0, "password")
	if err != nil {
		h.t.Fatal(err)
	}
	return tok.AccessToken
}

func (h *stepUpHarness) do(token, method, path, body string) (int, string) {
	h.t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), method, h.srv.URL+path, strings.NewReader(body))
	if err != nil {
		h.t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		h.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	var e struct {
		Code string `json:"code"`
	}
	_ = json.Unmarshal(b, &e)
	if e.Code != "" {
		return resp.StatusCode, e.Code
	}
	return resp.StatusCode, string(b)
}

// probe calls the sensitive probe route and reports whether step-up let it
// through (404 for the unknown key) or refused it.
func (h *stepUpHarness) probe(token string) string {
	h.t.Helper()
	code, body := h.do(token, http.MethodDelete, "/api/v1/api-keys/"+uuid.NewString(), "")
	switch {
	case code == http.StatusNotFound:
		return "allowed"
	case code == http.StatusForbidden && strings.HasPrefix(body, "STEP_UP"):
		return body
	default:
		h.t.Fatalf("probe: unexpected %d %s", code, body)
		return ""
	}
}

func (h *stepUpHarness) stepUp(token, body string) (int, string) {
	h.t.Helper()
	return h.do(token, http.MethodPost, "/api/v1/auth/step-up", body)
}

func (h *stepUpHarness) audits(userID, action string) int {
	h.t.Helper()
	var n int
	if err := h.db.QueryRowContext(context.Background(),
		`SELECT COUNT(*) FROM audit_logs WHERE tenant_id = $1 AND resource_id = $2 AND action = $3`,
		h.tenant, userID, action).Scan(&n); err != nil {
		h.t.Fatal(err)
	}
	return n
}

func (h *stepUpHarness) stepUpAt(sessionID string) sql.NullTime {
	h.t.Helper()
	var at sql.NullTime
	if err := h.db.QueryRowContext(context.Background(), `SELECT step_up_at FROM sessions WHERE id = $1`, sessionID).Scan(&at); err != nil {
		h.t.Fatal(err)
	}
	return at
}

func TestStepUp_PasswordOpensWindowOnThisSessionOnly_DB(t *testing.T) {
	h := newStepUpHarness(t)
	u := h.owner(true)

	// A fresh sign-in is inside the window without a step-up.
	_, fresh := h.signIn(u, time.Minute)
	if got := h.probe(fresh); got != "allowed" {
		t.Fatalf("fresh sign-in: %s", got)
	}

	sessA, tokA := h.signIn(u, time.Hour)
	_, tokB := h.signIn(u, time.Hour)
	if got := h.probe(tokA); got != "STEP_UP_REQUIRED" {
		t.Fatalf("old session before step-up: %s", got)
	}

	// The state endpoint asks for the password and reports a closed window.
	code, body := h.do(tokA, http.MethodGet, "/api/v1/auth/step-up", "")
	if code != http.StatusOK || !strings.Contains(body, `"method":"password"`) || strings.Contains(body, "valid_until") {
		t.Fatalf("state: %d %s", code, body)
	}

	// A wrong password opens nothing and is audited.
	if code, body := h.stepUp(tokA, `{"password":"wrong-password"}`); code != http.StatusForbidden || body != "STEP_UP_FAILED" {
		t.Fatalf("wrong password: %d %s", code, body)
	}
	if h.stepUpAt(sessA).Valid {
		t.Fatal("a failed step-up stamped the session")
	}
	if got := h.probe(tokA); got != "STEP_UP_REQUIRED" {
		t.Fatalf("after a wrong password: %s", got)
	}
	if n := h.audits(u.id, "auth.step_up_failed"); n != 1 {
		t.Fatalf("auth.step_up_failed rows: %d", n)
	}

	// The right password opens the window on session A, audited.
	if code, body := h.stepUp(tokA, `{"password":"`+stepUpTestPassword+`"}`); code != http.StatusOK || !strings.Contains(body, "valid_until") {
		t.Fatalf("step-up: %d %s", code, body)
	}
	if got := h.probe(tokA); got != "allowed" {
		t.Fatalf("after step-up: %s", got)
	}
	if n := h.audits(u.id, "auth.step_up"); n != 1 {
		t.Fatalf("auth.step_up rows: %d", n)
	}

	// Cross-session: session B of the same user is still outside its window.
	if got := h.probe(tokB); got != "STEP_UP_REQUIRED" {
		t.Fatalf("other session after step-up on A: %s", got)
	}

	// Expired window: the stamp is older than the window.
	h.exec(`UPDATE sessions SET step_up_at = NOW() - interval '11 minutes' WHERE id = $1`, sessA)
	if got := h.probe(tokA); got != "STEP_UP_REQUIRED" {
		t.Fatalf("expired window: %s", got)
	}

	// A revoked session cannot use its window.
	h.exec(`UPDATE sessions SET step_up_at = NOW() WHERE id = $1`, sessA)
	h.exec(`UPDATE sessions SET status = 'revoked' WHERE id = $1`, sessA)
	if got := h.probe(tokA); got != "STEP_UP_REQUIRED" {
		t.Fatalf("revoked session: %s", got)
	}
}

func TestStepUp_TOTPReplayAndRecoveryCodesAreRefused_DB(t *testing.T) {
	h := newStepUpHarness(t)
	u := h.owner(true)
	secret := h.enrollTOTP(u)
	sess, tok := h.signIn(u, time.Hour)

	// With an authenticator, the password is not enough.
	if code, body := h.stepUp(tok, `{"password":"`+stepUpTestPassword+`"}`); code != http.StatusBadRequest {
		t.Fatalf("password instead of TOTP: %d %s", code, body)
	}
	code6, err := totp.Code(secret, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if code, body := h.stepUp(tok, `{"totp":"`+code6+`"}`); code != http.StatusOK {
		t.Fatalf("TOTP step-up: %d %s", code, body)
	}
	first := h.stepUpAt(sess)

	// Replay: the same code again is refused and does not move the window.
	if code, body := h.stepUp(tok, `{"totp":"`+code6+`"}`); code != http.StatusForbidden || body != "STEP_UP_FAILED" {
		t.Fatalf("replayed code: %d %s", code, body)
	}
	if again := h.stepUpAt(sess); !again.Time.Equal(first.Time) {
		t.Fatalf("a replayed code moved the window: %v -> %v", first.Time, again.Time)
	}
	if got := h.probe(tok); got != "allowed" {
		t.Fatalf("inside the TOTP window: %s", got)
	}
}

func TestStepUp_CrossUserSessionAndSSOOnly_DB(t *testing.T) {
	h := newStepUpHarness(t)
	alice := h.owner(true)
	bob := h.owner(true)
	sessAlice, _ := h.signIn(alice, time.Minute)

	// A token naming Alice's fresh session but Bob's identity: the session is
	// not Bob's, so it is neither recent auth for him nor his to stamp.
	forged := h.token(bob, sessAlice)
	if got := h.probe(forged); got != "STEP_UP_REQUIRED" {
		t.Fatalf("another user's session: %s", got)
	}
	if code, body := h.stepUp(forged, `{"password":"`+stepUpTestPassword+`"}`); code != http.StatusForbidden || body != "STEP_UP_UNAVAILABLE" {
		t.Fatalf("step-up on another user's session: %d %s", code, body)
	}
	if h.stepUpAt(sessAlice).Valid {
		t.Fatal("another user stamped the session")
	}

	// An SSO-only account has nothing to verify here: it signs in again.
	sso := h.owner(false)
	sessSSO, tokSSO := h.signIn(sso, 9*time.Minute)
	if code, body := h.do(tokSSO, http.MethodGet, "/api/v1/auth/step-up", ""); code != http.StatusOK || !strings.Contains(body, `"method":"fresh_sign_in"`) {
		t.Fatalf("SSO state: %d %s", code, body)
	}
	// Its fresh session cannot stretch its own window with a step-up call.
	if code, body := h.stepUp(tokSSO, `{}`); code != http.StatusForbidden || body != "STEP_UP_UNAVAILABLE" {
		t.Fatalf("SSO step-up: %d %s", code, body)
	}
	if h.stepUpAt(sessSSO).Valid {
		t.Fatal("an SSO session extended its window without a proof")
	}
}

func TestStepUp_FailuresLockTheAccountAndAreRateLimited_DB(t *testing.T) {
	h := newStepUpHarness(t)
	u := h.owner(true)
	_, tok := h.signIn(u, time.Hour)

	// MaxLoginAttempts is 3 in the harness: the fourth try, even with the
	// right password, meets a locked account.
	for i := range 3 {
		if code, body := h.stepUp(tok, `{"password":"wrong-password"}`); code != http.StatusForbidden {
			t.Fatalf("wrong password %d: %d %s", i, code, body)
		}
	}
	if code, body := h.stepUp(tok, `{"password":"`+stepUpTestPassword+`"}`); code != http.StatusForbidden || body == "" {
		t.Fatalf("locked account: %d %s", code, body)
	}
	var locked bool
	if err := h.db.QueryRowContext(context.Background(), `SELECT locked_until > NOW() FROM users WHERE id = $1`, u.id).Scan(&locked); err != nil || !locked {
		t.Fatalf("account not locked: %v %v", locked, err)
	}
	if got := h.probe(tok); got != "STEP_UP_REQUIRED" {
		t.Fatalf("locked account probe: %s", got)
	}
	// The per-IP bucket (5/min) refuses further calls before any check.
	limited := false
	for range 3 {
		if code, _ := h.stepUp(tok, `{"password":"x"}`); code == http.StatusTooManyRequests {
			limited = true
			break
		}
	}
	if !limited {
		t.Fatal("step-up is not rate limited")
	}
}

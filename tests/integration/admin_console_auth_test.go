package integration

// End-to-end check of platform admin console login (RFC-022) over HTTP against
// a real Postgres: handler -> admin auth middleware -> service -> repository.
// Exercises the cookies, CSRF and session lifecycle a browser would.
//
// Requires DATABASE_URL pointing at a database migrated through 000225.

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	_ "github.com/lib/pq"

	"github.com/openctemio/api/internal/app/adminconsole"
	"github.com/openctemio/api/internal/infra/http/handler"
	"github.com/openctemio/api/internal/infra/http/middleware"
	"github.com/openctemio/api/internal/infra/postgres"
	"github.com/openctemio/api/pkg/crypto"
	"github.com/openctemio/api/pkg/domain/admin"
	"github.com/openctemio/api/pkg/logger"
	"github.com/openctemio/api/pkg/totp"
)

func openConsoleDB(t *testing.T) *postgres.DB {
	t.Helper()
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		t.Skip("DATABASE_URL not set; skipping admin console integration test")
	}
	sqlDB, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Skipf("open db: %v", err)
	}
	if err := sqlDB.Ping(); err != nil {
		t.Skipf("database not available: %v", err)
	}
	var exists bool
	if err := sqlDB.QueryRow(`SELECT to_regclass('public.admin_sessions') IS NOT NULL`).Scan(&exists); err != nil || !exists {
		t.Skip("admin_sessions missing: run migration 000225")
	}
	t.Cleanup(func() { _ = sqlDB.Close() })
	return &postgres.DB{DB: sqlDB}
}

type consoleClient struct {
	t    *testing.T
	base string
	http *http.Client
}

func (c *consoleClient) do(method, path string, body any, apiKey string) (*http.Response, []byte) {
	c.t.Helper()
	var buf bytes.Buffer
	if body != nil {
		_ = json.NewEncoder(&buf).Encode(body)
	}
	req, _ := http.NewRequestWithContext(c.t.Context(), method, c.base+path, &buf)
	req.Header.Set("Content-Type", "application/json")
	if apiKey != "" {
		req.Header.Set(middleware.AdminAPIKeyHeader, apiKey)
	}
	// Browser behavior: echo the readable admin CSRF cookie on writes.
	u, _ := url.Parse(c.base + "/")
	for _, ck := range c.http.Jar.Cookies(u) {
		if ck.Name == middleware.AdminCSRFCookie && method != http.MethodGet {
			req.Header.Set(middleware.CSRFHeaderName, ck.Value)
		}
	}
	resp, err := c.http.Do(req)
	if err != nil {
		c.t.Fatalf("%s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	var out bytes.Buffer
	_, _ = out.ReadFrom(resp.Body)
	return resp, out.Bytes()
}

func TestAdminConsoleLoginEndToEnd(t *testing.T) {
	db := openConsoleDB(t)
	log := logger.NewNop()
	admins := postgres.NewAdminRepository(db)
	consoleRepo := postgres.NewAdminConsoleRepository(db)
	auditRepo := postgres.NewAuditLogRepository(db)
	cipher, err := crypto.NewCipher([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}

	// A fresh super admin, as bootstrap-admin would create it.
	email := "console-it-" + time.Now().Format("150405.000000") + "@example.test"
	a, apiKey, err := admin.NewAdminUser(email, "Console IT", admin.AdminRoleSuperAdmin, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := admins.Create(t.Context(), a); err != nil {
		t.Fatalf("create admin: %v", err)
	}
	t.Cleanup(func() { _ = admins.Delete(t.Context(), a.ID()) })

	svc := adminconsole.NewService(admins, consoleRepo, auditRepo, cipher, log)
	h := handler.NewAdminConsoleHandler(svc, false, log)
	validate := handler.NewAdminAuthHandler(log)
	authMW := middleware.NewAdminAuthMiddleware(admins, log).WithSessions(svc)

	// Same guards as routes/admin.go for the auth group.
	r := chi.NewRouter()
	r.Route("/api/v1/admin/auth", func(r chi.Router) {
		r.With(authMW.Authenticate).Get("/validate", validate.Validate)
		r.Post("/login", h.Login)
		r.Post("/mfa", h.VerifyMFA)
		r.Post("/logout", h.Logout)
		r.With(authMW.Authenticate).Post("/password", h.SetPassword)
	})
	srv := httptest.NewServer(r)
	defer srv.Close()

	jar, _ := cookiejar.New(nil)
	c := &consoleClient{t: t, base: srv.URL, http: &http.Client{Jar: jar}}
	const pw = "integration pass phrase"

	// 1. No password yet: login fails generically.
	if resp, _ := c.do("POST", "/api/v1/admin/auth/login", map[string]string{"email": email, "password": pw}, ""); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("login before password: %d", resp.StatusCode)
	}
	// 2. Bootstrap path: set the password with the API key.
	if resp, body := c.do("POST", "/api/v1/admin/auth/password", map[string]string{"new_password": pw}, apiKey); resp.StatusCode != http.StatusNoContent {
		t.Fatalf("set password with api key: %d %s", resp.StatusCode, body)
	}
	// 3. Password step: first login demands MFA enrollment.
	resp, body := c.do("POST", "/api/v1/admin/auth/login", map[string]string{"email": email, "password": pw}, "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("login: %d %s", resp.StatusCode, body)
	}
	var login handler.AdminLoginResponse
	_ = json.Unmarshal(body, &login)
	if login.Status != string(adminconsole.StatusMFAEnrollment) || login.Secret == "" {
		t.Fatalf("expected enrollment, got %+v", login)
	}
	// A password-only (pending) login must not reach authenticated routes.
	if resp, _ := c.do("GET", "/api/v1/admin/auth/validate", nil, ""); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("validate before mfa: %d", resp.StatusCode)
	}
	// 4. Wrong code, then the right one.
	if resp, _ := c.do("POST", "/api/v1/admin/auth/mfa", map[string]string{"code": "000000"}, ""); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("wrong code: %d", resp.StatusCode)
	}
	code, _ := totp.Code(login.Secret, time.Now())
	if resp, body := c.do("POST", "/api/v1/admin/auth/mfa", map[string]string{"code": code}, ""); resp.StatusCode != http.StatusOK {
		t.Fatalf("mfa: %d %s", resp.StatusCode, body)
	}
	// 5. The session cookie now authenticates, as the right admin.
	resp, body = c.do("GET", "/api/v1/admin/auth/validate", nil, "")
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), email) {
		t.Fatalf("validate with session: %d %s", resp.StatusCode, body)
	}
	// 6. A write without the CSRF header is refused.
	u, _ := url.Parse(srv.URL + "/")
	var sessionCookie *http.Cookie
	for _, ck := range jar.Cookies(u) {
		if ck.Name == middleware.AdminSessionCookie {
			sessionCookie = ck
		}
	}
	if sessionCookie == nil {
		// The session cookie is path-scoped to /api/v1/admin.
		au, _ := url.Parse(srv.URL + "/api/v1/admin/")
		for _, ck := range jar.Cookies(au) {
			if ck.Name == middleware.AdminSessionCookie {
				sessionCookie = ck
			}
		}
	}
	if sessionCookie == nil {
		t.Fatal("no admin_session cookie issued")
	}
	req, _ := http.NewRequestWithContext(t.Context(), "POST", srv.URL+"/api/v1/admin/auth/password", strings.NewReader(`{"current_password":"x","new_password":"yyyyyyyyyyyyyyyy"}`))
	req.AddCookie(sessionCookie)
	noCSRF, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = noCSRF.Body.Close()
	if noCSRF.StatusCode != http.StatusUnauthorized {
		t.Fatalf("write without csrf: %d, want 401", noCSRF.StatusCode)
	}
	// 7. Logout ends the session.
	if resp, _ := c.do("POST", "/api/v1/admin/auth/logout", nil, ""); resp.StatusCode != http.StatusNoContent {
		t.Fatalf("logout: %d", resp.StatusCode)
	}
	req, _ = http.NewRequestWithContext(t.Context(), "GET", srv.URL+"/api/v1/admin/auth/validate", nil)
	req.AddCookie(sessionCookie) // replay the old cookie after logout
	after, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = after.Body.Close()
	if after.StatusCode != http.StatusUnauthorized {
		t.Fatalf("old session after logout: %d, want 401", after.StatusCode)
	}
	// 8. Audit trail recorded the console events.
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM admin_audit_logs WHERE admin_id = $1 AND action LIKE 'console.%'`, a.ID().String()).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n < 4 { // password_set, mfa_failed, mfa_enrolled, login, logout
		t.Fatalf("console audit entries: %d", n)
	}
}

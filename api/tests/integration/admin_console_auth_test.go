package integration

// End-to-end check of opening the platform admin console (RFC-022) over HTTP
// against a real Postgres: handler -> admin auth middleware -> service ->
// repository. The administrator's normal /login session is stubbed (a refresh
// token naming a real users row); everything after it, including the users
// link, cookies, CSRF and session lifecycle, is real.
//
// Requires DATABASE_URL pointing at a database migrated through 000226.

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/lib/pq"

	"github.com/openctemio/openctem/api/internal/app/adminconsole"
	"github.com/openctemio/openctem/api/internal/infra/http/handler"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/internal/testdb"
	"github.com/openctemio/openctem/api/pkg/crypto"
	"github.com/openctemio/openctem/api/pkg/domain/admin"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/totp"
)

func openConsoleDB(t *testing.T) *postgres.DB {
	t.Helper()
	dsn := testdb.URL()
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
	if err := sqlDB.QueryRow(`SELECT EXISTS (SELECT 1 FROM information_schema.columns
		WHERE table_name = 'admin_users' AND column_name = 'user_id')`).Scan(&exists); err != nil || !exists {
		t.Skip("admin_users.user_id missing: run migration 000226")
	}
	t.Cleanup(func() { _ = sqlDB.Close() })
	return &postgres.DB{DB: sqlDB}
}

type consoleClient struct {
	t    *testing.T
	base string
	http *http.Client
}

func (c *consoleClient) do(method, path string, body any) (*http.Response, []byte) {
	c.t.Helper()
	var buf bytes.Buffer
	if body != nil {
		_ = json.NewEncoder(&buf).Encode(body)
	}
	req, _ := http.NewRequestWithContext(c.t.Context(), method, c.base+path, &buf)
	req.Header.Set("Content-Type", "application/json")
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

// stubSignIn resolves one refresh token to one user, standing in for the
// normal /login session.
type stubSignIn struct {
	token string
	user  adminconsole.SignedInUser
}

func (s stubSignIn) SignedInUser(_ context.Context, token string) (*adminconsole.SignedInUser, error) {
	if token != s.token {
		return nil, errors.New("invalid refresh token")
	}
	u := s.user
	return &u, nil
}

func (s stubSignIn) EndSignIn(context.Context, string) error { return nil }

func (s stubSignIn) CreateAccount(context.Context, string, string) (shared.ID, string, error) {
	return shared.ID{}, "", errors.New("not used")
}

func (s stubSignIn) AccountActive(_ context.Context, userID shared.ID) (bool, error) {
	return userID == s.user.UserID, nil
}

func (s stubSignIn) ChangePassword(context.Context, shared.ID, string, string) error {
	return errors.New("not used")
}

// createUser inserts a bare users row and removes it (and anything cascading
// from it) after the test.
func createUser(t *testing.T, db *postgres.DB, email string) shared.ID {
	t.Helper()
	id := shared.NewID()
	if _, err := db.ExecContext(t.Context(), `INSERT INTO users (id, email, name) VALUES ($1, $2, 'IT')`, id.String(), email); err != nil {
		t.Fatalf("create user: %v", err)
	}
	t.Cleanup(func() { _, _ = db.ExecContext(context.Background(), `DELETE FROM users WHERE id = $1`, id.String()) })
	return id
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

	// A super admin linked to a users-table account.
	stamp := time.Now().Format("150405.000000")
	email := "console-it-" + stamp + "@example.test"
	a, err := admin.NewAdminUser(email, "Console IT", admin.AdminRoleSuperAdmin, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := admins.Create(t.Context(), a); err != nil {
		t.Fatalf("create admin: %v", err)
	}
	t.Cleanup(func() { _ = admins.Delete(context.Background(), a.ID()) })
	userID := createUser(t, db, email)
	if err := admins.LinkUser(t.Context(), a.ID(), userID); err != nil {
		t.Fatalf("link user: %v", err)
	}
	if got, err := admins.GetByUserID(t.Context(), userID); err != nil || got.ID() != a.ID() {
		t.Fatalf("GetByUserID: %v", err)
	}

	const refresh = "it-refresh-token"
	signIn := stubSignIn{token: refresh, user: adminconsole.SignedInUser{UserID: userID, Email: email, Active: true, PasswordSignIn: true}}
	svc := adminconsole.NewService(admins, consoleRepo, auditRepo, cipher, signIn, log)
	h := handler.NewAdminConsoleHandler(svc, false, "refresh_token", log)
	validate := handler.NewAdminAuthHandler(log)
	authMW := middleware.NewAdminAuthMiddleware(svc, log)

	// Same guards as routes/admin.go for the auth group, plus a probe write
	// route to check the console CSRF guard.
	r := chi.NewRouter()
	r.Route("/api/v1/admin/auth", func(r chi.Router) {
		r.With(authMW.Authenticate).Get("/validate", validate.Validate)
		r.Post("/session", h.StartSession)
		r.Post("/mfa", h.VerifyMFA)
		r.Post("/logout", h.Logout)
		r.With(authMW.Authenticate).Post("/probe", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
	})
	srv := httptest.NewServer(r)
	defer srv.Close()

	jar, _ := cookiejar.New(nil)
	c := &consoleClient{t: t, base: srv.URL, http: &http.Client{Jar: jar}}
	base, _ := url.Parse(srv.URL + "/")

	// 1. Not signed in on /login: refused.
	if resp, _ := c.do("POST", "/api/v1/admin/auth/session", nil); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("session without sign-in: %d", resp.StatusCode)
	}
	// 2. Signed in (refresh cookie from /login): first time demands enrollment.
	jar.SetCookies(base, []*http.Cookie{{Name: "refresh_token", Value: refresh, Path: "/"}})
	resp, body := c.do("POST", "/api/v1/admin/auth/session", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("session: %d %s", resp.StatusCode, body)
	}
	var login handler.AdminLoginResponse
	_ = json.Unmarshal(body, &login)
	if login.Status != string(adminconsole.StatusMFAEnrollment) || login.Secret == "" {
		t.Fatalf("expected enrollment, got %+v", login)
	}
	// A pending (pre-TOTP) session must not reach authenticated routes.
	if resp, _ := c.do("GET", "/api/v1/admin/auth/validate", nil); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("validate before mfa: %d", resp.StatusCode)
	}
	// 3. Wrong code, then the right one.
	if resp, _ := c.do("POST", "/api/v1/admin/auth/mfa", map[string]string{"code": "000000"}); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("wrong code: %d", resp.StatusCode)
	}
	code, _ := totp.Code(login.Secret, time.Now())
	if resp, body := c.do("POST", "/api/v1/admin/auth/mfa", map[string]string{"code": code}); resp.StatusCode != http.StatusOK {
		t.Fatalf("mfa: %d %s", resp.StatusCode, body)
	}
	// 4. The session cookie now authenticates, as the right admin.
	resp, body = c.do("GET", "/api/v1/admin/auth/validate", nil)
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), email) {
		t.Fatalf("validate with session: %d %s", resp.StatusCode, body)
	}
	// 5. A write without the CSRF header is refused; with it, allowed.
	var sessionCookie *http.Cookie
	au, _ := url.Parse(srv.URL + "/api/v1/admin/")
	for _, ck := range jar.Cookies(au) {
		if ck.Name == middleware.AdminSessionCookie {
			sessionCookie = ck
		}
	}
	if sessionCookie == nil {
		t.Fatal("no admin_session cookie issued")
	}
	req, _ := http.NewRequestWithContext(t.Context(), "POST", srv.URL+"/api/v1/admin/auth/probe", nil)
	req.AddCookie(sessionCookie)
	noCSRF, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = noCSRF.Body.Close()
	if noCSRF.StatusCode != http.StatusUnauthorized {
		t.Fatalf("write without csrf: %d, want 401", noCSRF.StatusCode)
	}
	if resp, _ := c.do("POST", "/api/v1/admin/auth/probe", nil); resp.StatusCode != http.StatusNoContent {
		t.Fatalf("write with csrf: %d", resp.StatusCode)
	}
	// 6. Logout ends the session.
	if resp, _ := c.do("POST", "/api/v1/admin/auth/logout", nil); resp.StatusCode != http.StatusNoContent {
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
	// 7. Audit trail recorded the console events.
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM admin_audit_logs WHERE admin_id = $1 AND action LIKE 'console.%'`, a.ID().String()).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n < 4 { // mfa_failed, mfa_enrolled, login, logout
		t.Fatalf("console audit entries: %d", n)
	}
}

// TestPlatformAdminCannotJoinOrganization checks the database guarantee
// behind the platform administrator model: an administrator's account belongs to no
// organization, and an organization member cannot be made an administrator.
func TestPlatformAdminCannotJoinOrganization(t *testing.T) {
	db := openConsoleDB(t)
	admins := postgres.NewAdminRepository(db)
	stamp := time.Now().Format("150405.000000")

	tenantID := shared.NewID()
	if _, err := db.ExecContext(t.Context(), `INSERT INTO tenants (id, name, slug) VALUES ($1, 'IT org', $2)`, tenantID.String(), "it-org-"+strings.ReplaceAll(stamp, ".", "")); err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	t.Cleanup(func() {
		_, _ = db.ExecContext(context.Background(), `DELETE FROM tenants WHERE id = $1`, tenantID.String())
	})

	newAdmin := func(email string) *admin.AdminUser {
		a, err := admin.NewAdminUser(email, "IT", admin.AdminRoleReadonly, nil)
		if err != nil {
			t.Fatal(err)
		}
		if err := admins.Create(t.Context(), a); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = admins.Delete(context.Background(), a.ID()) })
		return a
	}

	// An administrator's account cannot be added to an organization.
	adminEmail := "admin-it-" + stamp + "@example.test"
	a := newAdmin(adminEmail)
	adminUser := createUser(t, db, adminEmail)
	if err := admins.LinkUser(t.Context(), a.ID(), adminUser); err != nil {
		t.Fatal(err)
	}
	_, err := db.ExecContext(t.Context(), `INSERT INTO tenant_members (user_id, tenant_id) VALUES ($1, $2)`, adminUser.String(), tenantID.String())
	var pqErr *pq.Error
	if !errors.As(err, &pqErr) || pqErr.Code != "23514" {
		t.Fatalf("membership insert for an administrator: got %v, want check_violation", err)
	}

	// An organization member cannot be linked as an administrator.
	memberEmail := "member-it-" + stamp + "@example.test"
	b := newAdmin(memberEmail)
	member := createUser(t, db, memberEmail)
	if _, err := db.ExecContext(t.Context(), `INSERT INTO tenant_members (user_id, tenant_id) VALUES ($1, $2)`, member.String(), tenantID.String()); err != nil {
		t.Fatal(err)
	}
	if err := admins.LinkUser(t.Context(), b.ID(), member); !errors.Is(err, admin.ErrUserHasMemberships) {
		t.Fatalf("link a member: got %v, want ErrUserHasMemberships", err)
	}

	// One account backs at most one administrator.
	if err := admins.LinkUser(t.Context(), b.ID(), adminUser); !errors.Is(err, admin.ErrUserAlreadyAdmin) {
		t.Fatalf("link an already-linked account: got %v, want ErrUserAlreadyAdmin", err)
	}
}

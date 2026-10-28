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
	// csrf is the token the console keeps in memory, from the sign-in and
	// validate responses (never a readable cookie).
	csrf string
}

func (c *consoleClient) do(method, path string, body any) (*http.Response, []byte) {
	c.t.Helper()
	var buf bytes.Buffer
	if body != nil {
		_ = json.NewEncoder(&buf).Encode(body)
	}
	req, _ := http.NewRequestWithContext(c.t.Context(), method, c.base+path, &buf)
	req.Header.Set("Content-Type", "application/json")
	// Browser behavior: the console echoes the token it keeps in memory.
	if c.csrf != "" && method != http.MethodGet {
		req.Header.Set(middleware.CSRFHeaderName, c.csrf)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		c.t.Fatalf("%s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	var out bytes.Buffer
	_, _ = out.ReadFrom(resp.Body)
	var withToken struct {
		CSRFToken string `json:"csrf_token"`
		Admin     *struct {
			CSRFToken string `json:"csrf_token"`
		} `json:"admin"`
	}
	if json.Unmarshal(out.Bytes(), &withToken) == nil {
		if withToken.CSRFToken != "" {
			c.csrf = withToken.CSRFToken
		} else if withToken.Admin != nil && withToken.Admin.CSRFToken != "" {
			c.csrf = withToken.Admin.CSRFToken
		}
	}
	return resp, out.Bytes()
}

// stubSignIn resolves one refresh token to one user, standing in for the
// normal /login session.
type stubSignIn struct {
	password string
	user     adminconsole.SignedInUser
}

func (s stubSignIn) VerifyPassword(_ context.Context, email, password string, _ adminconsole.ClientInfo) (*adminconsole.SignedInUser, error) {
	if email != s.user.Email || password != s.password {
		return nil, admin.ErrInvalidCredentials
	}
	u := s.user
	return &u, nil
}

func (s stubSignIn) RecordPasswordSuccess(context.Context, shared.ID) {}

func (s stubSignIn) RecordPasswordFailure(context.Context, shared.ID) {}

func (s stubSignIn) CreateInvitedAccount(context.Context, string, string, time.Duration) (shared.ID, adminconsole.Invitation, error) {
	return shared.ID{}, adminconsole.Invitation{}, errors.New("not used")
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

	const pw = "It-Console-Pass-1"
	signIn := stubSignIn{password: pw, user: adminconsole.SignedInUser{UserID: userID, Email: email, Active: true}}
	svc := adminconsole.NewService(admins, consoleRepo, auditRepo, cipher, signIn, log)
	h := handler.NewAdminConsoleHandler(svc, false, log)
	validate := handler.NewAdminAuthHandler(log)
	authMW := middleware.NewAdminAuthMiddleware(svc, log)

	// Same guards as routes/admin.go for the auth group, plus a probe write
	// route to check the console CSRF guard.
	r := chi.NewRouter()
	r.Route("/api/v1/admin/auth", func(r chi.Router) {
		r.With(authMW.Authenticate).Get("/validate", validate.Validate)
		r.Post("/login", h.Login)
		r.Post("/mfa", h.VerifyMFA)
		r.Post("/logout", h.Logout)
		r.With(authMW.Authenticate).Post("/probe", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
	})
	srv := httptest.NewServer(r)
	defer srv.Close()

	jar, _ := cookiejar.New(nil)
	c := &consoleClient{t: t, base: srv.URL, http: &http.Client{Jar: jar}}
	// 1. A wrong password is refused, like an unknown email; a tenant
	// session plays no part.
	for _, creds := range []map[string]string{{"email": email, "password": "wrong"}, {"email": "nobody@example.com", "password": pw}} {
		if resp, _ := c.do("POST", "/api/v1/admin/auth/login", creds); resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("login %v: %d, want 401", creds, resp.StatusCode)
		}
	}
	// 2. The right email and password: first time demands enrollment.
	resp, body := c.do("POST", "/api/v1/admin/auth/login", map[string]string{"email": email, "password": pw})
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
	signInToken := c.csrf
	if signInToken == "" {
		t.Fatal("the sign-in response carries no csrf_token")
	}
	// No console cookie is readable by a page script (the jar holds what a
	// script could see only on a non-HttpOnly cookie; none at the root).
	for _, ck := range jar.Cookies(&url.URL{Scheme: "http", Host: strings.TrimPrefix(srv.URL, "http://"), Path: "/"}) {
		t.Errorf("cookie %s is sent to every page of the host", ck.Name)
	}
	// 4. The session cookie now authenticates, as the right admin, and
	// validate hands the same token back (a reloaded console).
	c.csrf = ""
	resp, body = c.do("GET", "/api/v1/admin/auth/validate", nil)
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), email) {
		t.Fatalf("validate with session: %d %s", resp.StatusCode, body)
	}
	if c.csrf != signInToken {
		t.Fatalf("validate csrf_token %q, want the sign-in one %q", c.csrf, signInToken)
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

// TestPlatformAdminAccountMayJoinOrganization checks the single-identity model
// (RFC-134): the platform role is an attribute of the one users account,
// effective only on the console plane, so an administrator's account may be an
// ordinary member of an organization and a member may be linked as an
// administrator. One account still backs at most one administrator.
func TestPlatformAdminAccountMayJoinOrganization(t *testing.T) {
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

	// An administrator's account joins an organization like any other account.
	adminEmail := "admin-it-" + stamp + "@example.test"
	a := newAdmin(adminEmail)
	adminUser := createUser(t, db, adminEmail)
	if err := admins.LinkUser(t.Context(), a.ID(), adminUser); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(t.Context(), `INSERT INTO tenant_members (user_id, tenant_id) VALUES ($1, $2)`, adminUser.String(), tenantID.String()); err != nil {
		t.Fatalf("membership insert for an administrator's account: %v", err)
	}

	// An organization member can be linked as an administrator.
	memberEmail := "member-it-" + stamp + "@example.test"
	b := newAdmin(memberEmail)
	member := createUser(t, db, memberEmail)
	if _, err := db.ExecContext(t.Context(), `INSERT INTO tenant_members (user_id, tenant_id) VALUES ($1, $2)`, member.String(), tenantID.String()); err != nil {
		t.Fatal(err)
	}
	if err := admins.LinkUser(t.Context(), b.ID(), member); err != nil {
		t.Fatalf("link a member: %v", err)
	}

	// Removing the platform role never deletes the account or its membership.
	if err := admins.Delete(t.Context(), b.ID()); err != nil {
		t.Fatal(err)
	}
	var stillMember bool
	if err := db.QueryRowContext(t.Context(), `SELECT EXISTS (SELECT 1 FROM tenant_members m JOIN users u ON u.id = m.user_id WHERE m.user_id = $1)`, member.String()).Scan(&stillMember); err != nil || !stillMember {
		t.Fatalf("account and membership after removing the platform role: member=%v err=%v", stillMember, err)
	}

	// A break-glass administrator stays console-only: its account cannot join
	// an organization, and an account that is a member cannot be marked
	// break-glass.
	bgEmail := "bg-it-" + stamp + "@example.test"
	bg := newAdmin(bgEmail)
	bgUser := createUser(t, db, bgEmail)
	if err := admins.LinkUser(t.Context(), bg.ID(), bgUser); err != nil {
		t.Fatal(err)
	}
	if err := bg.SetBreakGlass(true); err != nil {
		t.Fatal(err)
	}
	if err := admins.GuardedUpdate(t.Context(), bg); err != nil {
		t.Fatalf("mark a member-less account break-glass: %v", err)
	}
	_, err := db.ExecContext(t.Context(), `INSERT INTO tenant_members (user_id, tenant_id) VALUES ($1, $2)`, bgUser.String(), tenantID.String())
	var pqErr *pq.Error
	if !errors.As(err, &pqErr) || pqErr.Code != "23514" || pqErr.Constraint != "break_glass_console_only" {
		t.Fatalf("membership for a break-glass account: got %v, want break_glass_console_only", err)
	}
	if err := a.SetBreakGlass(true); err != nil {
		t.Fatal(err)
	}
	if err := admins.GuardedUpdate(t.Context(), a); !errors.Is(err, admin.ErrBreakGlassHasMemberships) {
		t.Fatalf("mark a member account break-glass: got %v, want ErrBreakGlassHasMemberships", err)
	}

	// One account backs at most one administrator.
	c := newAdmin("other-it-" + stamp + "@example.test")
	if err := admins.LinkUser(t.Context(), c.ID(), adminUser); !errors.Is(err, admin.ErrUserAlreadyAdmin) {
		t.Fatalf("link an already-linked account: got %v, want ErrUserAlreadyAdmin", err)
	}
}

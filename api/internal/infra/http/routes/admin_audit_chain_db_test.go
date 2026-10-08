package routes

// The platform admin "Rebaseline audit chain" action, over the real route
// registration (admin console session, CSRF, role guard, organization scope)
// and real services against a migrated database:
//
//   - organization users (owner, admin, member) cannot reach it, with their
//     tenant token or by presenting it as a console cookie;
//   - a console session that has not passed the TOTP step is refused;
//   - a readonly administrator may classify but not rebaseline;
//   - a super admin must re-enter a fresh authenticator code (step-up);
//   - the rebaseline is refused (409, nothing rewritten) when a break is
//     unexplained or the chain changed since the reviewed classification;
//   - an explained chain is re-signed and then verifies with 0 breaks, and the
//     action is in both the organization's and the platform's audit logs.

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	_ "github.com/lib/pq"

	"github.com/openctemio/openctem/api/internal/app/adminconsole"
	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/internal/app/audit/chainclassify/chaintest"
	"github.com/openctemio/openctem/api/internal/app/tenant"
	"github.com/openctemio/openctem/api/internal/config"
	infrahttp "github.com/openctemio/openctem/api/internal/infra/http"
	"github.com/openctemio/openctem/api/internal/infra/http/handler"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/internal/testdb"
	"github.com/openctemio/openctem/api/pkg/crypto"
	"github.com/openctemio/openctem/api/pkg/domain/admin"
	auditdom "github.com/openctemio/openctem/api/pkg/domain/audit"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/jwt"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/totp"
	"github.com/openctemio/openctem/api/pkg/validator"
)

// chainSignIns stands in for the normal /login session: each refresh token
// names one users row.
type chainSignIns map[string]adminconsole.SignedInUser

func (s chainSignIns) SignedInUser(_ context.Context, token string) (*adminconsole.SignedInUser, error) {
	u, ok := s[token]
	if !ok {
		return nil, errors.New("invalid refresh token")
	}
	return &u, nil
}
func (s chainSignIns) EndSignIn(context.Context, string) error { return nil }
func (s chainSignIns) CreateAccount(context.Context, string, string) (shared.ID, string, error) {
	return shared.ID{}, "", errors.New("not used")
}
func (s chainSignIns) AccountActive(_ context.Context, id shared.ID) (bool, error) {
	for _, u := range s {
		if u.UserID == id {
			return true, nil
		}
	}
	return false, nil
}
func (s chainSignIns) ChangePassword(context.Context, shared.ID, string, string) error {
	return errors.New("not used")
}

type chainHarness struct {
	t       *testing.T
	db      *sql.DB
	srv     *httptest.Server
	gen     *jwt.Generator
	audit   *auditapp.AuditService
	signIns chainSignIns
	admins  *postgres.AdminRepository
}

// newChainHarness builds the console over a migrated database. extra adds
// more console handlers (other console route tests reuse the harness).
func newChainHarness(t *testing.T, extra ...func(h *Handlers, db *postgres.DB)) *chainHarness {
	t.Helper()
	dbURL := testdb.URL()
	if dbURL == "" {
		t.Skip("DATABASE_URL not set; skipping admin audit-chain route test")
	}
	sqldb, err := sql.Open("postgres", dbURL)
	if err != nil {
		t.Skipf("open db: %v", err)
	}
	t.Cleanup(func() { _ = sqldb.Close() })
	if err := sqldb.PingContext(context.Background()); err != nil {
		t.Skipf("cannot reach DATABASE_URL: %v", err)
	}

	// Register sets package-level chain parts; put them back afterwards.
	saved := []Middleware{csrfProtectionMiddleware, readRateLimitMiddleware, activeMembershipFromJWTMiddleware,
		permissionSyncMiddleware, ssoEnforcementMiddleware, ipAllowlistMiddleware}
	savedKeyAuth := apiKeyOrJWT
	t.Cleanup(func() {
		apiKeyOrJWT = savedKeyAuth
		csrfProtectionMiddleware, readRateLimitMiddleware, activeMembershipFromJWTMiddleware = saved[0], saved[1], saved[2]
		permissionSyncMiddleware, ssoEnforcementMiddleware, ipAllowlistMiddleware = saved[3], saved[4], saved[5]
	})

	db := &postgres.DB{DB: sqldb}
	log := logger.NewNop()
	tenantRepo := postgres.NewTenantRepository(db)
	userRepo := postgres.NewUserRepository(db)
	auditSvc := auditapp.NewAuditService(postgres.NewAuditRepository(db), log)
	tenantSvc := tenant.NewTenantService(tenantRepo, log, tenant.WithTenantAuditService(auditSvc))
	v := validator.New()
	cipher, err := crypto.NewCipher([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	admins := postgres.NewAdminRepository(db)
	adminAudit := postgres.NewAuditLogRepository(db)
	orgs := postgres.NewAdminOrganizationRepository(db)
	signIns := chainSignIns{}
	console := adminconsole.NewService(admins, postgres.NewAdminConsoleRepository(db), adminAudit, cipher, signIns, log)

	gen := jwt.NewGenerator(jwt.TokenConfig{Secret: "admin-audit-chain-route-test-secret-0123456789", Issuer: "test",
		AccessTokenDuration: time.Hour, RefreshTokenDuration: time.Hour})
	cfg := &config.Config{}
	cfg.Auth.Provider = config.AuthProviderLocal
	authCfg := AuthConfig{Provider: config.AuthProviderLocal, LocalValidator: gen}

	router := infrahttp.NewChiRouter()
	handlers := Handlers{
		Audit:               handler.NewAuditHandler(auditSvc, v, log),
		Tenant:              handler.NewTenantHandler(tenantSvc, v, log),
		AdminAuth:           handler.NewAdminAuthHandler(log),
		AdminOrganization:   handler.NewAdminOrganizationHandler(orgs, tenantSvc, userRepo, v, log),
		AdminConsole:        handler.NewAdminConsoleHandler(console, false, "refresh_token", log),
		AdminAuditChain:     handler.NewAdminAuditChainHandler(auditSvc, console, adminAudit, orgs, log),
		AdminAuthMiddleware: middleware.NewAdminAuthMiddleware(console, log),
	}
	for _, f := range extra {
		f(&handlers, db)
	}
	Register(router, handlers, cfg, log, authCfg, tenantRepo, tenant.NewUserService(userRepo, log), nil, nil, nil)

	srv := httptest.NewServer(router.(interface{ Handler() http.Handler }).Handler())
	t.Cleanup(srv.Close)
	return &chainHarness{t: t, db: sqldb, srv: srv, gen: gen, audit: auditSvc, signIns: signIns, admins: admins}
}

func (h *chainHarness) exec(q string, args ...any) {
	h.t.Helper()
	if _, err := h.db.ExecContext(context.Background(), q, args...); err != nil {
		h.t.Fatalf("%s: %v", q, err)
	}
}

// organization creates a tenant whose chain has n events, re-signed as kinds.
func (h *chainHarness) organization(n int, kinds ...chaintest.Kind) string {
	h.t.Helper()
	id := uuid.NewString()
	h.exec(`INSERT INTO tenants (id, name, slug) VALUES ($1, 'Audit chain IT', $2)`,
		id, "auditchain-"+strings.ReplaceAll(id[:13], "-", ""))
	h.t.Cleanup(func() {
		ctx := context.Background()
		for _, q := range []string{
			`DELETE FROM audit_chain_rebaseline_entries WHERE tenant_id = $1`,
			`DELETE FROM audit_chain_rebaselines WHERE tenant_id = $1`,
			`DELETE FROM audit_log_chain WHERE tenant_id = $1`,
			`DELETE FROM audit_logs WHERE tenant_id = $1`,
			`DELETE FROM user_roles WHERE tenant_id = $1`,
			`DELETE FROM tenant_members WHERE tenant_id = $1`,
			`DELETE FROM tenants WHERE id = $1`,
		} {
			_, _ = h.db.ExecContext(ctx, q, id)
		}
	})
	h.logEvents(id, n)
	if _, err := chaintest.Resign(context.Background(), h.db, id, kinds...); err != nil {
		h.t.Fatal(err)
	}
	return id
}

func (h *chainHarness) logEvents(tenantID string, n int) {
	h.t.Helper()
	for i := 0; i < n; i++ {
		ev := auditapp.NewSuccessEvent(auditdom.ActionSettingsUpdated, auditdom.ResourceTypeSettings, uuid.NewString())
		if err := h.audit.LogEvent(context.Background(), auditapp.AuditContext{TenantID: tenantID}, ev); err != nil {
			h.t.Fatal(err)
		}
	}
}

// tenantToken mints an organization user's access token as the token exchange
// does (owner/admin carry the admin bypass).
func (h *chainHarness) tenantToken(tenantID, role string) string {
	h.t.Helper()
	uid := uuid.NewString()
	email := "auditchain-" + uid + "@it.test"
	h.exec(`INSERT INTO users (id, email, name) VALUES ($1, $2, 'Audit chain IT')`, uid, email)
	h.t.Cleanup(func() { _, _ = h.db.ExecContext(context.Background(), `DELETE FROM users WHERE id = $1`, uid) })
	h.exec(`INSERT INTO tenant_members (id, user_id, tenant_id, role) VALUES ($1, $2, $3, $4)`,
		uuid.NewString(), uid, tenantID, role)
	isAdmin := role == "owner" || role == "admin"
	tok, err := h.gen.GenerateTenantScopedAccessTokenWithPermissions(uid, email, "IT", uuid.NewString(),
		jwt.TenantMembership{TenantID: tenantID, Role: role}, nil, isAdmin, 0, "password")
	if err != nil {
		h.t.Fatal(err)
	}
	return tok.AccessToken
}

// consoleAdmin is a platform administrator signed in to the console.
type consoleAdmin struct {
	h      *chainHarness
	a      *admin.AdminUser
	userID shared.ID
	jar    *cookiejar.Jar
	client *http.Client
	secret string
	// signInCode is the code that completed the TOTP step.
	signInCode string
}

// newAdmin provisions an administrator linked to a users row in no
// organization and opens the TOTP step of a console session. verify completes
// it.
func (h *chainHarness) newAdmin(role admin.AdminRole) *consoleAdmin {
	h.t.Helper()
	uid := shared.NewID()
	email := "auditchain-admin-" + uid.String() + "@it.test"
	h.exec(`INSERT INTO users (id, email, name) VALUES ($1, $2, 'Chain admin')`, uid.String(), email)
	h.t.Cleanup(func() { _, _ = h.db.ExecContext(context.Background(), `DELETE FROM users WHERE id = $1`, uid.String()) })
	a, err := admin.NewAdminUser(email, "Chain admin", role, nil)
	if err != nil {
		h.t.Fatal(err)
	}
	if err := h.admins.Create(context.Background(), a); err != nil {
		h.t.Fatal(err)
	}
	h.t.Cleanup(func() {
		_, _ = h.db.ExecContext(context.Background(), `DELETE FROM admin_audit_logs WHERE admin_id = $1`, a.ID().String())
		_ = h.admins.Delete(context.Background(), a.ID())
	})
	if err := h.admins.LinkUser(context.Background(), a.ID(), uid); err != nil {
		h.t.Fatal(err)
	}
	refresh := "refresh-" + uid.String()
	h.signIns[refresh] = adminconsole.SignedInUser{UserID: uid, Email: email, Active: true, PasswordSignIn: true}

	jar, _ := cookiejar.New(nil)
	base, _ := url.Parse(h.srv.URL + "/")
	jar.SetCookies(base, []*http.Cookie{{Name: "refresh_token", Value: refresh, Path: "/"}})
	c := &consoleAdmin{h: h, a: a, userID: uid, jar: jar, client: &http.Client{Jar: jar}}
	code, body := c.do(http.MethodPost, "/api/v1/admin/auth/session", nil, true)
	if code != http.StatusOK {
		h.t.Fatalf("console session: %d %s", code, body)
	}
	var login handler.AdminLoginResponse
	_ = json.Unmarshal([]byte(body), &login)
	if login.Secret == "" {
		h.t.Fatalf("expected TOTP enrollment: %s", body)
	}
	c.secret = login.Secret
	return c
}

func (c *consoleAdmin) verify() {
	c.h.t.Helper()
	code, _ := totp.Code(c.secret, time.Now())
	if st, body := c.do(http.MethodPost, "/api/v1/admin/auth/mfa", map[string]string{"code": code}, true); st != http.StatusOK {
		c.h.t.Fatalf("mfa: %d %s", st, body)
	}
	c.signInCode = code
}

// freshCode is a code for a step the replay guard has not seen: the next one,
// or (after resetReplayGuard) the current one.
func (c *consoleAdmin) freshCode(next bool) string {
	at := time.Now()
	if next {
		at = at.Add(totp.Period)
	}
	code, err := totp.Code(c.secret, at)
	if err != nil {
		c.h.t.Fatal(err)
	}
	return code
}

// resetReplayGuard lets the test use another code within one 30-second step.
func (c *consoleAdmin) resetReplayGuard() {
	c.h.exec(`UPDATE admin_credentials SET mfa_last_step = 0 WHERE admin_id = $1`, c.a.ID().String())
}

func (c *consoleAdmin) do(method, path string, body any, csrf bool) (int, string) {
	c.h.t.Helper()
	var r io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		r = strings.NewReader(string(b))
	}
	req, _ := http.NewRequestWithContext(context.Background(), method, c.h.srv.URL+path, r)
	req.Header.Set("Content-Type", "application/json")
	if csrf && method != http.MethodGet {
		u, _ := url.Parse(c.h.srv.URL + "/api/v1/admin/")
		for _, ck := range c.jar.Cookies(u) {
			if ck.Name == middleware.AdminCSRFCookie {
				req.Header.Set(middleware.CSRFHeaderName, ck.Value)
			}
		}
	}
	resp, err := c.client.Do(req)
	if err != nil {
		c.h.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func (c *consoleAdmin) classify(tenantID string) handler.AdminAuditChainStatusResponse {
	c.h.t.Helper()
	code, body := c.do(http.MethodGet, "/api/v1/admin/tenants/"+tenantID+"/audit-chain", nil, false)
	if code != http.StatusOK {
		c.h.t.Fatalf("classify: %d %s", code, body)
	}
	var st handler.AdminAuditChainStatusResponse
	if err := json.Unmarshal([]byte(body), &st); err != nil {
		c.h.t.Fatal(err)
	}
	return st
}

func (c *consoleAdmin) rebaseline(tenantID, fingerprint, code string) (int, string) {
	c.h.t.Helper()
	return c.do(http.MethodPost, "/api/v1/admin/tenants/"+tenantID+"/audit-chain/rebaseline",
		map[string]string{"fingerprint": fingerprint, "totp_code": code}, true)
}

func (h *chainHarness) raw(method, path string, header map[string]string, cookies ...*http.Cookie) int {
	h.t.Helper()
	req, _ := http.NewRequestWithContext(context.Background(), method, h.srv.URL+path, strings.NewReader(`{"fingerprint":"x","totp_code":"123456"}`))
	req.Header.Set("Content-Type", "application/json")
	for k, v := range header {
		req.Header.Set(k, v)
	}
	for _, ck := range cookies {
		req.AddCookie(ck)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		h.t.Fatal(err)
	}
	_ = resp.Body.Close()
	return resp.StatusCode
}

func (h *chainHarness) chainHashes(tenantID string) map[string]string {
	h.t.Helper()
	rows, err := h.db.QueryContext(context.Background(), `SELECT audit_log_id, prev_hash || ':' || hash FROM audit_log_chain WHERE tenant_id = $1`, tenantID)
	if err != nil {
		h.t.Fatal(err)
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var id, v string
		if err := rows.Scan(&id, &v); err != nil {
			h.t.Fatal(err)
		}
		out[id] = v
	}
	if err := rows.Err(); err != nil {
		h.t.Fatal(err)
	}
	return out
}

func (h *chainHarness) assertNotRewritten(tenantID string, before map[string]string) {
	h.t.Helper()
	after := h.chainHashes(tenantID)
	for id, v := range before {
		if after[id] != v {
			h.t.Fatalf("chain row %s was rewritten by a refused rebaseline", id)
		}
	}
	var n int
	if err := h.db.QueryRow(`SELECT count(*) FROM audit_chain_rebaselines WHERE tenant_id = $1`, tenantID).Scan(&n); err != nil || n != 0 {
		h.t.Fatalf("a refused rebaseline archived %d rows (err %v)", n, err)
	}
}

func TestAdminAuditChain_OrganizationUsersCannotReachIt_DB(t *testing.T) {
	h := newChainHarness(t)
	org := h.organization(3, chaintest.Legacy)
	classify := "/api/v1/admin/tenants/" + org + "/audit-chain"
	rebaseline := classify + "/rebaseline"

	for _, role := range []string{"owner", "admin", "member"} {
		tok := h.tenantToken(org, role)
		bearer := map[string]string{"Authorization": "Bearer " + tok}
		if got := h.raw(http.MethodGet, classify, bearer); got != http.StatusUnauthorized {
			t.Fatalf("%s token GET classify: %d, want 401", role, got)
		}
		if got := h.raw(http.MethodPost, rebaseline, bearer); got != http.StatusUnauthorized {
			t.Fatalf("%s token POST rebaseline: %d, want 401", role, got)
		}
		// The tenant token presented as a console session is not one either.
		asCookie := &http.Cookie{Name: middleware.AdminSessionCookie, Value: tok}
		csrf := &http.Cookie{Name: middleware.AdminCSRFCookie, Value: "c"}
		if got := h.raw(http.MethodPost, rebaseline, map[string]string{middleware.CSRFHeaderName: "c"}, asCookie, csrf); got != http.StatusUnauthorized {
			t.Fatalf("%s token as console cookie: %d, want 401", role, got)
		}
	}
	if n := len(h.chainHashes(org)); n != 3 {
		t.Fatalf("chain has %d rows, want the 3 seeded (nothing was attempted)", n)
	}
}

func TestAdminAuditChain_ConsoleGates_DB(t *testing.T) {
	h := newChainHarness(t)
	org := h.organization(3, chaintest.Legacy)
	path := "/api/v1/admin/tenants/" + org + "/audit-chain"

	// An administrator who has not passed the TOTP step: the pending token is
	// not a console session. (Presenting it ends it, so this administrator is
	// not used further.)
	pendingAdmin := h.newAdmin(admin.AdminRoleSuperAdmin)
	var pending string
	au, _ := url.Parse(h.srv.URL + "/api/v1/admin/auth/")
	for _, ck := range pendingAdmin.jar.Cookies(au) {
		if ck.Name == middleware.AdminMFACookie {
			pending = ck.Value
		}
	}
	if pending == "" {
		t.Fatal("no pending console cookie issued")
	}
	if got := h.raw(http.MethodGet, path, nil, &http.Cookie{Name: middleware.AdminSessionCookie, Value: pending}); got != http.StatusUnauthorized {
		t.Fatalf("pending session GET: %d, want 401", got)
	}
	if got := h.raw(http.MethodPost, path+"/rebaseline", map[string]string{middleware.CSRFHeaderName: "c"},
		&http.Cookie{Name: middleware.AdminSessionCookie, Value: pending},
		&http.Cookie{Name: middleware.AdminCSRFCookie, Value: "c"}); got != http.StatusUnauthorized {
		t.Fatalf("pending session POST: %d, want 401", got)
	}

	// A readonly administrator reviews but cannot rebaseline.
	ro := h.newAdmin(admin.AdminRoleReadonly)
	ro.verify()
	st := ro.classify(org)
	if st.Counts.LegacyTruncate != 1 || !st.RebaselineAllowed {
		t.Fatalf("classification: %+v", st)
	}
	if code, body := ro.rebaseline(org, st.Fingerprint, ro.freshCode(true)); code != http.StatusForbidden {
		t.Fatalf("readonly rebaseline: %d %s, want 403", code, body)
	}

	// A super admin: CSRF still applies, and the authenticator code is required.
	su := h.newAdmin(admin.AdminRoleSuperAdmin)
	su.verify()
	st = su.classify(org)
	before := h.chainHashes(org)
	if code, _ := su.do(http.MethodPost, path+"/rebaseline",
		map[string]string{"fingerprint": st.Fingerprint, "totp_code": su.freshCode(true)}, false); code != http.StatusUnauthorized {
		t.Fatalf("rebaseline without the CSRF header: %d, want 401", code)
	}
	if code, body := su.rebaseline(org, st.Fingerprint, ""); code != http.StatusUnauthorized || !strings.Contains(body, "STEP_UP_REQUIRED") {
		t.Fatalf("rebaseline without a code: %d %s", code, body)
	}
	if code, _ := su.rebaseline(org, st.Fingerprint, "000000"); code != http.StatusUnauthorized {
		t.Fatalf("rebaseline with a wrong code: %d, want 401", code)
	}
	// The code that opened the session is spent.
	if code, _ := su.rebaseline(org, st.Fingerprint, su.signInCode); code != http.StatusUnauthorized {
		t.Fatalf("rebaseline with the sign-in code: %d, want 401", code)
	}
	h.assertNotRewritten(org, before)
	var failures int
	_ = h.db.QueryRow(`SELECT count(*) FROM admin_audit_logs WHERE admin_id = $1 AND action = $2`,
		su.a.ID().String(), adminconsole.ActionStepUpFailed).Scan(&failures)
	if failures != 2 {
		t.Fatalf("step-up failures audited: %d, want 2", failures)
	}
	// A wrong code leaves nothing on the organization's chain.
	if n := len(h.chainHashes(org)); n != 3 {
		t.Fatalf("chain has %d rows after refused step-ups, want 3", n)
	}
}

func TestAdminAuditChain_RefusesAndThenReSigns_DB(t *testing.T) {
	h := newChainHarness(t)
	org := h.organization(6, chaintest.Current, chaintest.Legacy, chaintest.Pre79, chaintest.Legacy, chaintest.Current, chaintest.Pre79)
	tampered := h.organization(4, chaintest.Legacy, chaintest.Bogus)
	su := h.newAdmin(admin.AdminRoleSuperAdmin)
	su.verify()

	// 1. The chain changed after the administrator reviewed it.
	reviewed := su.classify(org)
	if reviewed.Breaks != 4 || reviewed.Counts.LegacyTruncate != 2 || reviewed.Counts.PreHashReduction != 2 || !reviewed.RebaselineAllowed {
		t.Fatalf("classification: %+v", reviewed)
	}
	h.logEvents(org, 1)
	before := h.chainHashes(org)
	stepUp := su.freshCode(true)
	code, body := su.rebaseline(org, reviewed.Fingerprint, stepUp)
	if code != http.StatusConflict || !strings.Contains(body, "AUDIT_CHAIN_CHANGED") {
		t.Fatalf("stale fingerprint: %d %s", code, body)
	}
	h.assertNotRewritten(org, before)
	// The same code cannot be used twice.
	if code, _ := su.rebaseline(org, reviewed.Fingerprint, stepUp); code != http.StatusUnauthorized {
		t.Fatalf("reused step-up code: %d, want 401", code)
	}

	// 2. An unexplained break: refused with the rows that block it.
	su.resetReplayGuard()
	st := su.classify(tampered)
	if st.Counts.Unexplained != 1 || st.RebaselineAllowed {
		t.Fatalf("tampered classification: %+v", st)
	}
	before = h.chainHashes(tampered)
	code, body = su.rebaseline(tampered, st.Fingerprint, su.freshCode(false))
	if code != http.StatusConflict || !strings.Contains(body, "AUDIT_CHAIN_UNEXPLAINED") {
		t.Fatalf("unexplained: %d %s", code, body)
	}
	var refusal struct {
		Details handler.AdminAuditChainStatusResponse `json:"details"`
	}
	if err := json.Unmarshal([]byte(body), &refusal); err != nil || refusal.Details.Counts.Unexplained != 1 {
		t.Fatalf("refusal details: %s (err %v)", body, err)
	}
	h.assertNotRewritten(tampered, before)

	// 3. The reviewed, explained chain is re-signed and verifies.
	su.resetReplayGuard()
	st = su.classify(org)
	code, body = su.rebaseline(org, st.Fingerprint, su.freshCode(false))
	if code != http.StatusOK {
		t.Fatalf("rebaseline: %d %s", code, body)
	}
	var res handler.AdminAuditChainRebaselineResponse
	if err := json.Unmarshal([]byte(body), &res); err != nil {
		t.Fatal(err)
	}
	if !res.OK || res.EntriesRewritten == 0 || res.Verify == nil || !res.Verify.OK || res.Verify.Breaks != 0 {
		t.Fatalf("rebaseline result: %s", body)
	}
	after := su.classify(org)
	if after.Breaks != 0 || after.Counts.Verifies != after.Total {
		t.Fatalf("after rebaseline: %+v", after)
	}

	// Both audit logs carry it: the organization's (on the re-signed chain) and
	// the platform's.
	var n int
	_ = h.db.QueryRow(`SELECT count(*) FROM audit_logs WHERE tenant_id = $1 AND action = 'audit.chain_rebaselined'
		AND result = 'success' AND actor_email = $2 AND metadata->>'rebaseline_id' = $3`,
		org, "platform-admin:"+su.a.Email(), res.RebaselineID).Scan(&n)
	if n != 1 {
		t.Fatalf("organization audit event: %d", n)
	}
	_ = h.db.QueryRow(`SELECT count(*) FROM audit_chain_rebaselines WHERE id = $1 AND actor_id = $2`,
		res.RebaselineID, su.userID.String()).Scan(&n)
	if n != 1 {
		t.Fatalf("archive row naming the administrator's account: %d", n)
	}
	rows, err := h.db.Query(`SELECT success, request_body::text FROM admin_audit_logs
		WHERE admin_id = $1 AND action = $2 AND resource_id = $3 ORDER BY created_at`,
		su.a.ID().String(), handler.AdminActionAuditChainRebaseline, org)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var outcomes []bool
	for rows.Next() {
		var ok bool
		var reqBody string
		if err := rows.Scan(&ok, &reqBody); err != nil {
			t.Fatal(err)
		}
		if strings.Contains(reqBody, "totp") {
			t.Fatalf("the admin audit row must not carry the code: %s", reqBody)
		}
		outcomes = append(outcomes, ok)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if len(outcomes) != 2 || outcomes[0] || !outcomes[1] {
		t.Fatalf("platform audit rows for the organization (refused, then done): %v", outcomes)
	}
}

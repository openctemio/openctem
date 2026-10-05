package routes

// `oct_` API keys on the tenant REST routes, over the real route registration
// (Register: auth chain, membership gate, CSRF, IP allowlist, the real
// /api/v1/api-keys routes) and the real apikey service against a migrated
// database.

import (
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	_ "github.com/lib/pq"

	"github.com/openctemio/openctem/api/internal/app"
	"github.com/openctemio/openctem/api/internal/app/apikey"
	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/internal/config"
	infrahttp "github.com/openctemio/openctem/api/internal/infra/http"
	"github.com/openctemio/openctem/api/internal/infra/http/handler"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/internal/testdb"
	auditdom "github.com/openctemio/openctem/api/pkg/domain/audit"
	"github.com/openctemio/openctem/api/pkg/domain/permission"
	"github.com/openctemio/openctem/api/pkg/domain/role"
	"github.com/openctemio/openctem/api/pkg/jwt"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/validator"
)

const (
	keyTestSysAdmin  = "00000000-0000-0000-0000-000000000002"
	keyTestSysViewer = "00000000-0000-0000-0000-000000000004"
)

// rolePermissionSource reads a user's permissions straight from the role
// tables, as PermissionCacheService does on a cache miss.
type rolePermissionSource struct{ roles *postgres.RoleRepository }

func (s rolePermissionSource) GetPermissionsWithFallback(ctx context.Context, tenantID, userID string) ([]string, error) {
	tid, err := role.ParseID(tenantID)
	if err != nil {
		return nil, err
	}
	uid, err := role.ParseID(userID)
	if err != nil {
		return nil, err
	}
	return s.roles.GetUserPermissions(ctx, tid, uid)
}

type keyRESTHarness struct {
	t     *testing.T
	db    *sql.DB
	srv   *httptest.Server
	keys  *apikey.Service
	gen   *jwt.Generator
	audit *auditapp.AuditService
}

// probeView is what the probe route reports about the request's principal.
type probeView struct {
	Tenant     string   `json:"tenant"`
	User       string   `json:"user"`
	Perms      []string `json:"perms"`
	KeyID      string   `json:"key_id"`
	CookieAuth bool     `json:"cookie_auth"`
	Admin      bool     `json:"admin"`
}

func newKeyRESTHarness(t *testing.T) *keyRESTHarness {
	t.Helper()
	dbURL := testdb.URL()
	if dbURL == "" {
		t.Skip("DATABASE_URL not set; skipping API-key REST route test")
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
	saved := []any{apiKeyOrJWT, csrfProtectionMiddleware, readRateLimitMiddleware, activeMembershipFromJWTMiddleware,
		permissionSyncMiddleware, ssoEnforcementMiddleware, ipAllowlistMiddleware}
	t.Cleanup(func() {
		apiKeyOrJWT = saved[0].(func(func(http.Handler) http.Handler) func(http.Handler) http.Handler)
		csrfProtectionMiddleware, _ = saved[1].(Middleware)
		readRateLimitMiddleware, _ = saved[2].(Middleware)
		activeMembershipFromJWTMiddleware, _ = saved[3].(Middleware)
		permissionSyncMiddleware, _ = saved[4].(Middleware)
		ssoEnforcementMiddleware, _ = saved[5].(Middleware)
		ipAllowlistMiddleware, _ = saved[6].(Middleware)
	})

	db := &postgres.DB{DB: sqldb}
	log := logger.NewNop()
	tenantRepo := postgres.NewTenantRepository(db)
	userRepo := postgres.NewUserRepository(db)

	keys := apikey.NewService(postgres.NewAPIKeyRepository(db), "route-test-pepper", log)
	keys.SetMembershipChecker(apikey.NewMembershipChecker(tenantRepo, userRepo))
	keys.SetHolderPermissions(apikey.NewHolderPermissions(tenantRepo, rolePermissionSource{postgres.NewRoleRepository(db)}))
	auditSvc := auditapp.NewAuditService(postgres.NewAuditRepository(db), log)

	gen := jwt.NewGenerator(jwt.TokenConfig{Secret: "apikey-rest-route-test-secret-0123456789abcdef", Issuer: "test",
		AccessTokenDuration: time.Hour, RefreshTokenDuration: time.Hour})
	cfg := &config.Config{}
	cfg.Auth.Provider = config.AuthProviderLocal
	authCfg := AuthConfig{Provider: config.AuthProviderLocal, LocalValidator: gen}
	userSvc := app.NewUserService(userRepo, log)

	router := infrahttp.NewChiRouter()
	keyAuth := middleware.NewAPIKeyAuth(keys, log)
	Register(router, Handlers{
		APIKey:     handler.NewAPIKeyHandler(keys, validator.New(), log),
		APIKeyAuth: keyAuth,
		// The real MCP mount, as cmd/server wires it (one authenticator for
		// REST and MCP). No data services: the tests only call initialize.
		MCP:     handler.NewMCPHandler(nil, nil, nil, nil, nil, nil, nil, log),
		MCPAuth: keyAuth.Handler,
	}, cfg, log, authCfg, tenantRepo, userSvc, nil, nil, nil)

	// A tenant data route on the real token-tenant chain.
	jwtAuth := middleware.UnifiedAuth(middleware.UnifiedAuthConfig{Provider: config.AuthProviderLocal, LocalValidator: gen, Logger: log})
	probe := func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		_ = auditSvc.LogEvent(ctx, auditapp.AuditContext{TenantID: middleware.GetTenantID(ctx), ActorID: middleware.GetUserID(ctx)},
			auditapp.NewSuccessEvent(auditdom.ActionMCPToolCalled, auditdom.ResourceTypeMCPTool, "rest-probe"))
		_ = json.NewEncoder(w).Encode(probeView{
			Tenant: middleware.GetTenantID(ctx), User: middleware.GetUserID(ctx), Perms: middleware.GetPermissions(ctx),
			KeyID: middleware.GetAPIKeyID(ctx), CookieAuth: middleware.IsCookieAuthenticated(ctx), Admin: middleware.IsAdmin(ctx),
		})
	}
	router.Group("/api/v1/key-probe", func(r Router) {
		r.GET("/", probe, middleware.Require(permission.AssetsRead))
		r.POST("/", probe, middleware.Require(permission.AssetsRead))
		r.GET("/audit", probe, middleware.Require(permission.AuditRead))
	}, buildTokenTenantMiddlewares(jwtAuth, middleware.UserSync(userSvc, log))...)

	srv := httptest.NewServer(router.(interface{ Handler() http.Handler }).Handler())
	t.Cleanup(srv.Close)
	return &keyRESTHarness{t: t, db: sqldb, srv: srv, keys: keys, gen: gen, audit: auditSvc}
}

func (h *keyRESTHarness) exec(q string, args ...any) {
	h.t.Helper()
	if _, err := h.db.ExecContext(context.Background(), q, args...); err != nil {
		h.t.Fatalf("%s: %v", q, err)
	}
}

// tenant creates a tenant with the given settings JSON.
func (h *keyRESTHarness) tenant(settings string) string {
	h.t.Helper()
	id := uuid.NewString()
	h.exec(`INSERT INTO tenants (id, name, slug, settings) VALUES ($1, 'API key REST IT', $2, $3::jsonb)`,
		id, "akrest-"+strings.ReplaceAll(id[:13], "-", ""), settings)
	h.t.Cleanup(func() {
		ctx := context.Background()
		for _, q := range []string{
			`DELETE FROM audit_log_chain WHERE tenant_id = $1`,
			`DELETE FROM audit_logs WHERE tenant_id = $1`,
			`DELETE FROM api_keys WHERE tenant_id = $1`,
			`DELETE FROM user_roles WHERE tenant_id = $1`,
			`DELETE FROM tenant_members WHERE tenant_id = $1`,
			`DELETE FROM tenants WHERE id = $1`,
		} {
			_, _ = h.db.ExecContext(ctx, q, id)
		}
	})
	return id
}

// member creates a user with the given membership role in tenantID. The
// tenant_members trigger grants the matching system role, as in production.
func (h *keyRESTHarness) member(tenantID, membershipRole string) string {
	h.t.Helper()
	id := uuid.NewString()
	h.exec(`INSERT INTO users (id, email, name) VALUES ($1, $2, 'API key REST IT')`, id, "akrest-"+id[:8]+"@it.test")
	h.t.Cleanup(func() { _, _ = h.db.ExecContext(context.Background(), `DELETE FROM users WHERE id = $1`, id) })
	h.exec(`INSERT INTO tenant_members (user_id, tenant_id, role) VALUES ($1, $2, $3)`, id, tenantID, membershipRole)
	return id
}

func (h *keyRESTHarness) mint(tenantID, userID string, rateLimit int, scopes ...string) (string, string) {
	h.t.Helper()
	res, err := h.keys.Create(context.Background(), apikey.CreateInput{
		TenantID: tenantID, UserID: userID, Name: "rest-it-" + uuid.NewString()[:8], Scopes: scopes, RateLimit: rateLimit,
		ExpiresInDays: 90,
	})
	if err != nil {
		h.t.Fatalf("mint key: %v", err)
	}
	return res.Plaintext, res.Key.ID().String()
}

type keyReq struct {
	method, path string
	headers      map[string]string
	cookies      []*http.Cookie
}

func (h *keyRESTHarness) do(rq keyReq) (int, string) {
	h.t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), rq.method, h.srv.URL+rq.path, strings.NewReader("{}"))
	if err != nil {
		h.t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range rq.headers {
		req.Header.Set(k, v)
	}
	for _, c := range rq.cookies {
		req.AddCookie(c)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		h.t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(body)
}

func (h *keyRESTHarness) probeWithKey(key string) (int, probeView) {
	h.t.Helper()
	code, body := h.do(keyReq{method: http.MethodGet, path: "/api/v1/key-probe", headers: map[string]string{"Authorization": "Bearer " + key}})
	var v probeView
	if code == http.StatusOK {
		if err := json.Unmarshal([]byte(body), &v); err != nil {
			h.t.Fatalf("probe body %q: %v", body, err)
		}
	}
	return code, v
}

func TestAPIKeyREST_DB(t *testing.T) {
	h := newKeyRESTHarness(t)
	tenantID := h.tenant(`{}`)
	userID := h.member(tenantID, "member")
	key, keyID := h.mint(tenantID, userID, 0, "assets:read", "assets:write", "findings:read")
	bearer := map[string]string{"Authorization": "Bearer " + key}

	t.Run("key reads as its tenant and user, with its scopes only", func(t *testing.T) {
		code, v := h.probeWithKey(key)
		if code != http.StatusOK {
			t.Fatalf("GET with key: %d", code)
		}
		if v.Tenant != tenantID || v.User != userID || v.KeyID != keyID {
			t.Fatalf("principal = %+v, want tenant %s user %s key %s", v, tenantID, userID, keyID)
		}
		slices.Sort(v.Perms)
		if !slices.Equal(v.Perms, []string{"assets:read", "assets:write", "findings:read"}) {
			t.Errorf("perms = %v, want exactly the key's scopes", v.Perms)
		}
		if v.Admin || v.CookieAuth {
			t.Errorf("key request must be neither admin nor cookie-authenticated: %+v", v)
		}
	})

	t.Run("X-API-Key header works too", func(t *testing.T) {
		code, _ := h.do(keyReq{method: http.MethodGet, path: "/api/v1/key-probe", headers: map[string]string{"X-API-Key": key}})
		if code != http.StatusOK {
			t.Fatalf("GET with X-API-Key: %d", code)
		}
	})

	t.Run("last_used is recorded", func(t *testing.T) {
		var uses int64
		var lastUsed sql.NullTime
		if err := h.db.QueryRow(`SELECT use_count, last_used_at FROM api_keys WHERE id = $1`, keyID).Scan(&uses, &lastUsed); err != nil {
			t.Fatal(err)
		}
		if uses < 2 || !lastUsed.Valid {
			t.Errorf("use_count=%d last_used_at=%v, want touched", uses, lastUsed)
		}
	})

	t.Run("audit entry carries the key and its user", func(t *testing.T) {
		var actor sql.NullString
		var meta []byte
		err := h.db.QueryRow(`SELECT actor_id::text, metadata FROM audit_logs WHERE tenant_id = $1 AND resource_id = 'rest-probe'
			ORDER BY logged_at DESC LIMIT 1`, tenantID).Scan(&actor, &meta)
		if err != nil {
			t.Fatalf("audit row: %v", err)
		}
		var m map[string]any
		_ = json.Unmarshal(meta, &m)
		if actor.String != userID || m["api_key_id"] != keyID || m["auth_method"] != "api_key" {
			t.Errorf("audit actor=%q metadata=%v, want user %s and key %s", actor.String, m, userID, keyID)
		}
	})

	t.Run("writes are refused even with a write scope", func(t *testing.T) {
		for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete} {
			code, body := h.do(keyReq{method: method, path: "/api/v1/key-probe", headers: bearer})
			if method == http.MethodPost && (code != http.StatusForbidden || !strings.Contains(body, "read-only")) {
				t.Errorf("POST with key: %d %s, want 403 read-only", code, body)
			}
			if code == http.StatusOK {
				t.Errorf("%s with key reached the handler", method)
			}
		}
	})

	t.Run("key management and self routes refuse keys", func(t *testing.T) {
		for _, p := range []string{"/api/v1/api-keys", "/api/v1/api-keys/" + keyID, "/api/v1/api-keys/" + keyID + "/revoke"} {
			for _, method := range []string{http.MethodGet, http.MethodPost} {
				code, _ := h.do(keyReq{method: method, path: p, headers: bearer})
				if code != http.StatusForbidden {
					t.Errorf("%s %s with key: %d, want 403", method, p, code)
				}
			}
		}
		var n int
		_ = h.db.QueryRow(`SELECT count(*) FROM api_keys WHERE tenant_id = $1`, tenantID).Scan(&n)
		if n != 1 {
			t.Errorf("a key minted another key: %d keys in tenant", n)
		}
	})

	t.Run("cookie session plus key: the key alone decides", func(t *testing.T) {
		admin := h.member(tenantID, "admin")
		tok, err := h.gen.GenerateTenantScopedAccessToken(admin, "a@it.test", "Admin", uuid.NewString(),
			jwt.TenantMembership{TenantID: tenantID, Role: "admin"}, true, 0, "password")
		if err != nil {
			t.Fatal(err)
		}
		session := &http.Cookie{Name: middleware.DefaultAccessTokenCookieName, Value: tok.AccessToken}
		csrf := &http.Cookie{Name: middleware.CSRFTokenCookieName, Value: "csrf-pair"}

		// The session on its own still works, and still needs CSRF to write.
		if code, _ := h.do(keyReq{method: http.MethodGet, path: "/api/v1/key-probe", cookies: []*http.Cookie{session}}); code != http.StatusOK {
			t.Fatalf("cookie session GET: %d", code)
		}
		if code, _ := h.do(keyReq{method: http.MethodPost, path: "/api/v1/key-probe", cookies: []*http.Cookie{session}}); code != http.StatusForbidden {
			t.Errorf("cookie POST without CSRF: %d, want 403", code)
		}
		if code, _ := h.do(keyReq{method: http.MethodPost, path: "/api/v1/key-probe", cookies: []*http.Cookie{session, csrf},
			headers: map[string]string{"X-CSRF-Token": "csrf-pair"}}); code != http.StatusOK {
			t.Errorf("cookie POST with CSRF: %d, want 200", code)
		}

		// With a key, the request is the key's, never the admin session's.
		code, body := h.do(keyReq{method: http.MethodGet, path: "/api/v1/key-probe", headers: bearer, cookies: []*http.Cookie{session}})
		var v probeView
		_ = json.Unmarshal([]byte(body), &v)
		if code != http.StatusOK || v.User != userID || v.Admin || v.CookieAuth || v.KeyID != keyID {
			t.Errorf("cookie+key GET = %d %+v, want the key's principal", code, v)
		}
		// A bad key does not fall back to the session.
		if code, _ := h.do(keyReq{method: http.MethodGet, path: "/api/v1/key-probe",
			headers: map[string]string{"Authorization": "Bearer oct_not-a-real-key"}, cookies: []*http.Cookie{session}}); code != http.StatusUnauthorized {
			t.Errorf("cookie + bad key: %d, want 401", code)
		}
		// A key cannot carry a cookie session's write past CSRF or read-only.
		if code, _ := h.do(keyReq{method: http.MethodPost, path: "/api/v1/key-probe", cookies: []*http.Cookie{session, csrf},
			headers: map[string]string{"X-CSRF-Token": "csrf-pair", "X-API-Key": key}}); code != http.StatusForbidden {
			t.Errorf("cookie + CSRF + key POST: %d, want 403", code)
		}
	})

	t.Run("demotion narrows the key at once", func(t *testing.T) {
		h.exec(`DELETE FROM user_roles WHERE user_id = $1 AND tenant_id = $2`, userID, tenantID)
		h.exec(`INSERT INTO user_roles (user_id, tenant_id, role_id) VALUES ($1, $2, $3)`, userID, tenantID, keyTestSysViewer)
		code, v := h.probeWithKey(key)
		if code != http.StatusOK {
			t.Fatalf("viewer key GET: %d", code)
		}
		if slices.Contains(v.Perms, "assets:write") || !slices.Contains(v.Perms, "assets:read") {
			t.Errorf("after demotion to viewer perms = %v, want assets:write dropped", v.Perms)
		}
		h.exec(`DELETE FROM user_roles WHERE user_id = $1 AND tenant_id = $2`, userID, tenantID)
		if code, _ := h.probeWithKey(key); code != http.StatusForbidden {
			t.Errorf("key of a user with no roles: %d, want 403", code)
		}
		h.exec(`INSERT INTO user_roles (user_id, tenant_id, role_id) VALUES ($1, $2, $3)`, userID, tenantID, keyTestSysViewer)
	})

	t.Run("suspended member and inactive account stop the key", func(t *testing.T) {
		h.exec(`UPDATE tenant_members SET status = 'suspended' WHERE user_id = $1 AND tenant_id = $2`, userID, tenantID)
		if code, _ := h.probeWithKey(key); code != http.StatusUnauthorized {
			t.Errorf("suspended member's key: %d, want 401", code)
		}
		h.exec(`UPDATE tenant_members SET status = 'active' WHERE user_id = $1 AND tenant_id = $2`, userID, tenantID)
		h.exec(`UPDATE users SET status = 'suspended' WHERE id = $1`, userID)
		if code, _ := h.probeWithKey(key); code != http.StatusUnauthorized {
			t.Errorf("suspended account's key: %d, want 401", code)
		}
		h.exec(`UPDATE users SET status = 'active' WHERE id = $1`, userID)
		if code, _ := h.probeWithKey(key); code != http.StatusOK {
			t.Errorf("reactivated key: %d, want 200", code)
		}
	})

	t.Run("expired and revoked keys are refused", func(t *testing.T) {
		h.exec(`UPDATE api_keys SET expires_at = NOW() - INTERVAL '1 hour' WHERE id = $1`, keyID)
		if code, _ := h.probeWithKey(key); code != http.StatusUnauthorized {
			t.Errorf("expired key: %d, want 401", code)
		}
		h.exec(`UPDATE api_keys SET expires_at = NULL, status = 'revoked', revoked_at = NOW() WHERE id = $1`, keyID)
		if code, _ := h.probeWithKey(key); code != http.StatusUnauthorized {
			t.Errorf("revoked key: %d, want 401", code)
		}
	})

	t.Run("per-key rate limit", func(t *testing.T) {
		limited, _ := h.mint(tenantID, h.member(tenantID, "admin"), 2, "assets:read")
		codes := []int{}
		for range 3 {
			c, _ := h.probeWithKey(limited)
			codes = append(codes, c)
		}
		if !slices.Equal(codes, []int{200, 200, 429}) {
			t.Errorf("codes = %v, want [200 200 429]", codes)
		}
	})

	t.Run("organization IP allowlist binds keys", func(t *testing.T) {
		fenced := h.tenant(`{"security":{"ip_whitelist":["203.0.113.0/24"]}}`)
		k, _ := h.mint(fenced, h.member(fenced, "admin"), 0, "assets:read")
		if code, _ := h.probeWithKey(k); code != http.StatusForbidden {
			t.Errorf("key from outside the allowlist: %d, want 403", code)
		}
	})

	// 23b S-H2: MCP used to run only [rate limit, key auth], so a key REST
	// refused for its network kept reading through MCP. Same key, same
	// refusal on both surfaces; an allowed network works on both.
	t.Run("organization IP allowlist binds keys on MCP exactly as on REST", func(t *testing.T) {
		mcp := func(key string) (int, string) {
			return h.do(keyReq{method: http.MethodPost, path: "/api/v1/mcp",
				headers: map[string]string{"Authorization": "Bearer " + key}})
		}
		initialize := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`
		mcpInit := func(key string) (int, string) {
			req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, h.srv.URL+"/api/v1/mcp", strings.NewReader(initialize))
			if err != nil {
				t.Fatal(err)
			}
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Authorization", "Bearer "+key)
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			body, _ := io.ReadAll(resp.Body)
			return resp.StatusCode, string(body)
		}

		fenced := h.tenant(`{"security":{"ip_whitelist":["203.0.113.0/24"]}}`)
		blocked, _ := h.mint(fenced, h.member(fenced, "member"), 0, "assets:read", "findings:read")
		restCode, restBody := h.do(keyReq{method: http.MethodGet, path: "/api/v1/key-probe", headers: map[string]string{"Authorization": "Bearer " + blocked}})
		mcpCode, mcpBody := mcp(blocked)
		if restCode != http.StatusForbidden || !strings.Contains(restBody, string(middleware.CodeIPNotAllowed)) {
			t.Fatalf("REST from outside the allowlist: %d %s, want 403 %s", restCode, restBody, middleware.CodeIPNotAllowed)
		}
		if mcpCode != restCode || mcpBody != restBody {
			t.Errorf("MCP from outside the allowlist = %d %s, want the REST refusal %d %s", mcpCode, mcpBody, restCode, restBody)
		}

		// The test client connects from loopback: an allowlist that includes
		// it, and no allowlist at all, both let the key through on MCP.
		for name, settings := range map[string]string{
			"allowed network": `{"security":{"ip_whitelist":["127.0.0.1/32","::1/128"]}}`,
			"no allowlist":    `{}`,
		} {
			tid := h.tenant(settings)
			k, _ := h.mint(tid, h.member(tid, "member"), 0, "assets:read", "findings:read")
			code, body := mcpInit(k)
			if code != http.StatusOK || !strings.Contains(body, `"result"`) {
				t.Errorf("%s: MCP initialize = %d %s, want 200 with a result", name, code, body)
			}
		}
	})

	t.Run("admin's key keeps its scopes but is never admin", func(t *testing.T) {
		admin := h.member(tenantID, "admin")
		h.exec(`INSERT INTO user_roles (user_id, tenant_id, role_id) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING`, admin, tenantID, keyTestSysAdmin)
		k, _ := h.mint(tenantID, admin, 0, "assets:read")
		code, v := h.probeWithKey(k)
		if code != http.StatusOK || v.Admin || !slices.Equal(v.Perms, []string{"assets:read"}) {
			t.Errorf("admin key = %d %+v, want only assets:read and no admin bypass", code, v)
		}
		// Not in its scopes: refused even though the user is an admin.
		if code, _ := h.do(keyReq{method: http.MethodGet, path: "/api/v1/key-probe/audit", headers: map[string]string{"X-API-Key": k}}); code != http.StatusForbidden {
			t.Errorf("admin key on a route outside its scopes: %d, want 403", code)
		}
	})
}

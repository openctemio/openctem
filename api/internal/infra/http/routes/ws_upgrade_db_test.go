package routes

// The real-time WebSocket upgrade (/api/v1/ws) over the real route
// registration (Register) against a migrated database (RFC-045): the session
// cookie authenticates it, through the same tenant chain as any tenant route
// (SSO enforcement, organization IP allowlist, active membership, revoked
// sessions), behind the Origin allowlist. No credential travels in the URL.

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	gws "github.com/gorilla/websocket"
	_ "github.com/lib/pq"

	tenantapp "github.com/openctemio/openctem/api/internal/app/tenant"
	"github.com/openctemio/openctem/api/internal/config"
	infrahttp "github.com/openctemio/openctem/api/internal/infra/http"
	"github.com/openctemio/openctem/api/internal/infra/http/handler"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/internal/infra/websocket"
	"github.com/openctemio/openctem/api/internal/testdb"
	"github.com/openctemio/openctem/api/pkg/jwt"
	"github.com/openctemio/openctem/api/pkg/logger"
)

const wsUIOrigin = "https://ui.example.test"

// memRevokedSessions stands in for the Redis session revocation store.
type memRevokedSessions struct {
	mu      sync.Mutex
	revoked map[string]bool
}

func (m *memRevokedSessions) IsSessionRevoked(_ context.Context, sid string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.revoked[sid], nil
}

type wsUpgradeHarness struct {
	t        *testing.T
	db       *sql.DB
	srv      *httptest.Server
	gen      *jwt.Generator
	sessions *memRevokedSessions
}

func newWSUpgradeHarness(t *testing.T) *wsUpgradeHarness {
	t.Helper()
	dbURL := testdb.URL()
	if dbURL == "" {
		t.Skip("DATABASE_URL not set; skipping WS upgrade route test")
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
		apiKeyOrJWT, _ = saved[0].(func(func(http.Handler) http.Handler) func(http.Handler) http.Handler)
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

	gen := jwt.NewGenerator(jwt.TokenConfig{Secret: "ws-upgrade-route-test-secret-0123456789abcdef", Issuer: "test",
		AccessTokenDuration: time.Hour, RefreshTokenDuration: time.Hour})
	cfg := &config.Config{}
	cfg.Auth.Provider = config.AuthProviderLocal
	sessions := &memRevokedSessions{revoked: map[string]bool{}}
	authCfg := AuthConfig{Provider: config.AuthProviderLocal, LocalValidator: gen, RevokedSessions: sessions}

	hub := websocket.NewHub(log)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go hub.Run(ctx)

	router := infrahttp.NewChiRouter()
	Register(router, Handlers{
		// Registered so the test can show /auth/ws-token is gone.
		LocalAuth: handler.NewLocalAuthHandler(nil, nil, nil, nil, cfg.Auth, log),
		WebSocket: websocket.NewHandler(hub, log, []string{wsUIOrigin}, config.EnvProduction),
	}, cfg, log, authCfg, tenantRepo, tenantapp.NewUserService(userRepo, log), nil, nil, nil)

	srv := httptest.NewServer(router.(interface{ Handler() http.Handler }).Handler())
	t.Cleanup(srv.Close)
	return &wsUpgradeHarness{t: t, db: sqldb, srv: srv, gen: gen, sessions: sessions}
}

func (h *wsUpgradeHarness) exec(q string, args ...any) {
	h.t.Helper()
	if _, err := h.db.ExecContext(context.Background(), q, args...); err != nil {
		h.t.Fatalf("%s: %v", q, err)
	}
}

func (h *wsUpgradeHarness) tenant(settings string) string {
	h.t.Helper()
	id := uuid.NewString()
	h.exec(`INSERT INTO tenants (id, name, slug, settings) VALUES ($1, 'WS upgrade IT', $2, $3::jsonb)`,
		id, "wsup-"+strings.ReplaceAll(id[:13], "-", ""), settings)
	h.t.Cleanup(func() {
		ctx := context.Background()
		for _, q := range []string{
			`DELETE FROM user_roles WHERE tenant_id = $1`,
			`DELETE FROM tenant_members WHERE tenant_id = $1`,
			`DELETE FROM tenants WHERE id = $1`,
		} {
			_, _ = h.db.ExecContext(ctx, q, id)
		}
	})
	return id
}

// user creates a user; when tenantID is non-empty it is a member there.
func (h *wsUpgradeHarness) user(tenantID, membershipRole string) string {
	h.t.Helper()
	id := uuid.NewString()
	h.exec(`INSERT INTO users (id, email, name) VALUES ($1, $2, 'WS upgrade IT')`, id, "wsup-"+id[:8]+"@it.test")
	h.t.Cleanup(func() { _, _ = h.db.ExecContext(context.Background(), `DELETE FROM users WHERE id = $1`, id) })
	if tenantID != "" {
		h.exec(`INSERT INTO tenant_members (user_id, tenant_id, role) VALUES ($1, $2, $3)`, id, tenantID, membershipRole)
	}
	return id
}

// token mints a password-session access token scoped to tenantID; it returns
// the token and its session id.
func (h *wsUpgradeHarness) token(userID, tenantID string) (string, string) {
	h.t.Helper()
	sid := uuid.NewString()
	tok, err := h.gen.GenerateTenantScopedAccessToken(userID, "wsup@it.test", "WS", sid,
		jwt.TenantMembership{TenantID: tenantID, Role: "member"}, false, 0, "password")
	if err != nil {
		h.t.Fatal(err)
	}
	return tok.AccessToken, sid
}

type dialOpts struct {
	cookie, bearer, origin, query string
}

// dial opens /ws. Returns the connection (nil on refusal) and the HTTP status
// of the upgrade response.
func (h *wsUpgradeHarness) dial(o dialOpts) (*gws.Conn, int) {
	h.t.Helper()
	u := "ws" + strings.TrimPrefix(h.srv.URL, "http") + "/api/v1/ws/" + o.query
	hdr := http.Header{}
	if o.cookie != "" {
		hdr.Set("Cookie", middleware.DefaultAccessTokenCookieName+"="+o.cookie)
	}
	if o.bearer != "" {
		hdr.Set("Authorization", "Bearer "+o.bearer)
	}
	if o.origin != "" {
		hdr.Set("Origin", o.origin)
	}
	conn, resp, err := gws.DefaultDialer.Dial(u, hdr)
	if resp != nil && resp.Body != nil {
		defer resp.Body.Close()
	}
	if err != nil {
		if resp == nil {
			h.t.Fatalf("dial: %v", err)
		}
		return nil, resp.StatusCode
	}
	h.t.Cleanup(func() { _ = conn.Close() })
	return conn, resp.StatusCode
}

// subscribe asks for a channel and returns the reply type.
func subscribe(t *testing.T, conn *gws.Conn, channel string) string {
	t.Helper()
	data, _ := json.Marshal(websocket.SubscribeRequest{Channel: channel, RequestID: channel})
	if err := conn.WriteJSON(websocket.Message{Type: websocket.MessageTypeSubscribe, Data: data}); err != nil {
		t.Fatal(err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	for {
		var msg websocket.Message
		if err := conn.ReadJSON(&msg); err != nil {
			t.Fatalf("read reply for %s: %v", channel, err)
		}
		if msg.Type == websocket.MessageTypeSubscribed || msg.Type == websocket.MessageTypeError {
			return string(msg.Type)
		}
	}
}

func TestWSUpgrade_CookieSessionAndTenantGates_DB(t *testing.T) {
	h := newWSUpgradeHarness(t)

	open := h.tenant(`{}`)
	member := h.user(open, "member")
	memberTok, _ := h.token(member, open)

	t.Run("upgrade without a session is refused", func(t *testing.T) {
		if conn, status := h.dial(dialOpts{origin: wsUIOrigin}); conn != nil || status != http.StatusUnauthorized {
			t.Fatalf("no session: status %d, want 401", status)
		}
	})

	t.Run("a ticket in the URL is not a credential", func(t *testing.T) {
		q := "?ticket=" + strings.Repeat("ab", 32) + "&token=" + memberTok
		if conn, status := h.dial(dialOpts{origin: wsUIOrigin, query: q}); conn != nil || status != http.StatusUnauthorized {
			t.Fatalf("query credentials only: status %d, want 401", status)
		}
	})

	t.Run("session cookie and allowed Origin connect; channel authorization holds", func(t *testing.T) {
		conn, status := h.dial(dialOpts{cookie: memberTok, origin: wsUIOrigin})
		if conn == nil {
			t.Fatalf("upgrade refused: %d", status)
		}
		if got := subscribe(t, conn, "tenant:"+open); got != string(websocket.MessageTypeSubscribed) {
			t.Errorf("own tenant channel: %s, want subscribed", got)
		}
		if got := subscribe(t, conn, "user:"+open+":"+member); got != string(websocket.MessageTypeSubscribed) {
			t.Errorf("own user channel: %s, want subscribed", got)
		}
		if got := subscribe(t, conn, "tenant:"+uuid.NewString()); got != string(websocket.MessageTypeError) {
			t.Errorf("foreign tenant channel: %s, want error", got)
		}
		if got := subscribe(t, conn, "user:"+open+":"+uuid.NewString()); got != string(websocket.MessageTypeError) {
			t.Errorf("another user's channel: %s, want error", got)
		}
	})

	t.Run("an old client still sending ?ticket= connects on its cookie", func(t *testing.T) {
		if conn, status := h.dial(dialOpts{cookie: memberTok, origin: wsUIOrigin, query: "?ticket=" + strings.Repeat("cd", 32)}); conn == nil {
			t.Fatalf("cookie + stale ticket param: status %d, want 101", status)
		}
	})

	t.Run("foreign Origin is refused", func(t *testing.T) {
		for _, o := range []string{"https://evil.example", "https://ui.example.test.evil.example", "null"} {
			if conn, status := h.dial(dialOpts{cookie: memberTok, origin: o}); conn != nil || status != http.StatusForbidden {
				t.Fatalf("origin %q: status %d, want 403", o, status)
			}
		}
	})

	t.Run("cookie session without an Origin is refused", func(t *testing.T) {
		if conn, status := h.dial(dialOpts{cookie: memberTok}); conn != nil || status != http.StatusForbidden {
			t.Fatalf("cookie without Origin: status %d, want 403", status)
		}
	})

	t.Run("bearer token without an Origin connects (not an ambient credential)", func(t *testing.T) {
		if conn, status := h.dial(dialOpts{bearer: memberTok}); conn == nil {
			t.Fatalf("bearer without Origin: status %d, want 101", status)
		}
	})

	t.Run("revoked session is refused", func(t *testing.T) {
		tok, sid := h.token(member, open)
		h.sessions.mu.Lock()
		h.sessions.revoked[sid] = true
		h.sessions.mu.Unlock()
		if conn, status := h.dial(dialOpts{cookie: tok, origin: wsUIOrigin}); conn != nil || status != http.StatusUnauthorized {
			t.Fatalf("revoked session: status %d, want 401", status)
		}
	})

	t.Run("suspended member is refused", func(t *testing.T) {
		suspended := h.user(open, "member")
		tok, _ := h.token(suspended, open)
		h.exec(`UPDATE tenant_members SET status = 'suspended' WHERE user_id = $1 AND tenant_id = $2`, suspended, open)
		if conn, status := h.dial(dialOpts{cookie: tok, origin: wsUIOrigin}); conn != nil || status != http.StatusForbidden {
			t.Fatalf("suspended member: status %d, want 403", status)
		}
	})

	t.Run("non-member of the token's tenant is refused", func(t *testing.T) {
		other := h.tenant(`{}`)
		outsider := h.user(other, "member")
		tok, _ := h.token(outsider, open)
		if conn, status := h.dial(dialOpts{cookie: tok, origin: wsUIOrigin}); conn != nil || status != http.StatusForbidden {
			t.Fatalf("non-member: status %d, want 403", status)
		}
	})

	t.Run("caller outside the organization IP allowlist is refused", func(t *testing.T) {
		fenced := h.tenant(`{"security":{"ip_whitelist":["203.0.113.0/24"]}}`)
		u := h.user(fenced, "member")
		tok, _ := h.token(u, fenced)
		if conn, status := h.dial(dialOpts{cookie: tok, origin: wsUIOrigin}); conn != nil || status != http.StatusForbidden {
			t.Fatalf("outside allowlist: status %d, want 403", status)
		}
	})

	t.Run("caller inside the organization IP allowlist connects", func(t *testing.T) {
		allowed := h.tenant(`{"security":{"ip_whitelist":["127.0.0.0/8","::1/128"]}}`)
		u := h.user(allowed, "member")
		tok, _ := h.token(u, allowed)
		if conn, status := h.dial(dialOpts{cookie: tok, origin: wsUIOrigin}); conn == nil {
			t.Fatalf("inside allowlist: status %d, want 101", status)
		}
	})

	t.Run("password session is refused when the tenant enforces SSO", func(t *testing.T) {
		sso := h.tenant(`{"security":{"sso_enforced":true}}`)
		u := h.user(sso, "member")
		tok, _ := h.token(u, sso)
		if conn, status := h.dial(dialOpts{cookie: tok, origin: wsUIOrigin}); conn != nil || status != http.StatusForbidden {
			t.Fatalf("SSO-enforced tenant: status %d, want 403", status)
		}
	})

	t.Run("the ticket endpoint is gone", func(t *testing.T) {
		req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, h.srv.URL+"/api/v1/auth/ws-token", nil)
		req.Header.Set("Authorization", "Bearer "+memberTok)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound && resp.StatusCode != http.StatusMethodNotAllowed {
			t.Fatalf("GET /auth/ws-token: %d, want 404", resp.StatusCode)
		}
	})
}

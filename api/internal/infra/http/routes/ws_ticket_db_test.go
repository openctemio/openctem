package routes

// WebSocket ticket issuance (/auth/ws-token) and redemption (/ws) over the
// real route registration (Register) against a migrated database: the ticket
// route runs the tenant gates (SSO enforcement, organization IP allowlist,
// active membership) and the upgrade re-checks membership for the user and
// tenant the ticket is bound to.

import (
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	gws "github.com/gorilla/websocket"
	_ "github.com/lib/pq"

	"github.com/openctemio/openctem/api/internal/app"
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

// memTicketStore is an in-process stand-in for the Redis ticket store.
type memTicketStore struct {
	mu sync.Mutex
	m  map[string]string
}

func (s *memTicketStore) Set(_ context.Context, key, value string, _ time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.m[key] = value
	return nil
}

func (s *memTicketStore) GetDel(_ context.Context, key string) (string, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.m[key]
	delete(s.m, key)
	return v, ok, nil
}

type wsTicketHarness struct {
	t   *testing.T
	db  *sql.DB
	srv *httptest.Server
	gen *jwt.Generator
}

func newWSTicketHarness(t *testing.T) *wsTicketHarness {
	t.Helper()
	dbURL := testdb.URL()
	if dbURL == "" {
		t.Skip("DATABASE_URL not set; skipping WS ticket route test")
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

	gen := jwt.NewGenerator(jwt.TokenConfig{Secret: "ws-ticket-route-test-secret-0123456789abcdef", Issuer: "test",
		AccessTokenDuration: time.Hour, RefreshTokenDuration: time.Hour})
	cfg := &config.Config{}
	cfg.Auth.Provider = config.AuthProviderLocal
	authCfg := AuthConfig{Provider: config.AuthProviderLocal, LocalValidator: gen}

	tickets := app.NewWSTicketService(&memTicketStore{m: map[string]string{}}, 30*time.Second, log)
	localAuth := handler.NewLocalAuthHandler(nil, nil, nil, nil, cfg.Auth, log)
	localAuth.SetWSTicketService(tickets)

	hub := websocket.NewHub(log)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go hub.Run(ctx)

	router := infrahttp.NewChiRouter()
	Register(router, Handlers{
		LocalAuth:        localAuth,
		WebSocket:        websocket.NewHandler(hub, log, nil, ""),
		WSTicketRedeemer: tickets,
	}, cfg, log, authCfg, tenantRepo, app.NewUserService(userRepo, log), nil, nil, nil)

	srv := httptest.NewServer(router.(interface{ Handler() http.Handler }).Handler())
	t.Cleanup(srv.Close)
	return &wsTicketHarness{t: t, db: sqldb, srv: srv, gen: gen}
}

func (h *wsTicketHarness) exec(q string, args ...any) {
	h.t.Helper()
	if _, err := h.db.ExecContext(context.Background(), q, args...); err != nil {
		h.t.Fatalf("%s: %v", q, err)
	}
}

func (h *wsTicketHarness) tenant(settings string) string {
	h.t.Helper()
	id := uuid.NewString()
	h.exec(`INSERT INTO tenants (id, name, slug, settings) VALUES ($1, 'WS ticket IT', $2, $3::jsonb)`,
		id, "wstk-"+strings.ReplaceAll(id[:13], "-", ""), settings)
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
func (h *wsTicketHarness) user(tenantID, membershipRole string) string {
	h.t.Helper()
	id := uuid.NewString()
	h.exec(`INSERT INTO users (id, email, name) VALUES ($1, $2, 'WS ticket IT')`, id, "wstk-"+id[:8]+"@it.test")
	h.t.Cleanup(func() { _, _ = h.db.ExecContext(context.Background(), `DELETE FROM users WHERE id = $1`, id) })
	if tenantID != "" {
		h.exec(`INSERT INTO tenant_members (user_id, tenant_id, role) VALUES ($1, $2, $3)`, id, tenantID, membershipRole)
	}
	return id
}

// token mints a password-session access token scoped to tenantID.
func (h *wsTicketHarness) token(userID, tenantID, role string) string {
	h.t.Helper()
	tok, err := h.gen.GenerateTenantScopedAccessToken(userID, "wstk@it.test", "WS", uuid.NewString(),
		jwt.TenantMembership{TenantID: tenantID, Role: role}, false, 0, "password")
	if err != nil {
		h.t.Fatal(err)
	}
	return tok.AccessToken
}

// wsToken calls GET /auth/ws-token with the bearer token.
func (h *wsTicketHarness) wsToken(bearer string) (int, string, string) {
	h.t.Helper()
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, h.srv.URL+"/api/v1/auth/ws-token", nil)
	req.Header.Set("Authorization", "Bearer "+bearer)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		h.t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	var out handler.WSTokenResponse
	_ = json.Unmarshal(body, &out)
	return resp.StatusCode, out.Token, string(body)
}

// dial opens /ws with the ticket. Returns the connection (nil on refusal) and
// the HTTP status of the upgrade response.
func (h *wsTicketHarness) dial(ticket string) (*gws.Conn, int) {
	h.t.Helper()
	u := "ws" + strings.TrimPrefix(h.srv.URL, "http") + "/api/v1/ws/?ticket=" + ticket
	conn, resp, err := gws.DefaultDialer.Dial(u, nil)
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

func TestWSTicketTenantGates_DB(t *testing.T) {
	h := newWSTicketHarness(t)

	open := h.tenant(`{}`)
	member := h.user(open, "member")

	t.Run("active member gets a ticket and the upgrade works", func(t *testing.T) {
		code, ticket, body := h.wsToken(h.token(member, open, "member"))
		if code != http.StatusOK || ticket == "" {
			t.Fatalf("ws-token: %d %s, want 200 with a ticket", code, body)
		}
		conn, status := h.dial(ticket)
		if conn == nil {
			t.Fatalf("upgrade refused: %d", status)
		}
		// Hub channel authorization is unchanged: own tenant yes, another
		// tenant / another user's notifications no.
		if got := subscribe(t, conn, "tenant:"+open); got != string(websocket.MessageTypeSubscribed) {
			t.Errorf("own tenant channel: %s, want subscribed", got)
		}
		if got := subscribe(t, conn, "tenant:"+uuid.NewString()); got != string(websocket.MessageTypeError) {
			t.Errorf("foreign tenant channel: %s, want error", got)
		}
		if got := subscribe(t, conn, "user:"+open+":"+uuid.NewString()); got != string(websocket.MessageTypeError) {
			t.Errorf("another user's channel: %s, want error", got)
		}
		// Single use: the same ticket cannot open a second socket.
		if c2, status := h.dial(ticket); c2 != nil || status != http.StatusUnauthorized {
			t.Errorf("ticket replay: status %d, want 401", status)
		}
	})

	t.Run("suspended member gets no ticket", func(t *testing.T) {
		suspended := h.user(open, "member")
		h.exec(`UPDATE tenant_members SET status = 'suspended' WHERE user_id = $1 AND tenant_id = $2`, suspended, open)
		if code, ticket, body := h.wsToken(h.token(suspended, open, "member")); code != http.StatusForbidden || ticket != "" {
			t.Fatalf("suspended member ws-token: %d %s, want 403", code, body)
		}
	})

	t.Run("non-member of the token's tenant gets no ticket", func(t *testing.T) {
		other := h.tenant(`{}`)
		outsider := h.user(other, "member")
		// A token claiming a tenant the user does not belong to.
		if code, ticket, body := h.wsToken(h.token(outsider, open, "member")); code != http.StatusForbidden || ticket != "" {
			t.Fatalf("non-member ws-token: %d %s, want 403", code, body)
		}
	})

	t.Run("caller outside the organization IP allowlist gets no ticket", func(t *testing.T) {
		fenced := h.tenant(`{"security":{"ip_whitelist":["203.0.113.0/24"]}}`)
		u := h.user(fenced, "member")
		code, ticket, body := h.wsToken(h.token(u, fenced, "member"))
		if code != http.StatusForbidden || ticket != "" || !strings.Contains(body, string(middleware.CodeIPNotAllowed)) {
			t.Fatalf("outside allowlist ws-token: %d %s, want 403 %s", code, body, middleware.CodeIPNotAllowed)
		}
	})

	t.Run("caller inside the organization IP allowlist gets a ticket", func(t *testing.T) {
		allowed := h.tenant(`{"security":{"ip_whitelist":["127.0.0.0/8","::1/128"]}}`)
		u := h.user(allowed, "member")
		code, ticket, body := h.wsToken(h.token(u, allowed, "member"))
		if code != http.StatusOK || ticket == "" {
			t.Fatalf("inside allowlist ws-token: %d %s, want 200", code, body)
		}
		if conn, status := h.dial(ticket); conn == nil {
			t.Fatalf("upgrade refused: %d", status)
		}
	})

	t.Run("password session gets no ticket when the tenant enforces SSO", func(t *testing.T) {
		sso := h.tenant(`{"security":{"sso_enforced":true}}`)
		u := h.user(sso, "member")
		if code, ticket, body := h.wsToken(h.token(u, sso, "member")); code != http.StatusForbidden || ticket != "" {
			t.Fatalf("SSO-enforced ws-token: %d %s, want 403", code, body)
		}
	})

	t.Run("member suspended between issue and upgrade cannot connect", func(t *testing.T) {
		u := h.user(open, "member")
		code, ticket, body := h.wsToken(h.token(u, open, "member"))
		if code != http.StatusOK || ticket == "" {
			t.Fatalf("ws-token: %d %s, want 200", code, body)
		}
		h.exec(`UPDATE tenant_members SET status = 'suspended' WHERE user_id = $1 AND tenant_id = $2`, u, open)
		if conn, status := h.dial(ticket); conn != nil || status != http.StatusForbidden {
			t.Fatalf("upgrade after suspension: status %d, want 403", status)
		}
	})

	t.Run("member removed between issue and upgrade cannot connect", func(t *testing.T) {
		u := h.user(open, "member")
		code, ticket, body := h.wsToken(h.token(u, open, "member"))
		if code != http.StatusOK || ticket == "" {
			t.Fatalf("ws-token: %d %s, want 200", code, body)
		}
		h.exec(`DELETE FROM tenant_members WHERE user_id = $1 AND tenant_id = $2`, u, open)
		if conn, status := h.dial(ticket); conn != nil || status != http.StatusForbidden {
			t.Fatalf("upgrade after removal: status %d, want 403", status)
		}
	})
}

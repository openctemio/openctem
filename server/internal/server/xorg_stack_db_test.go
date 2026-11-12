package server

// Cross-organization isolation over the whole composition root: the real
// repositories, services, handlers, route registration, authentication and
// tenant middleware chain, a migrated database and real signed access tokens.
//
// Organization A owns the rows; an owner of organization B holds a valid
// token of B. Every request B sends names A's ids. The contract, for each:
//   - the answer is the one B gets for an id that does not exist (never 403
//     with existence, never A's data);
//   - nothing of A changed afterwards (a digest of every tenant-owned table's
//     rows for A is compared before and after).
//
// A positive control then repeats the request as A: a 404 in B's hands only
// proves isolation when A really can reach the row.

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/openctemio/openctem/server/internal/config"
	httpinfra "github.com/openctemio/openctem/server/internal/infra/http"
	"github.com/openctemio/openctem/server/internal/infra/http/routes"
	"github.com/openctemio/openctem/server/internal/infra/postgres"
	"github.com/openctemio/openctem/server/internal/infra/redis"
	"github.com/openctemio/openctem/server/internal/testdb"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
	"github.com/openctemio/openctem/server/pkg/jwt"
	"github.com/openctemio/openctem/server/pkg/validator"
)

const (
	// xoMarker is in the name of every row A owns, so a response that carries
	// it has leaked A's data.
	xoMarker       = "xo-victim-secret"
	xoOwnerRoleID  = "00000000-0000-0000-0000-000000000001"
	xoRedisPortEnv = "XT_REDIS_PORT"
)

// xoStack is the booted server plus the two organizations.
type xoStack struct {
	t   *testing.T
	db  *sql.DB
	srv *httptest.Server
	gen *jwt.Generator

	tenantA, tenantB   shared.ID
	userA, userB       shared.ID
	tokenA, tokenB     string
	sessionA, sessionB string
	slugA, slugB       string
	services           *Services
	handlers           routes.Handlers
	cfg                *config.Config
}

// newXOStack boots the stack once per test. It skips without a test database
// and, when a Redis is needed but absent, skips too (OPENCTEM_TEST_DB_REQUIRED
// turns the skip into a failure in CI, where both exist).
func newXOStack(t *testing.T) *xoStack {
	t.Helper()
	dbURL := testdb.URL()
	if dbURL == "" {
		t.Skip("DATABASE_URL not set to a test database; skipping cross-organization isolation test")
	}
	u, err := url.Parse(dbURL)
	if err != nil {
		t.Skipf("DATABASE_URL: %v", err)
	}
	pw, _ := u.User.Password()
	redisHost, redisPort := os.Getenv("REDIS_HOST"), os.Getenv("REDIS_PORT")
	if redisHost == "" {
		redisHost = "127.0.0.1"
	}
	if redisPort == "" {
		redisPort = os.Getenv(xoRedisPortEnv)
	}
	for k, v := range map[string]string{
		"APP_ENV": "development", "DB_HOST": u.Hostname(), "DB_PORT": u.Port(), "DB_USER": u.User.Username(),
		"DB_PASSWORD": pw, "DB_NAME": strings.TrimPrefix(u.Path, "/"), "DB_SSLMODE": u.Query().Get("sslmode"),
		"REDIS_HOST": redisHost, "REDIS_PORT": redisPort,
		"APP_ENCRYPTION_KEY": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		"AUTH_COOKIE_SECURE": "false", "SMTP_BASE_URL": "http://localhost:3000", "LOG_LEVEL": "error",
	} {
		t.Setenv(k, v)
	}
	if u.Query().Get("sslmode") == "" {
		t.Setenv("DB_SSLMODE", "disable")
	}
	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("config: %v", err)
	}
	log := initLogger(cfg)
	db, err := postgres.New(&cfg.Database)
	if err != nil {
		t.Skipf("database: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	rc, err := redis.New(&cfg.Redis, log)
	if err != nil {
		t.Skipf("redis (REDIS_HOST/REDIS_PORT): %v", err)
	}
	t.Cleanup(func() { _ = rc.Close() })

	repos := NewRepositories(db)
	services, err := NewServices(&ServiceDeps{Config: cfg, Log: log, DB: db.DB, Repos: repos, IngestDB: db, RedisClient: rc})
	if err != nil {
		t.Fatalf("services: %v", err)
	}
	services.InitAuthServices(cfg, repos, log, rc)
	if err := services.InitEmailServices(cfg, log); err != nil {
		t.Fatalf("email services: %v", err)
	}
	handlers := NewHandlers(&HandlerDeps{
		Config: cfg, Log: log, Validator: validator.New(), DB: db, RedisClient: rc,
		WebSocketHub: services.WebSocketHub, Repos: repos, Services: services,
	})
	InitLocalAuthHandler(&handlers, services, repos, cfg, log)
	srv := httpinfra.NewServer(cfg, log)
	authCfg := routes.AuthConfig{Provider: cfg.Auth.Provider, LocalValidator: services.JWTGenerator}
	if services.SessionRevocations != nil {
		authCfg.RevokedSessions = services.SessionRevocations
	}
	routes.Register(srv.Router(), handlers, cfg, log, authCfg, repos.Tenant, services.User, services.MembershipCache, services.PermCache, services.PermVersion)
	hubCtx, stopHub := context.WithCancel(context.Background())
	t.Cleanup(stopHub)
	go services.WebSocketHub.Run(hubCtx)
	ts := httptest.NewServer(srv.Router().Handler())
	t.Cleanup(ts.Close)

	h := &xoStack{t: t, db: db.DB, srv: ts, gen: services.JWTGenerator, services: services, handlers: handlers, cfg: cfg}
	h.seedOrganizations()
	return h
}

func (h *xoStack) exec(q string, args ...any) {
	h.t.Helper()
	if _, err := h.db.ExecContext(context.Background(), q, args...); err != nil {
		h.t.Fatalf("seed %.120q: %v", q, err)
	}
}

func (h *xoStack) seedOrganizations() {
	h.tenantA, h.tenantB = shared.NewID(), shared.NewID()
	h.userA, h.userB = shared.NewID(), shared.NewID()
	h.slugA, h.slugB = "xo-a-"+xoShort(h.tenantA.String()), "xo-b-"+xoShort(h.tenantB.String())
	for _, o := range []struct {
		tenant, user shared.ID
		slug         string
	}{{h.tenantA, h.userA, h.slugA}, {h.tenantB, h.userB, h.slugB}} {
		h.exec(`INSERT INTO tenants (id, name, slug) VALUES ($1, $2, $2)`, o.tenant.String(), o.slug)
		h.exec(`INSERT INTO users (id, email, name) VALUES ($1, $2, $3)`, o.user.String(), o.user.String()+"@xo.test", "xo owner")
		h.exec(`INSERT INTO tenant_members (user_id, tenant_id, role) VALUES ($1, $2, 'owner')`, o.user.String(), o.tenant.String())
		h.exec(`INSERT INTO user_roles (user_id, tenant_id, role_id) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING`, o.user.String(), o.tenant.String(), xoOwnerRoleID)
	}
	h.t.Cleanup(func() {
		ctx := context.Background()
		for _, tn := range []shared.ID{h.tenantA, h.tenantB} {
			_, _ = h.db.ExecContext(ctx, `DELETE FROM tenants WHERE id = $1`, tn.String())
		}
		for _, us := range []shared.ID{h.userA, h.userB} {
			_, _ = h.db.ExecContext(ctx, `DELETE FROM users WHERE id = $1`, us.String())
		}
	})
	h.sessionA, h.sessionB = h.seedSession(h.userA), h.seedSession(h.userB)
	h.tokenA = h.mint(h.userA, h.tenantA, h.slugA, h.sessionA)
	h.tokenB = h.mint(h.userB, h.tenantB, h.slugB, h.sessionB)
}

// seedSession stores an active session: a fresh sign-in is the proof of
// identity the step-up gate looks for, so routes behind it are reached.
func (h *xoStack) seedSession(user shared.ID) string {
	id := shared.NewID().String()
	h.exec(`INSERT INTO sessions (id, user_id, access_token_hash, expires_at) VALUES ($1, $2, $3, now() + interval '2 hours')`,
		id, user.String(), "xo-"+id)
	return id
}

// freshProof renews both sessions' proof of identity (an every-time action
// spends it) before a request.
func (h *xoStack) freshProof() {
	h.t.Helper()
	h.exec(`UPDATE sessions SET step_up_at = now(), step_up_spent_at = NULL, created_at = now() WHERE id = ANY($1::uuid[])`,
		"{"+h.sessionA+","+h.sessionB+"}")
}

func (h *xoStack) mint(user, tenant shared.ID, slug, session string) string {
	h.t.Helper()
	tok, err := h.gen.GenerateTenantScopedAccessToken(user.String(), user.String()+"@xo.test", "xo owner", session,
		jwt.TenantMembership{TenantID: tenant.String(), TenantSlug: slug, Role: "owner"}, true, 0, "password")
	if err != nil {
		h.t.Fatalf("mint token: %v", err)
	}
	return tok.AccessToken
}

// call sends one request with the bearer token and returns status and body.
func (h *xoStack) call(token, method, path string, body any) (int, string) {
	h.t.Helper()
	h.freshProof()
	self := h.userB.String()
	if token == h.tokenA {
		self = h.userA.String()
	}
	path = strings.ReplaceAll(path, "@self", self)
	if b, ok := body.(string); ok {
		body = strings.ReplaceAll(b, "@self", self)
	}
	var rdr io.Reader
	switch b := body.(type) {
	case nil:
	case string:
		rdr = strings.NewReader(b)
	default:
		raw, err := json.Marshal(b)
		if err != nil {
			h.t.Fatal(err)
		}
		rdr = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(context.Background(), method, h.srv.URL+path, rdr)
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
	out, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(out)
}

var (
	xoUUIDRe = regexp.MustCompile(`[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}`)
	xoTimeRe = regexp.MustCompile(`\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})`)
)

// normalize hides what legitimately differs between two answers to the same
// kind of request: ids (the requested one is echoed) and timestamps.
func xoNormalize(body string) string {
	return xoTimeRe.ReplaceAllString(xoUUIDRe.ReplaceAllString(body, "<id>"), "<ts>")
}

// tenantDigest hashes, per table, every row that carries tenant_id = the
// organization, so any write to the organization's data, in any table the
// request could reach, shows as a changed digest.
func (h *xoStack) tenantDigest(tenant shared.ID) map[string]string {
	h.t.Helper()
	rows, err := h.db.QueryContext(context.Background(), `SELECT c.table_name FROM information_schema.columns c
		JOIN information_schema.tables t ON t.table_schema = c.table_schema AND t.table_name = c.table_name AND t.table_type = 'BASE TABLE'
		WHERE c.table_schema = 'public' AND c.column_name = 'tenant_id' ORDER BY 1`)
	if err != nil {
		h.t.Fatalf("list tables: %v", err)
	}
	defer func() { _ = rows.Close() }()
	var tables []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			h.t.Fatal(err)
		}
		tables = append(tables, n)
	}
	if err := rows.Err(); err != nil {
		h.t.Fatal(err)
	}
	out := make(map[string]string, len(tables))
	for _, tb := range tables {
		// A table whose tenant_id is not a uuid (or any other mismatch) is
		// skipped: it cannot hold this organization's rows by uuid.
		q := fmt.Sprintf(`SELECT coalesce(md5(string_agg(x::text, '|' ORDER BY x::text)), ''), count(*) FROM %q x WHERE x.tenant_id::text = $1`, tb)
		var sum string
		var n int
		if err := h.db.QueryRowContext(context.Background(), q, tenant.String()).Scan(&sum, &n); err != nil {
			continue
		}
		if n > 0 {
			out[tb] = fmt.Sprintf("%d:%s", n, sum)
		}
	}
	return out
}

func xoDiffDigest(before, after map[string]string) []string {
	var diff []string
	keys := map[string]bool{}
	for k := range before {
		keys[k] = true
	}
	for k := range after {
		keys[k] = true
	}
	for k := range keys {
		if before[k] != after[k] {
			diff = append(diff, k)
		}
	}
	sort.Strings(diff)
	return diff
}

func TestXOStack_BootsAndAuthenticates(t *testing.T) {
	h := newXOStack(t)
	for _, c := range []struct{ token, who string }{{h.tokenA, "A"}, {h.tokenB, "B"}} {
		status, body := h.call(c.token, http.MethodGet, "/api/v1/findings?page=1&per_page=5", nil)
		if status != http.StatusOK {
			t.Errorf("%s: list findings = %d %.200s", c.who, status, body)
		}
	}
}

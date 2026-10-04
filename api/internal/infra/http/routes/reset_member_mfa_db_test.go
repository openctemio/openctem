package routes

// POST /api/v1/tenants/{tenant}/members/{membership}/reset-2fa over the real
// routes, services and a migrated database: an organization administrator
// turns off a member's second factor, which signs the member out and is
// audited in that organization; a membership of another organization, an
// administrator target and a member who also belongs to another organization
// are refused, and nothing changes.

import (
	"context"
	"database/sql"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	_ "github.com/lib/pq"

	"github.com/openctemio/openctem/api/internal/app"
	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
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
	"github.com/openctemio/openctem/api/pkg/validator"
)

type resetMFAHarness struct {
	*authzPolicyHarness
	sessions *postgres.SessionRepository
}

func newResetMFAHarness(t *testing.T) *resetMFAHarness {
	t.Helper()
	dbURL := testdb.URL()
	if dbURL == "" {
		t.Skip("DATABASE_URL not set; skipping reset-2fa route test")
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
	t.Cleanup(func() {
		csrfProtectionMiddleware, readRateLimitMiddleware, activeMembershipFromJWTMiddleware = saved[0], saved[1], saved[2]
		permissionSyncMiddleware, ssoEnforcementMiddleware, ipAllowlistMiddleware = saved[3], saved[4], saved[5]
	})

	db := &postgres.DB{DB: sqldb}
	log := logger.NewNop()
	tenantRepo := postgres.NewTenantRepository(db)
	userRepo := postgres.NewUserRepository(db)
	sessions := postgres.NewSessionRepository(sqldb)
	auditSvc := auditapp.NewAuditService(postgres.NewAuditRepository(db), log)
	authCfgApp := config.AuthConfig{
		JWTSecret: "reset-mfa-route-test-secret-0123456789abcdef", JWTIssuer: "test",
		AccessTokenDuration: time.Hour, RefreshTokenDuration: time.Hour, SessionDuration: time.Hour,
	}
	authSvc := app.NewAuthService(userRepo, sessions, postgres.NewRefreshTokenRepository(sqldb), tenantRepo, auditSvc, authCfgApp, log)
	cipher, err := crypto.NewCipher([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	authSvc.SetMFA(postgres.NewUserMFARepository(db), cipher, "OpenCTEM")

	gen := jwt.NewGenerator(jwt.TokenConfig{Secret: "authz-policy-route-test-secret-0123456789abcdef", Issuer: "test",
		AccessTokenDuration: time.Hour, RefreshTokenDuration: time.Hour})
	cfg := &config.Config{}
	cfg.Auth.Provider = config.AuthProviderLocal
	v := validator.New()
	router := infrahttp.NewChiRouter()
	Register(router, Handlers{
		Tenant:    handler.NewTenantHandler(app.NewTenantService(tenantRepo, log, app.WithTenantAuditService(auditSvc)), v, log),
		LocalAuth: handler.NewLocalAuthHandler(authSvc, nil, nil, nil, authCfgApp, log),
	}, cfg, log, AuthConfig{Provider: config.AuthProviderLocal, LocalValidator: gen}, tenantRepo, app.NewUserService(userRepo, log), nil, nil, nil)
	srv := httptest.NewServer(router.(interface{ Handler() http.Handler }).Handler())
	t.Cleanup(srv.Close)

	return &resetMFAHarness{
		authzPolicyHarness: &authzPolicyHarness{t: t, db: sqldb, srv: srv, gen: gen, roles: postgres.NewRoleRepository(db)},
		sessions:           sessions,
	}
}

// enroll gives the user a password and an enabled factor with recovery codes,
// and one live session.
func (h *resetMFAHarness) enroll(u policyUser) string {
	h.t.Helper()
	h.exec(`UPDATE users SET password_hash = 'x', auth_provider = 'local' WHERE id = $1`, u.id)
	h.exec(`INSERT INTO user_mfa (user_id, secret_encrypted, enabled, enabled_at) VALUES ($1, 'enc', TRUE, NOW())`, u.id)
	h.exec(`INSERT INTO user_mfa_recovery_codes (user_id, code_hash) VALUES ($1, 'h1'), ($1, 'h2')`, u.id)
	s, err := session.New(shared.MustIDFromString(u.id), "tok-"+u.id, "10.0.0.1", "Browser", time.Hour)
	if err != nil {
		h.t.Fatal(err)
	}
	if err := h.sessions.Create(context.Background(), s); err != nil {
		h.t.Fatal(err)
	}
	h.t.Cleanup(func() {
		_, _ = h.db.ExecContext(context.Background(), `DELETE FROM sessions WHERE user_id = $1`, u.id)
	})
	return s.ID().String()
}

func (h *resetMFAHarness) count(q string, args ...any) int {
	h.t.Helper()
	var n int
	if err := h.db.QueryRowContext(context.Background(), q, args...).Scan(&n); err != nil {
		h.t.Fatalf("%s: %v", q, err)
	}
	return n
}

func (h *resetMFAHarness) factorCount(u policyUser) int {
	return h.count(`SELECT (SELECT COUNT(*) FROM user_mfa WHERE user_id = $1) + (SELECT COUNT(*) FROM user_mfa_recovery_codes WHERE user_id = $1)`, u.id)
}

func TestResetMemberMFA_DB(t *testing.T) {
	h := newResetMFAHarness(t)
	tidA, tidB := h.tenant(), h.tenant()
	adminA := h.member(tidA, "admin")
	path := func(tid, membershipID string) string {
		return "/api/v1/tenants/" + tid + "/members/" + membershipID + "/reset-2fa"
	}

	// A member of A: reset succeeds, factor and codes gone, session revoked, audited in A.
	memberA := h.member(tidA, "member")
	sid := h.enroll(memberA)
	h.expect(adminA, http.MethodPost, path(tidA, memberA.membershipID), "", http.StatusOK)
	if n := h.factorCount(memberA); n != 0 {
		t.Fatalf("factor rows left after reset: %d", n)
	}
	if n := h.count(`SELECT COUNT(*) FROM sessions WHERE id = $1 AND status = 'active'`, sid); n != 0 {
		t.Fatal("the member's session is still active")
	}
	if n := h.count(`SELECT COUNT(*) FROM audit_logs WHERE tenant_id = $1 AND action = 'auth.mfa_reset' AND resource_id = $2 AND actor_id = $3`,
		tidA, memberA.id, adminA.id); n != 1 {
		t.Fatalf("want one auth.mfa_reset audit row in A, got %d", n)
	}
	// Again: nothing left to reset.
	h.expect(adminA, http.MethodPost, path(tidA, memberA.membershipID), "", http.StatusBadRequest)

	// A member of B through A's URL: not found, unchanged.
	memberB := h.member(tidB, "member")
	h.enroll(memberB)
	h.expect(adminA, http.MethodPost, path(tidA, memberB.membershipID), "", http.StatusNotFound)
	// And through B's URL, where adminA is not a member: refused by the chain.
	if code, _ := h.do(adminA, http.MethodPost, path(tidB, memberB.membershipID), ""); code != http.StatusForbidden && code != http.StatusNotFound {
		t.Fatalf("reset in an organization the caller is not in: status %d", code)
	}
	if h.factorCount(memberB) == 0 {
		t.Fatal("cross-organization reset removed the factor")
	}

	// A peer administrator: owner only.
	peer := h.member(tidA, "admin")
	h.enroll(peer)
	body := h.expect(adminA, http.MethodPost, path(tidA, peer.membershipID), "", http.StatusForbidden)
	if !strings.Contains(body, "owner") {
		t.Fatalf("refusal does not explain the owner rule: %s", body)
	}
	if h.factorCount(peer) == 0 {
		t.Fatal("refused reset removed the factor")
	}

	// A member of A who also belongs to B: refused, unchanged.
	both := h.member(tidA, "member")
	h.enroll(both)
	h.exec(`INSERT INTO tenant_members (id, user_id, tenant_id, role) VALUES ($1, $2, $3, 'viewer')`, uuid.NewString(), both.id, tidB)
	h.expect(adminA, http.MethodPost, path(tidA, both.membershipID), "", http.StatusForbidden)
	if h.factorCount(both) == 0 {
		t.Fatal("reset of a member of another organization removed the factor")
	}

	// A member cannot reset anyone.
	h.expect(h.member(tidA, "member"), http.MethodPost, path(tidA, peer.membershipID), "", http.StatusForbidden)
}

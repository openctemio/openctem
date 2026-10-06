package routes

// The owner-approved authorization policy (2026-10-02), checked over the real
// route registration (Register: auth chain, membership gate, the real route
// gates and handlers) and real services against a migrated database. Each
// caller's token is minted the way the token exchange mints it: owner/admin
// get the IsAdmin bypass, everyone else carries the permissions the role
// tables grant them. So these tests exercise the seed migration and the route
// gates together:
//
//   - sensors: create / rotate key / revoke / activate / deactivate are owner
//     and admin only; members and viewers keep read;
//   - the audit log is owner/admin only; rebaseline is owner only;
//   - members see only their own API keys;
//   - billing read is no longer granted to member or viewer;
//   - administrators cannot demote, suspend, reactivate or remove a peer
//     administrator; the owner can; administrators still manage members;
//   - SCIM token create / revoke is owner only;
//   - custom scanner templates, template sources and inline command templates
//     are written by owners and admins only; members keep read;
//   - a scope exclusion a member creates is pending and suppresses nothing;
//     approving or rejecting it needs attack_surface:scope:exclusions:approve
//     (owner/admin), and nobody approves their own exclusion;
//   - scan commands through POST /api/v1/commands are owner/admin only and
//     their targets get the scan trigger's checks (RFC-040 Q5 (c));
//   - business units are deleted by owners and admins only;
//   - member emails in the member list are shown to owners and admins only.

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	_ "github.com/lib/pq"

	"github.com/openctemio/openctem/api/internal/app"
	"github.com/openctemio/openctem/api/internal/app/apikey"
	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	commandapp "github.com/openctemio/openctem/api/internal/app/command"
	scanapp "github.com/openctemio/openctem/api/internal/app/scan"
	"github.com/openctemio/openctem/api/internal/app/scim"
	scopeapp "github.com/openctemio/openctem/api/internal/app/scope"
	templateapp "github.com/openctemio/openctem/api/internal/app/template"
	"github.com/openctemio/openctem/api/internal/config"
	infrahttp "github.com/openctemio/openctem/api/internal/infra/http"
	"github.com/openctemio/openctem/api/internal/infra/http/handler"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/internal/testdb"
	"github.com/openctemio/openctem/api/pkg/domain/role"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/jwt"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/validator"
)

type authzPolicyHarness struct {
	t     *testing.T
	db    *sql.DB
	srv   *httptest.Server
	gen   *jwt.Generator
	roles *postgres.RoleRepository
	keys  *apikey.Service
}

func newAuthzPolicyHarness(t *testing.T) *authzPolicyHarness {
	t.Helper()
	dbURL := testdb.URL()
	if dbURL == "" {
		t.Skip("DATABASE_URL not set; skipping authorization policy route test")
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
	savedKeyAuth, savedStepUp := apiKeyOrJWT, stepUpChecker
	t.Cleanup(func() {
		apiKeyOrJWT, stepUpChecker = savedKeyAuth, savedStepUp
		csrfProtectionMiddleware, readRateLimitMiddleware, activeMembershipFromJWTMiddleware = saved[0], saved[1], saved[2]
		permissionSyncMiddleware, ssoEnforcementMiddleware, ipAllowlistMiddleware = saved[3], saved[4], saved[5]
	})

	db := &postgres.DB{DB: sqldb}
	log := logger.NewNop()
	tenantRepo := postgres.NewTenantRepository(db)
	userRepo := postgres.NewUserRepository(db)
	roleRepo := postgres.NewRoleRepository(db)
	auditSvc := auditapp.NewAuditService(postgres.NewAuditRepository(db), log)
	keys := apikey.NewService(postgres.NewAPIKeyRepository(db), "authz-policy-pepper", log)
	tenantSvc := app.NewTenantService(tenantRepo, log, app.WithTenantAuditService(auditSvc))
	v := validator.New()

	gen := jwt.NewGenerator(jwt.TokenConfig{Secret: "authz-policy-route-test-secret-0123456789abcdef", Issuer: "test",
		AccessTokenDuration: time.Hour, RefreshTokenDuration: time.Hour})
	cfg := &config.Config{}
	cfg.Auth.Provider = config.AuthProviderLocal
	authCfg := AuthConfig{Provider: config.AuthProviderLocal, LocalValidator: gen}

	// Scan commands get the scan trigger's target checks: real scope
	// exclusions and scan zones from the database.
	commandHandler := handler.NewCommandHandler(commandapp.NewService(postgres.NewCommandRepository(db), log,
		commandapp.WithSensorLookup(postgres.NewSensorRepository(db))), v, log)
	commandHandler.SetAuditService(auditSvc)
	commandHandler.SetScanCommandGate(scanapp.NewService(nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, log,
		scanapp.WithScopeExclusionFilter(scopeapp.NewService(nil, postgres.NewScopeExclusionRepository(db), nil, log)),
		scanapp.WithScanZones(postgres.NewScanZoneRepository(db), nil)))

	router := infrahttp.NewChiRouter()
	Register(router, Handlers{
		Sensor:    handler.NewSensorHandler(app.NewSensorService(postgres.NewSensorRepository(db), auditSvc, log), v, log),
		Audit:     handler.NewAuditHandler(auditSvc, v, log),
		APIKey:    handler.NewAPIKeyHandler(keys, v, log),
		Tenant:    handler.NewTenantHandler(tenantSvc, v, log),
		SCIMToken: handler.NewSCIMTokenHandler(scim.NewTokenService(postgres.NewScimTokenRepository(db), "authz-policy-pepper", log), log),
		ScannerTemplate: handler.NewScannerTemplateHandler(
			app.NewScannerTemplateService(postgres.NewScannerTemplateRepository(db), "authz-policy-template-signing-key-0123456789", log), v, log),
		TemplateSource: handler.NewTemplateSourceHandler(templateapp.NewSourceService(postgres.NewTemplateSourceRepository(db), log), v, log),
		Command:        commandHandler,
		Scope: handler.NewScopeHandler(scopeapp.NewService(postgres.NewScopeTargetRepository(db),
			postgres.NewScopeExclusionRepository(db),
			postgres.NewAssetRepository(db), log), v, log),
		BusinessUnit: handler.NewBusinessUnitHandler(
			app.NewBusinessUnitService(postgres.NewBusinessUnitRepository(db), postgres.NewAssetRepository(db), log), log),
		// Not about step-up (step_up_db_test.go is): every session is fresh.
		StepUp: alwaysSteppedUp{},
	}, cfg, log, authCfg, tenantRepo, app.NewUserService(userRepo, log), nil, nil, nil)

	srv := httptest.NewServer(router.(interface{ Handler() http.Handler }).Handler())
	t.Cleanup(srv.Close)
	return &authzPolicyHarness{t: t, db: sqldb, srv: srv, gen: gen, roles: roleRepo, keys: keys}
}

func (h *authzPolicyHarness) exec(q string, args ...any) {
	h.t.Helper()
	if _, err := h.db.ExecContext(context.Background(), q, args...); err != nil {
		h.t.Fatalf("%s: %v", q, err)
	}
}

func (h *authzPolicyHarness) tenant() string {
	h.t.Helper()
	id := uuid.NewString()
	h.exec(`INSERT INTO tenants (id, name, slug) VALUES ($1, 'Authz policy IT', $2)`,
		id, "authzpol-"+strings.ReplaceAll(id[:13], "-", ""))
	h.t.Cleanup(func() {
		ctx := context.Background()
		for _, q := range []string{
			`DELETE FROM audit_log_chain WHERE tenant_id = $1`,
			`DELETE FROM audit_logs WHERE tenant_id = $1`,
			`DELETE FROM api_keys WHERE tenant_id = $1`,
			`DELETE FROM scim_tokens WHERE tenant_id = $1`,
			`DELETE FROM commands WHERE tenant_id = $1`,
			`DELETE FROM scanner_templates WHERE tenant_id = $1`,
			`DELETE FROM template_sources WHERE tenant_id = $1`,
			`DELETE FROM sensors WHERE tenant_id = $1`,
			`DELETE FROM scope_exclusions WHERE tenant_id = $1`,
			`DELETE FROM scope_targets WHERE tenant_id = $1`,
			`DELETE FROM tenant_tool_configs WHERE tenant_id = $1`,
			`DELETE FROM tools WHERE tenant_id = $1`,
			`DELETE FROM business_units WHERE tenant_id = $1`,
			`DELETE FROM user_roles WHERE tenant_id = $1`,
			`DELETE FROM tenant_members WHERE tenant_id = $1`,
			`DELETE FROM tenants WHERE id = $1`,
		} {
			_, _ = h.db.ExecContext(ctx, q, id)
		}
	})
	return id
}

type policyUser struct {
	id, membershipID, role, token string
}

// member creates a user with the given membership role in tenantID (the
// tenant_members trigger grants the matching system role, as in production)
// and mints their access token the way the token exchange does.
func (h *authzPolicyHarness) member(tenantID, membershipRole string) policyUser {
	h.t.Helper()
	u := policyUser{id: uuid.NewString(), membershipID: uuid.NewString(), role: membershipRole}
	email := "authzpol-" + u.id[:8] + "@it.test"
	h.exec(`INSERT INTO users (id, email, name) VALUES ($1, $2, 'Authz policy IT')`, u.id, email)
	h.t.Cleanup(func() { _, _ = h.db.ExecContext(context.Background(), `DELETE FROM users WHERE id = $1`, u.id) })
	h.exec(`INSERT INTO tenant_members (id, user_id, tenant_id, role) VALUES ($1, $2, $3, $4)`,
		u.membershipID, u.id, tenantID, membershipRole)
	h.mintToken(&u, tenantID)
	return u
}

// mintToken (re)issues u's access token with the permissions u holds now.
func (h *authzPolicyHarness) mintToken(u *policyUser, tenantID string) {
	h.t.Helper()
	email := "authzpol-" + u.id[:8] + "@it.test"
	isAdmin := u.role == "owner" || u.role == "admin"
	var perms []string
	if !isAdmin {
		var err error
		perms, err = h.roles.GetUserPermissions(context.Background(), role.MustParseID(tenantID), role.MustParseID(u.id))
		if err != nil {
			h.t.Fatalf("permissions of %s: %v", u.role, err)
		}
	}
	tok, err := h.gen.GenerateTenantScopedAccessTokenWithPermissions(u.id, email, "Authz policy IT", uuid.NewString(),
		jwt.TenantMembership{TenantID: tenantID, Role: u.role}, perms, isAdmin, 0, "password")
	if err != nil {
		h.t.Fatalf("mint token: %v", err)
	}
	u.token = tok.AccessToken
}

// grantCustomRole gives u a custom role of tenantID carrying perms, and
// re-mints u's token.
func (h *authzPolicyHarness) grantCustomRole(u *policyUser, tenantID string, perms ...string) {
	h.t.Helper()
	roleID := uuid.NewString()
	h.exec(`INSERT INTO roles (id, tenant_id, slug, name, is_system, hierarchy_level) VALUES ($1, $2, $3, $3, FALSE, 10)`,
		roleID, tenantID, "custom-"+roleID[:8])
	for _, p := range perms {
		h.exec(`INSERT INTO role_permissions (role_id, permission_id) VALUES ($1, $2)`, roleID, p)
	}
	h.exec(`INSERT INTO user_roles (user_id, tenant_id, role_id) VALUES ($1, $2, $3)`, u.id, tenantID, roleID)
	h.mintToken(u, tenantID)
}

func (h *authzPolicyHarness) do(u policyUser, method, path, body string) (int, string) {
	h.t.Helper()
	if body == "" {
		body = "{}"
	}
	req, err := http.NewRequestWithContext(context.Background(), method, h.srv.URL+path, strings.NewReader(body))
	if err != nil {
		h.t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+u.token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		h.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func (h *authzPolicyHarness) expect(u policyUser, method, path, body string, want int) string {
	h.t.Helper()
	code, resp := h.do(u, method, path, body)
	if code != want {
		h.t.Fatalf("%s %s %s as %s: status %d, want %d (body %s)", method, path, body, u.role, code, want, resp)
	}
	return resp
}

func (h *authzPolicyHarness) sensor(tenantID string) string {
	h.t.Helper()
	id := uuid.NewString()
	h.exec(`INSERT INTO sensors (id, tenant_id, name, type, status, health, execution_mode, api_key_hash, api_key_prefix)
	        VALUES ($1, $2, $3, 'worker', 'active', 'unknown', 'standalone', $4, 'rda_test')`,
		id, tenantID, "authzpol-"+id[:8], "hash-"+id)
	return id
}

func TestAuthzPolicy_SensorsAreAdminOnly_DB(t *testing.T) {
	h := newAuthzPolicyHarness(t)
	tid := h.tenant()
	admin, member, viewer := h.member(tid, "admin"), h.member(tid, "member"), h.member(tid, "viewer")
	sid := h.sensor(tid)
	create := `{"name":"sensor-x","type":"worker"}`

	for _, u := range []policyUser{member, viewer} {
		h.expect(u, http.MethodGet, "/api/v1/sensors", "", http.StatusOK)
		h.expect(u, http.MethodGet, "/api/v1/sensors/"+sid, "", http.StatusOK)
		h.expect(u, http.MethodPost, "/api/v1/sensors", create, http.StatusForbidden)
		h.expect(u, http.MethodPut, "/api/v1/sensors/"+sid, `{"name":"renamed"}`, http.StatusForbidden)
		h.expect(u, http.MethodPost, "/api/v1/sensors/"+sid+"/regenerate-key", "", http.StatusForbidden)
		h.expect(u, http.MethodPost, "/api/v1/sensors/"+sid+"/revoke", "", http.StatusForbidden)
		h.expect(u, http.MethodPost, "/api/v1/sensors/"+sid+"/deactivate", "", http.StatusForbidden)
		h.expect(u, http.MethodPost, "/api/v1/sensors/"+sid+"/activate", "", http.StatusForbidden)
		h.expect(u, http.MethodDelete, "/api/v1/sensors/"+sid, "", http.StatusForbidden)
	}

	// The administrator still creates sensors and rotates keys.
	body := h.expect(admin, http.MethodPost, "/api/v1/sensors", create, http.StatusCreated)
	if !strings.Contains(body, "octs_") {
		t.Fatalf("admin create returned no sensor key: %s", body)
	}
	body = h.expect(admin, http.MethodPost, "/api/v1/sensors/"+sid+"/regenerate-key", "", http.StatusOK)
	if !strings.Contains(body, "octs_") {
		t.Fatalf("admin regenerate returned no sensor key: %s", body)
	}
}

func TestAuthzPolicy_AuditLogIsAdminOnly_DB(t *testing.T) {
	h := newAuthzPolicyHarness(t)
	tid := h.tenant()
	owner, admin, member, viewer := h.member(tid, "owner"), h.member(tid, "admin"), h.member(tid, "member"), h.member(tid, "viewer")

	for _, u := range []policyUser{member, viewer} {
		h.expect(u, http.MethodGet, "/api/v1/audit-logs", "", http.StatusForbidden)
		h.expect(u, http.MethodGet, "/api/v1/audit-logs/stats", "", http.StatusForbidden)
		h.expect(u, http.MethodGet, "/api/v1/audit-logs/user/"+owner.id, "", http.StatusForbidden)
		h.expect(u, http.MethodGet, "/api/v1/audit-logs/resource/asset/"+uuid.NewString(), "", http.StatusForbidden)
	}
	h.expect(admin, http.MethodGet, "/api/v1/audit-logs", "", http.StatusOK)
	h.expect(owner, http.MethodGet, "/api/v1/audit-logs", "", http.StatusOK)

	// Everyone still reads their own activity (/account/activity).
	for _, u := range []policyUser{member, viewer} {
		h.expect(u, http.MethodGet, "/api/v1/audit-logs/user/"+u.id, "", http.StatusOK)
	}
	h.expect(admin, http.MethodGet, "/api/v1/audit-logs/user/"+member.id, "", http.StatusOK)

	// Rebaseline overwrites the tamper-evident chain: owner only.
	h.expect(admin, http.MethodPost, "/api/v1/audit-logs/rebaseline", `{"reason":"benign hashing change"}`, http.StatusForbidden)
	if code, body := h.do(owner, http.MethodPost, "/api/v1/audit-logs/rebaseline", `{"reason":"benign hashing change"}`); code == http.StatusForbidden {
		t.Fatalf("owner rebaseline refused: %s", body)
	}
}

func TestAuthzPolicy_BillingNotGrantedToMemberOrViewer_DB(t *testing.T) {
	h := newAuthzPolicyHarness(t)
	rows, err := h.db.Query(`SELECT r.slug, rp.permission_id FROM role_permissions rp JOIN roles r ON r.id = rp.role_id
		WHERE r.is_system AND r.slug IN ('member','viewer')
		  AND rp.permission_id IN ('audit:read','sensors:write','sensors:delete')`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var slug, perm string
		_ = rows.Scan(&slug, &perm)
		t.Errorf("system role %s still holds %s", slug, perm)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	// Owners and administrators keep them.
	var n int
	if err := h.db.QueryRow(`SELECT count(*) FROM role_permissions rp JOIN roles r ON r.id = rp.role_id
		WHERE r.is_system AND r.slug IN ('owner','admin')
		  AND rp.permission_id IN ('audit:read','sensors:write')`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 4 {
		t.Fatalf("owner+admin hold %d of the 4 admin-only grants, want 4", n)
	}
	// Members and viewers keep reading sensors.
	if err := h.db.QueryRow(`SELECT count(*) FROM role_permissions rp JOIN roles r ON r.id = rp.role_id
		WHERE r.is_system AND r.slug IN ('member','viewer') AND rp.permission_id = 'sensors:read'`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Fatalf("member/viewer sensors:read grants = %d, want 2", n)
	}
}

func TestAuthzPolicy_MembersSeeOnlyTheirOwnAPIKeys_DB(t *testing.T) {
	h := newAuthzPolicyHarness(t)
	tid := h.tenant()
	admin, member := h.member(tid, "admin"), h.member(tid, "member")
	mint := func(owner policyUser) string {
		res, err := h.keys.Create(context.Background(), apikey.CreateInput{TenantID: tid, UserID: owner.id, Name: "k-" + uuid.NewString()[:8], ExpiresInDays: 90})
		if err != nil {
			t.Fatalf("mint key: %v", err)
		}
		return res.Key.ID().String()
	}
	adminKey, memberKey := mint(admin), mint(member)

	type listResp struct {
		Data []struct {
			ID string `json:"id"`
		} `json:"data"`
		Total int `json:"total"`
	}
	ids := func(u policyUser) []string {
		var lr listResp
		if err := json.Unmarshal([]byte(h.expect(u, http.MethodGet, "/api/v1/api-keys", "", http.StatusOK)), &lr); err != nil {
			t.Fatal(err)
		}
		out := make([]string, 0, len(lr.Data))
		for _, d := range lr.Data {
			out = append(out, d.ID)
		}
		return out
	}
	if got := ids(member); len(got) != 1 || got[0] != memberKey {
		t.Fatalf("member lists %v, want only their own key %s", got, memberKey)
	}
	if got := ids(admin); len(got) != 2 {
		t.Fatalf("admin lists %v, want both keys", got)
	}
	h.expect(member, http.MethodGet, "/api/v1/api-keys/"+memberKey, "", http.StatusOK)
	h.expect(member, http.MethodGet, "/api/v1/api-keys/"+adminKey, "", http.StatusNotFound)
	h.expect(admin, http.MethodGet, "/api/v1/api-keys/"+memberKey, "", http.StatusOK)

	// Revoke and delete follow the same rule (settings audit A-M3): a member
	// whose custom role lets them revoke and delete keys may do it to their
	// own keys only; someone else's key reads as not found.
	h.grantCustomRole(&member, tid, "integrations:api_keys:write", "integrations:api_keys:delete")
	h.expect(member, http.MethodPost, "/api/v1/api-keys/"+adminKey+"/revoke", "", http.StatusNotFound)
	h.expect(member, http.MethodDelete, "/api/v1/api-keys/"+adminKey, "", http.StatusNotFound)
	var status string
	if err := h.db.QueryRow(`SELECT status FROM api_keys WHERE id = $1`, adminKey).Scan(&status); err != nil {
		t.Fatalf("admin key after refused revoke/delete: %v", err)
	}
	if status != "active" {
		t.Fatalf("admin key status = %q after a refused revoke", status)
	}
	h.expect(member, http.MethodPost, "/api/v1/api-keys/"+memberKey+"/revoke", "", http.StatusOK)
	other := mint(member)
	h.expect(admin, http.MethodPost, "/api/v1/api-keys/"+other+"/revoke", "", http.StatusOK)
	h.expect(admin, http.MethodDelete, "/api/v1/api-keys/"+other, "", http.StatusNoContent)

	// Every key expires (settings decision B14): no expiry, or more than a
	// year, is refused.
	h.expect(admin, http.MethodPost, "/api/v1/api-keys", `{"name":"never"}`, http.StatusUnprocessableEntity)
	h.expect(admin, http.MethodPost, "/api/v1/api-keys", `{"name":"never","expires_in_days":0}`, http.StatusUnprocessableEntity)
	h.expect(admin, http.MethodPost, "/api/v1/api-keys", `{"name":"too-long","expires_in_days":366}`, http.StatusUnprocessableEntity)
	h.expect(admin, http.MethodPost, "/api/v1/api-keys", `{"name":"a-year","expires_in_days":365}`, http.StatusCreated)
}

func TestAuthzPolicy_PeerAdminsAreOwnerManaged_DB(t *testing.T) {
	h := newAuthzPolicyHarness(t)
	tid := h.tenant()
	owner, admin, peer := h.member(tid, "owner"), h.member(tid, "admin"), h.member(tid, "admin")
	member := h.member(tid, "member")
	base := "/api/v1/tenants/" + tid + "/members/"

	// An administrator cannot act on a peer administrator.
	h.expect(admin, http.MethodPatch, base+peer.membershipID, `{"role":"member"}`, http.StatusForbidden)
	h.expect(admin, http.MethodPost, base+peer.membershipID+"/suspend", "", http.StatusForbidden)
	h.expect(admin, http.MethodDelete, base+peer.membershipID, "", http.StatusForbidden)
	var status string
	if err := h.db.QueryRow(`SELECT COALESCE(status,'active') FROM tenant_members WHERE id = $1`, peer.membershipID).Scan(&status); err != nil {
		t.Fatal(err)
	}
	if status != "active" {
		t.Fatalf("peer admin status changed to %q by a refused request", status)
	}

	// An administrator still manages members.
	h.expect(admin, http.MethodPost, base+member.membershipID+"/suspend", "", http.StatusOK)
	h.expect(admin, http.MethodPost, base+member.membershipID+"/reactivate", "", http.StatusOK)

	// The owner manages administrators.
	h.expect(owner, http.MethodPost, base+peer.membershipID+"/suspend", "", http.StatusOK)
	h.expect(admin, http.MethodPost, base+peer.membershipID+"/reactivate", "", http.StatusForbidden)
	h.expect(owner, http.MethodPost, base+peer.membershipID+"/reactivate", "", http.StatusOK)
	h.expect(owner, http.MethodDelete, base+peer.membershipID, "", http.StatusNoContent)
}

func TestAuthzPolicy_SCIMTokensAreOwnerOnly_DB(t *testing.T) {
	h := newAuthzPolicyHarness(t)
	tid := h.tenant()
	owner, admin := h.member(tid, "owner"), h.member(tid, "admin")

	h.expect(admin, http.MethodPost, "/api/v1/scim-tokens", `{"name":"idp"}`, http.StatusForbidden)
	h.expect(admin, http.MethodGet, "/api/v1/scim-tokens", "", http.StatusOK)
	body := h.expect(owner, http.MethodPost, "/api/v1/scim-tokens", `{"name":"idp"}`, http.StatusCreated)
	var created struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal([]byte(body), &created); err != nil || created.ID == "" {
		t.Fatalf("owner create body %s: %v", body, err)
	}
	h.expect(admin, http.MethodDelete, "/api/v1/scim-tokens/"+created.ID, "", http.StatusForbidden)
	if code, b := h.do(owner, http.MethodDelete, "/api/v1/scim-tokens/"+created.ID, ""); code >= 300 {
		t.Fatalf("owner revoke: %d %s", code, b)
	}
}

// Custom templates are trusted code (owner decision 2026-10-02, migration
// 000262): a template decides which hosts a sensor contacts and what it
// sends. Members and viewers read templates and sources; only owners and
// administrators write them, and only they may embed one in a command.
func TestAuthzPolicy_CustomTemplatesAreAdminOnly_DB(t *testing.T) {
	h := newAuthzPolicyHarness(t)
	tid := h.tenant()
	owner, admin, member, viewer := h.member(tid, "owner"), h.member(tid, "admin"), h.member(tid, "member"), h.member(tid, "viewer")

	content := base64.StdEncoding.EncodeToString([]byte(`id: authz-policy-template
info:
  name: authz policy template
  author: test
  severity: info
http:
  - method: GET
    path:
      - "{{BaseURL}}/"
    matchers:
      - type: status
        status:
          - 200
`))
	tmpl := func(name string) string {
		return `{"name":"` + name + `","template_type":"nuclei","content":"` + content + `"}`
	}
	source := func(name string) string {
		return `{"name":"` + name + `","source_type":"git","template_type":"nuclei",` +
			`"git_config":{"url":"https://github.com/projectdiscovery/nuclei-templates.git","branch":"main"}}`
	}
	inline := `{"type":"scan","payload":{"scanner":"nuclei","target":"https://example.test",` +
		`"custom_templates":[{"name":"inline.yaml","template_type":"nuclei","content":"` + content + `"}]}}`

	// Owners and administrators write.
	var created struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal([]byte(h.expect(admin, http.MethodPost, "/api/v1/scanner-templates", tmpl("admin-template"), http.StatusCreated)), &created); err != nil || created.ID == "" {
		t.Fatalf("admin template create: id %q, err %v", created.ID, err)
	}
	templateID := created.ID
	h.expect(owner, http.MethodPost, "/api/v1/scanner-templates", tmpl("owner-template"), http.StatusCreated)
	created.ID = ""
	if err := json.Unmarshal([]byte(h.expect(admin, http.MethodPost, "/api/v1/template-sources", source("admin-source"), http.StatusCreated)), &created); err != nil || created.ID == "" {
		t.Fatalf("admin source create: id %q, err %v", created.ID, err)
	}
	sourceID := created.ID
	if code, body := h.do(admin, http.MethodPost, "/api/v1/commands", inline); code == http.StatusForbidden {
		t.Fatalf("admin inline-template command refused: %s", body)
	}

	for _, u := range []policyUser{member, viewer} {
		// Reads stay.
		h.expect(u, http.MethodGet, "/api/v1/scanner-templates", "", http.StatusOK)
		h.expect(u, http.MethodGet, "/api/v1/scanner-templates/"+templateID, "", http.StatusOK)
		h.expect(u, http.MethodGet, "/api/v1/template-sources", "", http.StatusOK)
		h.expect(u, http.MethodGet, "/api/v1/template-sources/"+sourceID, "", http.StatusOK)

		// Writes are refused.
		h.expect(u, http.MethodPost, "/api/v1/scanner-templates", tmpl("member-template"), http.StatusForbidden)
		h.expect(u, http.MethodPut, "/api/v1/scanner-templates/"+templateID, `{"name":"renamed"}`, http.StatusForbidden)
		h.expect(u, http.MethodPost, "/api/v1/scanner-templates/"+templateID+"/deprecate", "", http.StatusForbidden)
		h.expect(u, http.MethodDelete, "/api/v1/scanner-templates/"+templateID, "", http.StatusForbidden)
		h.expect(u, http.MethodPost, "/api/v1/template-sources", source("member-source"), http.StatusForbidden)
		h.expect(u, http.MethodPut, "/api/v1/template-sources/"+sourceID, `{"name":"renamed"}`, http.StatusForbidden)
		h.expect(u, http.MethodPost, "/api/v1/template-sources/"+sourceID+"/sync", "", http.StatusForbidden)
		h.expect(u, http.MethodPost, "/api/v1/template-sources/"+sourceID+"/disable", "", http.StatusForbidden)
		h.expect(u, http.MethodDelete, "/api/v1/template-sources/"+sourceID, "", http.StatusForbidden)
	}

	// A member still holds commands:write, but cannot carry a template in one.
	h.expect(member, http.MethodPost, "/api/v1/commands", inline, http.StatusForbidden)

	// The seed: the system member and viewer roles hold neither write grant.
	var n int
	if err := h.db.QueryRow(`SELECT count(*) FROM role_permissions rp JOIN roles r ON r.id = rp.role_id
		WHERE r.is_system AND r.slug IN ('member','viewer')
		  AND rp.permission_id IN ('scans:templates:write','scans:sources:write','scans:templates:delete','scans:sources:delete')`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("member/viewer still hold %d template write grants, want 0", n)
	}
}

// excluded reports whether prod.example.com is excluded for tenantID through
// the same service read the scan dispatcher uses.
func (h *authzPolicyHarness) excluded(tenantID string) bool {
	h.t.Helper()
	svc := scopeapp.NewService(nil, postgres.NewScopeExclusionRepository(&postgres.DB{DB: h.db}), nil, logger.NewNop())
	id := shared.NewID()
	set, err := svc.ExcludedTargets(context.Background(), tenantID,
		[]scopeapp.ExclusionCandidate{{ID: id, Values: []string{"prod.example.com"}}})
	if err != nil {
		h.t.Fatalf("ExcludedTargets: %v", err)
	}
	return set[id]
}

func TestAuthzPolicy_ScopeExclusionsNeedApproval_DB(t *testing.T) {
	h := newAuthzPolicyHarness(t)
	tid := h.tenant()
	owner, admin := h.member(tid, "owner"), h.member(tid, "admin")
	member, other, viewer := h.member(tid, "member"), h.member(tid, "member"), h.member(tid, "viewer")
	create := func(u policyUser, pattern string) string {
		t.Helper()
		var out struct {
			ID       string `json:"id"`
			Status   string `json:"status"`
			InEffect bool   `json:"in_effect"`
		}
		body := h.expect(u, http.MethodPost, "/api/v1/scope/exclusions",
			`{"exclusion_type":"domain","pattern":"`+pattern+`","reason":"noisy host"}`, http.StatusCreated)
		if err := json.Unmarshal([]byte(body), &out); err != nil {
			t.Fatalf("decode %s: %v", body, err)
		}
		if out.Status != "pending" || out.InEffect {
			t.Fatalf("new exclusion by %s: status %q in_effect %v, want pending and not in effect", u.role, out.Status, out.InEffect)
		}
		return out.ID
	}

	// A member requests an exclusion: it is pending and suppresses nothing.
	id := create(member, "prod.example.com")
	if h.excluded(tid) {
		t.Fatal("a pending exclusion suppressed scanning")
	}
	base := "/api/v1/scope/exclusions/" + id

	// scope:write is not enough to approve, reject or switch it on.
	for _, u := range []policyUser{member, other, viewer} {
		h.expect(u, http.MethodPost, base+"/approve", "", http.StatusForbidden)
		h.expect(u, http.MethodPost, base+"/reject", "", http.StatusForbidden)
	}
	h.expect(member, http.MethodPost, base+"/activate", "", http.StatusConflict)
	if h.excluded(tid) {
		t.Fatal("exclusion took effect without an approval")
	}

	// An administrator approves; it takes effect. Approving twice conflicts.
	h.expect(admin, http.MethodPost, base+"/approve", "", http.StatusOK)
	if !h.excluded(tid) {
		t.Fatal("an approved exclusion is not applied")
	}
	h.expect(owner, http.MethodPost, base+"/approve", "", http.StatusConflict)

	// The approver may hold the permission and still not approve their own
	// exclusion (separation of duties).
	own := create(admin, "own.example.com")
	h.expect(admin, http.MethodPost, "/api/v1/scope/exclusions/"+own+"/approve", "", http.StatusForbidden)
	h.expect(owner, http.MethodPost, "/api/v1/scope/exclusions/"+own+"/approve", "", http.StatusOK)

	// A rejected exclusion never takes effect.
	h.expect(admin, http.MethodDelete, base, "", http.StatusNoContent)
	rej := create(member, "prod.example.com")
	h.expect(owner, http.MethodPost, "/api/v1/scope/exclusions/"+rej+"/reject", "", http.StatusOK)
	h.expect(admin, http.MethodPost, "/api/v1/scope/exclusions/"+rej+"/approve", "", http.StatusConflict)
	h.expect(member, http.MethodPost, "/api/v1/scope/exclusions/"+rej+"/activate", "", http.StatusConflict)
	if h.excluded(tid) {
		t.Fatal("a rejected exclusion suppressed scanning")
	}
}

// A member could send a scan command for any address to any sensor of the
// tenant, past exclusions, zones and the private-range check (RFC-040 Q5 (c)).
func TestAuthzPolicy_ScanCommandsAreAdminOnlyAndScoped_DB(t *testing.T) {
	h := newAuthzPolicyHarness(t)
	tid := h.tenant()
	owner, admin, member := h.member(tid, "owner"), h.member(tid, "admin"), h.member(tid, "member")
	sensorID := h.sensor(tid)

	// An approved exclusion for prod.example.com.
	var excl struct {
		ID string `json:"id"`
	}
	body := h.expect(member, http.MethodPost, "/api/v1/scope/exclusions",
		`{"exclusion_type":"domain","pattern":"prod.example.com","reason":"fragile"}`, http.StatusCreated)
	if err := json.Unmarshal([]byte(body), &excl); err != nil {
		t.Fatal(err)
	}
	h.expect(owner, http.MethodPost, "/api/v1/scope/exclusions/"+excl.ID+"/approve", "", http.StatusOK)

	scanCmd := func(target string) string {
		return `{"type":"scan","sensor_id":"` + sensorID + `","payload":{"scanner":"nuclei","target":"` + target + `"}}`
	}

	// A member keeps commands:write for other command types, not for scans.
	h.expect(member, http.MethodPost, "/api/v1/commands", scanCmd("app.example.com"), http.StatusForbidden)
	h.expect(member, http.MethodPost, "/api/v1/commands", `{"type":"health_check","sensor_id":"`+sensorID+`"}`, http.StatusCreated)

	// An administrator is refused for an excluded or internal target.
	h.expect(admin, http.MethodPost, "/api/v1/commands", scanCmd("prod.example.com"), http.StatusBadRequest)
	h.expect(admin, http.MethodPost, "/api/v1/commands", scanCmd("10.0.0.5"), http.StatusBadRequest)
	h.expect(admin, http.MethodPost, "/api/v1/commands", scanCmd("169.254.169.254"), http.StatusBadRequest)

	// An in-scope target is accepted.
	h.expect(admin, http.MethodPost, "/api/v1/commands", scanCmd("app.example.com"), http.StatusCreated)

	var stored int
	if err := h.db.QueryRow(`SELECT count(*) FROM commands WHERE tenant_id = $1 AND type = 'scan'`, tid).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if stored != 1 {
		t.Fatalf("stored %d scan commands, want only the in-scope one", stored)
	}

	// Every attempt is in the audit log: four refusals and the creation.
	var denied, created int
	if err := h.db.QueryRow(`SELECT count(*) FILTER (WHERE result = 'denied'), count(*) FILTER (WHERE result = 'success' AND resource_name = 'scan')
		FROM audit_logs WHERE tenant_id = $1 AND action = 'command.created'`, tid).Scan(&denied, &created); err != nil {
		t.Fatal(err)
	}
	if denied != 4 || created != 1 {
		t.Fatalf("audit: %d denied, %d created scan commands; want 4 and 1", denied, created)
	}
}

package integration

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	_ "github.com/lib/pq"

	"github.com/openctemio/openctem/api/internal/app"
	"github.com/openctemio/openctem/api/internal/app/auth/domainverify"
	"github.com/openctemio/openctem/api/internal/config"
	"github.com/openctemio/openctem/api/internal/infra/http/handler"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/internal/testdb"
	"github.com/openctemio/openctem/api/pkg/crypto"
	"github.com/openctemio/openctem/api/pkg/domain/admin"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// txtResolver answers every TXT lookup with the configured value.
type txtResolver struct{ value string }

func (f *txtResolver) LookupTXT(context.Context, string) ([]string, error) {
	return []string{f.value}, nil
}

func selfSignedCertPEM(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "idp.example.test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

// A platform administrator could point an organization at a new identity
// provider (with JIT provisioning as admin), or change its SAML config or
// verified domains, and the organization's own audit log recorded nothing.
// Against the real repositories, every one of those changes made through the
// admin console now lands in the organization's audit log, attributed to
// "platform-admin:<email>" with the client IP (not the proxy socket address),
// and without the client secret or the certificate.
func TestAdminOrgSSOChangesReachOrganizationAuditLog(t *testing.T) {
	dsn := testdb.URL()
	if dsn == "" {
		t.Skip("DATABASE_URL not set; skipping admin organization SSO audit DB test")
	}
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := db.Ping(); err != nil {
		t.Skipf("database not available: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	ctx := context.Background()

	tenantID := uuid.NewString()
	if _, err := db.ExecContext(ctx, `INSERT INTO tenants (id, name, slug) VALUES ($1, 'SSO audit IT', $2)`,
		tenantID, "sso-audit-"+strings.ReplaceAll(tenantID[:13], "-", "")); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		for _, q := range []string{
			`DELETE FROM saml_providers WHERE tenant_id = $1`,
			`DELETE FROM tenant_identity_providers WHERE tenant_id = $1`,
			`DELETE FROM verified_domains WHERE tenant_id = $1`,
			`DELETE FROM audit_logs WHERE tenant_id = $1`,
			`DELETE FROM tenants WHERE id = $1`,
		} {
			_, _ = db.ExecContext(ctx, q, tenantID)
		}
	})

	pg := &postgres.DB{DB: db}
	log := logger.NewNop()
	auditSvc := app.NewAuditService(postgres.NewAuditRepository(pg), log)
	tenantRepo := postgres.NewTenantRepository(pg)
	sso := app.NewSSOService(postgres.NewIdentityProviderRepository(pg), tenantRepo, postgres.NewUserRepository(pg),
		postgres.NewSessionRepository(db), postgres.NewRefreshTokenRepository(db), crypto.NewNoOpEncryptor(),
		config.AuthConfig{JWTSecret: strings.Repeat("s", 64), JWTIssuer: "it"}, log)
	resolver := &txtResolver{}
	domains := domainverify.NewService(postgres.NewVerifiedDomainRepository(pg), resolver, log)
	saml := app.NewSAMLService(postgres.NewSAMLProviderRepository(pg), tenantRepo, sso, log)

	ssoH := handler.NewSSOHandler(sso, log)
	ssoH.SetAuditService(auditSvc)
	domainH := handler.NewVerifiedDomainHandler(domains, log)
	domainH.SetAuditService(auditSvc)
	samlH := handler.NewSAMLHandler(saml, handler.CookieConfig{}, "https://app.example.test", log)
	samlH.SetAuditService(auditSvc)
	// Admin-console SSO changes go through the owner-approval service (RFC-022
	// revision 8). The test organization has no owner, so they apply directly.
	ssoChanges := app.NewSSOChangeService(postgres.NewSSOChangeRepository(pg), saml, sso, tenantRepo, tenantRepo, log)
	samlH.SetChangeApproval(ssoChanges)
	ssoH.SetChangeApproval(ssoChanges)

	operator, err := admin.NewAdminUser("ops@platform.example.test", "Ops", admin.AdminRoleSuperAdmin, nil)
	if err != nil {
		t.Fatal(err)
	}
	scope := middleware.AdminTenantScope(func(context.Context, shared.ID) error { return nil })
	asAdmin := func(h http.HandlerFunc) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			r = r.WithContext(context.WithValue(r.Context(), middleware.AdminUserKey, operator))
			scope(h).ServeHTTP(w, r)
		})
	}
	mux := http.NewServeMux()
	base := "/api/v1/admin/tenants/{tenantId}/sso"
	mux.Handle("PUT "+base+"/saml", asAdmin(samlH.SetConfig))
	mux.Handle("DELETE "+base+"/saml", asAdmin(samlH.DeleteConfig))
	mux.Handle("POST "+base+"/identity-providers", asAdmin(ssoH.CreateProvider))
	mux.Handle("PUT "+base+"/identity-providers/{id}", asAdmin(ssoH.UpdateProvider))
	mux.Handle("DELETE "+base+"/identity-providers/{id}", asAdmin(ssoH.DeleteProvider))
	mux.Handle("POST "+base+"/verified-domains", asAdmin(domainH.AddDomain))
	mux.Handle("POST "+base+"/verified-domains/{id}/verify", asAdmin(domainH.Verify))
	mux.Handle("DELETE "+base+"/verified-domains/{id}", asAdmin(domainH.Delete))

	orgBase := "/api/v1/admin/tenants/" + tenantID + "/sso"
	call := func(method, path string, body any, want int) map[string]any {
		t.Helper()
		var rd *bytes.Reader
		if body != nil {
			raw, _ := json.Marshal(body)
			rd = bytes.NewReader(raw)
		} else {
			rd = bytes.NewReader(nil)
		}
		req := httptest.NewRequest(method, orgBase+path, rd)
		req.RemoteAddr = "203.0.113.9:47380"
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		if rec.Code != want {
			t.Fatalf("%s %s: got %d %s, want %d", method, path, rec.Code, rec.Body.String(), want)
		}
		out := map[string]any{}
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
		return out
	}

	const clientSecret = "very-secret-client-value"
	cert := selfSignedCertPEM(t)

	call(http.MethodPut, "/saml", map[string]any{
		"idp_entity_id": "https://idp.example.test/entity", "idp_sso_url": "https://idp.example.test/sso",
		"idp_certificate": cert, "allowed_domains": []string{"victim.example.test"},
		"default_role": "member", "auto_provision": true, "enabled": true,
	}, http.StatusOK)
	idp := call(http.MethodPost, "/identity-providers", map[string]any{
		"provider": "google_workspace", "display_name": "Rogue IdP", "client_id": "cid",
		"client_secret": clientSecret, "allowed_domains": []string{"victim.example.test"}, "auto_provision": true,
	}, http.StatusCreated)
	idpID, _ := idp["id"].(string)
	call(http.MethodPut, "/identity-providers/"+idpID, map[string]any{"client_secret": clientSecret + "-2"}, http.StatusOK)
	dom := call(http.MethodPost, "/verified-domains", map[string]any{"domain": "victim.example.test"}, http.StatusCreated)
	domID, _ := dom["id"].(string)
	instr, _ := dom["instructions"].(map[string]any)
	resolver.value, _ = instr["value"].(string)
	call(http.MethodPost, "/verified-domains/"+domID+"/verify", nil, http.StatusOK)
	call(http.MethodDelete, "/verified-domains/"+domID, nil, http.StatusNoContent)
	call(http.MethodDelete, "/identity-providers/"+idpID, nil, http.StatusNoContent)
	call(http.MethodDelete, "/saml", nil, http.StatusNoContent)

	rows, err := db.QueryContext(ctx, `SELECT action, COALESCE(actor_email, ''), COALESCE(actor_ip::text, ''),
			actor_id IS NULL, COALESCE(metadata::text, ''), COALESCE(resource_name, '')
		FROM audit_logs WHERE tenant_id = $1 ORDER BY logged_at`, tenantID)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	got := map[string]int{}
	for rows.Next() {
		var action, email, ip, meta, name string
		var noActorID bool
		if err := rows.Scan(&action, &email, &ip, &noActorID, &meta, &name); err != nil {
			t.Fatal(err)
		}
		got[action]++
		if email != "platform-admin:ops@platform.example.test" {
			t.Errorf("%s: actor_email = %q", action, email)
		}
		if !noActorID {
			t.Errorf("%s: actor_id is set; the platform admin is not a users row", action)
		}
		if strings.Contains(ip, ":47380") || !strings.HasPrefix(ip, "203.0.113.9") {
			t.Errorf("%s: actor_ip = %q, want the client IP without the port", action, ip)
		}
		if strings.Contains(meta, clientSecret) || strings.Contains(meta, "BEGIN CERTIFICATE") {
			t.Errorf("%s: metadata carries a secret: %s", action, meta)
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	for _, action := range []string{
		"sso.saml_config_updated", "sso.saml_config_deleted",
		"sso.identity_provider_created", "sso.identity_provider_updated", "sso.identity_provider_deleted",
		"sso.verified_domain_added", "sso.verified_domain_verified", "sso.verified_domain_deleted",
	} {
		if got[action] != 1 {
			t.Errorf("audit rows for %s = %d, want 1 (all: %v)", action, got[action], got)
		}
	}
}

// A platform administrator created a user with the admin role and the
// response said "member" (the membership label), although login and the member
// list show admin. The service now reports the effective role.
func TestCreatedOrgUserReportsEffectiveRole(t *testing.T) {
	dsn := testdb.URL()
	if dsn == "" {
		t.Skip("DATABASE_URL not set; skipping created-user role DB test")
	}
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := db.Ping(); err != nil {
		t.Skipf("database not available: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	ctx := context.Background()

	tenantID := uuid.NewString()
	if _, err := db.ExecContext(ctx, `INSERT INTO tenants (id, name, slug) VALUES ($1, 'Created role IT', $2)`,
		tenantID, "created-role-"+strings.ReplaceAll(tenantID[:13], "-", "")); err != nil {
		t.Fatal(err)
	}
	var created []string
	t.Cleanup(func() {
		_, _ = db.ExecContext(ctx, `DELETE FROM audit_logs WHERE tenant_id = $1`, tenantID)
		_, _ = db.ExecContext(ctx, `DELETE FROM user_roles WHERE tenant_id = $1`, tenantID)
		_, _ = db.ExecContext(ctx, `DELETE FROM tenant_members WHERE tenant_id = $1`, tenantID)
		for _, id := range created {
			_, _ = db.ExecContext(ctx, `DELETE FROM users WHERE id = $1`, id)
		}
		_, _ = db.ExecContext(ctx, `DELETE FROM tenants WHERE id = $1`, tenantID)
	})

	pg := &postgres.DB{DB: db}
	log := logger.NewNop()
	tenantRepo := postgres.NewTenantRepository(pg)
	roles := app.NewRoleService(postgres.NewRoleRepository(pg), postgres.NewPermissionRepository(pg), log,
		app.WithRoleMembershipReader(tenantRepo))
	svc := app.NewUserProvisioningService(tenantRepo, postgres.NewUserRepository(pg), roles, nil, nil, log)

	for _, tc := range []struct{ roleID, want string }{
		{"00000000-0000-0000-0000-000000000002", "admin"},
		{"00000000-0000-0000-0000-000000000003", "member"},
		{"00000000-0000-0000-0000-000000000004", "viewer"},
	} {
		email := "role-" + tc.want + "-" + uuid.NewString()[:8] + "@created.example.test"
		res, err := svc.CreateUser(ctx, app.CreateUserInput{
			TenantID: tenantID, Email: email, Name: "Created", RoleIDs: []string{tc.roleID},
		}, app.AuditContext{ActorEmail: "platform-admin:ops@platform.example.test"})
		if err != nil {
			t.Fatalf("create %s: %v", tc.want, err)
		}
		created = append(created, res.User.ID().String())
		if res.EffectiveRole != tc.want {
			t.Errorf("role %s: EffectiveRole = %q, want %q (membership label %q)",
				tc.want, res.EffectiveRole, tc.want, res.Membership.Role().String())
		}
	}
}

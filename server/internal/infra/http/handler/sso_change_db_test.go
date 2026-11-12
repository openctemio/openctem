package handler

// A platform administrator's SAML / identity-provider change waits for an
// owner of the organization (RFC-022, owner decision 2026-10-02). Exercised
// through the real handlers, services and repositories.
//
// Needs DATABASE_URL (CI's Test job provides one); skipped otherwise.

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	_ "github.com/lib/pq"

	"github.com/openctemio/openctem/api/internal/app/auth"
	"github.com/openctemio/openctem/api/internal/config"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/internal/testdb"
	"github.com/openctemio/openctem/api/pkg/crypto"
	"github.com/openctemio/openctem/api/pkg/domain/admin"
	notificationdom "github.com/openctemio/openctem/api/pkg/domain/notification"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	userdom "github.com/openctemio/openctem/api/pkg/domain/user"
	"github.com/openctemio/openctem/api/pkg/logger"
)

type capturedNotifications struct {
	mu     sync.Mutex
	inApp  []notificationdom.NotificationParams
	emails []string
}

func (c *capturedNotifications) Notify(_ context.Context, p notificationdom.NotificationParams) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.inApp = append(c.inApp, p)
	return nil
}

func (c *capturedNotifications) NotifySSOChangePending(_ context.Context, ownerEmail, _, _, summary string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.emails = append(c.emails, ownerEmail+"|"+summary)
}

func (c *capturedNotifications) reset() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.inApp, c.emails = nil, nil
}

func testCertPEM(t *testing.T, cn string) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func TestAdminSSOChange_RequiresOwnerApproval_DB(t *testing.T) {
	dbURL := testdb.URL()
	if dbURL == "" {
		t.Skip("DATABASE_URL not set; skipping DB-backed test")
	}
	raw, err := sql.Open("postgres", dbURL)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer raw.Close()
	if err := raw.Ping(); err != nil {
		t.Skipf("cannot reach test DB: %v", err)
	}
	ctx := context.Background()
	pg := &postgres.DB{DB: raw}
	log := logger.NewNop()
	tenantRepo := postgres.NewTenantRepository(pg)
	userRepo := postgres.NewUserRepository(pg)
	ipRepo := postgres.NewIdentityProviderRepository(pg)
	ssoSvc := auth.NewSSOService(ipRepo, tenantRepo, userRepo, postgres.NewSessionRepository(raw),
		postgres.NewRefreshTokenRepository(raw), crypto.NewNoOpEncryptor(), config.AuthConfig{JWTSecret: strings.Repeat("s", 64)}, log)
	samlSvc := auth.NewSAMLService(postgres.NewSAMLProviderRepository(pg), tenantRepo, ssoSvc, log)
	changes := auth.NewSSOChangeService(postgres.NewSSOChangeRepository(pg), samlSvc, ssoSvc, tenantRepo, tenantRepo, log)
	sent := &capturedNotifications{}
	changes.SetNotificationService(sent)
	changes.SetMailer(sent)

	samlH := NewSAMLHandler(samlSvc, CookieConfig{}, "http://localhost", log)
	samlH.SetChangeApproval(changes)
	ssoH := NewSSOHandler(ssoSvc, log)
	ssoH.SetChangeApproval(changes)
	decideH := NewSSOChangeHandler(changes, nil, log)

	// --- fixtures ---
	adminID := shared.NewID()
	adminEmail := "sso-chg-admin-" + uuid.NewString()[:8] + "@it.test"
	if _, err := raw.Exec(`INSERT INTO admin_users (id, email, name, role) VALUES ($1, $2, 'IT admin', 'super_admin')`,
		adminID.String(), adminEmail); err != nil {
		t.Fatalf("seed admin: %v", err)
	}
	t.Cleanup(func() { _, _ = raw.Exec(`DELETE FROM admin_users WHERE id = $1`, adminID.String()) })
	platformAdmin := admin.Reconstitute(adminID, adminEmail, "IT admin", admin.AdminRoleSuperAdmin,
		true, nil, nil, "", 0, nil, nil, "", time.Now(), nil, time.Now())

	newOrg := func() shared.ID {
		id := uuid.NewString()
		if _, err := raw.Exec(`INSERT INTO tenants (id, name, slug) VALUES ($1, 'SSO change IT', $2)`,
			id, "sso-chg-"+strings.ReplaceAll(id[:13], "-", "")); err != nil {
			t.Fatalf("seed org: %v", err)
		}
		t.Cleanup(func() {
			_, _ = raw.Exec(`DELETE FROM users WHERE id IN (SELECT user_id FROM tenant_members WHERE tenant_id = $1)`, id)
			for _, q := range []string{`DELETE FROM sso_pending_changes WHERE tenant_id = $1`,
				`DELETE FROM saml_providers WHERE tenant_id = $1`, `DELETE FROM tenant_identity_providers WHERE tenant_id = $1`,
				`DELETE FROM user_roles WHERE tenant_id = $1`, `DELETE FROM tenant_members WHERE tenant_id = $1`, `DELETE FROM tenants WHERE id = $1`} {
				_, _ = raw.Exec(q, id)
			}
		})
		tid, _ := shared.IDFromString(id)
		return tid
	}
	addMember := func(org shared.ID, role string) *userdom.User {
		u, err := userdom.NewProvisionedLocalUser("sso-chg-"+role+"-"+uuid.NewString()[:8]+"@it.test", strings.ToUpper(role[:1])+role[1:])
		if err != nil {
			t.Fatal(err)
		}
		if err := userRepo.Create(ctx, u); err != nil {
			t.Fatalf("create user: %v", err)
		}
		if _, err := raw.Exec(`INSERT INTO tenant_members (id, user_id, tenant_id, role) VALUES ($1, $2, $3, $4)`,
			uuid.NewString(), u.ID().String(), org.String(), role); err != nil {
			t.Fatalf("seed membership: %v", err)
		}
		return u
	}

	// --- request helpers ---
	adminReq := func(method string, org shared.ID, body any, pathValues map[string]string) *http.Request {
		b, _ := json.Marshal(body)
		req := httptest.NewRequest(method, "/api/v1/admin/tenants/"+org.String()+"/sso", bytes.NewReader(b))
		for k, v := range pathValues {
			req.SetPathValue(k, v)
		}
		c := context.WithValue(req.Context(), middleware.AdminUserKey, platformAdmin)
		c = context.WithValue(c, middleware.TenantIDKey, org.String())
		c = context.WithValue(c, middleware.UserIDKey, "")
		return req.WithContext(c)
	}
	putSAML := func(org shared.ID, cert string) (int, map[string]any) {
		rec := httptest.NewRecorder()
		samlH.SetConfig(rec, adminReq(http.MethodPut, org, map[string]any{
			"idp_entity_id": "https://idp.example/" + org.String(), "idp_sso_url": "https://idp.example/sso",
			"idp_certificate": cert, "default_role": "member", "auto_provision": true, "enabled": true,
		}, nil))
		out := map[string]any{}
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
		return rec.Code, out
	}
	decide := func(verb string, org shared.ID, u *userdom.User, changeID string) (int, map[string]any) {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/tenants/x/settings/sso/changes/"+changeID+"/"+verb, nil)
		req.SetPathValue("changeId", changeID)
		c := context.WithValue(req.Context(), middleware.TeamIDKey, org)
		if u != nil {
			c = context.WithValue(c, middleware.LocalUserKey, u)
		}
		rec := httptest.NewRecorder()
		if verb == "approve" {
			decideH.Approve(rec, req.WithContext(c))
		} else {
			decideH.Reject(rec, req.WithContext(c))
		}
		out := map[string]any{}
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
		return rec.Code, out
	}
	liveCert := func(org shared.ID) string {
		var cert string
		err := raw.QueryRow(`SELECT idp_certificate FROM saml_providers WHERE tenant_id = $1`, org.String()).Scan(&cert)
		if err == sql.ErrNoRows {
			return ""
		}
		if err != nil {
			t.Fatalf("read live saml: %v", err)
		}
		return cert
	}
	status := func(changeID string) string {
		var s string
		if err := raw.QueryRow(`SELECT status FROM sso_pending_changes WHERE id = $1`, changeID).Scan(&s); err != nil {
			t.Fatalf("read change status: %v", err)
		}
		return s
	}

	t.Run("admin SAML change on an owned org is pending; owners notified", func(t *testing.T) {
		org := newOrg()
		owner := addMember(org, "owner")
		orgAdmin := addMember(org, "admin")
		member := addMember(org, "member")
		sent.reset()

		cert := testCertPEM(t, "attacker-idp")
		code, body := putSAML(org, cert)
		if code != http.StatusAccepted {
			t.Fatalf("status %d (%v), want 202", code, body)
		}
		if body["status"] != "pending" || body["kind"] != "saml_config" {
			t.Fatalf("body %v, want a pending saml_config change", body)
		}
		if body["certificate_sha256"] != auth.CertificateFingerprint(cert) {
			t.Fatalf("certificate_sha256 %v does not identify the submitted certificate", body["certificate_sha256"])
		}
		if got := liveCert(org); got != "" {
			t.Fatal("the live SAML config changed before an owner approved")
		}
		if len(sent.inApp) != 1 || sent.inApp[0].AudienceID == nil || *sent.inApp[0].AudienceID != owner.ID() {
			t.Fatalf("in-app notifications %+v, want exactly one, to the owner", sent.inApp)
		}
		if sent.inApp[0].NotificationType != notificationdom.TypeSSOChangePending {
			t.Fatalf("notification type %q", sent.inApp[0].NotificationType)
		}
		if len(sent.emails) != 1 || !strings.HasPrefix(sent.emails[0], owner.Email()+"|") {
			t.Fatalf("emails %v, want one to the owner", sent.emails)
		}
		id, _ := body["id"].(string)

		// An administrator or member of the organization cannot approve.
		for _, u := range []*userdom.User{orgAdmin, member, nil} {
			if c, b := decide("approve", org, u, id); c != http.StatusForbidden {
				t.Fatalf("non-owner approve: status %d (%v), want 403", c, b)
			}
		}
		if liveCert(org) != "" || status(id) != "pending" {
			t.Fatal("a refused approval changed something")
		}

		// The owner approves: applied.
		if c, b := decide("approve", org, owner, id); c != http.StatusOK || b["status"] != "approved" {
			t.Fatalf("owner approve: status %d (%v), want 200 approved", c, b)
		}
		if liveCert(org) != cert {
			t.Fatal("approval did not apply the SAML config")
		}
		// Not twice.
		if c, _ := decide("approve", org, owner, id); c != http.StatusConflict {
			t.Fatalf("second approve: status %d, want 409", c)
		}
	})

	t.Run("reject discards; live config unchanged", func(t *testing.T) {
		org := newOrg()
		owner := addMember(org, "owner")
		code, body := putSAML(org, testCertPEM(t, "rejected"))
		if code != http.StatusAccepted {
			t.Fatalf("status %d (%v)", code, body)
		}
		id, _ := body["id"].(string)
		if c, b := decide("reject", org, owner, id); c != http.StatusOK || b["status"] != "rejected" {
			t.Fatalf("reject: status %d (%v)", c, b)
		}
		if liveCert(org) != "" {
			t.Fatal("a rejected change was applied")
		}
		if c, _ := decide("approve", org, owner, id); c != http.StatusConflict {
			t.Fatalf("approve after reject: status %d, want 409", c)
		}
	})

	t.Run("an expired change cannot be approved", func(t *testing.T) {
		org := newOrg()
		owner := addMember(org, "owner")
		_, body := putSAML(org, testCertPEM(t, "expired"))
		id, _ := body["id"].(string)
		if _, err := raw.Exec(`UPDATE sso_pending_changes SET expires_at = NOW() - INTERVAL '1 hour' WHERE id = $1`, id); err != nil {
			t.Fatal(err)
		}
		if c, b := decide("approve", org, owner, id); c != http.StatusGone {
			t.Fatalf("approve expired: status %d (%v), want 410", c, b)
		}
		if liveCert(org) != "" {
			t.Fatal("an expired change was applied")
		}
	})

	t.Run("an owner of another organization cannot approve", func(t *testing.T) {
		orgA, orgB := newOrg(), newOrg()
		addMember(orgA, "owner")
		ownerB := addMember(orgB, "owner")
		_, body := putSAML(orgA, testCertPEM(t, "cross-tenant"))
		id, _ := body["id"].(string)

		// From their own organization: the change is not there.
		if c, _ := decide("approve", orgB, ownerB, id); c != http.StatusNotFound {
			t.Fatalf("cross-tenant approve via own org: status %d, want 404", c)
		}
		// Naming the other organization: not its owner.
		if c, _ := decide("approve", orgA, ownerB, id); c != http.StatusForbidden {
			t.Fatalf("cross-tenant approve via org A: status %d, want 403", c)
		}
		if liveCert(orgA) != "" || status(id) != "pending" {
			t.Fatal("a cross-tenant approval changed something")
		}
	})

	t.Run("organization without an owner: applies directly", func(t *testing.T) {
		org := newOrg()
		addMember(org, "admin") // members, but no owner
		cert := testCertPEM(t, "bootstrap")
		code, body := putSAML(org, cert)
		if code != http.StatusOK {
			t.Fatalf("status %d (%v), want 200", code, body)
		}
		if liveCert(org) != cert {
			t.Fatal("bootstrap SAML config was not applied")
		}
		var n int
		_ = raw.QueryRow(`SELECT COUNT(*) FROM sso_pending_changes WHERE tenant_id = $1`, org.String()).Scan(&n)
		if n != 0 {
			t.Fatalf("%d pending changes stored for an organization without an owner", n)
		}
	})

	// A suspended owner still owns the organization (RFC-022 revision 7). If the
	// change applied directly while every owner is suspended, an administrator
	// could suspend the owners and install their own identity provider.
	t.Run("organization whose owners are all suspended: the change waits", func(t *testing.T) {
		org := newOrg()
		owner := addMember(org, "owner")
		if _, err := raw.Exec(`UPDATE tenant_members SET status = 'suspended' WHERE tenant_id = $1 AND user_id = $2`,
			org.String(), owner.ID().String()); err != nil {
			t.Fatalf("suspend owner: %v", err)
		}
		code, body := putSAML(org, testCertPEM(t, "suspended-owner"))
		if code != http.StatusAccepted {
			t.Fatalf("status %d (%v), want 202: a suspended owner must still approve", code, body)
		}
		if liveCert(org) != "" {
			t.Fatal("the SAML config was applied while the organization's owners are suspended")
		}
	})

	t.Run("a newer submission supersedes the older one", func(t *testing.T) {
		org := newOrg()
		owner := addMember(org, "owner")
		_, first := putSAML(org, testCertPEM(t, "first"))
		second := testCertPEM(t, "second")
		_, next := putSAML(org, second)
		if c, _ := decide("approve", org, owner, first["id"].(string)); c != http.StatusConflict {
			t.Fatalf("approve superseded: status %d, want 409", c)
		}
		if c, _ := decide("approve", org, owner, next["id"].(string)); c != http.StatusOK {
			t.Fatalf("approve latest: status %d", c)
		}
		if liveCert(org) != second {
			t.Fatal("the latest change was not the one applied")
		}
	})

	t.Run("identity provider create and update wait; secret never exposed", func(t *testing.T) {
		org := newOrg()
		owner := addMember(org, "owner")
		const secret = "super-secret-client-value"

		rec := httptest.NewRecorder()
		ssoH.CreateProvider(rec, adminReq(http.MethodPost, org, map[string]any{
			"provider": "google_workspace", "display_name": "Attacker IdP", "client_id": "cid-1",
			"client_secret": secret, "auto_provision": true, "default_role": "member",
		}, nil))
		if rec.Code != http.StatusAccepted {
			t.Fatalf("create: status %d (%s), want 202", rec.Code, rec.Body.String())
		}
		if strings.Contains(rec.Body.String(), secret) {
			t.Fatal("the client secret is in the response")
		}
		var created map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &created)
		// The owner approves what the summary says: the provider by name.
		if sum, _ := created["summary"].(string); !strings.Contains(sum, `Google Workspace identity provider "Attacker IdP"`) ||
			strings.Contains(sum, "google_workspace") {
			t.Fatalf("create summary %q does not name the provider", sum)
		}
		var payload string
		_ = raw.QueryRow(`SELECT payload::text FROM sso_pending_changes WHERE id = $1`, created["id"]).Scan(&payload)
		if strings.Contains(payload, secret) {
			t.Fatal("the client secret is stored in the payload")
		}
		var live int
		_ = raw.QueryRow(`SELECT COUNT(*) FROM tenant_identity_providers WHERE tenant_id = $1`, org.String()).Scan(&live)
		if live != 0 {
			t.Fatal("identity provider created before an owner approved")
		}
		if c, b := decide("approve", org, owner, created["id"].(string)); c != http.StatusOK {
			t.Fatalf("approve create: status %d (%v)", c, b)
		}
		var ipID, storedSecret string
		var auto bool
		if err := raw.QueryRow(`SELECT id, client_secret_encrypted, auto_provision FROM tenant_identity_providers WHERE tenant_id = $1`,
			org.String()).Scan(&ipID, &storedSecret, &auto); err != nil {
			t.Fatalf("provider not created on approval: %v", err)
		}
		if storedSecret != secret || !auto { // no-op encryptor in tests
			t.Fatalf("approved provider secret/auto_provision wrong: %q %v", storedSecret, auto)
		}
		var leftover sql.NullString
		_ = raw.QueryRow(`SELECT secret_encrypted FROM sso_pending_changes WHERE id = $1`, created["id"]).Scan(&leftover)
		if leftover.Valid {
			t.Fatal("the pending secret was kept after the decision")
		}

		// Update: pending, then applied on approval.
		rec = httptest.NewRecorder()
		ssoH.UpdateProvider(rec, adminReq(http.MethodPut, org, map[string]any{"client_id": "cid-2"}, map[string]string{"id": ipID}))
		if rec.Code != http.StatusAccepted {
			t.Fatalf("update: status %d (%s), want 202", rec.Code, rec.Body.String())
		}
		var updated map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &updated)
		if sum, _ := updated["summary"].(string); !strings.Contains(sum, `the Google Workspace identity provider "Attacker IdP" (client ID)`) ||
			strings.Contains(sum, ipID) {
			t.Fatalf("update summary %q does not name the provider", sum)
		}
		var clientID string
		_ = raw.QueryRow(`SELECT client_id FROM tenant_identity_providers WHERE id = $1`, ipID).Scan(&clientID)
		if clientID != "cid-1" {
			t.Fatal("identity provider updated before an owner approved")
		}
		if c, b := decide("approve", org, owner, updated["id"].(string)); c != http.StatusOK {
			t.Fatalf("approve update: status %d (%v)", c, b)
		}
		_ = raw.QueryRow(`SELECT client_id FROM tenant_identity_providers WHERE id = $1`, ipID).Scan(&clientID)
		if clientID != "cid-2" {
			t.Fatalf("client_id %q after approval, want cid-2", clientID)
		}
	})

	t.Run("admin list shows what is pending", func(t *testing.T) {
		org := newOrg()
		addMember(org, "owner")
		putSAML(org, testCertPEM(t, "listed"))
		req := adminReq(http.MethodGet, org, nil, nil)
		rec := httptest.NewRecorder()
		decideH.AdminList(rec, req)
		var out SSOChangeListResponse
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
		if rec.Code != http.StatusOK || len(out.Changes) != 1 || out.Changes[0].Status != "pending" {
			t.Fatalf("admin list: %d %+v", rec.Code, out)
		}
	})
}

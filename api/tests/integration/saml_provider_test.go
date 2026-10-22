package integration

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/internal/app/auth"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/samlprovider"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

func samlTestCertPEM(t *testing.T) string {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test-idp"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

// TestSAMLProvider_Repository_RoundTrip exercises the postgres SAML config
// against real SQL: upsert (incl the allowed_domains TEXT[] array + enabled
// flag), read back, update, delete.
func TestSAMLProvider_Repository_RoundTrip(t *testing.T) {
	sqlDB := setupTestDB(t)
	db := &postgres.DB{DB: sqlDB}
	ctx := context.Background()

	tenantID := createTestTenant(t, sqlDB, "saml")
	t.Cleanup(func() { cleanupTestData(sqlDB, tenantID) })

	repo := postgres.NewSAMLProviderRepository(db)
	cert := samlTestCertPEM(t)

	p := samlprovider.New(shared.NewID(), tenantID, "https://idp.example", "https://idp.example/sso", cert)
	p.SetAllowedDomains([]string{"acme.com", "acme.io"})
	p.SetEnabled(true)
	if err := repo.Upsert(ctx, p); err != nil {
		t.Fatalf("upsert: %v", err)
	}

	got, err := repo.GetByTenant(ctx, tenantID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.IDPEntityID() != "https://idp.example" || !got.Enabled() {
		t.Errorf("round-trip mismatch: %+v", got)
	}
	if len(got.AllowedDomains()) != 2 || got.AllowedDomains()[0] != "acme.com" {
		t.Errorf("allowed_domains array round-trip failed: %v", got.AllowedDomains())
	}
	if got.IDPCertificate() != cert {
		t.Error("certificate round-trip failed")
	}

	// Update (upsert again) — should not create a duplicate (UNIQUE tenant_id).
	p2 := samlprovider.New(got.ID(), tenantID, "https://idp2.example", "https://idp2/sso", cert)
	p2.SetEnabled(false)
	if err := repo.Upsert(ctx, p2); err != nil {
		t.Fatalf("update upsert: %v", err)
	}
	got2, _ := repo.GetByTenant(ctx, tenantID)
	if got2.IDPEntityID() != "https://idp2.example" || got2.Enabled() {
		t.Errorf("update not applied: %+v", got2)
	}

	if err := repo.Delete(ctx, tenantID); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := repo.GetByTenant(ctx, tenantID); !errors.Is(err, samlprovider.ErrNotFound) {
		t.Error("config should be gone after delete")
	}
}

// TestSAMLService_Metadata generates SP metadata for a real tenant and checks
// the SP entity id / ACS URL are present.
func TestSAMLService_Metadata(t *testing.T) {
	sqlDB := setupTestDB(t)
	db := &postgres.DB{DB: sqlDB}
	ctx := context.Background()

	// A tenant with a known slug so Metadata's GetBySlug resolves it.
	tenantID := shared.NewID()
	slug := "saml-meta-test"
	if _, err := sqlDB.Exec(
		`INSERT INTO tenants (id, name, slug, created_at, updated_at) VALUES ($1, 'SAML Meta', $2, NOW(), NOW())`,
		tenantID.String(), slug,
	); err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	t.Cleanup(func() { cleanupTestData(sqlDB, tenantID) })

	svc := auth.NewSAMLService(postgres.NewSAMLProviderRepository(db), postgres.NewTenantRepository(db), nil, logger.NewNop())

	xmlStr, err := svc.Metadata(ctx, slug, "https://app.openctem.io")
	if err != nil {
		t.Fatalf("metadata: %v", err)
	}
	acs := "https://app.openctem.io/api/v1/auth/saml/" + slug + "/acs"
	if !strings.Contains(xmlStr, acs) {
		t.Errorf("metadata missing ACS URL %q\n%s", acs, xmlStr)
	}
	if !strings.Contains(xmlStr, "EntityDescriptor") {
		t.Error("metadata is not a SAML EntityDescriptor")
	}
}

// The certificate-expiry notice state is per organization, and replacing the
// IdP certificate resets it so the new certificate gets its own alerts. A
// disabled config is never swept.
func TestSAMLProvider_CertificateNoticeState(t *testing.T) {
	sqlDB := setupTestDB(t)
	db := &postgres.DB{DB: sqlDB}
	ctx := context.Background()

	tenantA := createTestTenant(t, sqlDB, "saml-cert-a")
	tenantB := createTestTenant(t, sqlDB, "saml-cert-b")
	t.Cleanup(func() { cleanupTestData(sqlDB, tenantA); cleanupTestData(sqlDB, tenantB) })

	repo := postgres.NewSAMLProviderRepository(db)
	for _, tid := range []shared.ID{tenantA, tenantB} {
		p := samlprovider.New(shared.NewID(), tid, "https://idp.example", "https://idp.example/sso", samlTestCertPEM(t))
		p.SetEnabled(true)
		if err := repo.Upsert(ctx, p); err != nil {
			t.Fatalf("upsert: %v", err)
		}
	}
	if err := repo.SetCertificateNotice(ctx, tenantA, 7); err != nil {
		t.Fatalf("set notice: %v", err)
	}
	notice := func(tid shared.ID) *int {
		recs, err := repo.ListEnabledCertificates(ctx, shared.ID{}, 10000)
		if err != nil {
			t.Fatalf("list: %v", err)
		}
		for _, r := range recs {
			if r.TenantID == tid {
				return r.NoticeDays
			}
		}
		t.Fatalf("tenant %s not listed", tid)
		return nil
	}
	if n := notice(tenantA); n == nil || *n != 7 {
		t.Fatalf("tenant A notice: %v", n)
	}
	if n := notice(tenantB); n != nil {
		t.Fatalf("tenant B must be untouched by tenant A's notice, got %d", *n)
	}

	// Same certificate re-saved (another field changed): notice kept.
	same, _ := repo.GetByTenant(ctx, tenantA)
	same.SetDefaultRole("member")
	if err := repo.Upsert(ctx, same); err != nil {
		t.Fatalf("re-save: %v", err)
	}
	if n := notice(tenantA); n == nil || *n != 7 {
		t.Fatalf("re-saving the same certificate must keep the notice, got %v", n)
	}

	// New certificate: notice reset.
	cur, _ := repo.GetByTenant(ctx, tenantA)
	next := samlprovider.Reconstruct(cur.ID(), tenantA, cur.IDPEntityID(), cur.IDPSSOURL(), samlTestCertPEM(t),
		cur.AllowedDomains(), cur.DefaultRole(), cur.AutoProvision(), true, cur.CreatedAt(), cur.UpdatedAt())
	if err := repo.Upsert(ctx, next); err != nil {
		t.Fatalf("rotate: %v", err)
	}
	if n := notice(tenantA); n != nil {
		t.Fatalf("a new certificate must reset the notice, got %d", *n)
	}

	// Disabled: not swept.
	next.SetEnabled(false)
	if err := repo.Upsert(ctx, next); err != nil {
		t.Fatalf("disable: %v", err)
	}
	recs, _ := repo.ListEnabledCertificates(ctx, shared.ID{}, 10000)
	for _, r := range recs {
		if r.TenantID == tenantA {
			t.Fatal("a disabled SAML config must not be swept")
		}
	}
}

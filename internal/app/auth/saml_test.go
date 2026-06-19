package auth

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
	"testing"
	"time"

	samldom "github.com/openctemio/api/pkg/domain/samlprovider"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/logger"
)

type fakeSAMLRepo struct {
	byTenant map[shared.ID]*samldom.SAMLProvider
}

func newFakeSAMLRepo() *fakeSAMLRepo {
	return &fakeSAMLRepo{byTenant: map[shared.ID]*samldom.SAMLProvider{}}
}
func (f *fakeSAMLRepo) GetByTenant(_ context.Context, tenantID shared.ID) (*samldom.SAMLProvider, error) {
	if p, ok := f.byTenant[tenantID]; ok {
		return p, nil
	}
	return nil, samldom.ErrNotFound
}
func (f *fakeSAMLRepo) Upsert(_ context.Context, p *samldom.SAMLProvider) error {
	f.byTenant[p.TenantID()] = p
	return nil
}
func (f *fakeSAMLRepo) Delete(_ context.Context, tenantID shared.ID) error {
	delete(f.byTenant, tenantID)
	return nil
}

func genTestCertPEM(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
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

func TestValidateCertificatePEM(t *testing.T) {
	if err := validateCertificatePEM(genTestCertPEM(t)); err != nil {
		t.Errorf("valid cert rejected: %v", err)
	}
	for _, bad := range []string{"", "not a cert", "-----BEGIN CERTIFICATE-----\nZ\n-----END CERTIFICATE-----"} {
		if err := validateCertificatePEM(bad); err == nil {
			t.Errorf("expected error for invalid cert %q", bad)
		}
	}
}

func newSAMLForTest() (*SAMLService, *fakeSAMLRepo) {
	repo := newFakeSAMLRepo()
	return NewSAMLService(repo, nil, nil, logger.NewNop()), repo
}

func TestSAMLUpsertConfig_Validation(t *testing.T) {
	svc, _ := newSAMLForTest()
	cert := genTestCertPEM(t)
	tenantID := shared.NewID()
	ctx := context.Background()

	// Missing required fields.
	if _, err := svc.UpsertConfig(ctx, tenantID, SAMLConfigInput{IDPCertificate: cert}); !errors.Is(err, shared.ErrValidation) {
		t.Errorf("missing entity/sso should be ErrValidation, got %v", err)
	}
	// Bad certificate.
	if _, err := svc.UpsertConfig(ctx, tenantID, SAMLConfigInput{
		IDPEntityID: "https://idp", IDPSSOURL: "https://idp/sso", IDPCertificate: "garbage",
	}); err == nil {
		t.Error("bad cert should be rejected")
	}
	// Bad role.
	if _, err := svc.UpsertConfig(ctx, tenantID, SAMLConfigInput{
		IDPEntityID: "https://idp", IDPSSOURL: "https://idp/sso", IDPCertificate: cert, DefaultRole: "owner",
	}); !errors.Is(err, shared.ErrValidation) {
		t.Errorf("owner role should be rejected, got %v", err)
	}
}

func TestSAMLUpsertConfig_StoresAndUpdates(t *testing.T) {
	svc, _ := newSAMLForTest()
	cert := genTestCertPEM(t)
	tenantID := shared.NewID()
	ctx := context.Background()

	p, err := svc.UpsertConfig(ctx, tenantID, SAMLConfigInput{
		IDPEntityID: "https://idp", IDPSSOURL: "https://idp/sso", IDPCertificate: cert,
		AllowedDomains: []string{"acme.com"}, Enabled: true,
	})
	if err != nil {
		t.Fatalf("upsert: %v", err)
	}
	if p.DefaultRole() != "member" || !p.Enabled() {
		t.Errorf("unexpected stored config: role=%s enabled=%v", p.DefaultRole(), p.Enabled())
	}

	// Update preserves the id (true upsert).
	p2, err := svc.UpsertConfig(ctx, tenantID, SAMLConfigInput{
		IDPEntityID: "https://idp2", IDPSSOURL: "https://idp/sso", IDPCertificate: cert, DefaultRole: "admin",
	})
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	if p2.ID() != p.ID() {
		t.Error("upsert should preserve the existing id")
	}
	if p2.DefaultRole() != "admin" || p2.IDPEntityID() != "https://idp2" {
		t.Errorf("update not applied: %+v", p2)
	}
}

func TestSAMLConfig_GetAndDelete(t *testing.T) {
	svc, _ := newSAMLForTest()
	tenantID := shared.NewID()
	ctx := context.Background()

	if _, err := svc.GetConfig(ctx, tenantID); !errors.Is(err, samldom.ErrNotFound) {
		t.Errorf("expected ErrNotFound for missing config, got %v", err)
	}
	if _, err := svc.UpsertConfig(ctx, tenantID, SAMLConfigInput{
		IDPEntityID: "https://idp", IDPSSOURL: "https://idp/sso", IDPCertificate: genTestCertPEM(t),
	}); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	if _, err := svc.GetConfig(ctx, tenantID); err != nil {
		t.Errorf("get after upsert: %v", err)
	}
	if err := svc.DeleteConfig(ctx, tenantID); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := svc.GetConfig(ctx, tenantID); !errors.Is(err, samldom.ErrNotFound) {
		t.Error("config should be gone after delete")
	}
}

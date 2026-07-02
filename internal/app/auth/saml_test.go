package auth

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/crewjam/saml"

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

func TestBuildIDPMetadata(t *testing.T) {
	certPEM := genTestCertPEM(t)
	p := samldom.Reconstruct(shared.NewID(), shared.NewID(),
		"https://idp.example.com/entity", "https://idp.example.com/sso", certPEM,
		nil, "member", true, true, time.Now(), time.Now())

	md, err := buildIDPMetadata(p)
	if err != nil {
		t.Fatalf("buildIDPMetadata: %v", err)
	}
	if md.EntityID != "https://idp.example.com/entity" {
		t.Errorf("entity id = %q", md.EntityID)
	}
	if len(md.IDPSSODescriptors) != 1 {
		t.Fatalf("want 1 IDPSSODescriptor, got %d", len(md.IDPSSODescriptors))
	}
	sso := md.IDPSSODescriptors[0]
	if len(sso.SingleSignOnServices) != 1 || sso.SingleSignOnServices[0].Location != "https://idp.example.com/sso" {
		t.Errorf("sso endpoint = %+v", sso.SingleSignOnServices)
	}
	// The cert data must be base64 DER that parses back to an X.509 cert — this
	// is exactly what crewjam getIDPSigningCerts does to verify assertions.
	certData := sso.KeyDescriptors[0].KeyInfo.X509Data.X509Certificates[0].Data
	der, err := base64.StdEncoding.DecodeString(certData)
	if err != nil {
		t.Fatalf("cert data not base64: %v", err)
	}
	if _, err := x509.ParseCertificate(der); err != nil {
		t.Fatalf("cert data not a valid DER cert: %v", err)
	}
}

func TestBuildIDPMetadata_InvalidCert(t *testing.T) {
	p := samldom.Reconstruct(shared.NewID(), shared.NewID(),
		"e", "https://idp/sso", "not-a-pem",
		nil, "member", true, true, time.Now(), time.Now())
	if _, err := buildIDPMetadata(p); err == nil {
		t.Fatal("expected error for invalid cert PEM")
	}
}

func TestExtractEmailName(t *testing.T) {
	tests := []struct {
		name      string
		assertion *saml.Assertion
		wantEmail string
		wantName  string
	}{
		{
			name:      "email nameid (lowercased)",
			assertion: &saml.Assertion{Subject: &saml.Subject{NameID: &saml.NameID{Value: "Alice@Example.com"}}},
			wantEmail: "alice@example.com",
		},
		{
			name: "email + displayName attributes",
			assertion: &saml.Assertion{
				AttributeStatements: []saml.AttributeStatement{{
					Attributes: []saml.Attribute{
						{Name: "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress", Values: []saml.AttributeValue{{Value: "bob@corp.com"}}},
						{FriendlyName: "displayName", Name: "urn:oid:2.16.840.1.113730.3.1.241", Values: []saml.AttributeValue{{Value: "Bob Jones"}}},
					},
				}},
			},
			wantEmail: "bob@corp.com",
			wantName:  "Bob Jones",
		},
		{
			name: "mail + cn attributes",
			assertion: &saml.Assertion{
				AttributeStatements: []saml.AttributeStatement{{
					Attributes: []saml.Attribute{
						{Name: "mail", Values: []saml.AttributeValue{{Value: "carol@x.io"}}},
						{Name: "cn", Values: []saml.AttributeValue{{Value: "Carol"}}},
					},
				}},
			},
			wantEmail: "carol@x.io",
			wantName:  "Carol",
		},
		{
			name:      "non-email nameid yields no email",
			assertion: &saml.Assertion{Subject: &saml.Subject{NameID: &saml.NameID{Value: "not-an-email"}}},
			wantEmail: "",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			email, name := extractEmailName(tc.assertion)
			if email != tc.wantEmail {
				t.Errorf("email = %q, want %q", email, tc.wantEmail)
			}
			if name != tc.wantName {
				t.Errorf("name = %q, want %q", name, tc.wantName)
			}
		})
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

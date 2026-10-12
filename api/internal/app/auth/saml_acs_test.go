package auth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/crewjam/saml"

	samldom "github.com/openctemio/openctem/api/pkg/domain/samlprovider"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	tenantdom "github.com/openctemio/openctem/api/pkg/domain/tenant"
	userdom "github.com/openctemio/openctem/api/pkg/domain/user"
	"github.com/openctemio/openctem/api/pkg/logger"
)

type acsTenantRepo struct {
	tenantdom.Repository
	t *tenantdom.Tenant
}

func (r acsTenantRepo) GetBySlug(_ context.Context, slug string) (*tenantdom.Tenant, error) {
	if r.t.Slug() == slug {
		return r.t, nil
	}
	return nil, shared.ErrNotFound
}

type acsSPProvider struct{ md *saml.EntityDescriptor }

func (p acsSPProvider) GetServiceProvider(*http.Request, string) (*saml.EntityDescriptor, error) {
	return p.md, nil
}

// The ACS must read the IdP's POSTed form itself. crewjam's ParseResponse reads
// r.PostForm, which is empty until ParseForm runs, so before this fix every
// signed response was rejected as "invalid xml: no root" and SAML sign-in could
// never succeed. A valid signed assertion must now get past validation (here it
// stops at the password-account takeover guard, which proves it was parsed and
// verified).
func TestSAMLACS_ParsesPostedSignedResponse(t *testing.T) {
	_, err := runSAMLACS(t, false, time.Now())
	if errors.Is(err, ErrSAMLResponseInvalid) {
		t.Fatalf("a valid signed response was rejected (form not parsed?): %v", err)
	}
	if !errors.Is(err, ErrSSOFederatedTakeover) {
		t.Fatalf("expected the takeover guard after successful validation, got %v", err)
	}
}

// runSAMLACS runs an SP-initiated login (with ForceAuthn when forceAuthn)
// and posts back a signed assertion whose AuthnInstant is authnAt. The
// account is password-backed, so a response that passes validation stops at
// the takeover guard.
func runSAMLACS(t *testing.T, forceAuthn bool, authnAt time.Time) (*saml.IdpAuthnRequest, error) {
	t.Helper()
	const base = "https://app.example.com"
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: "idp"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	certPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))

	tn, _ := tenantdom.NewTenant("Acme", "acme", shared.NewID().String())
	repo := newFakeSAMLRepo()
	repo.byTenant[tn.ID()] = samldom.Reconstruct(shared.NewID(), tn.ID(), "https://idp.example.com/metadata",
		"https://idp.example.com/sso", certPEM, nil, "viewer", true, true, time.Now(), time.Now())

	pwUser, _ := userdom.NewLocalUser("owner@acme.com", "Owner", "hash")
	sso := &SSOService{userRepo: &fakeUserRepo{byEmail: pwUser}, logger: logger.NewNop()}
	svc := NewSAMLService(repo, acsTenantRepo{t: tn}, sso, logger.NewNop())

	redirect, requestID, err := svc.Login(context.Background(), "acme", base, forceAuthn)
	if err != nil {
		t.Fatalf("Login: %v", err)
	}

	spMD := svc.baseServiceProvider("acme", base).Metadata()
	mdURL, _ := url.Parse("https://idp.example.com/metadata")
	ssoURL, _ := url.Parse("https://idp.example.com/sso")
	idp := &saml.IdentityProvider{Key: key, Certificate: cert, MetadataURL: *mdURL, SSOURL: *ssoURL,
		ServiceProviderProvider: acsSPProvider{md: spMD}}
	authnHTTP, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, redirect, nil)
	authn, err := saml.NewIdpAuthnRequest(idp, authnHTTP)
	if err != nil {
		t.Fatal(err)
	}
	if err := authn.Validate(); err != nil {
		t.Fatalf("authn request: %v", err)
	}
	now := time.Now()
	if err := (saml.DefaultAssertionMaker{}).MakeAssertion(authn, &saml.Session{
		ID: "s", CreateTime: authnAt, ExpireTime: now.Add(time.Hour), Index: "1",
		NameID: "owner@acme.com", NameIDFormat: string(saml.EmailAddressNameIDFormat), UserEmail: "owner@acme.com",
	}); err != nil {
		t.Fatal(err)
	}
	form, err := authn.PostBinding()
	if err != nil {
		t.Fatal(err)
	}

	body := url.Values{"SAMLResponse": {form.SAMLResponse}, "RelayState": {form.RelayState}}.Encode()
	r := httptest.NewRequest(http.MethodPost, "/api/v1/auth/saml/acme/acs", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	_, err = svc.ACS(context.Background(), "acme", base, r, []string{requestID}, forceAuthn)
	return authn, err
}

// Step-up for a SAML account: the re-sign-in sends ForceAuthn and the ACS
// refuses an assertion whose AuthnInstant is not fresh.
func TestSAMLForceAuthn(t *testing.T) {
	authn, err := runSAMLACS(t, true, time.Now())
	if authn.Request.ForceAuthn == nil || !*authn.Request.ForceAuthn {
		t.Fatal("the re-authentication AuthnRequest must carry ForceAuthn")
	}
	if !errors.Is(err, ErrSSOFederatedTakeover) {
		t.Fatalf("a fresh forced authentication must pass validation, got %v", err)
	}
	if _, err := runSAMLACS(t, true, time.Now().Add(-time.Hour)); !errors.Is(err, ErrSAMLResponseInvalid) {
		t.Fatalf("an hour-old AuthnInstant answered a ForceAuthn request, got %v", err)
	}
	plain, err := runSAMLACS(t, false, time.Now().Add(-time.Hour))
	if plain.Request.ForceAuthn != nil && *plain.Request.ForceAuthn {
		t.Fatal("an ordinary sign-in must not force re-authentication")
	}
	if !errors.Is(err, ErrSSOFederatedTakeover) {
		t.Fatalf("an ordinary sign-in with an old AuthnInstant must pass validation, got %v", err)
	}
}

func TestAssertionAuthnInstant(t *testing.T) {
	early, late := time.Now().Add(-time.Hour), time.Now()
	a := &saml.Assertion{AuthnStatements: []saml.AuthnStatement{{AuthnInstant: early}, {AuthnInstant: late}}}
	if got := assertionAuthnInstant(a); !got.Equal(late) {
		t.Fatalf("got %v, want the latest instant", got)
	}
	if got := assertionAuthnInstant(&saml.Assertion{}); !got.IsZero() {
		t.Fatalf("no statement: %v", got)
	}
}

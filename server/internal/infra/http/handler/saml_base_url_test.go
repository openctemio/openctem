package handler

import (
	"bytes"
	"compress/flate"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/openctemio/openctem/server/internal/app/auth"
	samldom "github.com/openctemio/openctem/server/pkg/domain/samlprovider"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
	tenantdom "github.com/openctemio/openctem/server/pkg/domain/tenant"
	"github.com/openctemio/openctem/server/pkg/httpsec"
	"github.com/openctemio/openctem/server/pkg/logger"
)

// The SP origin (entity ID, ACS URL, and the audience, recipient and
// destination an assertion must carry) comes from configuration only. When it
// was derived from the request, a Host or X-Forwarded-Host header chose the
// audience the SP checks, so an assertion the IdP issued to another service
// provider could be replayed here, and the metadata and AuthnRequest
// advertised addresses the sender chose.

const samlTestPublicURL = "https://ctem.example.com"

type samlURLTenantRepo struct {
	tenantdom.Repository
	t *tenantdom.Tenant
}

func (f samlURLTenantRepo) GetBySlug(_ context.Context, slug string) (*tenantdom.Tenant, error) {
	if f.t != nil && f.t.Slug() == slug {
		return f.t, nil
	}
	return nil, shared.ErrNotFound
}

type samlURLProviderRepo struct {
	samldom.Repository
	p *samldom.SAMLProvider
}

func (f samlURLProviderRepo) GetByTenant(_ context.Context, tenantID shared.ID) (*samldom.SAMLProvider, error) {
	if f.p != nil && f.p.TenantID() == tenantID {
		return f.p, nil
	}
	return nil, samldom.ErrNotFound
}

func samlURLTestCert(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test-idp"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

// newSAMLURLHandler is a handler over an organization "acme" with an enabled
// SAML configuration. publicURL is what the server would have configured.
func newSAMLURLHandler(t *testing.T, publicURL string) *SAMLHandler {
	t.Helper()
	tn, err := tenantdom.NewTenant("Acme", "acme", shared.NewID().String())
	if err != nil {
		t.Fatal(err)
	}
	p := samldom.Reconstruct(shared.NewID(), tn.ID(), "https://idp.example.org/entity", "https://idp.example.org/sso",
		samlURLTestCert(t), nil, "viewer", false, true, time.Now(), time.Now())
	svc := auth.NewSAMLService(samlURLProviderRepo{p: p}, samlURLTenantRepo{t: tn}, nil, logger.NewNop())
	h := NewSAMLHandler(svc, CookieConfig{}, "https://app.example.com", logger.NewNop())
	h.SetPublicURL(publicURL)
	return h
}

// hostileSAMLRequest is a request whose every client-controlled address
// header names another host, sent through a peer the server trusts as a
// proxy: the strongest position a header can have.
func hostileSAMLRequest(t *testing.T, method, path string, body io.Reader) *http.Request {
	t.Helper()
	prev := trustedProxiesForAuth
	trustedProxiesForAuth = httpsec.NewTrustedProxySet([]string{"10.0.0.0/8"})
	t.Cleanup(func() { trustedProxiesForAuth = prev })

	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("org", "acme")
	ctx := context.WithValue(context.Background(), chi.RouteCtxKey, rctx)
	r := httptest.NewRequestWithContext(ctx, method, "http://evil.example"+path, body)
	r.Host = "evil.example"
	r.RemoteAddr = "10.0.0.2:4000"
	r.Header.Set("X-Forwarded-Host", "evil.example")
	r.Header.Set("X-Forwarded-Proto", "http")
	r.Header.Set("Forwarded", "host=evil.example;proto=http")
	return r
}

func TestSAMLMetadata_HostileHostNeverChangesTheURLs(t *testing.T) {
	h := newSAMLURLHandler(t, samlTestPublicURL+"/")
	w := httptest.NewRecorder()
	h.Metadata(w, hostileSAMLRequest(t, http.MethodGet, "/api/v1/auth/saml/acme/metadata", nil))

	if w.Code != http.StatusOK {
		t.Fatalf("status %d, want 200: %s", w.Code, w.Body.String())
	}
	doc := w.Body.String()
	if strings.Contains(doc, "evil.example") {
		t.Fatalf("metadata names the host of the request:\n%s", doc)
	}
	for _, want := range []string{
		`entityID="` + samlTestPublicURL + `/api/v1/auth/saml/acme/metadata"`,
		`Location="` + samlTestPublicURL + `/api/v1/auth/saml/acme/acs"`,
	} {
		if !strings.Contains(doc, want) {
			t.Errorf("metadata lacks %s:\n%s", want, doc)
		}
	}
}

func TestSAMLLogin_HostileHostNeverChangesTheAuthnRequest(t *testing.T) {
	h := newSAMLURLHandler(t, samlTestPublicURL)
	w := httptest.NewRecorder()
	h.Login(w, hostileSAMLRequest(t, http.MethodGet, "/api/v1/auth/saml/acme/login", nil))

	if w.Code != http.StatusFound {
		t.Fatalf("status %d, want 302", w.Code)
	}
	loc, err := url.Parse(w.Header().Get("Location"))
	if err != nil || loc.Host != "idp.example.org" {
		t.Fatalf("redirect %q, want the configured IdP", w.Header().Get("Location"))
	}
	raw, err := base64.StdEncoding.DecodeString(loc.Query().Get("SAMLRequest"))
	if err != nil {
		t.Fatalf("SAMLRequest: %v", err)
	}
	xmlBytes, err := io.ReadAll(flate.NewReader(bytes.NewReader(raw)))
	if err != nil {
		t.Fatalf("inflate SAMLRequest: %v", err)
	}
	req := string(xmlBytes)
	if strings.Contains(req, "evil.example") {
		t.Fatalf("AuthnRequest names the host of the request:\n%s", req)
	}
	for _, want := range []string{
		`AssertionConsumerServiceURL="` + samlTestPublicURL + `/api/v1/auth/saml/acme/acs"`,
		samlTestPublicURL + `/api/v1/auth/saml/acme/metadata</`, // Issuer = the audience the ACS requires
	} {
		if !strings.Contains(req, want) {
			t.Errorf("AuthnRequest lacks %s:\n%s", want, req)
		}
	}
}

// Without a configured origin there is no SAML. The service is nil here: a
// handler that reached it (to build URLs from the request) would panic.
func TestSAML_RefusedWithoutConfiguredPublicURL(t *testing.T) {
	for _, publicURL := range []string{"", "ctem.example.com", "ftp://ctem.example.com", "//ctem.example.com"} {
		h := NewSAMLHandler(nil, CookieConfig{}, "https://app.example.com", logger.NewNop())
		h.SetPublicURL(publicURL)

		w := httptest.NewRecorder()
		h.Metadata(w, hostileSAMLRequest(t, http.MethodGet, "/api/v1/auth/saml/acme/metadata", nil))
		if w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), "SAML_PUBLIC_URL_UNSET") {
			t.Errorf("publicURL %q: metadata %d %s, want 409 SAML_PUBLIC_URL_UNSET", publicURL, w.Code, w.Body.String())
		}

		w = httptest.NewRecorder()
		h.Login(w, hostileSAMLRequest(t, http.MethodGet, "/api/v1/auth/saml/acme/login", nil))
		if got := w.Header().Get("Location"); w.Code != http.StatusFound || got != "https://app.example.com/login?error=saml_failed" {
			t.Errorf("publicURL %q: login %d %q, want a redirect to the sign-in page with saml_failed", publicURL, w.Code, got)
		}

		w = httptest.NewRecorder()
		form := strings.NewReader("SAMLResponse=" + url.QueryEscape(base64.StdEncoding.EncodeToString([]byte("<Response/>"))))
		r := hostileSAMLRequest(t, http.MethodPost, "/api/v1/auth/saml/acme/acs", form)
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		h.ACS(w, r)
		if got := w.Header().Get("Location"); w.Code != http.StatusFound || got != "https://app.example.com/login?error=saml_failed" {
			t.Errorf("publicURL %q: ACS %d %q, want a redirect to the sign-in page with saml_failed", publicURL, w.Code, got)
		}
		for _, c := range w.Result().Cookies() {
			if c.Value != "" {
				t.Errorf("publicURL %q: ACS set cookie %s without a configured origin", publicURL, c.Name)
			}
		}
	}
}

// The origin is the scheme and host of the configured URL; a path, a trailing
// slash or surrounding space never reach the SP URLs.
func TestSAMLBaseURL_IsTheConfiguredOrigin(t *testing.T) {
	for in, want := range map[string]string{
		"https://ctem.example.com":        "https://ctem.example.com",
		"https://ctem.example.com/":       "https://ctem.example.com",
		" https://ctem.example.com/app ":  "https://ctem.example.com",
		"http://localhost:8080":           "http://localhost:8080",
		"https://ctem.example.com:8443/x": "https://ctem.example.com:8443",
	} {
		h := &SAMLHandler{}
		h.SetPublicURL(in)
		if got, ok := h.baseURL(); !ok || got != want {
			t.Errorf("SetPublicURL(%q): base %q ok=%v, want %q", in, got, ok, want)
		}
	}
}

func TestIsSafeIdPRedirect(t *testing.T) {
	ok := []string{"https://idp.example.com/sso?SAMLRequest=abc&RelayState=acme", "http://127.0.0.1:8080/sso"}
	bad := []string{
		"", "/", "//evil.example/x", "/\\evil.example", "javascript:alert(1)",
		"data:text/html,x", "https:///nohost", "https://user:pw@idp.example.com/",
		"https://idp.example.com/\r\nSet-Cookie: a=b", "ftp://idp.example.com/", "https:\\\\evil.example",
	}
	for _, u := range ok {
		if !isSafeIdPRedirect(u) {
			t.Errorf("%q should be allowed", u)
		}
	}
	for _, u := range bad {
		if isSafeIdPRedirect(u) {
			t.Errorf("%q must be refused", u)
		}
	}
}

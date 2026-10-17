package internalapi

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/internal/app/entitlement"
	tenantapp "github.com/openctemio/openctem/api/internal/app/tenant"
	"github.com/openctemio/openctem/api/pkg/domain/limits"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	tenantdom "github.com/openctemio/openctem/api/pkg/domain/tenant"
)

type pki struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

func newCA(t *testing.T, cn string) pki {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: cn}, NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().Add(time.Hour), IsCA: true, KeyUsage: x509.KeyUsageCertSign, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	return pki{cert: c, key: key}
}

func (ca pki) issue(t *testing.T, cn string, server bool) tls.Certificate {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: cn},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature}
	if server {
		tpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		tpl.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
	} else {
		tpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func writePEM(t *testing.T, dir, name, typ string, der []byte) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

type fakeEnt struct {
	applied     []shared.ID
	lastLimits  limits.Limits
	lastDenies  []string
	lastCall    entitlement.ControlPlaneCall
	selfService limits.Limits
}

func (f *fakeEnt) ApplyControlPlane(_ context.Context, id shared.ID, l limits.Limits, d []string, c entitlement.ControlPlaneCall) error {
	f.applied, f.lastLimits, f.lastDenies, f.lastCall = append(f.applied, id), l, d, c
	return nil
}
func (f *fakeEnt) ApplySelfServiceDefaultsFromControlPlane(_ context.Context, d limits.Limits, c entitlement.ControlPlaneCall) error {
	f.selfService, f.lastCall = d, c
	return nil
}
func (f *fakeEnt) Usage(context.Context, shared.ID, bool) (map[limits.Key]int, error) {
	return map[limits.Key]int{limits.Seats: 3, limits.Assets: 7}, nil
}

type fakeIdle struct{ enabled map[shared.ID]bool }

func (f *fakeIdle) ChangePolicyByControlPlane(_ context.Context, id shared.ID, on bool, _, _, _ string) error {
	f.enabled[id] = on
	return nil
}

type fakeOrgs struct{ known []shared.ID }

func (f fakeOrgs) Exists(_ context.Context, id shared.ID) (bool, error) {
	for _, k := range f.known {
		if k == id {
			return true, nil
		}
	}
	return false, nil
}
func (f fakeOrgs) Page(_ context.Context, _ *shared.ID, limit int) ([]OrganizationRef, error) {
	out := []OrganizationRef{}
	for i, k := range f.known {
		if i >= limit {
			break
		}
		out = append(out, OrganizationRef{ID: k, CreatedAt: time.Now()})
	}
	return out, nil
}

type fakeProvisioner struct {
	got      tenantapp.CreateOrganizationInput
	existing string
}

func (f *fakeProvisioner) Create(_ context.Context, in tenantapp.CreateOrganizationInput) (*tenantapp.CreatedOrganization, error) {
	f.got = in
	if in.NewOwnerOnly && in.OwnerEmail == f.existing {
		return nil, tenantapp.ErrOwnerAccountExists
	}
	t, err := tenantdom.NewTenant(in.Name, in.Slug, shared.NewID().String())
	if err != nil {
		return nil, err
	}
	return &tenantapp.CreatedOrganization{Tenant: t, OwnerCreated: true, OwnerSetup: &tenantapp.ProvisionedUser{EmailSent: true, SetupToken: "secret-setup-token"}}, nil
}

type harness struct {
	url     string
	client  *http.Client // trusted client certificate
	foreign *http.Client // client certificate from another CA
	anon    *http.Client // no client certificate
	priv    ed25519.PrivateKey
	ent     *fakeEnt
	idle    *fakeIdle
	prov    *fakeProvisioner
	org     shared.ID
	n       int
}

func newHarness(t *testing.T, withProvisioner bool) *harness {
	t.Helper()
	dir := t.TempDir()
	serverCA, clientCA, otherCA := newCA(t, "server-ca"), newCA(t, "client-ca"), newCA(t, "other-ca")
	srvCert := serverCA.issue(t, "core", true)
	keyDER, _ := x509.MarshalPKCS8PrivateKey(srvCert.PrivateKey)
	certFile := writePEM(t, dir, "srv.crt", "CERTIFICATE", srvCert.Certificate[0])
	keyFile := writePEM(t, dir, "srv.key", "PRIVATE KEY", keyDER)
	caFile := writePEM(t, dir, "client-ca.crt", "CERTIFICATE", clientCA.cert.Raw)
	tlsCfg, err := TLSConfig(certFile, keyFile, caFile)
	if err != nil {
		t.Fatal(err)
	}
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	v, _ := NewVerifier([]ed25519.PublicKey{pub}, "openctem-cloud", NewMemoryReplayCache())
	h := &harness{priv: priv, ent: &fakeEnt{}, idle: &fakeIdle{enabled: map[shared.ID]bool{}}, org: shared.NewID()}
	deps := Deps{Verifier: v, Entitlements: h.ent, IdlePolicy: h.idle, Organizations: fakeOrgs{known: []shared.ID{h.org}}}
	if withProvisioner {
		h.prov = &fakeProvisioner{}
		deps.Provisioner = h.prov
	}
	srv := httptest.NewUnstartedServer(NewHandler(deps))
	srv.TLS = tlsCfg
	srv.StartTLS()
	t.Cleanup(srv.Close)
	h.url = srv.URL

	roots := x509.NewCertPool()
	roots.AddCert(serverCA.cert)
	mk := func(certs []tls.Certificate) *http.Client {
		return &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{
			RootCAs: roots, Certificates: certs, MinVersion: tls.VersionTLS13}}}
	}
	h.client = mk([]tls.Certificate{clientCA.issue(t, "cloud", false)})
	h.foreign = mk([]tls.Certificate{otherCA.issue(t, "intruder", false)})
	h.anon = mk(nil)
	return h
}

func (h *harness) token(t *testing.T, scope string) string {
	t.Helper()
	h.n++
	now := time.Now()
	return sign(t, tokenOpts{key: h.priv, iss: "openctem-cloud", aud: Audience, sub: "cloud", jti: "jti-" + string(rune('a'+h.n)) + now.String(),
		scope: scope, iat: now, exp: now.Add(time.Minute)})
}

func (h *harness) do(t *testing.T, c *http.Client, method, path, token, body string) (int, string) {
	t.Helper()
	req, _ := http.NewRequestWithContext(context.Background(), method, h.url+path, strings.NewReader(body))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := c.Do(req)
	if err != nil {
		return 0, err.Error()
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func TestInternalAPITransportAndScopes(t *testing.T) {
	h := newHarness(t, false)
	org := h.org.String()

	if code, _ := h.do(t, h.anon, http.MethodGet, "/internal/v1/catalog", h.token(t, ScopeUsageRead), ""); code != 0 {
		t.Fatalf("no client certificate: the handshake must fail, got %d", code)
	}
	if code, _ := h.do(t, h.foreign, http.MethodGet, "/internal/v1/catalog", h.token(t, ScopeUsageRead), ""); code != 0 {
		t.Fatalf("a client certificate from another CA: the handshake must fail, got %d", code)
	}
	if code, _ := h.do(t, h.client, http.MethodGet, "/internal/v1/catalog", "", ""); code != http.StatusUnauthorized {
		t.Fatalf("no token: %d", code)
	}
	code, body := h.do(t, h.client, http.MethodGet, "/internal/v1/catalog", h.token(t, ScopeUsageRead), "")
	if code != http.StatusOK || !strings.Contains(body, `"orgs_per_user"`) || !strings.Contains(body, `"features"`) {
		t.Fatalf("catalog: %d %s", code, body)
	}
	// One token, one call.
	tok := h.token(t, ScopeUsageRead)
	if code, _ := h.do(t, h.client, http.MethodGet, "/internal/v1/catalog", tok, ""); code != http.StatusOK {
		t.Fatalf("first use: %d", code)
	}
	if code, _ := h.do(t, h.client, http.MethodGet, "/internal/v1/catalog", tok, ""); code != http.StatusUnauthorized {
		t.Fatalf("replayed token: %d", code)
	}
	// Scope per endpoint.
	put := `{"limits":{"seats":5},"denied_features":[],"reason":"tier"}`
	if code, _ := h.do(t, h.client, http.MethodPut, "/internal/v1/organizations/"+org+"/entitlements", h.token(t, ScopeUsageRead), put); code != http.StatusForbidden {
		t.Fatalf("usage:read writing limits: %d", code)
	}
	if code, _ := h.do(t, h.client, http.MethodGet, "/internal/v1/usage", h.token(t, ScopeLimitsWrite), ""); code != http.StatusForbidden {
		t.Fatalf("limits:write reading usage: %d", code)
	}
	if len(h.ent.applied) != 0 {
		t.Fatal("a refused call must not write")
	}
	// No tenant data is reachable: only the listed endpoints exist.
	for _, p := range []string{"/api/v1/findings", "/api/v1/assets", "/internal/v1/organizations/" + org + "/findings",
		"/internal/v1/organizations/" + org + "/members", "/internal/v1/organizations/" + org} {
		if code, _ := h.do(t, h.client, http.MethodGet, p, h.token(t, "limits:write orgs:provision usage:read"), ""); code != http.StatusNotFound && code != http.StatusMethodNotAllowed {
			t.Errorf("%s must not exist: %d", p, code)
		}
	}
}

func TestInternalAPIWrites(t *testing.T) {
	h := newHarness(t, true)
	org := h.org.String()
	w := func(method, path, body string) (int, string) {
		return h.do(t, h.client, method, path, h.token(t, "limits:write orgs:provision usage:read"), body)
	}

	code, _ := w(http.MethodPut, "/internal/v1/organizations/"+org+"/entitlements", `{"limits":{"seats":5,"assets":500},"denied_features":["pentest"],"reason":"service tier"}`)
	if code != http.StatusOK || len(h.ent.applied) != 1 || h.ent.applied[0] != h.org || h.ent.lastLimits[limits.Seats] != 5 ||
		h.ent.lastCall.Subject != "cloud" || h.ent.lastCall.TokenID == "" || h.ent.lastCall.Reason != "service tier" {
		t.Fatalf("entitlements: %d %+v", code, h.ent)
	}
	for name, body := range map[string]string{
		"unknown key":         `{"limits":{"gold":1},"reason":"x"}`,
		"per-person key":      `{"limits":{"orgs_per_user":1},"reason":"x"}`,
		"negative":            `{"limits":{"seats":-1},"reason":"x"}`,
		"unknown feature":     `{"limits":{},"denied_features":["dashboard"],"reason":"x"}`,
		"no reason":           `{"limits":{"seats":1}}`,
		"unknown field":       `{"limits":{},"reason":"x","plan":"pro"}`,
		"not json":            `seats=1`,
		"over the body limit": `{"reason":"` + strings.Repeat("x", 70<<10) + `"}`,
	} {
		if code, _ := w(http.MethodPut, "/internal/v1/organizations/"+org+"/entitlements", body); code != http.StatusBadRequest {
			t.Errorf("%s: %d", name, code)
		}
	}
	if code, _ := w(http.MethodPut, "/internal/v1/organizations/"+shared.NewID().String()+"/entitlements", `{"limits":{},"reason":"x"}`); code != http.StatusNotFound {
		t.Fatalf("unknown organization: %d", code)
	}
	if len(h.ent.applied) != 1 {
		t.Fatal("refused calls must not write")
	}

	if code, _ := w(http.MethodPut, "/internal/v1/self-service-limits", `{"limits":{"seats":5,"orgs_per_user":1},"reason":"hosted defaults"}`); code != http.StatusOK ||
		h.ent.selfService[limits.OrgsPerUser] != 1 {
		t.Fatalf("self-service limits: %d %v", code, h.ent.selfService)
	}
	if code, _ := w(http.MethodPut, "/internal/v1/organizations/"+org+"/idle-policy", `{"enabled":true,"reason":"hosted"}`); code != http.StatusOK || !h.idle.enabled[h.org] {
		t.Fatalf("idle policy: %d", code)
	}

	code, body := w(http.MethodPost, "/internal/v1/organizations", `{"name":"Acme","slug":"acme-it","owner_email":"owner@example.com","limits":{"seats":5},"denied_features":["pentest"],"idle_policy":true,"reason":"sign-up"}`)
	if code != http.StatusCreated || strings.Contains(body, "secret-setup-token") || !strings.Contains(body, `"owner_account":"created"`) {
		t.Fatalf("provision: %d %s", code, body)
	}
	if p := h.prov.got.Provisioned; p == nil || p.Limits[limits.Seats] != 5 || !p.IdlePolicy || len(p.DeniedFeatures) != 1 || !h.prov.got.NewOwnerOnly {
		t.Fatalf("provisioned entitlements: %+v", h.prov.got)
	}
	// An existing account is never made owner by the control plane.
	h.prov.existing = "someone@example.com"
	code, body = w(http.MethodPost, "/internal/v1/organizations", `{"name":"Other","slug":"other-it","owner_email":"someone@example.com","reason":"sign-up"}`)
	if code != http.StatusConflict || !strings.Contains(body, "OWNER_ACCOUNT_EXISTS") {
		t.Fatalf("existing owner account: %d %s", code, body)
	}

	code, body = w(http.MethodGet, "/internal/v1/usage?limit=1", "")
	var page UsagePageResponse
	_ = json.Unmarshal([]byte(body), &page)
	if code != http.StatusOK || len(page.Items) != 1 || page.Items[0].Usage["seats"] != 3 || page.Next != org || page.Items[0].CreatedAt == "" {
		t.Fatalf("usage page: %d %s", code, body)
	}
	if code, _ := w(http.MethodGet, "/internal/v1/usage?limit=501", ""); code != http.StatusBadRequest {
		t.Fatalf("page limit: %d", code)
	}
}

func TestInternalAPIProvisioningOffWithoutProvisioner(t *testing.T) {
	h := newHarness(t, false)
	code, _ := h.do(t, h.client, http.MethodPost, "/internal/v1/organizations", h.token(t, ScopeOrgsProvision),
		`{"name":"Acme","slug":"acme","owner_email":"o@example.com","reason":"x"}`)
	if code != http.StatusServiceUnavailable {
		t.Fatalf("no provisioner: %d", code)
	}
}

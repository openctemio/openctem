package sensortransport

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect"

	sensorapp "github.com/openctemio/openctem/api/internal/app/sensor"
	sensordom "github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
	sensorv3 "github.com/openctemio/openctem/api/pkg/sensorproto/v3"
	"github.com/openctemio/openctem/api/pkg/sensorproto/v3/sensorv3connect"
	"github.com/openctemio/openctem/api/pkg/sensorsig"
)

func TestLoadCACreatesOnceAndReloads(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "ca")
	var wg sync.WaitGroup
	cas := make([]*CA, 8)
	errs := make([]error, 8)
	for i := range cas {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			cas[i], errs[i] = LoadCA("", "", dir)
		}(i)
	}
	wg.Wait()
	for i := range cas {
		if errs[i] != nil {
			t.Fatalf("load %d: %v", i, errs[i])
		}
		if cas[i].Fingerprint() != cas[0].Fingerprint() {
			t.Fatal("replicas created different CAs")
		}
	}
	st, err := os.Stat(filepath.Join(dir, caFileName))
	if err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("CA file mode %v %v", st.Mode(), err)
	}
	if d, _ := os.Stat(dir); d.Mode().Perm() != 0o700 {
		t.Fatalf("CA dir mode %v", d.Mode())
	}
	again, err := LoadCA("", "", dir)
	if err != nil || again.Fingerprint() != cas[0].Fingerprint() {
		t.Fatalf("reload: %v", err)
	}
	if strings.Contains(again.CertificatePEM(), "PRIVATE KEY") {
		t.Fatal("the CA bundle carries the key")
	}
}

func TestLoadCARefusesBadMaterial(t *testing.T) {
	dir := t.TempDir()
	good, _ := newCAPEM(time.Now())
	other, _ := newCAPEM(time.Now())
	write := func(name string, b []byte) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, b, 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	cert := write("c.pem", good)
	otherKey := write("k.pem", other)
	if _, err := LoadCA(cert, otherKey, ""); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("mismatched key: %v", err)
	}
	if _, err := LoadCA(cert, "", ""); err == nil {
		t.Fatal("cert without key accepted")
	}
	if _, err := LoadCA("", "", ""); err == nil {
		t.Fatal("no CA source accepted")
	}
	// A leaf certificate is not a CA.
	ca, _ := parseCA(good, good)
	leaf, _ := ca.ServerCertificate("x.test")
	leafPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.Certificate[0]})
	keyDER, _ := x509.MarshalPKCS8PrivateKey(leaf.PrivateKey)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	if _, err := LoadCA(write("l.pem", leafPEM), write("lk.pem", keyPEM), ""); err == nil {
		t.Fatal("a leaf accepted as CA")
	}
}

func TestIssueClient(t *testing.T) {
	ca := testCA(t)
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	tid, sid := shared.NewID().String(), shared.NewID().String()
	got, err := ca.IssueClient(pub, tid, sid, 0)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(got.DER)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Verify(x509.VerifyOptions{Roots: ca.Pool(), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		t.Fatalf("verify: %v", err)
	}
	if gt, gs, ok := SensorIDs(c); !ok || gt != tid || gs != sid {
		t.Fatalf("ids %q %q", gt, gs)
	}
	if d := c.NotAfter.Sub(time.Now()); d < DefaultCertTTL-time.Minute || d > DefaultCertTTL+time.Minute {
		t.Fatalf("lifetime %v", d)
	}
	if !c.PublicKey.(ed25519.PublicKey).Equal(pub) {
		t.Fatal("certifies another key")
	}
	if ClampCertTTL(time.Second) != MinCertTTL || ClampCertTTL(365*24*time.Hour) != MaxCertTTL {
		t.Fatal("ttl not clamped")
	}
	if _, err := ca.IssueClient(pub[:5], tid, sid, 0); err == nil {
		t.Fatal("bad key certified")
	}
}

func TestSensorIDsRefusesForgedURIs(t *testing.T) {
	tid, sid := shared.NewID().String(), shared.NewID().String()
	for _, u := range []string{
		"spiffe://other/tenant/" + tid + "/sensor/" + sid,
		"https://openctem/tenant/" + tid + "/sensor/" + sid,
		"spiffe://openctem/tenant/" + tid + "/sensor/" + sid + "/x",
		"spiffe://openctem/tenant/../sensor/" + sid,
		"spiffe://openctem/tenant/" + tid + "/sensor/" + sid + "?a=b",
	} {
		c := &x509.Certificate{}
		parsed, _ := parseURL(u)
		c.URIs = append(c.URIs, parsed)
		if _, _, ok := SensorIDs(c); ok {
			t.Errorf("accepted %s", u)
		}
	}
}

// --- the listener -----------------------------------------------------------

type memKeys struct {
	mu       sync.Mutex
	byThumb  map[string]sensorapp.SensorIdentity
	pubs     map[string]ed25519.PublicKey
	revoked  map[string]bool
	resolves int
}

func (m *memKeys) add(t *testing.T, tenantID string) (sensorapp.SensorIdentity, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	tid, _ := shared.IDFromString(tenantID)
	id := sensorapp.SensorIdentity{Sensor: &sensordom.Sensor{ID: shared.NewID(), TenantID: &tid}}
	m.mu.Lock()
	defer m.mu.Unlock()
	th := sensorsig.Thumbprint(pub)
	m.byThumb[th], m.pubs[th] = id, pub
	return id, priv
}

func (m *memKeys) SigningIdentity(_ context.Context, keyID string, _ bool) (sensorapp.SensorIdentity, ed25519.PublicKey, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.resolves++
	id, ok := m.byThumb[keyID]
	if !ok || m.revoked[keyID] {
		return sensorapp.SensorIdentity{}, nil, errors.New("unauthorized")
	}
	return id, m.pubs[keyID], nil
}

func (m *memKeys) RecordSignedUse(sensorapp.SensorIdentity, string) {}

func testCA(t *testing.T) *CA {
	t.Helper()
	raw, err := newCAPEM(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	ca, err := parseCA(raw, raw)
	if err != nil {
		t.Fatal(err)
	}
	return ca
}

type mtlsEnv struct {
	addr string
	ca   *CA
	keys *memKeys
}

func startMTLS(t *testing.T) *mtlsEnv {
	t.Helper()
	ca := testCA(t)
	keys := &memKeys{byThumb: map[string]sensorapp.SensorIdentity{}, pubs: map[string]ed25519.PublicKey{}, revoked: map[string]bool{}}
	s := NewServer(Config{}, nil, logger.NewNop())
	s.Attach(&fakeV2{status: 200, body: `{"protocol":2}`}, noHints{}, sameAuth{})
	srv, err := s.NewMTLSServer(MTLSConfig{Addr: "127.0.0.1:0", Host: "sensors.test"}, ca, keys)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.ServeTLS(ln, "", "") }()
	t.Cleanup(func() { _ = srv.Close() })
	return &mtlsEnv{addr: ln.Addr().String(), ca: ca, keys: keys}
}

// clientCert certifies key under ca with the given ids and validity.
func clientCert(t *testing.T, ca *CA, key ed25519.PrivateKey, tenantID, sensorID string, notBefore, notAfter time.Time) tls.Certificate {
	t.Helper()
	saved := ca.now
	ca.now = func() time.Time { return notBefore.Add(clockSkew) }
	issued, err := ca.IssueClient(key.Public().(ed25519.PublicKey), tenantID, sensorID, notAfter.Sub(notBefore))
	ca.now = saved
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{issued.DER}, PrivateKey: key}
}

func (e *mtlsEnv) client(cert *tls.Certificate, mutate func(*tls.Config)) sensorv3connect.SensorServiceClient {
	cfg := &tls.Config{RootCAs: e.ca.Pool(), ServerName: "sensors.test", MinVersion: tls.VersionTLS12}
	if cert != nil {
		cfg.Certificates = []tls.Certificate{*cert}
	}
	if mutate != nil {
		mutate(cfg)
	}
	hc := &http.Client{Transport: h2Transport(cfg), Timeout: 5 * time.Second}
	return sensorv3connect.NewSensorServiceClient(hc, "https://"+e.addr, connect.WithGRPC())
}

func hello(c sensorv3connect.SensorServiceClient) (*connect.Response[sensorv3.HelloResponse], error) {
	return c.Hello(context.Background(), connect.NewRequest(&sensorv3.HelloRequest{}))
}

func TestMTLSAcceptsOnlyLiveSensorCertificates(t *testing.T) {
	e := startMTLS(t)
	tenant := shared.NewID().String()
	id, key := e.keys.add(t, tenant)
	now := time.Now()
	good := clientCert(t, e.ca, key, tenant, id.Sensor.ID.String(), now, now.Add(time.Hour))

	out, err := hello(e.client(&good, nil))
	if err != nil {
		t.Fatalf("valid certificate: %v", err)
	}
	if out.Msg.GetBinding() != sensorv3.Binding_BINDING_GRPC {
		t.Fatalf("binding %v", out.Msg.GetBinding())
	}

	refused := func(name string, c sensorv3connect.SensorServiceClient) {
		t.Helper()
		if _, err := hello(c); err == nil {
			t.Fatalf("%s: accepted", name)
		}
	}
	// No client certificate.
	refused("no certificate", e.client(nil, nil))
	// Expired.
	expired := clientCert(t, e.ca, key, tenant, id.Sensor.ID.String(), now.Add(-3*time.Hour), now.Add(-time.Hour))
	refused("expired", e.client(&expired, nil))
	// Issued by another CA for the same key and ids.
	other := testCA(t)
	foreign := clientCert(t, other, key, tenant, id.Sensor.ID.String(), now, now.Add(time.Hour))
	refused("foreign CA", e.client(&foreign, nil))
	// The right CA, but the SAN names another tenant (the key's row is A).
	cross := clientCert(t, e.ca, key, shared.NewID().String(), id.Sensor.ID.String(), now, now.Add(time.Hour))
	refused("cross-tenant SAN", e.client(&cross, nil))
	// A key no sensor holds.
	_, stranger, _ := ed25519.GenerateKey(rand.Reader)
	unknown := clientCert(t, e.ca, stranger, tenant, id.Sensor.ID.String(), now, now.Add(time.Hour))
	refused("unregistered key", e.client(&unknown, nil))
	// TLS 1.2 is refused.
	refused("TLS 1.2", e.client(&good, func(c *tls.Config) { c.MaxVersion = tls.VersionTLS12 }))
	// An ECDSA client key (not a sensor key) is refused even from our CA.
	ek, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: mustSerial(t), NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, URIs: []*urlT{SensorURI(tenant, id.Sensor.ID.String())}}
	der, _ := x509.CreateCertificate(rand.Reader, tpl, e.ca.cert, &ek.PublicKey, e.ca.key)
	refused("ECDSA key", e.client(&tls.Certificate{Certificate: [][]byte{der}, PrivateKey: ek}, nil))

	// Revoked after the handshake: the next call on the same connection is
	// refused once the cache entry expires.
	c := e.client(&good, nil)
	if _, err := hello(c); err != nil {
		t.Fatal(err)
	}
	e.keys.mu.Lock()
	e.keys.revoked[sensorsig.Thumbprint(key.Public().(ed25519.PublicKey))] = true
	e.keys.mu.Unlock()
	time.Sleep(CacheTTL + 200*time.Millisecond)
	if _, err := hello(c); connect.CodeOf(err) != connect.CodeUnauthenticated {
		t.Fatalf("revoked key on a live connection: %v", err)
	}
}

func TestMTLSRefusesHTTP1(t *testing.T) {
	e := startMTLS(t)
	tenant := shared.NewID().String()
	id, key := e.keys.add(t, tenant)
	good := clientCert(t, e.ca, key, tenant, id.Sensor.ID.String(), time.Now(), time.Now().Add(time.Hour))
	tr := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: e.ca.Pool(), ServerName: "sensors.test",
		Certificates: []tls.Certificate{good}, NextProtos: []string{"http/1.1"}, MinVersion: tls.VersionTLS13}}
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://"+e.addr+"/", nil)
	resp, err := (&http.Client{Transport: tr, Timeout: 5 * time.Second}).Do(req)
	if err == nil {
		_ = resp.Body.Close()
		t.Fatalf("HTTP/1.1 served: %s", resp.Proto)
	}
}

func mustSerial(t *testing.T) *bigInt {
	t.Helper()
	s, err := randomSerial()
	if err != nil {
		t.Fatal(err)
	}
	return s
}

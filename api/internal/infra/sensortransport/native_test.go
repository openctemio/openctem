package sensortransport

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"testing"
	"time"

	proxyproto "github.com/pires/go-proxyproto"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
	sensorv3 "github.com/openctemio/openctem/api/pkg/sensorproto/v3"
)

// publicCert is a self-signed certificate for api.test and 127.0.0.1: the
// operator's certificate on the API listener.
func publicCert(t *testing.T) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "api.test"},
		DNSNames: []string{"api.test"}, IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IsCA: true, BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(der)
	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, pool
}

type nativeEnv struct {
	addr   string
	ca     *CA
	keys   *memKeys
	public *x509.CertPool
}

// startNative serves one TLS port the way the API does with
// SERVER_TLS_CERT_FILE: the public HTTP server on SplitTLS's listener,
// the gRPC binding (when mtls) on the same port.
func startNative(t *testing.T, mtls bool, trusted []string) *nativeEnv {
	t.Helper()
	ca := testCA(t)
	keys := &memKeys{byThumb: map[string]sensorIdentity{}, pubs: map[string]edPub{}, revoked: map[string]bool{}}
	s := NewServer(Config{}, nil, logger.NewNop())
	s.Attach(&fakeV2{status: 200, body: `{"protocol":2}`}, noHints{}, sameAuth{})
	if mtls {
		if err := s.EnableMTLS(MTLSConfig{Addr: "127.0.0.1:0", Host: "127.0.0.1", TrustedProxies: trusted}, ca, keys); err != nil {
			t.Fatal(err)
		}
	}
	cert, pool := publicCert(t)
	pub := &tls.Config{MinVersion: tls.VersionTLS12, NextProtos: []string{alpnH2, "http/1.1"}, Certificates: []tls.Certificate{cert}}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	apiLn, err := s.SplitTLS(ln, pub)
	if err != nil {
		t.Fatal(err)
	}
	api := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = io.WriteString(w, "api "+r.Proto)
		}),
		TLSConfig:         pub.Clone(),
		ReadHeaderTimeout: 5 * time.Second,
	}
	go func() { _ = api.Serve(apiLn) }()
	t.Cleanup(func() {
		_ = s.Shutdown(context.Background())
		_ = api.Close()
	})
	return &nativeEnv{addr: addr, ca: ca, keys: keys, public: pool}
}

func offerProtos(protos ...string) func(*tls.Config) {
	return func(c *tls.Config) { c.NextProtos = protos; c.ServerName = "127.0.0.1" }
}

// rawHandshake dials raw TLS and reports the negotiated protocol and the
// server's verdict (a refused client certificate arrives with the first
// read in TLS 1.3; a live connection just times out).
func rawHandshake(addr string, cfg *tls.Config) (string, error) {
	conn, err := tls.Dial("tcp", addr, cfg)
	if err != nil {
		return "", err
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	_, err = conn.Read(make([]byte, 1))
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		err = nil
	}
	return conn.ConnectionState().NegotiatedProtocol, err
}

func TestSplitTLSBrowserGetsThePublicCertificate(t *testing.T) {
	e := startNative(t, true, nil)
	for _, h2 := range []bool{true, false} {
		tr := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: e.public, ServerName: "api.test", MinVersion: tls.VersionTLS12}}
		if h2 {
			tr.ForceAttemptHTTP2 = true
		}
		hc := &http.Client{Transport: tr, Timeout: 5 * time.Second}
		req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://"+e.addr+"/", nil)
		resp, err := hc.Do(req)
		if err != nil {
			t.Fatalf("browser-like client (h2 %t): %v", h2, err)
		}
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		want := "api HTTP/1.1"
		if h2 {
			want = "api HTTP/2.0"
		}
		if string(body) != want {
			t.Fatalf("browser-like client (h2 %t): %q, want %q", h2, body, want)
		}
		tr.CloseIdleConnections()
	}
	// The sensor CA does not verify the public certificate: a client that
	// does not offer the sensor ALPN id never reaches the gRPC binding.
	if _, err := rawHandshake(e.addr, &tls.Config{RootCAs: e.ca.Pool(), ServerName: "127.0.0.1",
		NextProtos: []string{alpnH2}, MinVersion: tls.VersionTLS12}); err == nil {
		t.Fatal("h2-only client verified the public certificate against the sensor CA")
	}
}

func TestSplitTLSSensorALPNNeedsALiveSensorCertificate(t *testing.T) {
	e := startNative(t, true, nil)
	tenant := shared.NewID().String()
	id, key := e.keys.add(t, tenant)
	now := time.Now()
	good := clientCert(t, e.ca, key, tenant, id.Sensor.ID.String(), now, now.Add(time.Hour))
	c := &mtlsEnv{addr: e.addr, ca: e.ca, keys: e.keys}

	out, err := hello(c.client(&good, offerProtos(alpnH2, SensorALPN)))
	if err != nil {
		t.Fatalf("sensor with a live certificate on the shared port: %v", err)
	}
	if out.Msg.GetBinding() != sensorv3.Binding_BINDING_GRPC {
		t.Fatalf("binding %v, want gRPC", out.Msg.GetBinding())
	}

	// No client certificate: refused.
	if _, err := hello(c.client(nil, offerProtos(alpnH2, SensorALPN))); err == nil {
		t.Fatal("sensor ALPN without a client certificate was served")
	}
	// A certificate from another CA: refused.
	other := testCA(t)
	foreign := clientCert(t, other, key, tenant, id.Sensor.ID.String(), now, now.Add(time.Hour))
	if _, err := hello(c.client(&foreign, offerProtos(alpnH2, SensorALPN))); err == nil {
		t.Fatal("a certificate from another CA was served")
	}
	// The sensor ALPN id alone (no h2): refused, as on the dedicated listener.
	if _, err := rawHandshake(e.addr, &tls.Config{RootCAs: e.ca.Pool(), ServerName: "127.0.0.1",
		Certificates: []tls.Certificate{good}, NextProtos: []string{SensorALPN}, MinVersion: tls.VersionTLS13}); err == nil {
		t.Fatal("a ClientHello offering only the sensor ALPN id was served")
	}
}

func TestSplitTLSIsAdvertisedForALPNClients(t *testing.T) {
	e := startNative(t, true, nil)
	probe := TLSProbe(e.ca.Pool())
	adv := NewAdvertiser(GRPCStatus{State: GRPCPending})
	st := NewProber(adv, e.addr, probe, ProberConfig{}).Check(context.Background())
	if st.State != GRPCAdvertised || !st.RequiresALPN || adv.Endpoint() != "" || adv.ALPNEndpoint() != e.addr {
		t.Fatalf("shared port: %+v endpoint %q alpn %q; want advertised as grpc_alpn_endpoint only", st, adv.Endpoint(), adv.ALPNEndpoint())
	}
}

func TestSplitTLSWithoutTheGRPCBindingServesOnlyTheAPI(t *testing.T) {
	e := startNative(t, false, nil)
	conn, err := tls.Dial("tcp", e.addr, &tls.Config{RootCAs: e.public, ServerName: "api.test",
		NextProtos: []string{alpnH2, SensorALPN}, MinVersion: tls.VersionTLS12})
	if err != nil {
		t.Fatalf("sensor ALPN without the gRPC binding: %v", err)
	}
	defer func() { _ = conn.Close() }()
	if got := conn.ConnectionState().PeerCertificates[0].Subject.CommonName; got != "api.test" {
		t.Fatalf("served certificate %q, want the public one", got)
	}
	if got := TLSProbe(e.ca.Pool())(context.Background(), e.addr, probeProtosSensor); got != ReasonForeignCert {
		t.Fatalf("probe = %q, want %q (nothing to advertise)", got, ReasonForeignCert)
	}
}

func TestSplitTLSBelievesPROXYOnlyFromTrustedPeers(t *testing.T) {
	// 127.0.0.1 is not a trusted proxy: a PROXY header from it is refused,
	// a plain connection is served.
	e := startNative(t, true, []string{"10.0.0.0/8"})
	c, err := net.Dial("tcp", e.addr)
	if err != nil {
		t.Fatal(err)
	}
	h := proxyproto.HeaderProxyFromAddrs(2, &net.TCPAddr{IP: net.ParseIP("203.0.113.9"), Port: 4000}, c.RemoteAddr())
	if _, err := h.WriteTo(c); err != nil {
		t.Fatal(err)
	}
	tc := tls.Client(c, &tls.Config{RootCAs: e.public, ServerName: "api.test", MinVersion: tls.VersionTLS12})
	_ = tc.SetDeadline(time.Now().Add(5 * time.Second))
	if err := tc.Handshake(); err == nil {
		t.Fatal("PROXY header from an untrusted peer was accepted")
	}
	_ = tc.Close()
	if _, err := rawHandshake(e.addr, &tls.Config{RootCAs: e.public, ServerName: "api.test",
		NextProtos: []string{"http/1.1"}, MinVersion: tls.VersionTLS12}); err != nil {
		t.Fatalf("plain connection with trusted proxies configured: %v", err)
	}
}

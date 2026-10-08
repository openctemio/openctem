package sensortransport

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"
	proxyproto "github.com/pires/go-proxyproto"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
	sensorv3 "github.com/openctemio/openctem/api/pkg/sensorproto/v3"
	"github.com/openctemio/openctem/api/pkg/sensorproto/v3/sensorv3connect"
)

// startProxied serves the gRPC binding through Start with trusted PROXY
// sources; it returns the address and the in-process v2 fake.
func startProxied(t *testing.T, trusted []string) (string, *fakeV2, *mtlsEnv) {
	t.Helper()
	ca := testCA(t)
	keys := &memKeys{byThumb: map[string]sensorIdentity{}, pubs: map[string]edPub{}, revoked: map[string]bool{}}
	s := NewServer(Config{}, nil, logger.NewNop())
	f := &fakeV2{status: 200, body: `{}`}
	s.Attach(f, noHints{}, sameAuth{})
	// Reserve a port, then let Start listen on it.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	if err := s.EnableMTLS(MTLSConfig{Addr: addr, Host: "sensors.test", TrustedProxies: trusted}, ca, keys); err != nil {
		t.Fatal(err)
	}
	if err := s.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Shutdown(context.Background()) })
	return addr, f, &mtlsEnv{addr: addr, ca: ca, keys: keys}
}

// proxiedClient dials addr, writes a PROXY v2 header claiming src, then
// speaks TLS + HTTP/2 with cert.
func proxiedClient(e *mtlsEnv, cert tls.Certificate, src string) sensorv3connect.SensorServiceClient {
	cfg := &tls.Config{RootCAs: e.ca.Pool(), ServerName: "sensors.test", MinVersion: tls.VersionTLS13,
		Certificates: []tls.Certificate{cert}, NextProtos: []string{"h2"}}
	tr := h2Transport(cfg)
	tr.DialTLSContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		c, err := (&net.Dialer{}).DialContext(ctx, network, addr)
		if err != nil {
			return nil, err
		}
		srcAddr := &net.TCPAddr{IP: net.ParseIP(src), Port: 40000}
		h := proxyproto.HeaderProxyFromAddrs(2, srcAddr, c.RemoteAddr())
		if _, err := h.WriteTo(c); err != nil {
			_ = c.Close()
			return nil, err
		}
		tc := tls.Client(c, cfg)
		if err := tc.HandshakeContext(ctx); err != nil {
			_ = c.Close()
			return nil, err
		}
		return tc, nil
	}
	return sensorv3connect.NewSensorServiceClient(&http.Client{Transport: tr, Timeout: 5 * time.Second},
		"https://"+e.addr, connect.WithGRPC())
}

func TestMTLSBelievesPROXYOnlyFromTrustedPeers(t *testing.T) {
	tenant := shared.NewID().String()

	addr, f, e := startProxied(t, []string{"127.0.0.1/32"})
	id, key := e.keys.add(t, tenant)
	cert := clientCert(t, e.ca, key, tenant, id.Sensor.ID.String(), time.Now(), time.Now().Add(time.Hour))
	if _, err := proxiedClient(e, cert, "203.0.113.9").Hello(context.Background(),
		connect.NewRequest(&sensorv3.HelloRequest{})); err != nil {
		t.Fatalf("trusted PROXY: %v", err)
	}
	if !strings.HasPrefix(f.got.RemoteAddr, "203.0.113.9:") {
		t.Fatalf("peer %q, want the PROXY source", f.got.RemoteAddr)
	}
	_ = addr

	// A peer outside the trusted ranges cannot claim an address.
	_, f2, e2 := startProxied(t, []string{"10.0.0.0/8"})
	id2, key2 := e2.keys.add(t, tenant)
	cert2 := clientCert(t, e2.ca, key2, tenant, id2.Sensor.ID.String(), time.Now(), time.Now().Add(time.Hour))
	if _, err := proxiedClient(e2, cert2, "203.0.113.9").Hello(context.Background(),
		connect.NewRequest(&sensorv3.HelloRequest{})); err == nil {
		t.Fatal("an untrusted PROXY header was accepted")
	}
	if f2.got != nil {
		t.Fatal("the call reached the service")
	}
}

func TestEnableMTLSRefusesBadProxyRanges(t *testing.T) {
	s := NewServer(Config{}, nil, logger.NewNop())
	keys := &memKeys{byThumb: map[string]sensorIdentity{}, pubs: map[string]edPub{}, revoked: map[string]bool{}}
	if err := s.EnableMTLS(MTLSConfig{Addr: "127.0.0.1:0", Host: "sensors.test", TrustedProxies: []string{"not-a-cidr"}},
		testCA(t), keys); err == nil {
		t.Fatal("a malformed range accepted")
	}
}

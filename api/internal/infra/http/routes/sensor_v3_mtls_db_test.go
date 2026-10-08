package routes

// Sensor protocol v3, gRPC binding (docs/rfcs/RFC-059-sensor-transport-v3.md
// T7, T8, T10) against a migrated database: a key-bound sensor gets a client
// certificate over the signed HTTPS binding, then speaks gRPC over mTLS with
// it; the certificate's identity is the key's row (another tenant's command
// is NOT_FOUND), it renews over mTLS, and revoking the sensor ends its live
// control stream at once and refuses the next handshake.

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"net"
	"net/http"
	"path/filepath"
	"testing"
	"time"

	"connectrpc.com/connect"

	"github.com/openctemio/openctem/api/internal/infra/sensortransport"
	"github.com/openctemio/openctem/api/pkg/logger"
	sensorv3 "github.com/openctemio/openctem/api/pkg/sensorproto/v3"
	"github.com/openctemio/openctem/api/pkg/sensorproto/v3/sensorv3connect"
)

type mtlsBinding struct {
	addr string
	ca   *sensortransport.CA
}

// withMTLS loads a CA, wires IssueCertificate and serves the gRPC binding.
func (h *v3Harness) withMTLS() *mtlsBinding {
	h.t.Helper()
	ca, err := sensortransport.LoadCA("", "", filepath.Join(h.t.TempDir(), "ca"))
	if err != nil {
		h.t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		h.t.Fatal(err)
	}
	h.v3.SetCertificateIssuer(sensortransport.NewIssuer(ca, h.sensors, h.sensors, time.Hour, ln.Addr().String(), logger.NewNop()))
	srv, err := h.v3.NewMTLSServer(sensortransport.MTLSConfig{Addr: ln.Addr().String(), Host: "sensors.test"}, ca, h.sensors)
	if err != nil {
		h.t.Fatal(err)
	}
	go func() { _ = srv.ServeTLS(ln, "", "") }()
	h.t.Cleanup(func() { _ = srv.Close() })
	return &mtlsBinding{addr: ln.Addr().String(), ca: ca}
}

// grpcClient speaks gRPC over mTLS with chainPEM and s's key, pinning the
// CA bundle the platform returned.
func (b *mtlsBinding) grpcClient(t *testing.T, s v3Sensor, chainPEM, caPEM string) sensorv3connect.SensorServiceClient {
	t.Helper()
	block, _ := pem.Decode([]byte(chainPEM))
	if block == nil {
		t.Fatal("no certificate in the chain")
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM([]byte(caPEM)) {
		t.Fatal("no CA in the bundle")
	}
	cfg := &tls.Config{RootCAs: pool, ServerName: "sensors.test", MinVersion: tls.VersionTLS13,
		Certificates: []tls.Certificate{{Certificate: [][]byte{block.Bytes}, PrivateKey: s.key}}}
	p := new(http.Protocols)
	p.SetHTTP2(true)
	hc := &http.Client{Transport: &http.Transport{TLSClientConfig: cfg, Protocols: p}}
	return sensorv3connect.NewSensorServiceClient(hc, "https://"+b.addr, connect.WithGRPC())
}

func TestSensorV3MTLS_CertificateIdentityEndToEnd(t *testing.T) {
	h := newV3Harness(t)
	b := h.withMTLS()
	tidA, tidB := h.newTenant(), h.newTenant()
	a := h.newKeyBound(tidA)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Issued over the signed HTTPS binding.
	issued, err := h.client(a, false).IssueCertificate(ctx, connect.NewRequest(&sensorv3.IssueCertificateRequest{}))
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	m := issued.Msg
	if m.GetGrpcEndpoint() != b.addr || m.GetCaBundlePem() == "" || !m.GetRenewAfter().AsTime().Before(m.GetNotAfter().AsTime()) {
		t.Fatalf("issue answer %+v", m)
	}
	leafBlock, _ := pem.Decode([]byte(m.GetCertificateChainPem()))
	leaf, err := x509.ParseCertificate(leafBlock.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if tid, sid, ok := sensortransport.SensorIDs(leaf); !ok || tid != tidA || sid != a.id {
		t.Fatalf("certificate ids %q %q", tid, sid)
	}
	if !leaf.PublicKey.(ed25519.PublicKey).Equal(a.signer.PublicKey()) {
		t.Fatal("the certificate is not for the sensor's registered key")
	}
	var events int
	_ = h.db.QueryRow(`SELECT count(*) FROM sensor_events WHERE sensor_id = $1 AND type = 'certificate_issued'`, a.id).Scan(&events)
	if events != 1 {
		t.Fatalf("certificate_issued events: %d", events)
	}

	g := b.grpcClient(t, a, m.GetCertificateChainPem(), m.GetCaBundlePem())
	hello, err := g.Hello(ctx, connect.NewRequest(&sensorv3.HelloRequest{}))
	if err != nil || hello.Msg.GetBinding() != sensorv3.Binding_BINDING_GRPC {
		t.Fatalf("hello over mTLS: %v %+v", err, hello)
	}
	// The certificate's identity is tenant A's sensor: tenant B's command is
	// not found, tenant A's is claimed.
	other := h.newCommand(tidB, "")
	_, err = g.TransitionCommand(ctx, connect.NewRequest(&sensorv3.TransitionCommandRequest{
		CommandId: other, Transition: sensorv3.CommandTransition_COMMAND_TRANSITION_CLAIM}))
	wantCode(t, err, connect.CodeNotFound)
	mine := h.newCommand(tidA, "")
	claimed, err := g.ClaimCommands(ctx, connect.NewRequest(&sensorv3.ClaimCommandsRequest{Limit: 5}))
	if err != nil {
		t.Fatalf("claim over mTLS: %v", err)
	}
	if list := decodeAs[struct {
		Commands []struct{ ID string } `json:"commands"`
	}](t, claimed.Msg.GetCommandsJson()); len(list.Commands) != 1 || list.Commands[0].ID != mine {
		t.Fatalf("claimed %s", claimed.Msg.GetCommandsJson())
	}

	// Renewal over mTLS.
	renewed, err := g.IssueCertificate(ctx, connect.NewRequest(&sensorv3.IssueCertificateRequest{}))
	if err != nil || renewed.Msg.GetCertificateChainPem() == m.GetCertificateChainPem() {
		t.Fatalf("renew over mTLS: %v", err)
	}

	// Revocation ends a live control stream at once (the status change
	// wakes it; the periodic re-check is 30 s here) and refuses the next
	// handshake.
	stream, err := g.Subscribe(ctx, connect.NewRequest(&sensorv3.SubscribeRequest{}))
	if err != nil || !stream.Receive() {
		t.Fatalf("subscribe: %v", err)
	}
	start := time.Now()
	if _, err := h.sensors.RevokeSensor(ctx, tidA, a.id, "test", nil); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	for stream.Receive() {
		if time.Since(start) > 5*time.Second {
			t.Fatal("the stream outlived the revocation")
		}
	}
	wantCode(t, stream.Err(), connect.CodeUnauthenticated)
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("stream ended %v after the revocation", d)
	}
	time.Sleep(sensortransport.CacheTTL)
	fresh := b.grpcClient(t, a, m.GetCertificateChainPem(), m.GetCaBundlePem())
	if _, err := fresh.Hello(ctx, connect.NewRequest(&sensorv3.HelloRequest{})); err == nil {
		t.Fatal("a revoked sensor completed a handshake")
	}
}

func TestSensorV3MTLS_PausedSensorGetsNoCertificate(t *testing.T) {
	h := newV3Harness(t)
	h.withMTLS()
	tid := h.newTenant()
	s := h.newKeyBound(tid)
	h.exec(`UPDATE sensors SET status = 'disabled' WHERE id = $1`, s.id)
	_, err := h.client(s, false).IssueCertificate(context.Background(), connect.NewRequest(&sensorv3.IssueCertificateRequest{}))
	wantCode(t, err, connect.CodePermissionDenied)
}

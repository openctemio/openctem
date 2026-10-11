package sensortransport

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
	sensorv3 "github.com/openctemio/openctem/api/pkg/sensorproto/v3"
)

// The gateway's ALPN routing (deploy/gateway/sensors/*.wrappers), emulated:
// a ClientHello that offers SensorALPN is passed through byte for byte to
// the mTLS listener; any other is handed to a server that terminates TLS
// with its own certificate (the web UI and the API behind the gateway).

var errPeeked = errors.New("client hello read")

// peekConn feeds the TLS server what the client sent, records it, and
// swallows the server's answers (the alert after the peek).
type peekConn struct {
	net.Conn
	r io.Reader
}

func (p peekConn) Read(b []byte) (int, error)  { return p.r.Read(b) }
func (p peekConn) Write(b []byte) (int, error) { return len(b), nil }

func startALPNRouter(t *testing.T, sensorAddr string) string {
	t.Helper()
	term := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "gateway")
	}))
	term.EnableHTTP2 = true
	term.StartTLS()
	t.Cleanup(term.Close)
	termAddr := term.Listener.Addr().String()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go routeByALPN(c, sensorAddr, termAddr)
		}
	}()
	return ln.Addr().String()
}

func routeByALPN(c net.Conn, sensorAddr, termAddr string) {
	defer func() { _ = c.Close() }()
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	var seen bytes.Buffer
	var protos []string
	_ = tls.Server(peekConn{Conn: c, r: io.TeeReader(c, &seen)}, &tls.Config{
		GetConfigForClient: func(h *tls.ClientHelloInfo) (*tls.Config, error) {
			protos = h.SupportedProtos
			return nil, errPeeked
		},
	}).Handshake()
	_ = c.SetReadDeadline(time.Time{})
	target := termAddr
	if slices.Contains(protos, SensorALPN) {
		target = sensorAddr
	}
	up, err := net.Dial("tcp", target)
	if err != nil {
		return
	}
	defer func() { _ = up.Close() }()
	if _, err := up.Write(seen.Bytes()); err != nil {
		return
	}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, _ = io.Copy(c, up)
		_ = c.Close()
	}()
	_, _ = io.Copy(up, c)
	_ = up.Close()
	wg.Wait()
}

func TestProbeThroughALPNRoutingNeedsTheSensorALPN(t *testing.T) {
	ca := testCA(t)
	direct := startMTLSOn(t, ca)
	routed := startALPNRouter(t, direct)
	probe := TLSProbe(ca.Pool())
	ctx := context.Background()

	if got := probe(ctx, routed, probeProtosSensor); got != ReasonProbeOK {
		t.Fatalf("probe offering the sensor ALPN through the router = %q, want ok", got)
	}
	if got := probe(ctx, routed, probeProtosDirect); got != ReasonForeignCert {
		t.Fatalf("probe offering h2 only through the router = %q, want %q (the gateway's own certificate)", got, ReasonForeignCert)
	}

	// Behind ALPN routing: advertised for clients that offer the id only.
	adv := NewAdvertiser(GRPCStatus{State: GRPCPending})
	st := NewProber(adv, routed, probe, ProberConfig{}).Check(ctx)
	if st.State != GRPCAdvertised || !st.RequiresALPN {
		t.Fatalf("routed endpoint: %+v, want advertised and requires_alpn", st)
	}
	if adv.Endpoint() != "" || adv.ALPNEndpoint() != routed {
		t.Fatalf("routed endpoint: grpc_endpoint %q (want none: older clients would meet the gateway's certificate), grpc_alpn_endpoint %q",
			adv.Endpoint(), adv.ALPNEndpoint())
	}
	srv := NewServer(Config{}, nil, logger.NewNop())
	srv.Attach(&fakeV2{status: 200, body: `{"protocol":2}`}, noHints{}, sameAuth{})
	srv.SetAdvertiser(adv)
	if got := srv.grpcEndpoint(); got != "" {
		t.Fatalf("v3 hello grpc_endpoint behind ALPN routing = %q, want none", got)
	}

	// A port of its own (or a dedicated SNI host): both fields.
	adv = NewAdvertiser(GRPCStatus{State: GRPCPending})
	st = NewProber(adv, direct, probe, ProberConfig{}).Check(ctx)
	if st.State != GRPCAdvertised || st.RequiresALPN || adv.Endpoint() != direct || adv.ALPNEndpoint() != direct {
		t.Fatalf("direct endpoint: %+v endpoint %q alpn %q", st, adv.Endpoint(), adv.ALPNEndpoint())
	}

	// A gateway without ALPN routing: nothing advertised.
	gw := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	gw.EnableHTTP2 = true
	gw.StartTLS()
	t.Cleanup(gw.Close)
	adv = NewAdvertiser(GRPCStatus{State: GRPCPending})
	st = NewProber(adv, gw.Listener.Addr().String(), probe, ProberConfig{}).Check(ctx)
	if st.State != GRPCUnavailable || st.Reason != ReasonForeignCert || adv.ALPNEndpoint() != "" || adv.Endpoint() != "" {
		t.Fatalf("stock gateway: %+v", st)
	}
}

func TestSensorClientThroughALPNRouting(t *testing.T) {
	e := startMTLS(t)
	tenant := shared.NewID().String()
	id, key := e.keys.add(t, tenant)
	good := clientCert(t, e.ca, key, tenant, id.Sensor.ID.String(), time.Now(), time.Now().Add(time.Hour))
	routed := &mtlsEnv{addr: startALPNRouter(t, e.addr), ca: e.ca, keys: e.keys}
	offer := func(protos ...string) func(*tls.Config) {
		return func(c *tls.Config) { c.NextProtos = protos }
	}

	// The sensor offers h2 and the sensor id: routed to the listener, which
	// negotiates h2 (net/http keeps the extra id in the ClientHello).
	out, err := hello(routed.client(&good, offer(alpnH2, SensorALPN)))
	if err != nil {
		t.Fatalf("sensor ALPN through the router: %v", err)
	}
	if out.Msg.GetBinding() != sensorv3.Binding_BINDING_GRPC {
		t.Fatalf("binding %v", out.Msg.GetBinding())
	}
	// Without the id the router terminates TLS itself: the sensor CA pin
	// refuses its certificate (the client must not send anything there).
	if _, err := hello(routed.client(&good, nil)); err == nil {
		t.Fatal("h2 only through the router reached the mTLS listener")
	}
	// The id routes, it does not authenticate: no client certificate is
	// still refused by the listener behind the router.
	if _, err := hello(routed.client(nil, offer(alpnH2, SensorALPN))); err == nil {
		t.Fatal("no client certificate accepted through the router")
	}
	// The listener speaks h2 only: a handshake offering the sensor id alone
	// is refused (net/http itself always adds h2, so dial raw TLS).
	rawDial := func(protos ...string) (string, error) {
		conn, err := tls.Dial("tcp", e.addr, &tls.Config{RootCAs: e.ca.Pool(), ServerName: "sensors.test",
			Certificates: []tls.Certificate{good}, NextProtos: protos, MinVersion: tls.VersionTLS13})
		if err != nil {
			return "", err
		}
		defer func() { _ = conn.Close() }()
		// TLS 1.3: the server's verdict on the client certificate arrives
		// with the first read; a live connection just times out.
		_ = conn.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
		_, err = conn.Read(make([]byte, 1))
		var ne net.Error
		if errors.As(err, &ne) && ne.Timeout() {
			err = nil
		}
		return conn.ConnectionState().NegotiatedProtocol, err
	}
	if proto, err := rawDial(alpnH2, SensorALPN); err != nil || proto != alpnH2 {
		t.Fatalf("h2 and the sensor id: negotiated %q, %v; want h2", proto, err)
	}
	if _, err := rawDial(SensorALPN); err == nil {
		t.Fatal("a ClientHello offering only the sensor id was served")
	}
}

package sensortransport

import (
	"context"
	"crypto/ed25519"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	sensorapp "github.com/openctemio/openctem/api/internal/app/sensor"
	"github.com/openctemio/openctem/api/pkg/logger"
	sensorv3 "github.com/openctemio/openctem/api/pkg/sensorproto/v3"

	"connectrpc.com/connect"
)

// startMTLSOn serves the gRPC binding for host (an address) on 127.0.0.1.
func startMTLSOn(t *testing.T, ca *CA) string {
	t.Helper()
	keys := &memKeys{byThumb: map[string]sensorapp.SensorIdentity{}, pubs: map[string]ed25519.PublicKey{}, revoked: map[string]bool{}}
	s := NewServer(Config{}, nil, logger.NewNop())
	s.Attach(&fakeV2{status: 200, body: `{"protocol":2}`}, noHints{}, sameAuth{})
	srv, err := s.NewMTLSServer(MTLSConfig{Addr: "127.0.0.1:0", Host: "127.0.0.1"}, ca, keys)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.ServeTLS(ln, "", "") }()
	t.Cleanup(func() { _ = srv.Close() })
	return ln.Addr().String()
}

func TestTLSProbeReachesOnlyTheMTLSListener(t *testing.T) {
	ca := testCA(t)
	probe := TLSProbe(ca.Pool())
	ctx := context.Background()

	if got := probe(ctx, startMTLSOn(t, ca)); got != ReasonProbeOK {
		t.Fatalf("probe of the mTLS listener = %q, want ok", got)
	}
	// A gateway that terminates TLS itself (its own certificate) answers
	// on the endpoint: not the listener, never advertised.
	gw := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	gw.EnableHTTP2 = true
	gw.StartTLS()
	t.Cleanup(gw.Close)
	if got := probe(ctx, strings.TrimPrefix(gw.URL, "https://")); got != ReasonForeignCert {
		t.Fatalf("probe of a terminating gateway = %q, want %q", got, ReasonForeignCert)
	}
	// Another platform's sensor CA is foreign too.
	if got := TLSProbe(testCA(t).Pool())(ctx, startMTLSOn(t, ca)); got != ReasonForeignCert {
		t.Fatalf("probe with another CA = %q, want %q", got, ReasonForeignCert)
	}
	// Nothing listening.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	closed := ln.Addr().String()
	_ = ln.Close()
	if got := probe(ctx, closed); got != ReasonUnreachable {
		t.Fatalf("probe of a closed port = %q, want %q", got, ReasonUnreachable)
	}
	if got := probe(ctx, "no-such-host.invalid:443"); got != ReasonDNSFailed {
		t.Fatalf("probe of an unknown name = %q, want %q", got, ReasonDNSFailed)
	}
}

func TestProberTogglesTheAdvertisement(t *testing.T) {
	var reason atomic.Value
	reason.Store(ReasonUnreachable)
	adv := NewAdvertiser(GRPCStatus{State: GRPCPending, Endpoint: "sensors.test:443", Reason: ReasonProbeNotFinished})
	if adv.Endpoint() != "" {
		t.Fatal("a pending endpoint must not be advertised")
	}
	var changes []GRPCStatus
	p := NewProber(adv, "sensors.test:443", func(context.Context, string) string { return reason.Load().(string) },
		ProberConfig{OnChange: func(st GRPCStatus) { changes = append(changes, st) }})

	srv := NewServer(Config{}, nil, logger.NewNop())
	srv.Attach(&fakeV2{status: 200, body: `{"protocol":2}`}, noHints{}, sameAuth{})
	srv.SetAdvertiser(adv)
	helloEndpoint := func() string {
		res, err := srv.Hello(context.Background(), connect.NewRequest(&sensorv3.HelloRequest{}))
		if err != nil {
			t.Fatal(err)
		}
		return res.Msg.GetGrpcEndpoint()
	}

	st := p.Check(context.Background())
	if st.State != GRPCUnavailable || st.Reason != ReasonUnreachable || adv.Endpoint() != "" || helloEndpoint() != "" {
		t.Fatalf("failing probe: %+v, hello endpoint %q", st, helloEndpoint())
	}
	reason.Store(ReasonProbeOK)
	st = p.Check(context.Background())
	if st.State != GRPCAdvertised || adv.Endpoint() != "sensors.test:443" || helloEndpoint() != "sensors.test:443" {
		t.Fatalf("passing probe: %+v, hello endpoint %q", st, helloEndpoint())
	}
	p.Check(context.Background()) // unchanged: no change callback
	reason.Store(ReasonForeignCert)
	if st = p.Check(context.Background()); st.State != GRPCUnavailable || helloEndpoint() != "" {
		t.Fatalf("probe failing again must withdraw the endpoint: %+v", st)
	}
	if len(changes) != 3 {
		t.Fatalf("change callbacks = %d, want 3 (unavailable, advertised, unavailable)", len(changes))
	}
	if got := srv.GRPCStatus(); got.Reason != ReasonForeignCert {
		t.Fatalf("status reason = %q", got.Reason)
	}
}

func TestNilAdvertiserIsOff(t *testing.T) {
	var a *Advertiser
	if a.Endpoint() != "" || a.Status().Reason != ReasonTransportOff {
		t.Fatal("a nil advertiser advertises nothing")
	}
}

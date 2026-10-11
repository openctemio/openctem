package sensortransport

// The gRPC binding self-probe (docs/rfcs/RFC-059-sensor-transport-v3.md §7):
// the platform advertises its gRPC endpoint to sensors only while it can
// reach that endpoint itself, the way a sensor would. A probe dials the
// advertised host:port (through whatever gateway sits in front), completes a
// TLS 1.3 handshake with ALPN h2 and verifies the server certificate against
// the sensor CA only. Only the API's own mTLS listener holds a certificate
// from that CA, so a passing probe proves the path reaches it; a gateway that
// terminates TLS itself, a closed port or a wrong name fail the probe, and
// sensors are then told about the HTTPS binding only instead of being sent
// to an endpoint that cannot work.
//
// The probe presents no client certificate: the listener refuses it after
// the handshake, which proves nothing more and is logged at debug level.

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// GRPC binding states.
const (
	// GRPCAdvertised: the last probe passed; hello names the endpoint.
	GRPCAdvertised = "advertised"
	// GRPCUnavailable: not advertised; Reason says why.
	GRPCUnavailable = "unavailable"
	// GRPCPending: the first probe has not finished yet (not advertised).
	GRPCPending = "pending"
)

// Reasons the gRPC binding is not advertised (bounded set: a metric label).
const (
	ReasonProbeOK          = ""
	ReasonTransportOff     = "transport_off"
	ReasonNoPublicHost     = "no_public_host"
	ReasonNoCA             = "sensor_ca_unavailable"
	ReasonListenerFailed   = "listener_failed"
	ReasonDNSFailed        = "dns_failed"
	ReasonUnreachable      = "unreachable"
	ReasonForeignCert      = "foreign_certificate"
	ReasonHandshakeFailed  = "handshake_failed"
	ReasonHTTP2Refused     = "http2_refused"
	ReasonProbeNotFinished = "probe_pending"
)

var (
	grpcAdvertisedGauge = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "openctem_sensor_transport_grpc_advertised",
		Help: "1 while the sensor protocol v3 gRPC binding passes its self-probe and is advertised to sensors, else 0.",
	})
	grpcProbeTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "openctem_sensor_transport_grpc_probe_total",
		Help: "Self-probes of the sensor protocol v3 gRPC endpoint by result (ok or the failure reason).",
	}, []string{"result"})
)

// GRPCStatus is the gRPC binding's state as the platform sees it.
type GRPCStatus struct {
	State     string    `json:"state"`
	Endpoint  string    `json:"endpoint,omitempty"`
	Reason    string    `json:"reason,omitempty"`
	CheckedAt time.Time `json:"checked_at,omitempty"`
}

// Advertiser holds what hello says about the gRPC binding. Safe for
// concurrent use; the zero value advertises nothing.
type Advertiser struct {
	st atomic.Pointer[GRPCStatus]
}

// NewAdvertiser starts in st.
func NewAdvertiser(st GRPCStatus) *Advertiser {
	a := &Advertiser{}
	a.set(st)
	return a
}

func (a *Advertiser) set(st GRPCStatus) {
	a.st.Store(&st)
	if st.State == GRPCAdvertised {
		grpcAdvertisedGauge.Set(1)
	} else {
		grpcAdvertisedGauge.Set(0)
	}
}

// Status is the current state.
func (a *Advertiser) Status() GRPCStatus {
	if a == nil {
		return GRPCStatus{State: GRPCUnavailable, Reason: ReasonTransportOff}
	}
	if p := a.st.Load(); p != nil {
		return *p
	}
	return GRPCStatus{State: GRPCUnavailable, Reason: ReasonTransportOff}
}

// Endpoint is the host:port hello names, "" while not advertised.
func (a *Advertiser) Endpoint() string {
	st := a.Status()
	if st.State != GRPCAdvertised {
		return ""
	}
	return st.Endpoint
}

// ProbeFunc dials endpoint and returns "" when it reaches the mTLS listener,
// else the failure reason.
type ProbeFunc func(ctx context.Context, endpoint string) string

// Prober re-probes the endpoint and updates the advertiser.
type Prober struct {
	adv      *Advertiser
	endpoint string
	probe    ProbeFunc
	interval time.Duration
	retry    time.Duration
	now      func() time.Time
	onChange func(GRPCStatus)

	mu   sync.Mutex
	last string
}

// ProberConfig tunes a prober. Zero values take the defaults.
type ProberConfig struct {
	// Interval between probes while the endpoint passes (default 60 s).
	Interval time.Duration
	// Retry between probes while it fails (default 30 s).
	Retry time.Duration
	// OnChange is called when the state or reason changes.
	OnChange func(GRPCStatus)
}

// NewProber probes endpoint with probe.
func NewProber(adv *Advertiser, endpoint string, probe ProbeFunc, cfg ProberConfig) *Prober {
	if cfg.Interval <= 0 {
		cfg.Interval = time.Minute
	}
	if cfg.Retry <= 0 {
		cfg.Retry = 30 * time.Second
	}
	return &Prober{adv: adv, endpoint: endpoint, probe: probe, interval: cfg.Interval, retry: cfg.Retry,
		now: time.Now, onChange: cfg.OnChange, last: "\x00"}
}

// Check runs one probe and updates the advertisement.
func (p *Prober) Check(ctx context.Context) GRPCStatus {
	reason := p.probe(ctx, p.endpoint)
	result := "ok"
	st := GRPCStatus{State: GRPCAdvertised, Endpoint: p.endpoint, CheckedAt: p.now()}
	if reason != ReasonProbeOK {
		result = reason
		st.State, st.Reason = GRPCUnavailable, reason
	}
	grpcProbeTotal.WithLabelValues(result).Inc()
	p.adv.set(st)
	p.mu.Lock()
	changed := p.last != st.State+"|"+st.Reason
	p.last = st.State + "|" + st.Reason
	p.mu.Unlock()
	if changed && p.onChange != nil {
		p.onChange(st)
	}
	return st
}

// Run probes until ctx ends: every Interval while the endpoint passes,
// every Retry while it fails.
func (p *Prober) Run(ctx context.Context) {
	for {
		st := p.Check(ctx)
		wait := p.interval
		if st.State != GRPCAdvertised {
			wait = p.retry
		}
		t := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			t.Stop()
			return
		case <-t.C:
		}
	}
}

// probeTimeout bounds one probe (dial + handshake).
const probeTimeout = 5 * time.Second

// TLSProbe returns the probe that dials endpoint and verifies its server
// certificate against pool (the sensor CA) for the endpoint's host name.
func TLSProbe(pool *x509.CertPool) ProbeFunc {
	return func(ctx context.Context, endpoint string) string {
		host, port, err := net.SplitHostPort(endpoint)
		if err != nil {
			host, port = endpoint, "443"
		}
		ctx, cancel := context.WithTimeout(ctx, probeTimeout)
		defer cancel()
		d := &tls.Dialer{
			NetDialer: &net.Dialer{Timeout: probeTimeout},
			Config: &tls.Config{
				MinVersion: tls.VersionTLS13,
				ServerName: host,
				RootCAs:    pool,
				NextProtos: []string{alpnH2},
			},
		}
		conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(host, port))
		if err != nil {
			return probeReason(err)
		}
		defer func() { _ = conn.Close() }()
		tc, ok := conn.(*tls.Conn)
		if !ok || tc.ConnectionState().NegotiatedProtocol != alpnH2 {
			return ReasonHTTP2Refused
		}
		return ReasonProbeOK
	}
}

// probeReason classifies a failed dial or handshake.
func probeReason(err error) string {
	var dnsErr *net.DNSError
	var unknownCA x509.UnknownAuthorityError
	var hostErr x509.HostnameError
	var certErr *tls.CertificateVerificationError
	var opErr *net.OpError
	switch {
	case errors.As(err, &dnsErr):
		return ReasonDNSFailed
	case errors.As(err, &unknownCA), errors.As(err, &hostErr), errors.As(err, &certErr):
		// Something other than the API's mTLS listener answered (a gateway
		// that terminates TLS for this name, another service).
		return ReasonForeignCert
	case errors.As(err, &opErr) && opErr.Op == "dial":
		return ReasonUnreachable
	case errors.Is(err, context.DeadlineExceeded):
		return ReasonUnreachable
	default:
		return ReasonHandshakeFailed
	}
}

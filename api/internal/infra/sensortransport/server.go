// Package sensortransport serves sensor protocol v3
// (docs/rfcs/RFC-059-sensor-transport-v3.md): the openctem.sensor.v3
// SensorService over Connect, gRPC and gRPC-Web.
//
// Every RPC is one protocol v2 resource. The server builds the v2 request
// from the typed envelope and runs it through the v2 route group mounted
// in-process (routes.sensorV2InProcess), so authentication is the only part
// v3 does itself: limits, the edge chain, the services and their side effects
// are the v2 code, and a v2 answer becomes the v3 response or a Connect error
// carrying the RFC 9457 problem.
//
// Tenant isolation: the identity (and with it the tenant) is put in the
// context by the binding's authenticator (client certificate or RFC 9421
// signature). No message carries a tenant; every id a message names is
// looked up by the v2 handlers scoped to that tenant and sensor.
package sensortransport

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"time"

	"connectrpc.com/connect"

	sensorapp "github.com/openctemio/openctem/api/internal/app/sensor"
	"github.com/openctemio/openctem/api/internal/infra/http/handler"
	"github.com/openctemio/openctem/api/pkg/logger"
	sensorv3 "github.com/openctemio/openctem/api/pkg/sensorproto/v3"
	"github.com/openctemio/openctem/api/pkg/sensorproto/v3/sensorv3connect"
)

// PathPrefix is where the HTTPS binding is mounted on the API listener.
const PathPrefix = "/api/v3/sensor"

// ProtocolVersion is the protocol level a v3 answer announces.
const ProtocolVersion = 3

// maxEnvelopeBytes is what a message may carry besides the v2 content: ids,
// headers, the protobuf framing.
const maxEnvelopeBytes = 1 << 20

// Hints computes the doorbell of a control-stream event for the sensor in
// ctx (handler.SensorControlV2Handler).
type Hints interface {
	StreamHints(ctx context.Context, running []string) handler.StreamHints
}

// Authenticator re-resolves an identity for a long-lived connection
// (handler.SensorResultsV2Handler).
type Authenticator interface {
	Reauthenticate(ctx context.Context, id sensorapp.SensorIdentity) (sensorapp.SensorIdentity, error)
}

// Config tunes the server. Zero values take the defaults.
type Config struct {
	// GRPCEndpoint is host:port of the gRPC (mTLS) binding; "" when only
	// the HTTPS binding is served.
	GRPCEndpoint string
	// MaxContentBytes is the v2 results content limit; messages may carry
	// that plus the envelope.
	MaxContentBytes int64
	// Keepalive is how often an idle control stream sends a keepalive.
	Keepalive time.Duration
	// Recheck is how often a control stream re-resolves its identity and
	// the doorbell without a wake.
	Recheck time.Duration
	// MaxStreamAge closes a control stream after this long (jittered) so
	// identities are re-checked from scratch and streams rebalance across
	// replicas; the sensor reconnects at once.
	MaxStreamAge time.Duration
	// MaxStreamsPerSensor bounds concurrent control streams of one sensor.
	MaxStreamsPerSensor int
	// StreamOpensPerMinute and StreamOpenBurst are the token bucket on one
	// sensor's control-stream opens (per replica): a sensor that opens and
	// closes streams in a loop is refused with ResourceExhausted before any
	// database work.
	StreamOpensPerMinute int
	StreamOpenBurst      int
	// UnaryTimeout bounds one unary call.
	UnaryTimeout time.Duration
	// MaxUnaryInFlight bounds the unary calls this replica serves at once,
	// across both bindings and every sensor, counted before authentication
	// reads a byte (control streams have their own per-sensor bound).
	MaxUnaryInFlight int
	// MaxUnaryPerSensor bounds the unary calls of one sensor in flight on
	// the gRPC binding, where the identity is known before the body is
	// read: one sensor cannot hold many full-size messages in memory at
	// once before its rate budget applies.
	MaxUnaryPerSensor int
}

func (c Config) withDefaults() Config {
	if c.Keepalive <= 0 {
		c.Keepalive = 25 * time.Second
	}
	if c.Recheck <= 0 {
		c.Recheck = 30 * time.Second
	}
	if c.MaxStreamAge <= 0 {
		c.MaxStreamAge = 30 * time.Minute
	}
	if c.MaxStreamsPerSensor <= 0 {
		c.MaxStreamsPerSensor = 4
	}
	if c.StreamOpensPerMinute <= 0 {
		c.StreamOpensPerMinute = 6
	}
	if c.StreamOpenBurst <= 0 {
		c.StreamOpenBurst = 10
	}
	if c.UnaryTimeout <= 0 {
		c.UnaryTimeout = 30 * time.Second
	}
	if c.MaxContentBytes <= 0 {
		c.MaxContentBytes = 16 << 20
	}
	if c.MaxUnaryInFlight <= 0 {
		c.MaxUnaryInFlight = 256
	}
	if c.MaxUnaryPerSensor <= 0 {
		c.MaxUnaryPerSensor = 8
	}
	return c
}

// Server implements sensorv3connect.SensorServiceHandler.
type Server struct {
	sensorv3connect.UnimplementedSensorServiceHandler

	cfg Config
	log *logger.Logger
	hub *Hub
	// opens rate-limits each sensor's control-stream opens.
	opens  *openLimiter
	issuer CertificateIssuer
	// adv is what Hello says about the gRPC binding (SetAdvertiser); nil:
	// cfg.GRPCEndpoint.
	adv *Advertiser
	// prober re-checks the advertised endpoint (SetProber).
	prober *Prober
	// mtls is the gRPC binding's server (EnableMTLS); nil when not served.
	mtls *http.Server
	// mtlsProxies are the CIDRs whose PROXY header the listener believes.
	mtlsProxies []string
	// wakeBus fans wakes out across replicas (SetWakeBus); nil: this
	// replica only.
	wakeBus WakeBus
	// done is closed by Shutdown: control streams end so the listeners
	// can drain (a stream lives for minutes).
	done     chan struct{}
	doneOnce sync.Once

	mu    sync.RWMutex
	v2    http.Handler
	hints Hints
	auth  Authenticator

	// running is each sensor's last reported running list (from its v3
	// heartbeat), for the cancel ids of control-stream events.
	running sync.Map // sensor id -> []string

	// unary holds one slot per unary call in flight (MaxUnaryInFlight).
	unary chan struct{}
	// perSensor counts each sensor's unary calls in flight on the gRPC
	// binding (MaxUnaryPerSensor).
	perSensorMu sync.Mutex
	perSensor   map[string]int
}

// CertificateIssuer issues client certificates (IssueCertificate). nil
// answers Unimplemented.
type CertificateIssuer interface {
	Issue(ctx context.Context, id sensorapp.SensorIdentity) (*sensorv3.IssueCertificateResponse, error)
}

// NewServer builds a server. Attach must be called before it serves.
func NewServer(cfg Config, hub *Hub, log *logger.Logger) *Server {
	if hub == nil {
		hub = NewHub(0)
	}
	cfg = cfg.withDefaults()
	hub.maxPerSensor = cfg.MaxStreamsPerSensor
	return &Server{cfg: cfg, hub: hub, log: log.With("component", "sensor-v3"), done: make(chan struct{}),
		unary: make(chan struct{}, cfg.MaxUnaryInFlight), opens: newOpenLimiter(cfg.StreamOpensPerMinute, cfg.StreamOpenBurst)}
}

// admitSensorUnary takes one of the sensor's unary slots on the gRPC
// binding, or answers 503 and returns false. A control stream takes none.
// release is never nil.
func (s *Server) admitSensorUnary(w http.ResponseWriter, r *http.Request, sensorID string) (release func(), ok bool) {
	if isStream(r) || sensorID == "" {
		return func() {}, true
	}
	s.perSensorMu.Lock()
	defer s.perSensorMu.Unlock()
	if s.perSensor == nil {
		s.perSensor = map[string]int{}
	}
	if s.perSensor[sensorID] >= s.cfg.MaxUnaryPerSensor {
		w.Header().Set("Retry-After", "1")
		http.Error(w, http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
		return func() {}, false
	}
	s.perSensor[sensorID]++
	return func() {
		s.perSensorMu.Lock()
		defer s.perSensorMu.Unlock()
		if s.perSensor[sensorID]--; s.perSensor[sensorID] <= 0 {
			delete(s.perSensor, sensorID)
		}
	}, true
}

// admitUnary takes a unary slot for r, or answers 503 and returns false
// when every slot is taken. A control stream takes none (its own bound is
// per sensor, after authentication). release is never nil.
func (s *Server) admitUnary(w http.ResponseWriter, r *http.Request) (release func(), ok bool) {
	if isStream(r) {
		return func() {}, true
	}
	select {
	case s.unary <- struct{}{}:
		return func() { <-s.unary }, true
	default:
		w.Header().Set("Retry-After", "1")
		http.Error(w, http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
		return func() {}, false
	}
}

// Attach wires the in-process v2 route group, the doorbell and the
// re-authenticator (done by route registration, which owns them).
func (s *Server) Attach(v2 http.Handler, hints Hints, auth Authenticator) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.v2, s.hints, s.auth = v2, hints, auth
}

// SetCertificateIssuer wires IssueCertificate.
func (s *Server) SetCertificateIssuer(i CertificateIssuer) { s.issuer = i }

// Hub is the server's control-stream hub (the wake target).
func (s *Server) Hub() *Hub { return s.hub }

func (s *Server) backend() (http.Handler, Hints, Authenticator) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.v2, s.hints, s.auth
}

// Handler is the Connect handler (gRPC, gRPC-Web and Connect protocols) of
// the service, with the message limits. path is the service path
// ("/openctem.sensor.v3.SensorService/").
func (s *Server) Handler() (string, http.Handler) {
	return sensorv3connect.NewSensorServiceHandler(s,
		connect.WithReadMaxBytes(int(s.cfg.MaxContentBytes)+maxEnvelopeBytes),
		connect.WithSendMaxBytes(int(s.cfg.MaxContentBytes)+maxEnvelopeBytes),
		connect.WithInterceptors(s.requireIdentity()),
	)
}

// errNoIdentity is every call that reaches the service without an
// authenticated identity (a wiring fault: the binding authenticates first).
var errNoIdentity = errors.New("not authenticated")

// requireIdentity refuses a call without an identity, a tenant-less sensor
// (RFC-059 T11) and a server that is not attached yet, and bounds unary
// calls. It runs for both bindings.
func (s *Server) requireIdentity() connect.Interceptor {
	return identityInterceptor{s: s}
}

type identityInterceptor struct{ s *Server }

func (i identityInterceptor) check(ctx context.Context) error {
	if v2, _, _ := i.s.backend(); v2 == nil {
		return connect.NewError(connect.CodeUnavailable, errors.New("sensor protocol v3 is starting"))
	}
	id, ok := handler.SensorIdentityFrom(ctx)
	if !ok {
		return connect.NewError(connect.CodeUnauthenticated, errNoIdentity)
	}
	if !handler.TenantSensor(id.Sensor) {
		return connect.NewError(connect.CodePermissionDenied, errors.New("scope denied"))
	}
	return nil
}

func (i identityInterceptor) WrapUnary(next connect.UnaryFunc) connect.UnaryFunc {
	return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
		if err := i.check(ctx); err != nil {
			return nil, err
		}
		ctx, cancel := context.WithTimeout(ctx, i.s.cfg.UnaryTimeout)
		defer cancel()
		return next(ctx, req)
	}
}

func (i identityInterceptor) WrapStreamingClient(next connect.StreamingClientFunc) connect.StreamingClientFunc {
	return next
}

func (i identityInterceptor) WrapStreamingHandler(next connect.StreamingHandlerFunc) connect.StreamingHandlerFunc {
	return func(ctx context.Context, conn connect.StreamingHandlerConn) error {
		if err := i.check(ctx); err != nil {
			return err
		}
		return next(ctx, conn)
	}
}

// bindingContextKey carries the binding a call arrived on.
type bindingContextKey struct{}

// WithBinding marks ctx with the binding the call arrived on.
func WithBinding(ctx context.Context, b sensorv3.Binding) context.Context {
	return context.WithValue(ctx, bindingContextKey{}, b)
}

// BindingFrom is the binding WithBinding stored (unspecified when none).
func BindingFrom(ctx context.Context) sensorv3.Binding {
	b, _ := ctx.Value(bindingContextKey{}).(sensorv3.Binding)
	return b
}

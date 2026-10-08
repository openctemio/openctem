package sensortransport

// The gRPC binding (RFC-059 T5, T8, T10): a TLS 1.3 listener that requires a
// client certificate from the sensor CA. The certificate's key is a sensor's
// registered Ed25519 key; it is resolved through the key table at the
// handshake and again (cached at most CacheTTL) on every request, so a
// revoked key, a revoked or deleted sensor is refused without a revocation
// list. The tenant and sensor come from that row, and must match the
// certificate's SPIFFE URI.

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"time"

	sensorapp "github.com/openctemio/openctem/api/internal/app/sensor"
	"github.com/openctemio/openctem/api/internal/infra/http/handler"
	sensorv3 "github.com/openctemio/openctem/api/pkg/sensorproto/v3"
	"github.com/openctemio/openctem/api/pkg/sensorsig"
)

// KeyResolver resolves a key thumbprint to its sensor identity
// (sensorapp.SensorService).
type KeyResolver interface {
	SigningIdentity(ctx context.Context, keyID string, allowPaused bool) (sensorapp.SensorIdentity, ed25519.PublicKey, error)
	RecordSignedUse(id sensorapp.SensorIdentity, clientIP string)
}

// CacheTTL bounds how long a resolved certificate identity is reused.
const CacheTTL = 5 * time.Second

// maxCachedIdentities bounds the identity cache.
const maxCachedIdentities = 10000

// alpnH2 is the ALPN protocol id of HTTP/2 over TLS.
const alpnH2 = "h2"

var (
	errCertIdentity = errors.New("certificate identity refused")
	errNotH2        = errors.New("the gRPC binding speaks HTTP/2 only")
)

type certResolver struct {
	keys KeyResolver
	now  func() time.Time

	mu    sync.Mutex
	cache map[string]cachedIdentity
}

type cachedIdentity struct {
	id  sensorapp.SensorIdentity
	exp time.Time
}

func newCertResolver(keys KeyResolver) *certResolver {
	return &certResolver{keys: keys, now: time.Now, cache: map[string]cachedIdentity{}}
}

// resolve maps a verified client certificate to its sensor identity.
func (r *certResolver) resolve(ctx context.Context, leaf *x509.Certificate, peerIP string) (sensorapp.SensorIdentity, error) {
	pub, ok := leaf.PublicKey.(ed25519.PublicKey)
	if !ok {
		return sensorapp.SensorIdentity{}, errCertIdentity
	}
	tid, sid, ok := SensorIDs(leaf)
	if !ok {
		return sensorapp.SensorIdentity{}, errCertIdentity
	}
	thumb := sensorsig.Thumbprint(pub)
	key := thumb + "|" + leaf.SerialNumber.String()
	now := r.now()
	r.mu.Lock()
	if c, ok := r.cache[key]; ok && now.Before(c.exp) {
		r.mu.Unlock()
		return c.id, nil
	}
	r.mu.Unlock()

	id, _, err := r.keys.SigningIdentity(ctx, thumb, true)
	if err != nil || id.Sensor == nil || id.Sensor.TenantID == nil ||
		id.Sensor.ID.String() != sid || id.Sensor.TenantID.String() != tid {
		return sensorapp.SensorIdentity{}, errCertIdentity
	}
	r.keys.RecordSignedUse(id, peerIP)

	r.mu.Lock()
	if len(r.cache) >= maxCachedIdentities {
		for k, c := range r.cache {
			if !now.Before(c.exp) {
				delete(r.cache, k)
			}
		}
		if len(r.cache) >= maxCachedIdentities {
			r.cache = map[string]cachedIdentity{}
		}
	}
	r.cache[key] = cachedIdentity{id: id, exp: now.Add(CacheTTL)}
	r.mu.Unlock()
	return id, nil
}

// MTLSConfig configures the gRPC binding's listener.
type MTLSConfig struct {
	// Addr is the listen address (":8443").
	Addr string
	// Host is the name sensors dial; the server certificate is minted for it.
	Host string
	// TrustedProxies are the CIDRs whose PROXY protocol header is believed
	// (the gateway that passes the sensor host through at layer 4). From
	// any other peer a PROXY header closes the connection. Empty: no PROXY
	// protocol; the peer address is the TCP peer.
	TrustedProxies []string
}

// NewMTLSServer builds the gRPC binding's server: TLS 1.3 only, a client
// certificate from ca required and resolved through keys at the handshake,
// HTTP/2 only (ALPN h2). Serve it with ServeTLS(listener, "", "").
func (s *Server) NewMTLSServer(cfg MTLSConfig, ca *CA, keys KeyResolver) (*http.Server, error) {
	if ca == nil || keys == nil || cfg.Host == "" {
		return nil, errors.New("the gRPC binding needs the sensor CA, the key store and SENSOR_PUBLIC_HOST")
	}
	host := cfg.Host
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	if _, err := ca.ServerCertificate(host); err != nil {
		return nil, err
	}
	res := newCertResolver(keys)
	tlsCfg := &tls.Config{
		MinVersion: tls.VersionTLS13,
		ClientAuth: tls.RequireAndVerifyClientCert,
		ClientCAs:  ca.Pool(),
		NextProtos: []string{alpnH2},
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
			return ca.ServerCertificate(host)
		},
		// The chain is verified by crypto/tls (ClientCAs); this refuses a
		// certificate whose key or sensor no longer holds, at the handshake.
		VerifyConnection: func(cs tls.ConnectionState) error {
			// HTTP/2 only: a client that did not negotiate h2 (ALPN) is
			// refused at the handshake rather than served HTTP/1.1.
			if cs.NegotiatedProtocol != alpnH2 {
				return errNotH2
			}
			if len(cs.PeerCertificates) == 0 {
				return errCertIdentity
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_, err := res.resolve(ctx, cs.PeerCertificates[0], "")
			return err
		},
	}
	srv := &http.Server{
		Addr:              cfg.Addr,
		Handler:           s.mtlsHandler(res),
		TLSConfig:         tlsCfg,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       2 * time.Minute,
		MaxHeaderBytes:    64 << 10,
		// Refused handshakes (scanners, revoked sensors) are routine: debug.
		ErrorLog: slog.NewLogLogger(s.log.Stdlib().Handler(), slog.LevelDebug),
	}
	// HTTP/2 only: no HTTP/1.1 on this listener.
	srv.Protocols = new(http.Protocols)
	srv.Protocols.SetHTTP2(true)
	srv.HTTP2 = &http.HTTP2Config{
		MaxConcurrentStreams: 64,
		SendPingTimeout:      30 * time.Second,
		PingTimeout:          15 * time.Second,
	}
	return srv, nil
}

// mtlsHandler serves the service at the root (gRPC paths) for the identity
// of the client certificate.
func (s *Server) mtlsHandler(res *certResolver) http.Handler {
	path, h := s.Handler()
	mux := http.NewServeMux()
	mux.Handle(path, h)
	limit := s.cfg.MaxContentBytes + maxEnvelopeBytes
	return recoverer(s.log, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}
		ip := r.RemoteAddr
		if h, _, err := net.SplitHostPort(ip); err == nil {
			ip = h
		}
		id, err := res.resolve(r.Context(), r.TLS.PeerCertificates[0], ip)
		if err != nil {
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}
		if r.ContentLength > limit {
			http.Error(w, http.StatusText(http.StatusRequestEntityTooLarge), http.StatusRequestEntityTooLarge)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, limit)
		release, ok := s.admitUnary(w, r)
		defer release()
		if !ok {
			return
		}
		if !isStream(r) {
			// The listener has no ReadTimeout (it would cut the control
			// stream); a unary call must deliver its message in time.
			_ = http.NewResponseController(w).SetReadDeadline(time.Now().Add(s.cfg.UnaryTimeout))
		}
		ctx := handler.WithSensorIdentity(r.Context(), id)
		ctx = handler.WithSensorPeer(ctx, handler.SensorPeer{IP: ip, UserAgent: r.UserAgent()})
		ctx = WithBinding(ctx, sensorv3.Binding_BINDING_GRPC)
		mux.ServeHTTP(w, r.WithContext(ctx))
	}))
}

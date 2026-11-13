package sensortransport

// The single-port mode (docs/rfcs/RFC-059-sensor-transport-v3.md §5.1): when
// the API listener terminates TLS itself (SERVER_TLS_CERT_FILE), a
// ClientHello that offers SensorALPN is answered with the gRPC binding's own
// TLS config (sensor CA server certificate, client certificate from the
// sensor CA required and resolved at the handshake, h2 only) and the
// connection is served by the binding's server, which resolves the
// certificate again on every call. Any other ClientHello gets the public
// certificate and the normal HTTP API. Sensors reach the gRPC binding on the
// API's own port with no gateway and no extra port.
//
// The ALPN id routes, it does not authenticate: a connection that offers it
// meets exactly the checks of the dedicated mTLS listener.

import (
	"crypto/tls"
	"errors"
	"net"
	"slices"
	"sync"
	"time"
)

// splitHandshakeTimeout bounds the TLS handshake before a connection is
// handed to a server.
const splitHandshakeTimeout = 10 * time.Second

// SplitTLS terminates TLS on ln (raw TCP) for one port shared by the API and
// the gRPC binding. It returns the listener of the API's connections (TLS
// handshake done with public); connections that offer SensorALPN are served
// by the gRPC binding. A PROXY protocol v2 header is believed only from
// SENSOR_MTLS_TRUSTED_PROXIES, as on the dedicated listener; it precedes the
// ClientHello, so the rule covers the whole port. Without the gRPC binding
// every connection is the API's.
func (s *Server) SplitTLS(ln net.Listener, public *tls.Config) (net.Listener, error) {
	if public == nil {
		_ = ln.Close()
		return nil, errors.New("single-port TLS needs the public TLS config")
	}
	ln, err := s.proxyListener(ln)
	if err != nil {
		return nil, err
	}
	sp := &splitter{raw: ln, public: public, sensorTLS: s.mtlsTLS, log: s.log.Debug}
	sp.api = newQueueListener(ln.Addr(), func() { _ = ln.Close() })
	if s.mtls != nil && s.mtlsTLS != nil {
		sp.sensor = newQueueListener(ln.Addr(), nil)
		go func() { _ = s.mtls.Serve(sp.sensor) }()
	}
	go sp.acceptLoop()
	return sp.api, nil
}

type splitter struct {
	raw       net.Listener
	public    *tls.Config
	sensorTLS *tls.Config
	api       *queueListener
	sensor    *queueListener // nil: no gRPC binding
	log       func(msg string, args ...any)
}

func (sp *splitter) acceptLoop() {
	var backoff time.Duration
	for {
		c, err := sp.raw.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				sp.api.Close()
				if sp.sensor != nil {
					sp.sensor.Close()
				}
				return
			}
			// Transient (out of file descriptors, a refused PROXY header):
			// back off as net/http does.
			backoff = min(max(2*backoff, 5*time.Millisecond), time.Second)
			sp.log("single-port TLS accept failed", "error", err)
			time.Sleep(backoff)
			continue
		}
		backoff = 0
		go sp.handshake(c)
	}
}

// handshake picks the TLS config by the ClientHello's ALPN ids, completes
// the handshake and hands the connection to its server.
func (sp *splitter) handshake(c net.Conn) {
	sensor := false
	tc := tls.Server(c, &tls.Config{
		MinVersion: tls.VersionTLS12,
		GetConfigForClient: func(h *tls.ClientHelloInfo) (*tls.Config, error) {
			if sp.sensor != nil && slices.Contains(h.SupportedProtos, SensorALPN) {
				sensor = true
				return sp.sensorTLS, nil
			}
			return sp.public, nil
		},
	})
	_ = c.SetDeadline(time.Now().Add(splitHandshakeTimeout))
	if err := tc.Handshake(); err != nil {
		// Scanners, refused or revoked sensor certificates: routine.
		sp.log("single-port TLS handshake refused", "remote", c.RemoteAddr().String(), "sensor_alpn", sensor, "error", err)
		_ = c.Close()
		return
	}
	_ = c.SetDeadline(time.Time{})
	if sensor {
		sp.sensor.deliver(tc)
		return
	}
	sp.api.deliver(tc)
}

// queueListener is a net.Listener fed by the splitter.
type queueListener struct {
	addr    net.Addr
	ch      chan net.Conn
	done    chan struct{}
	once    sync.Once
	onClose func()
}

func newQueueListener(addr net.Addr, onClose func()) *queueListener {
	return &queueListener{addr: addr, ch: make(chan net.Conn), done: make(chan struct{}), onClose: onClose}
}

// deliver hands c to Accept, or closes it once the listener is closed.
func (q *queueListener) deliver(c net.Conn) {
	select {
	case q.ch <- c:
	case <-q.done:
		_ = c.Close()
	}
}

func (q *queueListener) Accept() (net.Conn, error) {
	select {
	case c := <-q.ch:
		return c, nil
	case <-q.done:
		return nil, net.ErrClosed
	}
}

// Close stops Accept; the API's listener also closes the TCP listener.
func (q *queueListener) Close() error {
	q.once.Do(func() {
		close(q.done)
		if q.onClose != nil {
			q.onClose()
		}
	})
	return nil
}

func (q *queueListener) Addr() net.Addr { return q.addr }

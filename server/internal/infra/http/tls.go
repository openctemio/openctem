package http

// The API listener terminates TLS itself when SERVER_TLS_CERT_FILE and
// SERVER_TLS_KEY_FILE are set: an API exposed with no TLS proxy in front.
// Sensors then reach the gRPC binding on the same port
// (docs/rfcs/RFC-059-sensor-transport-v3.md §5.1). The certificate files
// are re-read when they change, so a renewed certificate needs no restart.

import (
	"crypto/tls"
	"fmt"
	"net"
	"os"
	"sync"
	"time"
)

// TLSSplitter takes the API's TCP listener and the public TLS config and
// returns the listener of the API's TLS connections, serving the sensor
// connections on the same port itself (sensortransport.Server.SplitTLS).
type TLSSplitter func(ln net.Listener, public *tls.Config) (net.Listener, error)

// SetTLSSplitter shares the API's TLS port with the sensor gRPC binding.
// Without TLS on the API listener it has no effect. Call it before Start.
func (s *Server) SetTLSSplitter(f TLSSplitter) { s.splitTLS = f }

// certRecheck is how often the certificate files are checked for a change.
const certRecheck = time.Minute

// certReloader serves the certificate of a cert/key file pair, reloading it
// when either file's modification time changes.
type certReloader struct {
	certFile, keyFile string
	now               func() time.Time

	mu        sync.Mutex
	cert      *tls.Certificate
	certMod   time.Time
	keyMod    time.Time
	checkedAt time.Time
}

func newCertReloader(certFile, keyFile string) (*certReloader, error) {
	r := &certReloader{certFile: certFile, keyFile: keyFile, now: time.Now}
	if err := r.load(); err != nil {
		return nil, err
	}
	return r, nil
}

func (r *certReloader) load() error {
	cm, km, err := r.modTimes()
	if err != nil {
		return err
	}
	cert, err := tls.LoadX509KeyPair(r.certFile, r.keyFile)
	if err != nil {
		return fmt.Errorf("SERVER_TLS_CERT_FILE/SERVER_TLS_KEY_FILE: %w", err)
	}
	r.cert, r.certMod, r.keyMod, r.checkedAt = &cert, cm, km, r.now()
	return nil
}

func (r *certReloader) modTimes() (time.Time, time.Time, error) {
	ci, err := os.Stat(r.certFile)
	if err != nil {
		return time.Time{}, time.Time{}, fmt.Errorf("SERVER_TLS_CERT_FILE: %w", err)
	}
	ki, err := os.Stat(r.keyFile)
	if err != nil {
		return time.Time{}, time.Time{}, fmt.Errorf("SERVER_TLS_KEY_FILE: %w", err)
	}
	return ci.ModTime(), ki.ModTime(), nil
}

// GetCertificate returns the current certificate. A reload that fails
// (a half-written renewal) keeps serving the previous one and is retried at
// the next check.
func (r *certReloader) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if now := r.now(); now.Sub(r.checkedAt) >= certRecheck {
		r.checkedAt = now
		if cm, km, err := r.modTimes(); err == nil && (!cm.Equal(r.certMod) || !km.Equal(r.keyMod)) {
			_ = r.load() // on failure load changes nothing
		}
	}
	return r.cert, nil
}

// publicTLSConfig is the API listener's TLS config: the operator's
// certificate, TLS 1.2 or later, HTTP/2 and HTTP/1.1.
func publicTLSConfig(certFile, keyFile string) (*tls.Config, error) {
	r, err := newCertReloader(certFile, keyFile)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		MinVersion:     tls.VersionTLS12,
		NextProtos:     []string{"h2", "http/1.1"},
		GetCertificate: r.GetCertificate,
	}, nil
}

// tlsListener wraps the API's TCP listener: TLS with the public config,
// sharing the port with the sensor gRPC binding when a splitter is set.
func (s *Server) tlsListener(ln net.Listener) (net.Listener, error) {
	pub, err := publicTLSConfig(s.config.Server.TLSCertFile, s.config.Server.TLSKeyFile)
	if err != nil {
		_ = ln.Close()
		return nil, err
	}
	// net/http configures HTTP/2 from its own copy when it serves.
	s.httpServer.TLSConfig = pub.Clone()
	if s.splitTLS == nil {
		return tls.NewListener(ln, pub), nil
	}
	return s.splitTLS(ln, pub)
}

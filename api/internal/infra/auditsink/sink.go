// Package auditsink streams the platform administrators' audit log off the
// box (RFC-022 revision 20): every row, with its place in the hash chain,
// and the chain head at a fixed interval. A copy outside the application's
// database is what makes the chain worth having: someone who controls the
// database could re-sign the whole chain, but not the copy already sent.
//
// Destinations (ADMIN_AUDIT_SINK):
//
//	https://collector.example/path   one JSON object per POST (Bearer token)
//	syslog+tls://host:6514           RFC 5424 over TLS (RFC 5425 framing)
//	syslog+tcp://host:514            RFC 5424 over TCP, octet-counted
//	syslog+udp://host:514            RFC 5424 over UDP
//	file:///var/log/openctem/admin-audit.jsonl   JSON lines, appended
//
// The destination is an operator setting (environment only), never something
// a console user can change.
package auditsink

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

// Sink delivers one event (a JSON object).
type Sink interface {
	Send(ctx context.Context, event []byte) error
	Close() error
}

// New builds the sink for rawURL. token is the webhook's Bearer token
// (ADMIN_AUDIT_SINK_TOKEN); other sinks ignore it.
func New(rawURL, token string) (Sink, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("ADMIN_AUDIT_SINK: %w", err)
	}
	switch u.Scheme {
	case "https":
		if u.Host == "" {
			return nil, errors.New("ADMIN_AUDIT_SINK: an https URL needs a host")
		}
		// Not httpsec.SafeHTTPClient: the operator sets this URL in the
		// server's environment (no tenant or request input reaches it) and
		// it is usually a collector on a private network, which the SSRF
		// dialer refuses. Allow-listed in scripts/security-lint.sh.
		return &webhookSink{url: u.String(), token: token, client: &http.Client{
			Timeout: 10 * time.Second,
			// Never follow a redirect: the events go where the operator said.
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
			Transport: &http.Transport{
				TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS12},
				TLSHandshakeTimeout: 5 * time.Second,
				MaxIdleConns:        2,
				IdleConnTimeout:     time.Minute,
			},
		}}, nil
	case "syslog+tls", "syslog+tcp", "syslog+udp":
		if _, _, err := net.SplitHostPort(u.Host); err != nil {
			return nil, fmt.Errorf("ADMIN_AUDIT_SINK: %s needs host:port", u.Scheme)
		}
		return &syslogSink{network: strings.TrimPrefix(u.Scheme, "syslog+"), addr: u.Host, host: hostname()}, nil
	case "file":
		if u.Path == "" || !strings.HasPrefix(u.Path, "/") {
			return nil, errors.New("ADMIN_AUDIT_SINK: a file URL needs an absolute path (file:///path)")
		}
		return &fileSink{path: u.Path}, nil
	default:
		return nil, fmt.Errorf("ADMIN_AUDIT_SINK: scheme %q is not one of https, syslog+tls, syslog+tcp, syslog+udp, file", u.Scheme)
	}
}

func hostname() string {
	h, err := os.Hostname()
	if err != nil || h == "" {
		return "-"
	}
	return h
}

// webhookSink POSTs each event.
type webhookSink struct {
	url, token string
	client     *http.Client
}

func (s *webhookSink) Send(ctx context.Context, event []byte) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.url, bytes.NewReader(event))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "openctem-admin-audit")
	if s.token != "" {
		req.Header.Set("Authorization", "Bearer "+s.token)
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return err
	}
	_ = resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("audit sink answered %d", resp.StatusCode)
	}
	return nil
}

func (s *webhookSink) Close() error { return nil }

// syslogSink writes RFC 5424 messages (facility auth/security 10, severity
// notice 5 → PRI 85), reconnecting after an error.
type syslogSink struct {
	network, addr, host string

	mu   sync.Mutex
	conn net.Conn
}

func (s *syslogSink) dial(ctx context.Context) (net.Conn, error) {
	d := &net.Dialer{Timeout: 5 * time.Second}
	switch s.network {
	case "tls":
		host, _, _ := net.SplitHostPort(s.addr)
		td := &tls.Dialer{NetDialer: d, Config: &tls.Config{MinVersion: tls.VersionTLS12, ServerName: host}}
		return td.DialContext(ctx, "tcp", s.addr)
	default:
		return d.DialContext(ctx, s.network, s.addr)
	}
}

func (s *syslogSink) Send(ctx context.Context, event []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.conn == nil {
		c, err := s.dial(ctx)
		if err != nil {
			return err
		}
		s.conn = c
	}
	msg := fmt.Sprintf("<85>1 %s %s openctem-api - admin-audit - %s",
		time.Now().UTC().Format(time.RFC3339Nano), s.host, event)
	frame := msg
	if s.network != "udp" {
		// Octet counting (RFC 6587 / RFC 5425): the message length, a space, the message.
		frame = fmt.Sprintf("%d %s", len(msg), msg)
	}
	_ = s.conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	if _, err := s.conn.Write([]byte(frame)); err != nil {
		_ = s.conn.Close()
		s.conn = nil
		return err
	}
	return nil
}

func (s *syslogSink) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.conn != nil {
		err := s.conn.Close()
		s.conn = nil
		return err
	}
	return nil
}

// fileSink appends JSON lines, 0600, synced after each event.
type fileSink struct {
	path string
	mu   sync.Mutex
}

func (s *fileSink) Send(_ context.Context, event []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	f, err := os.OpenFile(s.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(append(append([]byte{}, event...), '\n')); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

func (s *fileSink) Close() error { return nil }

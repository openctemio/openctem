package adminauditfwd

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/openctemio/openctem/api/pkg/httpsec"
)

// Headers the webhook receiver verifies. The signature covers
// "<timestamp>.<body>" so a captured request cannot be replayed with a new
// timestamp; the receiver should refuse a timestamp older than a few minutes.
const (
	HeaderSignature = "X-OpenCTEM-Signature"
	HeaderTimestamp = "X-OpenCTEM-Timestamp"
	HeaderBatchID   = "X-OpenCTEM-Batch-Id"
)

// Sign returns the signature header value for a body sent at ts.
func Sign(secret []byte, ts, body []byte) string {
	m := hmac.New(sha256.New, secret)
	m.Write(ts)
	m.Write([]byte("."))
	m.Write(body)
	return "sha256=" + hex.EncodeToString(m.Sum(nil))
}

type webhookBody struct {
	Version       int               `json:"version"`
	Source        string            `json:"source"`
	SentAt        time.Time         `json:"sent_at"`
	FirstPosition int64             `json:"first_position,omitempty"`
	LastPosition  int64             `json:"last_position,omitempty"`
	Rows          []json.RawMessage `json:"rows"`
	Head          Head              `json:"head"`
	Chain         ChainStatus       `json:"chain"`
}

func marshalBatch(b Batch) ([]byte, error) {
	w := webhookBody{Version: 1, Source: "openctem-admin-audit", SentAt: b.SentAt.UTC(),
		Rows: make([]json.RawMessage, 0, len(b.Rows)), Head: b.Head, Chain: b.Chain}
	for _, r := range b.Rows {
		w.Rows = append(w.Rows, r.JSON)
	}
	if n := len(b.Rows); n > 0 {
		w.FirstPosition, w.LastPosition = b.Rows[0].Position, b.Rows[n-1].Position
	}
	return json.Marshal(w)
}

// WebhookSink posts a signed JSON batch over HTTPS.
type WebhookSink struct {
	url    string
	host   string
	secret []byte
	client *http.Client
}

// NewWebhookSink validates the URL (https, no credentials in it) and builds a
// sink on the SSRF-guarded client. The secret must be at least 16 bytes.
func NewWebhookSink(rawURL, secret string) (*WebhookSink, error) {
	return newWebhookSink(rawURL, secret, httpsec.SafeHTTPClient(20*time.Second))
}

func newWebhookSink(rawURL, secret string, client *http.Client) (*WebhookSink, error) {
	u, err := url.Parse(rawURL)
	if err != nil || u.Host == "" {
		return nil, errors.New("admin audit forward URL is not a valid URL")
	}
	if u.Scheme != "https" {
		return nil, errors.New("admin audit forward URL must use https")
	}
	if u.User != nil {
		return nil, errors.New("admin audit forward URL must not carry credentials; the HMAC secret authenticates the sender")
	}
	if len(secret) < 16 {
		return nil, errors.New("admin audit forward secret must be at least 16 characters")
	}
	c := *client
	// A redirect would carry the signed body to another host: a 3xx is a failure.
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &WebhookSink{url: rawURL, host: u.Hostname(), secret: []byte(secret), client: &c}, nil
}

// Name implements Sink.
func (s *WebhookSink) Name() string { return "webhook" }

// Send implements Sink. Errors name the host and the reason only.
func (s *WebhookSink) Send(ctx context.Context, b Batch) error {
	body, err := marshalBatch(b)
	if err != nil {
		return fmt.Errorf("encode batch: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.url, bytes.NewReader(body))
	if err != nil {
		return errors.New("build webhook request")
	}
	ts := []byte(strconv.FormatInt(b.SentAt.Unix(), 10))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "openctem-admin-audit-forwarder/1")
	req.Header.Set(HeaderTimestamp, string(ts))
	req.Header.Set(HeaderSignature, Sign(s.secret, ts, body))
	req.Header.Set(HeaderBatchID, b.ID())
	resp, err := s.client.Do(req)
	if err != nil {
		// *url.Error repeats the whole URL, which may hold a path token.
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err
		}
		return fmt.Errorf("webhook %s: %w", s.host, err)
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("webhook %s answered status %d", s.host, resp.StatusCode)
	}
	return nil
}

// SyslogSink writes RFC 5424 messages over TLS (RFC 5425), framed by octet
// counting (RFC 6587): one message per row, plus one for the chain head.
type SyslogSink struct {
	addr     string
	host     string
	tlsCfg   *tls.Config
	dial     func(ctx context.Context, network, addr string) (net.Conn, error)
	hostname string
}

// NewSyslogSink builds a sink for host:port. caFile is an optional PEM bundle
// that replaces the system roots. certFile and keyFile are an optional PEM
// client certificate and key (set together) presented to the collector, so it
// can accept only this sender (mutual TLS). The dial goes through the SSRF
// guard.
func NewSyslogSink(addr, caFile, certFile, keyFile string) (*SyslogSink, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil || host == "" || port == "" {
		return nil, errors.New("admin audit syslog address must be host:port")
	}
	cfg := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: host}
	if caFile != "" {
		pem, err := os.ReadFile(caFile) // #nosec G304 -- operator-set path
		if err != nil {
			return nil, fmt.Errorf("read admin audit syslog CA file: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, errors.New("admin audit syslog CA file has no certificate")
		}
		cfg.RootCAs = pool
	}
	if (certFile == "") != (keyFile == "") {
		return nil, errors.New("admin audit syslog client certificate and key must be set together")
	}
	if certFile != "" {
		pair, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			return nil, errors.New("load admin audit syslog client certificate: not a valid certificate and key pair")
		}
		cfg.Certificates = []tls.Certificate{pair}
	}
	hn, _ := os.Hostname()
	if hn == "" {
		hn = "-"
	}
	return &SyslogSink{addr: addr, host: host, tlsCfg: cfg, dial: httpsec.SafeDialContext, hostname: hn}, nil
}

// Name implements Sink.
func (s *SyslogSink) Name() string { return "syslog" }

// Send implements Sink.
func (s *SyslogSink) Send(ctx context.Context, b Batch) error {
	var buf bytes.Buffer
	for _, r := range b.Rows {
		buf.Write(frame(s.message("row", strconv.FormatInt(r.Position, 10), b.SentAt, r.JSON)))
	}
	hb, err := json.Marshal(struct {
		Head  Head        `json:"head"`
		Chain ChainStatus `json:"chain"`
	}{b.Head, b.Chain})
	if err != nil {
		return fmt.Errorf("encode head: %w", err)
	}
	buf.Write(frame(s.message("head", "head-"+strconv.FormatInt(b.Head.Position, 10), b.SentAt, hb)))

	dctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	raw, err := s.dial(dctx, "tcp", s.addr)
	if err != nil {
		return fmt.Errorf("syslog %s: %w", s.host, err)
	}
	conn := tls.Client(raw, s.tlsCfg)
	defer func() { _ = conn.Close() }()
	deadline, _ := dctx.Deadline()
	_ = conn.SetDeadline(deadline)
	if err := conn.HandshakeContext(dctx); err != nil {
		return fmt.Errorf("syslog %s: TLS handshake: %w", s.host, err)
	}
	if _, err := conn.Write(buf.Bytes()); err != nil {
		return fmt.Errorf("syslog %s: write: %w", s.host, err)
	}
	// close_notify so the receiver knows the stream ended cleanly.
	if err := conn.CloseWrite(); err != nil {
		return fmt.Errorf("syslog %s: close: %w", s.host, err)
	}
	return nil
}

// message renders one RFC 5424 message: facility log-audit (13), severity
// notice (5), no structured data.
func (s *SyslogSink) message(kind, id string, at time.Time, payload []byte) []byte {
	var m bytes.Buffer
	fmt.Fprintf(&m, "<109>1 %s %s openctem-admin-audit - %s-%s - ", at.UTC().Format(time.RFC3339), s.hostname, kind, id)
	m.Write(payload)
	return []byte(strings.ReplaceAll(m.String(), "\n", " "))
}

// frame prefixes a message with its length (octet counting).
func frame(msg []byte) []byte {
	return append([]byte(strconv.Itoa(len(msg))+" "), msg...)
}

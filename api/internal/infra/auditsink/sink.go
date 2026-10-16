package auditsink

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
	"sync"
	"time"
)

// MinSecretLen is the shortest accepted webhook HMAC secret, in bytes.
const MinSecretLen = 32

// Headers the webhook receiver verifies. The signature covers
// "<timestamp>.<body>" so a captured request cannot be replayed with a new
// timestamp; the receiver should refuse a timestamp older than a few minutes.
const (
	HeaderSignature = "X-OpenCTEM-Signature"
	HeaderTimestamp = "X-OpenCTEM-Timestamp"
	HeaderBatchID   = "X-OpenCTEM-Batch-Id"
)

// Options carry the destination settings besides the URL.
type Options struct {
	// Secret is the webhook's HMAC-SHA256 key (ADMIN_AUDIT_SINK_SECRET),
	// required for https, at least MinSecretLen bytes. Other sinks ignore it.
	Secret string
	// CAFile, ClientCert and ClientKey (PEM paths) are the syslog+tls server
	// roots and the client certificate for mutual TLS. ClientCert and
	// ClientKey are set together.
	CAFile, ClientCert, ClientKey string
}

// New builds the sink for rawURL.
func New(rawURL string, o Options) (Sink, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, errors.New("ADMIN_AUDIT_SINK: not a valid URL")
	}
	if u.Scheme != "syslog+tls" && (o.CAFile != "" || o.ClientCert != "" || o.ClientKey != "") {
		return nil, errors.New("ADMIN_AUDIT_SINK_SYSLOG_* settings apply to a syslog+tls:// destination only")
	}
	if u.Scheme != "https" && o.Secret != "" {
		return nil, errors.New("ADMIN_AUDIT_SINK_SECRET signs webhook requests; the destination is not an https URL")
	}
	switch u.Scheme {
	case "https":
		if u.Host == "" {
			return nil, errors.New("ADMIN_AUDIT_SINK: an https URL needs a host")
		}
		if u.User != nil {
			return nil, errors.New("ADMIN_AUDIT_SINK: the URL must not carry credentials; the HMAC secret authenticates the sender")
		}
		if len(o.Secret) < MinSecretLen {
			return nil, fmt.Errorf("ADMIN_AUDIT_SINK_SECRET must be at least %d bytes for an https destination", MinSecretLen)
		}
		// Not httpsec.SafeHTTPClient: the operator sets this URL in the
		// server's environment (no tenant or request input reaches it) and
		// it is usually a collector on a private network, which the SSRF
		// dialer refuses. Allow-listed in scripts/security-lint.sh.
		return newWebhookSink(u.String(), o.Secret, &http.Client{
			Timeout: 20 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS12},
				TLSHandshakeTimeout: 5 * time.Second,
				MaxIdleConns:        2,
				IdleConnTimeout:     time.Minute,
			},
		}), nil
	case "syslog+tls":
		return newSyslogSink(u.Host, o)
	case "file":
		if u.Path == "" || !strings.HasPrefix(u.Path, "/") {
			return nil, errors.New("ADMIN_AUDIT_SINK: a file URL needs an absolute path (file:///path)")
		}
		return &fileSink{path: u.Path}, nil
	default:
		return nil, fmt.Errorf("ADMIN_AUDIT_SINK: scheme %q is not one of https, syslog+tls, file (plaintext syslog is not supported)", u.Scheme)
	}
}

// rowEvent is one administrators' audit row and its place in the chain. The
// columns are explicit: the request body and user agent are not sent (they
// may name things a collector need not hold); the hash covers them, so the
// database row can still be checked against it. A column added to the table
// is not shipped until it is added here and to the store's column list.
type rowEvent struct {
	Position     int64     `json:"position"`
	PrevHash     string    `json:"prev_hash"`
	Hash         string    `json:"hash"`
	ID           string    `json:"id"`
	At           time.Time `json:"at"`
	AdminID      string    `json:"admin_id,omitempty"`
	AdminEmail   string    `json:"admin_email"`
	Action       string    `json:"action"`
	ResourceType string    `json:"resource_type,omitempty"`
	ResourceID   string    `json:"resource_id,omitempty"`
	ResourceName string    `json:"resource_name,omitempty"`
	Method       string    `json:"method,omitempty"`
	Path         string    `json:"path,omitempty"`
	Status       int       `json:"status,omitempty"`
	IP           string    `json:"ip,omitempty"`
	Success      bool      `json:"success"`
	Error        string    `json:"error,omitempty"`
	Severity     string    `json:"severity"`
}

func toRowEvent(e Row) rowEvent {
	ev := rowEvent{Position: e.Position, PrevHash: e.PrevHash, Hash: e.Hash}
	if l := e.Log; l != nil {
		ev.ID, ev.At, ev.AdminEmail, ev.Action = l.ID.String(), l.CreatedAt.UTC(), l.AdminEmail, l.Action
		ev.ResourceType, ev.ResourceName, ev.Method, ev.Path = l.ResourceType, l.ResourceName, l.RequestMethod, l.RequestPath
		ev.Status, ev.IP, ev.Success, ev.Error, ev.Severity = l.ResponseStatus, l.IPAddress, l.Success, l.ErrorMessage, l.Severity
		if l.AdminID != nil {
			ev.AdminID = l.AdminID.String()
		}
		if l.ResourceID != nil {
			ev.ResourceID = l.ResourceID.String()
		}
	}
	return ev
}

// batchBody is the payload: rows, chain head and chain verification state.
type batchBody struct {
	Version       int         `json:"version"`
	Source        string      `json:"source"`
	BatchID       string      `json:"batch_id"`
	SentAt        time.Time   `json:"sent_at"`
	FirstPosition int64       `json:"first_position,omitempty"`
	LastPosition  int64       `json:"last_position,omitempty"`
	Rows          []rowEvent  `json:"rows"`
	Head          Head        `json:"head"`
	Chain         ChainStatus `json:"chain"`
	Gap           *Gap        `json:"gap,omitempty"`
}

func marshalBatch(b Batch) ([]byte, error) {
	w := batchBody{Version: 1, Source: "openctem-admin-audit", BatchID: b.ID(), SentAt: b.SentAt.UTC(),
		Rows: make([]rowEvent, 0, len(b.Rows)), Head: b.Head, Chain: b.Chain, Gap: b.Gap}
	for _, r := range b.Rows {
		w.Rows = append(w.Rows, toRowEvent(r))
	}
	if n := len(b.Rows); n > 0 {
		w.FirstPosition, w.LastPosition = b.Rows[0].Position, b.Rows[n-1].Position
	}
	return json.Marshal(w)
}

// Sign returns the signature header value for a body sent at ts.
func Sign(secret, ts, body []byte) string {
	m := hmac.New(sha256.New, secret)
	m.Write(ts)
	m.Write([]byte("."))
	m.Write(body)
	return "sha256=" + hex.EncodeToString(m.Sum(nil))
}

// webhookSink POSTs each batch, signed.
type webhookSink struct {
	url    string
	host   string
	secret []byte
	client *http.Client
}

func newWebhookSink(rawURL, secret string, client *http.Client) *webhookSink {
	host := ""
	if u, err := url.Parse(rawURL); err == nil {
		host = u.Hostname()
	}
	c := *client
	// A redirect would carry the signed body to another host: a 3xx is a failure.
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &webhookSink{url: rawURL, host: host, secret: []byte(secret), client: &c}
}

func (s *webhookSink) Name() string { return "webhook" }

// Send errors name the host and the reason only: never the URL or the secret.
func (s *webhookSink) Send(ctx context.Context, b Batch) error {
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
	req.Header.Set("User-Agent", "openctem-admin-audit")
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

func (s *webhookSink) Close() error { return nil }

// syslogSink writes RFC 5424 messages over TLS (RFC 5425), framed by octet
// counting (RFC 6587): one message per row, plus one for the chain head. It
// connects per batch and ends the stream with close_notify.
type syslogSink struct {
	addr, host, hostname string
	tlsCfg               *tls.Config
	dial                 func(ctx context.Context, network, addr string) (net.Conn, error)
}

func newSyslogSink(addr string, o Options) (*syslogSink, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil || host == "" || port == "" {
		return nil, errors.New("ADMIN_AUDIT_SINK: syslog+tls needs host:port")
	}
	cfg := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: host}
	if o.CAFile != "" {
		pem, err := os.ReadFile(o.CAFile) // #nosec G304 -- operator-set path
		if err != nil {
			return nil, fmt.Errorf("read ADMIN_AUDIT_SINK_SYSLOG_CA_FILE: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, errors.New("ADMIN_AUDIT_SINK_SYSLOG_CA_FILE has no certificate")
		}
		cfg.RootCAs = pool
	}
	if (o.ClientCert == "") != (o.ClientKey == "") {
		return nil, errors.New("ADMIN_AUDIT_SINK_SYSLOG_CLIENT_CERT and _CLIENT_KEY must be set together")
	}
	if o.ClientCert != "" {
		pair, err := tls.LoadX509KeyPair(o.ClientCert, o.ClientKey)
		if err != nil {
			return nil, errors.New("load the syslog client certificate: not a valid certificate and key pair")
		}
		cfg.Certificates = []tls.Certificate{pair}
	}
	hn, _ := os.Hostname()
	if hn == "" {
		hn = "-"
	}
	d := &net.Dialer{Timeout: 5 * time.Second}
	return &syslogSink{addr: addr, host: host, hostname: hn, tlsCfg: cfg, dial: d.DialContext}, nil
}

func (s *syslogSink) Name() string { return "syslog" }

func (s *syslogSink) Send(ctx context.Context, b Batch) error {
	var buf bytes.Buffer
	for _, r := range b.Rows {
		ev, err := json.Marshal(toRowEvent(r))
		if err != nil {
			return fmt.Errorf("encode row: %w", err)
		}
		buf.Write(frame(s.message("row", strconv.FormatInt(r.Position, 10), b.SentAt, ev)))
	}
	hb, err := json.Marshal(struct {
		BatchID string      `json:"batch_id"`
		Head    Head        `json:"head"`
		Chain   ChainStatus `json:"chain"`
		Gap     *Gap        `json:"gap,omitempty"`
	}{b.ID(), b.Head, b.Chain, b.Gap})
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
	if err := conn.CloseWrite(); err != nil {
		return fmt.Errorf("syslog %s: close: %w", s.host, err)
	}
	// Syslog has no application-level acknowledgement. The weakest honest
	// signal is the collector reading to the end of the stream and closing
	// its side cleanly (close_notify) before the deadline; a timeout or a
	// reset means it may not have the batch.
	if _, err := io.Copy(io.Discard, io.LimitReader(conn, 64<<10)); err != nil {
		return fmt.Errorf("syslog %s: collector did not close the stream: %w", s.host, err)
	}
	return nil
}

func (s *syslogSink) Close() error { return nil }

// message renders one RFC 5424 message: facility log-audit (13), severity
// notice (5), no structured data.
func (s *syslogSink) message(kind, id string, at time.Time, payload []byte) []byte {
	var m bytes.Buffer
	fmt.Fprintf(&m, "<109>1 %s %s openctem-admin-audit - %s-%s - ", at.UTC().Format(time.RFC3339), s.hostname, kind, id)
	m.Write(payload)
	return []byte(strings.ReplaceAll(m.String(), "\n", " "))
}

// frame prefixes a message with its length (octet counting).
func frame(msg []byte) []byte {
	return append([]byte(strconv.Itoa(len(msg))+" "), msg...)
}

// fileSink appends one JSON batch per line, 0600, synced after each batch.
type fileSink struct {
	path string
	mu   sync.Mutex
}

func (s *fileSink) Name() string { return "file" }

func (s *fileSink) Send(_ context.Context, b Batch) error {
	body, err := marshalBatch(b)
	if err != nil {
		return fmt.Errorf("encode batch: %w", err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	f, err := os.OpenFile(s.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(append(body, '\n')); err != nil {
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

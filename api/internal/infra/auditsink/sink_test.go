package auditsink

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/admin"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

const testSecret = "0123456789abcdef0123456789abcdef-secret"

func sampleBatch() Batch {
	mk := func(pos int64, h string) Row {
		return Row{Position: pos, Hash: h, PrevHash: "p",
			Log: &admin.AuditLog{ID: shared.NewID(), CreatedAt: time.Unix(1_700_000_000, 0), Action: "token.revoke",
				AdminEmail: "root@example.com", Severity: "high", Success: true,
				RequestBody: map[string]any{"password": "hunter2-body"}, UserAgent: "agent-UA-string"}}
	}
	return Batch{SentAt: time.Unix(1_700_000_000, 0), Head: Head{Position: 2, Hash: "h2"},
		Chain: ChainStatus{Verified: true, OK: true}, Rows: []Row{mk(1, "h1"), mk(2, "h2")}}
}

func TestWebhookSignsAndDeliversOverTLS(t *testing.T) {
	var gotSig, gotTS, gotID string
	var gotBody []byte
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotSig, gotTS, gotID = r.Header.Get(HeaderSignature), r.Header.Get(HeaderTimestamp), r.Header.Get(HeaderBatchID)
		gotBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()
	s := newWebhookSink(srv.URL+"/ingest", testSecret, srv.Client())
	if err := s.Send(context.Background(), sampleBatch()); err != nil {
		t.Fatal(err)
	}
	if gotSig != Sign([]byte(testSecret), []byte(gotTS), gotBody) || gotID != "1-2" {
		t.Fatalf("signature/id mismatch: %s %s", gotSig, gotID)
	}
	for _, want := range []string{`"last_position":2`, `"hash":"h2"`, `"batch_id":"1-2"`, `"head":{"position":2,"hash":"h2"}`, `"chain":{"verified":true,"ok":true`} {
		if !strings.Contains(string(gotBody), want) {
			t.Fatalf("body lacks %s: %s", want, gotBody)
		}
	}
	// The request body and user agent are withheld.
	if strings.Contains(string(gotBody), "hunter2-body") || strings.Contains(string(gotBody), "agent-UA-string") || strings.Contains(string(gotBody), "request_body") {
		t.Fatalf("withheld column shipped: %s", gotBody)
	}
	if Sign([]byte("another-secret-value"), []byte(gotTS), gotBody) == gotSig {
		t.Fatal("signature does not depend on the secret")
	}
}

func TestWebhookNon2xxAndRedirectFail(t *testing.T) {
	for _, code := range []int{http.StatusInternalServerError, http.StatusFound} {
		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Location", "https://169.254.169.254/")
			w.WriteHeader(code)
		}))
		s := newWebhookSink(srv.URL+"/tok-SECRETPATH", testSecret, srv.Client())
		err := s.Send(context.Background(), sampleBatch())
		srv.Close()
		if err == nil || !strings.Contains(err.Error(), strconv.Itoa(code)) {
			t.Fatalf("status %d: err=%v", code, err)
		}
		if strings.Contains(err.Error(), "SECRETPATH") || strings.Contains(err.Error(), testSecret) {
			t.Fatalf("error leaks the URL path or secret: %v", err)
		}
	}
}

func TestWebhookErrorNeverLeaksURLOrSecret(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	url := srv.URL + "/tok-SECRETPATH"
	cl := srv.Client()
	srv.Close() // connection refused
	s := newWebhookSink(url, testSecret, cl)
	err := s.Send(context.Background(), sampleBatch())
	if err == nil {
		t.Fatal("expected error")
	}
	if strings.Contains(err.Error(), "SECRETPATH") || strings.Contains(err.Error(), testSecret) {
		t.Fatalf("error leaks: %v", err)
	}
}

func TestNewRefusesUnsafeOrUnknownDestinations(t *testing.T) {
	ok := Options{Secret: testSecret}
	for name, c := range map[string]struct {
		url string
		o   Options
	}{
		"http":          {"http://collector.example/x", ok},
		"ftp":           {"ftp://x", Options{}},
		"plain tcp":     {"syslog+tcp://h:514", Options{}},
		"plain udp":     {"syslog+udp://h:514", Options{}},
		"no host":       {"https:///path", ok},
		"credentials":   {"https://u:p@example.com/x", ok},
		"no secret":     {"https://example.com/x", Options{}},
		"short secret":  {"https://example.com/x", Options{Secret: "short"}},
		"secret on tls": {"syslog+tls://h:6514", Options{Secret: testSecret}},
		"ca on https":   {"https://example.com/x", Options{Secret: testSecret, CAFile: "/ca.pem"}},
		"no port":       {"syslog+tls://host", Options{}},
		"relative file": {"file:relative.jsonl", Options{}},
		"bad url":       {"::bad", Options{}},
	} {
		if _, err := New(c.url, c.o); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	for _, raw := range []string{"https://collector.example/x", "syslog+tls://h:6514", "file:///tmp/x.jsonl"} {
		o := Options{}
		if strings.HasPrefix(raw, "https") {
			o.Secret = testSecret
		}
		if _, err := New(raw, o); err != nil {
			t.Errorf("%q refused: %v", raw, err)
		}
	}
	if _, err := New("syslog+tls://h:6514", Options{ClientCert: "/c.pem"}); err == nil {
		t.Error("client certificate without key accepted")
	}
}

// The operator client never follows a redirect: the signed batch goes only
// where the operator said.
func TestNewWebhookClientRefusesRedirects(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/elsewhere", http.StatusFound)
	}))
	defer srv.Close()
	s, err := New(srv.URL+"/redirect", Options{Secret: testSecret})
	if err != nil {
		t.Fatal(err)
	}
	s.(*webhookSink).client.Transport = srv.Client().Transport
	if err := s.Send(context.Background(), sampleBatch()); err == nil {
		t.Fatal("a redirect must not count as delivered")
	}
}

func TestFileSinkAppendsBatchesWith0600(t *testing.T) {
	p := filepath.Join(t.TempDir(), "audit.jsonl")
	s, err := New("file://"+p, Options{})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if err := s.Send(context.Background(), sampleBatch()); err != nil {
			t.Fatal(err)
		}
	}
	b, _ := os.ReadFile(p)
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	if len(lines) != 2 || !strings.Contains(lines[0], `"batch_id":"1-2"`) || strings.Contains(string(b), "hunter2-body") {
		t.Fatalf("file %q", b)
	}
	if st, _ := os.Stat(p); st.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", st.Mode().Perm())
	}
}

func TestSyslogOverTLSFramesRowsAndHead(t *testing.T) {
	srv := httptest.NewUnstartedServer(nil)
	srv.StartTLS()
	srv.Close() // only the certificate is wanted
	cert := srv.TLS.Certificates[0]
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	got := make(chan string, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer func() { _ = c.Close() }()
		b, _ := io.ReadAll(bufio.NewReader(c))
		got <- string(b)
	}()

	s, err := newSyslogSink(ln.Addr().String(), Options{})
	if err != nil {
		t.Fatal(err)
	}
	s.tlsCfg.ServerName = "example.com"
	s.tlsCfg.RootCAs = srv.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs
	s.dial = func(ctx context.Context, n, a string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, n, a)
	}
	if err := s.Send(context.Background(), sampleBatch()); err != nil {
		t.Fatal(err)
	}
	out := <-got
	if strings.Count(out, "openctem-admin-audit") != 3 || !strings.Contains(out, `"position":2`) || !strings.Contains(out, "head-2") {
		t.Fatalf("stream %q", out)
	}
	// Octet counting: the first frame's length prefix matches its message.
	sp := strings.Index(out, " ")
	n, _ := strconv.Atoi(out[:sp])
	if !strings.HasPrefix(out[sp+1+n:], "") || !strings.HasPrefix(out[sp+1:], "<109>1 ") || out[sp+1+n-1] != '}' {
		t.Fatalf("bad framing: %q", out)
	}
}

// writePEM stores a tls certificate and its key as PEM files.
func writePEM(t *testing.T, cert tls.Certificate) (certFile, keyFile string) {
	t.Helper()
	dir := t.TempDir()
	certFile, keyFile = dir+"/c.pem", dir+"/k.pem"
	if err := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]}), 0o600); err != nil {
		t.Fatal(err)
	}
	kb, err := x509.MarshalPKCS8PrivateKey(cert.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kb}), 0o600); err != nil {
		t.Fatal(err)
	}
	return certFile, keyFile
}

// With a client certificate configured the sink presents it; a collector that
// requires one accepts the sender. Without it the handshake is refused.
func TestSyslogPresentsClientCertificate(t *testing.T) {
	srv := httptest.NewUnstartedServer(nil)
	srv.StartTLS()
	srv.Close() // only the certificate is wanted
	cert := srv.TLS.Certificates[0]
	roots := srv.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs
	certFile, keyFile := writePEM(t, cert)

	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{cert}, ClientAuth: tls.RequireAnyClientCert, MinVersion: tls.VersionTLS12})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	peers := make(chan int, 2)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = c.Close() }()
				tc := c.(*tls.Conn)
				if err := tc.Handshake(); err != nil {
					peers <- -1
					return
				}
				_, _ = io.ReadAll(tc)
				peers <- len(tc.ConnectionState().PeerCertificates)
			}()
		}
	}()
	dial := func(ctx context.Context, n, a string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, n, a)
	}
	build := func(c, k string) *syslogSink {
		s, err := newSyslogSink(ln.Addr().String(), Options{ClientCert: c, ClientKey: k})
		if err != nil {
			t.Fatal(err)
		}
		s.tlsCfg.ServerName = "example.com"
		s.tlsCfg.RootCAs = roots
		s.dial = dial
		return s
	}

	if err := build(certFile, keyFile).Send(context.Background(), sampleBatch()); err != nil {
		t.Fatal(err)
	}
	if n := <-peers; n != 1 {
		t.Fatalf("collector saw %d client certificates, want 1", n)
	}
	// No certificate: TLS 1.3 may let Write succeed, but the collector refuses.
	_ = build("", "").Send(context.Background(), sampleBatch())
	if n := <-peers; n != -1 {
		t.Fatalf("collector accepted a sender without a certificate (%d)", n)
	}

	if _, err := newSyslogSink("h:1", Options{ClientCert: certFile}); err == nil {
		t.Fatal("certificate without key accepted")
	}
	if _, err := newSyslogSink("h:1", Options{ClientCert: certFile, ClientKey: certFile}); err == nil || strings.Contains(err.Error(), certFile) {
		t.Fatalf("bad pair: want an error without the path, got %v", err)
	}
}

// A collector that reads the batch but never closes its side has not
// acknowledged anything: the send fails at the deadline instead of counting
// a local write as delivered.
func TestSyslogFailsWhenCollectorDoesNotClose(t *testing.T) {
	srv := httptest.NewUnstartedServer(nil)
	srv.StartTLS()
	srv.Close()
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{srv.TLS.Certificates[0]}})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	release := make(chan struct{})
	defer close(release)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer func() { _ = c.Close() }()
		buf := make([]byte, 4096)
		_, _ = c.Read(buf)
		<-release // hold the connection open, never answer
	}()
	s, err := newSyslogSink(ln.Addr().String(), Options{})
	if err != nil {
		t.Fatal(err)
	}
	s.tlsCfg.ServerName = "example.com"
	s.tlsCfg.RootCAs = srv.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs
	s.dial = func(ctx context.Context, n, a string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, n, a)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
	defer cancel()
	if err := s.Send(ctx, sampleBatch()); err == nil {
		t.Fatal("a collector that never closed counted as delivered")
	}
}

package adminauditfwd

import (
	"bufio"
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

const testSecret = "0123456789abcdef-secret"

func sampleBatch() Batch {
	return Batch{SentAt: time.Unix(1_700_000_000, 0), Head: Head{Position: 2, Hash: "h2"},
		Rows: []Row{{Position: 1, Hash: "h1", JSON: []byte(`{"chain_position":1}`)}, {Position: 2, Hash: "h2", JSON: []byte(`{"chain_position":2}`)}}}
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
	s, err := newWebhookSink(srv.URL+"/ingest", testSecret, srv.Client())
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Send(context.Background(), sampleBatch()); err != nil {
		t.Fatal(err)
	}
	if gotSig != Sign([]byte(testSecret), []byte(gotTS), gotBody) || gotID != "1-2" {
		t.Fatalf("signature/id mismatch: %s %s", gotSig, gotID)
	}
	if !strings.Contains(string(gotBody), `"last_position":2`) || !strings.Contains(string(gotBody), `"hash":"h2"`) {
		t.Fatalf("body %s", gotBody)
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
		s, _ := newWebhookSink(srv.URL+"/tok-SECRETPATH", testSecret, srv.Client())
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
	s, _ := newWebhookSink(url, testSecret, cl)
	err := s.Send(context.Background(), sampleBatch())
	if err == nil {
		t.Fatal("expected error")
	}
	if strings.Contains(err.Error(), "SECRETPATH") || strings.Contains(err.Error(), testSecret) {
		t.Fatalf("error leaks: %v", err)
	}
}

func TestWebhookSinkRefusesUnsafeConfig(t *testing.T) {
	for name, c := range map[string][2]string{
		"http":        {"http://example.com/x", testSecret},
		"credentials": {"https://u:p@example.com/x", testSecret},
		"no host":     {"https:///x", testSecret},
		"short":       {"https://example.com/x", "short"},
	} {
		if _, err := NewWebhookSink(c[0], c[1]); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

// The production sink dials through the SSRF guard: loopback, link-local
// metadata and private addresses are refused before any connection.
func TestWebhookSSRFRefused(t *testing.T) {
	for _, u := range []string{
		"https://127.0.0.1:9/audit",
		"https://169.254.169.254/latest/meta-data",
		"https://[::1]:9/audit",
		"https://localhost:9/audit",
	} {
		s, err := NewWebhookSink(u, testSecret)
		if err != nil {
			t.Fatalf("%s: %v", u, err)
		}
		err = s.Send(context.Background(), sampleBatch())
		if err == nil || !strings.Contains(err.Error(), "ssrf guard") {
			t.Errorf("%s: want ssrf guard refusal, got %v", u, err)
		}
	}
}

func TestSyslogSSRFRefused(t *testing.T) {
	s, err := NewSyslogSink("127.0.0.1:6514", "")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Send(context.Background(), sampleBatch()); err == nil || !strings.Contains(err.Error(), "ssrf guard") {
		t.Fatalf("want ssrf guard refusal, got %v", err)
	}
	if _, err := NewSyslogSink("no-port", ""); err == nil {
		t.Fatal("address without a port accepted")
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

	s, err := NewSyslogSink(ln.Addr().String(), "")
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
	if strings.Count(out, "openctem-admin-audit") != 3 || !strings.Contains(out, `{"chain_position":2}`) || !strings.Contains(out, "head-2") {
		t.Fatalf("stream %q", out)
	}
	// Octet counting: the first frame's length prefix matches its message.
	sp := strings.Index(out, " ")
	n, _ := strconv.Atoi(out[:sp])
	if !strings.HasPrefix(out[sp+1+n:], "") || !strings.HasPrefix(out[sp+1:], "<109>1 ") || out[sp+1+n-1] != '}' {
		t.Fatalf("bad framing: %q", out)
	}
}

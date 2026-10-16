package auditsink

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/admin"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

func TestNewRefusesUnsafeOrUnknownDestinations(t *testing.T) {
	for _, raw := range []string{
		"http://collector.example/x", // plain HTTP: events would cross the network in the clear
		"ftp://x", "https:///path", "syslog+tcp://host", "file:relative.jsonl", "::bad",
	} {
		if _, err := New(raw, ""); err == nil {
			t.Errorf("%q accepted", raw)
		}
	}
	for _, raw := range []string{"https://collector.example/x", "syslog+tls://h:6514", "syslog+tcp://h:514", "syslog+udp://h:514", "file:///tmp/x.jsonl"} {
		if _, err := New(raw, ""); err != nil {
			t.Errorf("%q refused: %v", raw, err)
		}
	}
}

func TestWebhookSinkSendsBearerJSONAndRefusesRedirects(t *testing.T) {
	var got struct {
		auth, ctype string
		body        []byte
	}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/redirect" {
			http.Redirect(w, r, "/elsewhere", http.StatusFound)
			return
		}
		got.auth, got.ctype = r.Header.Get("Authorization"), r.Header.Get("Content-Type")
		got.body, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()
	s, err := New(srv.URL+"/events", "tok-1")
	if err != nil {
		t.Fatal(err)
	}
	s.(*webhookSink).client.Transport = srv.Client().Transport
	if err := s.Send(context.Background(), []byte(`{"a":1}`)); err != nil {
		t.Fatal(err)
	}
	if got.auth != "Bearer tok-1" || got.ctype != "application/json" || string(got.body) != `{"a":1}` {
		t.Fatalf("got %+v", got)
	}
	r, _ := New(srv.URL+"/redirect", "")
	r.(*webhookSink).client.Transport = srv.Client().Transport
	if err := r.Send(context.Background(), []byte(`{}`)); err == nil {
		t.Fatal("a redirect must not count as delivered")
	}
}

func TestSyslogTCPSinkFramesRFC5424(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	lines := make(chan string, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		r := bufio.NewReader(c)
		var n int
		if _, err := fmt.Fscanf(r, "%d ", &n); err != nil {
			return
		}
		buf := make([]byte, n)
		_, _ = io.ReadFull(r, buf)
		lines <- string(buf)
	}()
	s, _ := New("syslog+tcp://"+ln.Addr().String(), "")
	defer s.Close()
	if err := s.Send(context.Background(), []byte(`{"type":"admin_audit"}`)); err != nil {
		t.Fatal(err)
	}
	select {
	case l := <-lines:
		if !strings.HasPrefix(l, "<85>1 ") || !strings.Contains(l, " openctem-api - admin-audit - ") || !strings.HasSuffix(l, `{"type":"admin_audit"}`) {
			t.Fatalf("frame %q", l)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no syslog message")
	}
}

func TestSyslogTLSSinkUsesTLS(t *testing.T) {
	// A server certificate nobody trusts (httptest's).
	hs := httptest.NewTLSServer(http.NotFoundHandler())
	cfg := hs.TLS.Clone()
	hs.Close()
	ln, err := tls.Listen("tcp", "127.0.0.1:0", cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err == nil {
			_ = c.(*tls.Conn).Handshake()
			c.Close()
		}
	}()
	s, _ := New("syslog+tls://"+ln.Addr().String(), "")
	// The test certificate is not trusted: the sink must refuse it rather
	// than send the events to an unverified peer.
	if err := s.Send(context.Background(), []byte(`{}`)); err == nil {
		t.Fatal("an untrusted TLS peer must be refused")
	}
}

func TestFileSinkAppends0600(t *testing.T) {
	p := filepath.Join(t.TempDir(), "audit.jsonl")
	s, _ := New("file://"+p, "")
	for _, e := range []string{`{"n":1}`, `{"n":2}`} {
		if err := s.Send(context.Background(), []byte(e)); err != nil {
			t.Fatal(err)
		}
	}
	b, _ := os.ReadFile(p)
	if string(b) != "{\"n\":1}\n{\"n\":2}\n" {
		t.Fatalf("file %q", b)
	}
	if st, _ := os.Stat(p); st.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", st.Mode().Perm())
	}
}

type memSink struct {
	mu     sync.Mutex
	events [][]byte
	fail   int
}

func (m *memSink) Send(_ context.Context, e []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.fail > 0 {
		m.fail--
		return errors.New("down")
	}
	m.events = append(m.events, append([]byte{}, e...))
	return nil
}
func (m *memSink) Close() error { return nil }
func (m *memSink) all() [][]byte {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([][]byte{}, m.events...)
}

func TestForwarderSendsRowsInOrderWithChainPlaceAndHeads(t *testing.T) {
	m := &memSink{fail: 1} // the first try fails: retried
	f := NewForwarder(m, logger.NewNop())
	f.backoff = time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { f.Run(ctx); close(done) }()
	aid := shared.NewID()
	for i, action := range []string{"console.login", "admin.update"} {
		f.Row(admin.AuditChainEntry{
			Log:      &admin.AuditLog{ID: shared.NewID(), AdminID: &aid, AdminEmail: "root@example.com", Action: action, Success: true, Severity: "info", CreatedAt: time.Now(), RequestBody: map[string]any{"password": "never-sent"}},
			Position: int64(i + 1), PrevHash: "p", Hash: "h",
		})
	}
	go f.ExportHead(ctx, func(context.Context) (int64, string, error) { return 2, "head-hash", nil }, time.Hour)
	deadline := time.Now().Add(5 * time.Second)
	for len(m.all()) < 3 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	<-done
	ev := m.all()
	if len(ev) != 3 {
		t.Fatalf("events: %d", len(ev))
	}
	var first, second map[string]any
	_ = json.Unmarshal(ev[0], &first)
	_ = json.Unmarshal(ev[1], &second)
	if first["type"] != EventAuditRow || first["action"] != "console.login" || first["position"] != float64(1) || first["hash"] != "h" || second["action"] != "admin.update" {
		t.Fatalf("rows: %s | %s", ev[0], ev[1])
	}
	for _, e := range ev {
		if strings.Contains(string(e), "never-sent") {
			t.Fatalf("request body sent: %s", e)
		}
	}
	if !strings.Contains(string(ev[2]), `"type":"admin_audit_chain_head"`) || !strings.Contains(string(ev[2]), `"hash":"head-hash"`) {
		t.Fatalf("head: %s", ev[2])
	}
}

func TestForwarderNeverBlocksWhenTheQueueIsFull(t *testing.T) {
	f := NewForwarder(&memSink{}, logger.NewNop()) // not running: nothing drains
	start := time.Now()
	for i := 0; i < QueueSize+10; i++ {
		f.Row(admin.AuditChainEntry{Log: &admin.AuditLog{ID: shared.NewID(), CreatedAt: time.Now()}})
	}
	if time.Since(start) > time.Second || f.Dropped() != 10 {
		t.Fatalf("dropped %d in %v", f.Dropped(), time.Since(start))
	}
}

package httpsec

import (
	"bufio"
	"context"
	"errors"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

func mustFeedProxy(t *testing.T, raw, noProxy string) *feedProxyConfig {
	t.Helper()
	cfg, err := parseFeedProxy(raw, noProxy)
	if err != nil || cfg == nil {
		t.Fatalf("parseFeedProxy(%q): %v", raw, err)
	}
	return cfg
}

func TestParseFeedProxy(t *testing.T) {
	if cfg, err := parseFeedProxy("  ", ""); cfg != nil || err != nil {
		t.Fatalf("empty: %v %v", cfg, err)
	}
	for _, ok := range []string{"http://proxy.corp:3128", "https://u:p@10.1.2.3:8443", "http://proxy.corp:3128/"} {
		if _, err := parseFeedProxy(ok, ""); err != nil {
			t.Errorf("%s refused: %v", ok, err)
		}
	}
	for _, bad := range []string{"socks5://p:1080", "proxy.corp:3128", "http://p:3128/path", "http://p:3128?x=1", "http://", "http://u:s3cr3t@p:3128#f", "://u:s3cr3t@x"} {
		_, err := parseFeedProxy(bad, "")
		if err == nil {
			t.Errorf("%s accepted", bad)
			continue
		}
		if strings.Contains(err.Error(), "s3cr3t") {
			t.Errorf("error quotes the password: %v", err)
		}
	}
}

// No feed proxy: the feed client is the guarded client and takes nothing from
// the environment.
func TestFeedClientIgnoresProxyEnvironment(t *testing.T) {
	t.Setenv("HTTPS_PROXY", "http://192.0.2.99:3128")
	t.Setenv("HTTP_PROXY", "http://192.0.2.99:3128")
	tr := newFeedHTTPClient(time.Second, nil, defaultDialer).Transport.(*http.Transport)
	if tr.Proxy != nil {
		t.Fatal("feed client without a feed proxy must not proxy")
	}
}

func proxyFor(t *testing.T, cfg *feedProxyConfig, d guardedDialer, raw string) (*url.URL, error) {
	t.Helper()
	tr := newFeedHTTPClient(time.Second, cfg, d).Transport.(*http.Transport)
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, raw, nil)
	if err != nil {
		t.Fatal(err)
	}
	return tr.Proxy(req)
}

// The destination check still applies through the proxy.
func TestFeedProxyChecksDestination(t *testing.T) {
	cfg := mustFeedProxy(t, "http://user:pw@10.1.2.3:3128", "mirror.corp.example,.internal.example")
	d := guardedDialer{resolver: net.DefaultResolver, dial: refuseDial(t)}

	// Public IP literal and a name the local resolver cannot answer: proxied.
	for _, raw := range []string{"https://93.184.215.14/kev.json", "https://feed.example.invalid/x"} {
		p, err := proxyFor(t, cfg, d, raw)
		if err != nil || p == nil || p.Host != "10.1.2.3:3128" {
			t.Errorf("%s: want the proxy, got %v %v", raw, p, err)
		}
	}
	// Blocked destinations never reach the proxy.
	for _, raw := range []string{"https://169.254.169.254/latest/meta-data",
		"https://10.0.0.7/", "https://metadata.google.internal/", "https://[fd00::1]/"} {
		p, err := proxyFor(t, cfg, d, raw)
		if !errors.Is(err, ErrBlockedDestination) {
			t.Errorf("%s: want ErrBlockedDestination, got %v %v", raw, p, err)
		}
	}
	// Plain http and loopback names are never proxied: they take the guarded
	// direct dial, which refuses loopback.
	for _, raw := range []string{"http://93.184.215.14/x", "https://127.0.0.1/", "https://localhost/", "https://[::1]/"} {
		if p, err := proxyFor(t, cfg, d, raw); p != nil {
			t.Errorf("%s went to the proxy (%v)", raw, err)
		}
	}
	if _, err := d.dialContext(context.Background(), "tcp", "127.0.0.1:443"); !errors.Is(err, ErrBlockedDestination) {
		t.Errorf("direct loopback dial not refused: %v", err)
	}
	// NO_PROXY hosts are dialed directly (through the guard).
	for _, raw := range []string{"https://mirror.corp.example/b", "https://a.internal.example/b"} {
		if p, err := proxyFor(t, cfg, d, raw); p != nil || err != nil {
			t.Errorf("%s: want direct, got %v %v", raw, p, err)
		}
	}
}

// The proxy may sit on a private address; any other private destination
// dialed directly stays blocked, and hard-blocked proxies are refused.
func TestFeedProxyDialPolicy(t *testing.T) {
	var dialed []string
	d := guardedDialer{resolver: net.DefaultResolver, dial: func(_ context.Context, _, addr string) (net.Conn, error) {
		dialed = append(dialed, addr)
		c1, c2 := net.Pipe()
		_ = c2.Close()
		return c1, nil
	}}
	tr := newFeedHTTPClient(time.Second, mustFeedProxy(t, "http://10.1.2.3:3128", ""), d).Transport.(*http.Transport)
	if c, err := tr.DialContext(context.Background(), "tcp", "10.1.2.3:3128"); err != nil {
		t.Fatalf("proxy dial refused: %v", err)
	} else {
		_ = c.Close()
	}
	if _, err := tr.DialContext(context.Background(), "tcp", "10.1.2.3:443"); !errors.Is(err, ErrBlockedDestination) {
		t.Fatalf("a private non-proxy address must stay blocked: %v", err)
	}
	if len(dialed) != 1 || dialed[0] != "10.1.2.3:3128" {
		t.Fatalf("dialed %v", dialed)
	}
	tr = newFeedHTTPClient(time.Second, mustFeedProxy(t, "http://169.254.169.254:80", ""), d).Transport.(*http.Transport)
	if _, err := tr.DialContext(context.Background(), "tcp", "169.254.169.254:80"); !errors.Is(err, ErrBlockedDestination) {
		t.Fatalf("a metadata-address proxy must be refused: %v", err)
	}
}

// End to end: the request goes to the proxy as CONNECT for the destination,
// with the proxy credentials, and the failure text carries no credentials.
func TestFeedProxyConnect(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	var mu sync.Mutex
	var gotTarget, gotAuth string
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		req, err := http.ReadRequest(bufio.NewReader(c))
		if err != nil {
			return
		}
		mu.Lock()
		gotTarget, gotAuth = req.Method+" "+req.Host, req.Header.Get("Proxy-Authorization")
		mu.Unlock()
		_, _ = c.Write([]byte("HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n"))
	}()
	// The proxy is "10.1.2.3:3128" to the guard; the test dial reaches the
	// local listener in its place.
	d := guardedDialer{resolver: net.DefaultResolver, dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
		if addr != "10.1.2.3:3128" {
			return nil, errors.New("unexpected dial " + addr)
		}
		return (&net.Dialer{}).DialContext(ctx, network, ln.Addr().String())
	}}
	c := newFeedHTTPClient(3*time.Second, mustFeedProxy(t, "http://feeduser:s3cr3t@10.1.2.3:3128", ""), d)
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://93.184.215.14/kev.json?sig=x", nil)
	resp, err := c.Do(req)
	if err == nil {
		_ = resp.Body.Close()
		t.Fatal("want the proxy's refusal")
	}
	if strings.Contains(err.Error(), "s3cr3t") {
		t.Fatalf("error carries the proxy password: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if gotTarget != "CONNECT 93.184.215.14:443" {
		t.Fatalf("proxy saw %q", gotTarget)
	}
	if !strings.HasPrefix(gotAuth, "Basic ") {
		t.Fatalf("proxy credentials not sent: %q", gotAuth)
	}
}

// A feed URL whose name does not resolve at start-up is accepted; a blocked
// one is not.
func TestValidateFeedURL(t *testing.T) {
	if err := ValidateFeedURL("https://feed.example.invalid/releases"); err != nil {
		t.Fatalf("unresolvable name refused: %v", err)
	}
	for _, bad := range []string{"https://169.254.169.254/x", "ftp://example.com/x", "https://metadata.google.internal/"} {
		if err := ValidateFeedURL(bad); err == nil {
			t.Errorf("%s accepted", bad)
		}
	}
}

package httpsec

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// The bypass suite: every known way of spelling an internal destination must
// end in a refusal, and the refusal must not tell the caller where a name
// points. Each case is a classic outbound-request-forgery technique.

// TestBypass_AddressForms covers the address spellings a dialer accepts for
// an internal service: IPv4-mapped and IPv4-compatible IPv6, the NAT64, 6to4
// and Teredo carriers, the unspecified addresses and the cloud metadata
// endpoints over both families.
func TestBypass_AddressForms(t *testing.T) {
	for _, s := range []string{
		"127.0.0.1", "127.255.255.254", "0.0.0.0", "0.1.2.3",
		"169.254.169.254", "169.254.170.2", "100.100.100.200", "100.64.0.1",
		"::1", "::", "::ffff:127.0.0.1", "::ffff:169.254.169.254", "0:0:0:0:0:ffff:7f00:1",
		"::127.0.0.1", "::a9fe:a9fe", "::7f00:1", // IPv4-compatible
		"64:ff9b::a9fe:a9fe", "64:ff9b:1::7f00:1", "2002:7f00:1::", "2001:0:4136:e378:8000:63bf:80ff:fffe",
		"fd00:ec2::254", "fd20:ce::254", "fe80::1", "fec0::1", "ff02::1",
		"224.0.0.1", "239.255.255.250", "255.255.255.255", "240.0.0.1", "192.0.0.170", "198.18.0.1",
		"10.0.0.1", "172.16.0.1", "192.168.1.1", "fc00::1", "fd12:3456::1",
	} {
		ip := net.ParseIP(s)
		if ip == nil {
			t.Fatalf("test table: %q does not parse", s)
		}
		if !IsIPBlocked(ip) {
			t.Errorf("%s is reachable; it must be refused", s)
		}
		if _, err := ValidateURL("http://[" + s + "]/"); err == nil && strings.Contains(s, ":") {
			t.Errorf("http://[%s]/ passed ValidateURL", s)
		}
	}
	for _, s := range []string{"93.184.215.14", "2606:2800:21f:cb07:6820:80da:af6b:8b2c", "8.8.8.8"} {
		if IsIPBlocked(net.ParseIP(s)) {
			t.Errorf("public address %s is refused", s)
		}
	}
}

// TestBypass_HostSpellings resolves through a scripted DNS server, so the
// decision is shown to be on the resolved address whatever the host string
// looks like: numeric forms a C resolver turns into 127.0.0.1, a wildcard
// DNS name embedding the metadata address, an internationalized name, and
// the blocked aliases with a trailing dot or in another case (refused before
// any lookup).
func TestBypass_HostSpellings(t *testing.T) {
	loop, imds := net.ParseIP("127.0.0.1"), net.ParseIP("169.254.169.254")
	dns := newRebindDNS(t, map[string][]net.IP{
		"2130706433":                  {loop},
		"0x7f000001":                  {loop},
		"0177.0.0.1":                  {loop},
		"127.1":                       {loop},
		"169.254.169.254.nip.example": {imds},
		"xn--lcalhost-4za.example":    {loop},
		"internal-name.example":       {net.ParseIP("10.1.2.3")},
	})
	d := guardedDialer{resolver: resolverFor(dns), dial: refuseDial(t)}
	for host := range map[string]bool{
		"2130706433": true, "0x7f000001": true, "0177.0.0.1": true, "127.1": true,
		"169.254.169.254.nip.example": true, "xn--lcalhost-4za.example": true, "internal-name.example": true,
		"localhost.": true, "LOCALHOST": true, "Metadata.Google.Internal.": true, "metadata": true,
	} {
		_, err := d.dialContext(context.Background(), "tcp", net.JoinHostPort(host, "80"))
		// Go's resolver refuses an all-numeric name outright (no lookup);
		// a C resolver turns it into 127.0.0.1, which the address check
		// refuses. Either way nothing is dialed.
		if !errors.Is(err, ErrBlockedDestination) && !errors.Is(err, ErrUnresolvable) {
			t.Errorf("%s: got %v, want a refusal", host, err)
		}
	}
}

// TestBypass_UserinfoAndParsing: the host is what the URL parser says it is,
// never the text before an @.
func TestBypass_UserinfoAndParsing(t *testing.T) {
	for _, raw := range []string{
		"http://good.example@127.0.0.1/",
		"http://good.example:pass@[::1]:8080/",
		"http://user@169.254.169.254/latest/meta-data/",
		"HTTP://127.0.0.1/",
		"http://127.0.0.1:6379/",
		"http://[::ffff:127.0.0.1]/",
		"http://0/",
	} {
		if _, err := ValidateURL(raw); err == nil {
			t.Errorf("%s passed ValidateURL", raw)
		}
	}
}

// TestBypass_Schemes: only http and https reach a guarded client, both at
// validation and in the transport itself.
func TestBypass_Schemes(t *testing.T) {
	for _, raw := range []string{
		"file:///etc/passwd", "gopher://example.com:70/_x", "dict://example.com:11211/stat", "ftp://example.com/",
		"ldap://example.com/", "unix:///var/run/docker.sock", "jar:http://example.com/a!/", "netdoc:///etc/passwd",
		"ws://example.com/", "git://example.com/repo", "ssh://git@example.com/repo",
	} {
		if _, err := ValidateURL(raw); err == nil {
			t.Errorf("%s passed ValidateURL", raw)
		}
		u, _ := url.Parse(raw)
		if u == nil {
			continue
		}
		req := &http.Request{Method: http.MethodGet, URL: u, Header: http.Header{}}
		if resp, err := SafeHTTPClient(time.Second).Do(req); err == nil {
			_ = resp.Body.Close()
			t.Errorf("%s was fetched by SafeHTTPClient", raw)
		}
	}
}

// TestBypass_RedirectToInternal: a public endpoint that answers 302 to an
// internal address is refused at the second dial.
func TestBypass_RedirectToInternal(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://169.254.169.254/latest/meta-data/iam/", http.StatusFound)
	}))
	defer upstream.Close()
	dns := newRebindDNS(t, map[string][]net.IP{"public.example": {net.ParseIP("192.0.2.30")}})
	dial := func(ctx context.Context, network, addr string) (net.Conn, error) {
		if strings.HasPrefix(addr, "192.0.2.30:") {
			var dl net.Dialer
			return dl.DialContext(ctx, network, upstream.Listener.Addr().String())
		}
		t.Errorf("dialed %s", addr)
		return nil, errUnexpectedDial
	}
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://public.example/hook", nil)
	resp, err := newSafeHTTPClient(3*time.Second, guardedDialer{resolver: resolverFor(dns), dial: dial}).Do(req)
	if resp != nil {
		_ = resp.Body.Close()
	}
	if !errors.Is(err, ErrBlockedDestination) {
		t.Fatalf("redirect to the metadata address: got %v, want ErrBlockedDestination", err)
	}
}

// TestBypass_RedirectPolicy: the default policy refuses a downgrade from
// https to http and bounds the chain.
func TestBypass_RedirectPolicy(t *testing.T) {
	mk := func(raw string) *http.Request { u, _ := url.Parse(raw); return &http.Request{URL: u} }
	if err := checkRedirect(mk("http://example.com/b"), []*http.Request{mk("https://example.com/a")}); err == nil {
		t.Error("https to http redirect was allowed")
	}
	if err := checkRedirect(mk("https://example.com/b"), []*http.Request{mk("http://example.com/a")}); err != nil {
		t.Errorf("http to https redirect refused: %v", err)
	}
	via := make([]*http.Request, maxRedirects)
	for i := range via {
		via[i] = mk("https://example.com/")
	}
	if err := checkRedirect(mk("https://example.com/next"), via); err == nil {
		t.Error("redirect chain is unbounded")
	}
	if SafeHTTPClient(time.Second).CheckRedirect == nil {
		t.Error("SafeHTTPClient has no redirect policy")
	}
}

// TestBypass_ProxyEnvironmentIgnored: an HTTP(S)_PROXY in the process
// environment must not route guarded traffic through a proxy (the dial
// check would then vet the proxy, not the destination).
func TestBypass_ProxyEnvironmentIgnored(t *testing.T) {
	t.Setenv("HTTP_PROXY", "http://192.0.2.99:3128")
	t.Setenv("HTTPS_PROXY", "http://192.0.2.99:3128")
	t.Setenv("NO_PROXY", "")
	for name, c := range map[string]*http.Client{
		"safe":           SafeHTTPClient(time.Second),
		"private":        PrivateAllowedHTTPClient(time.Second),
		"request-policy": RequestPolicyHTTPClient(time.Second),
		"header-timeout": SafeHTTPClientWithHeaderTimeout(time.Second, time.Second),
	} {
		tr, ok := c.Transport.(*http.Transport)
		if !ok {
			t.Fatalf("%s: transport is %T", name, c.Transport)
		}
		if tr.Proxy != nil {
			t.Errorf("%s: transport takes a proxy from the environment", name)
		}
	}
}

// TestBypass_ErrorsNameNoAddress: neither a refusal nor a lookup failure
// names the resolved address or the platform's resolver, so a probe of
// caller-chosen names cannot map the internal network.
func TestBypass_ErrorsNameNoAddress(t *testing.T) {
	dns := newRebindDNS(t, map[string][]net.IP{"gitlab.corp.example": {net.ParseIP("10.20.30.40")}})
	d := guardedDialer{resolver: resolverFor(dns), dial: refuseDial(t)}
	_, err := d.dialContext(context.Background(), "tcp", "gitlab.corp.example:443")
	if err == nil || strings.Contains(err.Error(), "10.20.30.40") {
		t.Fatalf("refusal names the resolved address: %v", err)
	}
	_, err = d.dialContext(context.Background(), "tcp", "missing.corp.example:443")
	if !errors.Is(err, ErrUnresolvable) {
		t.Fatalf("unknown name: got %v, want ErrUnresolvable", err)
	}
	var dnsErr *net.DNSError
	if !errors.As(err, &dnsErr) {
		t.Fatalf("the resolver's error is not kept for errors.As: %v", err)
	}
	if strings.Contains(err.Error(), dns.conn.LocalAddr().String()) || strings.Contains(err.Error(), "lookup") {
		t.Fatalf("lookup failure names the resolver: %v", err)
	}
	if _, err := ValidateURL("http://[::ffff:10.9.8.7]/"); err == nil || strings.Contains(err.Error(), "10.9.8.7") {
		t.Fatalf("ValidateURL refusal names the address: %v", err)
	}
}

// TestBypass_RequestPolicyNoReuse: the per-request client never reuses a
// connection, so one opened under the installation's private allowance is
// never handed to a request that may reach public addresses only.
func TestBypass_RequestPolicyNoReuse(t *testing.T) {
	tr, _ := RequestPolicyHTTPClient(time.Second).Transport.(*http.Transport)
	if tr == nil || !tr.DisableKeepAlives {
		t.Fatal("RequestPolicyHTTPClient reuses connections")
	}
}

// TestBypass_ResponseNotEchoedByDefault documents the size cap callers use:
// ReadLimited refuses a body past its limit instead of buffering it.
func TestBypass_ResponseNotEchoedByDefault(t *testing.T) {
	if _, err := ReadLimited(io.NopCloser(strings.NewReader(strings.Repeat("a", 2048))), 1024); err == nil {
		t.Fatal("ReadLimited buffered a body past its limit")
	}
}

func refuseDial(t *testing.T) func(context.Context, string, string) (net.Conn, error) {
	return func(_ context.Context, _, addr string) (net.Conn, error) {
		t.Errorf("guard dialed %s; it must refuse before connecting", addr)
		return nil, errUnexpectedDial
	}
}

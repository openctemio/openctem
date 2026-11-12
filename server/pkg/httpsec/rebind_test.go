package httpsec

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// rebindDNS is a scripted DNS server. Each A query for a name is answered
// with the next address in that name's script; once the script is exhausted
// the last address repeats. AAAA queries get an empty NOERROR answer. This is
// exactly what a DNS-rebinding attacker runs: a public address for the
// guard's lookup, an internal one for every lookup after it (TTL 0, so
// nothing caches the first answer).
type rebindDNS struct {
	conn    net.PacketConn
	mu      sync.Mutex
	scripts map[string][]net.IP
	queries map[string]int
}

func newRebindDNS(t *testing.T, scripts map[string][]net.IP) *rebindDNS {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen dns: %v", err)
	}
	d := &rebindDNS{conn: pc, scripts: scripts, queries: map[string]int{}}
	go d.serve()
	t.Cleanup(func() { _ = pc.Close() })
	return d
}

func (d *rebindDNS) aQueries(name string) int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.queries[name]
}

func (d *rebindDNS) serve() {
	buf := make([]byte, 1500)
	for {
		n, addr, err := d.conn.ReadFrom(buf)
		if err != nil {
			return
		}
		var p dnsmessage.Parser
		hdr, err := p.Start(buf[:n])
		if err != nil {
			continue
		}
		q, err := p.Question()
		if err != nil {
			continue
		}
		name := strings.TrimSuffix(q.Name.String(), ".")

		b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: hdr.ID, Response: true, Authoritative: true})
		_ = b.StartQuestions()
		_ = b.Question(q)
		_ = b.StartAnswers()

		d.mu.Lock()
		script, known := d.scripts[name]
		if known && q.Type == dnsmessage.TypeA {
			i := d.queries[name]
			d.queries[name] = i + 1
			if i >= len(script) {
				i = len(script) - 1
			}
			var a [4]byte
			copy(a[:], script[i].To4())
			_ = b.AResource(dnsmessage.ResourceHeader{Name: q.Name, Class: dnsmessage.ClassINET, TTL: 0}, dnsmessage.AResource{A: a})
		}
		d.mu.Unlock()

		out, err := b.Finish()
		if err != nil {
			continue
		}
		_, _ = d.conn.WriteTo(out, addr)
	}
}

// resolverFor returns a resolver that sends every query to d.
func resolverFor(d *rebindDNS) *net.Resolver {
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var dl net.Dialer
			return dl.DialContext(ctx, "udp", d.conn.LocalAddr().String())
		},
	}
}

// TestSafeHTTPClient_DNSRebinding is the exploit for the dial-time TOCTOU:
// the guard used to resolve the host, vet the answer, then hand the HOSTNAME
// to net.Dialer — which resolved it a second time. The attacker's DNS answers
// the first query with a public address and the second with 127.0.0.1, so
// the request lands on an internal service. The guard must dial the address
// it vetted, never a fresh resolution.
func TestSafeHTTPClient_DNSRebinding(t *testing.T) {
	var internalHits atomic.Int32
	internal := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		internalHits.Add(1)
		_, _ = io.WriteString(w, "internal-secret")
	}))
	defer internal.Close()
	_, port, _ := net.SplitHostPort(internal.Listener.Addr().String())

	// 192.0.2.10 (TEST-NET-1) stands in for "some public address": it is not
	// in any blocked range, and nothing listens there.
	dns := newRebindDNS(t, map[string][]net.IP{
		"rebind.attacker.test": {net.ParseIP("192.0.2.10"), net.ParseIP("127.0.0.1")},
	})
	res := resolverFor(dns)

	// The connect step resolves through the same scripted DNS, exactly as
	// net.Dialer would through the system resolver — so dialing a hostname
	// here is a second lookup the attacker answers with 127.0.0.1.
	client := newSafeHTTPClient(time.Second, guardedDialer{
		resolver: res,
		dial:     (&net.Dialer{Timeout: time.Second, Resolver: res}).DialContext,
	})
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "http://rebind.attacker.test:"+port+"/", nil)
	resp, err := client.Do(req)
	if err == nil {
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		t.Fatalf("SSRF via DNS rebinding: request reached the internal service (status %d, body %q)", resp.StatusCode, body)
	}
	if n := internalHits.Load(); n != 0 {
		t.Fatalf("SSRF via DNS rebinding: internal service received %d request(s)", n)
	}
	if q := dns.aQueries("rebind.attacker.test"); q != 1 {
		t.Fatalf("guard resolved the host %d times; it must resolve once and dial the vetted address", q)
	}
}

// TestSafeHTTPClient_DialsVettedAddress is the legitimate path: the dial must
// go to the address the guard vetted, while the request (Host header, and SNI
// for https) still carries the hostname so virtual hosting and certificate
// verification keep working.
func TestSafeHTTPClient_DialsVettedAddress(t *testing.T) {
	var gotHost string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHost = r.Host
		_, _ = io.WriteString(w, "ok")
	}))
	defer upstream.Close()

	dns := newRebindDNS(t, map[string][]net.IP{
		"hooks.partner.test": {net.ParseIP("192.0.2.20")},
	})
	// Nothing listens on 192.0.2.20 offline, so route that one vetted address
	// to the local upstream and record what the dialer was asked for.
	var dialed []string
	dial := func(ctx context.Context, network, addr string) (net.Conn, error) {
		dialed = append(dialed, addr)
		if strings.HasPrefix(addr, "192.0.2.20:") {
			var dl net.Dialer
			return dl.DialContext(ctx, network, upstream.Listener.Addr().String())
		}
		return nil, &net.OpError{Op: "dial", Net: network, Err: errUnexpectedDial}
	}

	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://hooks.partner.test:8443/hook", nil)
	resp, err := newSafeHTTPClient(3*time.Second, guardedDialer{resolver: resolverFor(dns), dial: dial}).Do(req)
	if err != nil {
		t.Fatalf("legitimate request failed: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if string(body) != "ok" {
		t.Fatalf("unexpected body %q", body)
	}
	if len(dialed) != 1 || dialed[0] != "192.0.2.20:8443" {
		t.Fatalf("dialer was asked for %v, want exactly the vetted address 192.0.2.20:8443", dialed)
	}
	if gotHost != "hooks.partner.test:8443" {
		t.Fatalf("Host header %q, want the original hostname", gotHost)
	}
}

// TestSafeHTTPClient_BlocksWhenAnyAnswerIsInternal keeps the existing rule: a
// name with one public and one internal record is refused outright.
func TestSafeHTTPClient_BlocksWhenAnyAnswerIsInternal(t *testing.T) {
	dns := newRebindDNS(t, map[string][]net.IP{
		"mixed.attacker.test": {net.ParseIP("169.254.169.254")},
	})

	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://mixed.attacker.test/latest/meta-data/", nil)
	resp, err := newSafeHTTPClient(2*time.Second, guardedDialer{resolver: resolverFor(dns), dial: defaultDialer.dial}).Do(req)
	if resp != nil {
		_ = resp.Body.Close()
	}
	if err == nil || !strings.Contains(err.Error(), "blocked") {
		t.Fatalf("expected a blocked error, got %v", err)
	}
}

type dialErr string

func (e dialErr) Error() string { return string(e) }

const errUnexpectedDial = dialErr("test dialer: unexpected address")

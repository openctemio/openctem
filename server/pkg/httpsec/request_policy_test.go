package httpsec

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// allowInstancePrivate opens 10.0.0.0/8 the way the installation's
// allow-list does, for one test.
func allowInstancePrivate(t *testing.T) {
	t.Helper()
	_, n, _ := net.ParseCIDR("10.0.0.0/8")
	prev := allowedPrivateCIDRs
	allowedPrivateCIDRs = []*net.IPNet{n}
	t.Cleanup(func() { allowedPrivateCIDRs = prev })
}

// SECURITY: the private-range decision is made per connection at dial time:
// without the instance-private mark a private address is refused even where
// the installation allow-lists its range; with the mark the allow-list
// applies; loopback stays refused either way.
func TestRequestPolicyDialer_PerConnectionDecision(t *testing.T) {
	allowInstancePrivate(t)
	for _, c := range []struct {
		name    string
		host    string
		marked  bool
		reached bool
	}{
		{"unmarked, allow-listed private", "10.1.2.3", false, false},
		{"marked, allow-listed private", "10.1.2.3", true, true},
		{"marked, private outside the allow-list", "192.168.1.1", true, false},
		{"unmarked, public", "93.184.216.34", false, true},
		{"marked, loopback", "127.0.0.1", true, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			rec := &recordingDial{}
			d := guardedDialer{resolver: net.DefaultResolver, dial: rec.dial, perRequest: true}
			ctx := context.Background()
			if c.marked {
				ctx = WithInstancePrivate(ctx)
			}
			_, _ = d.dialContext(ctx, "tcp", net.JoinHostPort(c.host, "443"))
			if (len(rec.addrs) == 1) != c.reached {
				t.Fatalf("dials %v, want reached=%v", rec.addrs, c.reached)
			}
		})
	}
}

// The mark survives http.Transport's dial: a request context marked with
// WithInstancePrivate reaches an allow-listed private address through the
// client, an unmarked one is refused before any connection, and (DNS
// rebinding) a name that answers private on the dial is judged at the dial.
func TestRequestPolicyClient_ContextReachesTheDial(t *testing.T) {
	allowInstancePrivate(t)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "ok") }))
	defer upstream.Close()
	_, port, _ := net.SplitHostPort(upstream.Listener.Addr().String())
	dns := newRebindDNS(t, map[string][]net.IP{"git.corp.test": {net.ParseIP("10.5.5.5")}})
	res := resolverFor(dns)
	var dialed []string
	d := guardedDialer{resolver: res, perRequest: true, dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
		dialed = append(dialed, addr)
		return (&net.Dialer{}).DialContext(ctx, network, upstream.Listener.Addr().String())
	}}
	client := newSafeHTTPClient(2*time.Second, d)
	client.Transport.(*http.Transport).DisableKeepAlives = true

	get := func(ctx context.Context) error {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "http://git.corp.test:"+port+"/", nil)
		resp, err := client.Do(req)
		if err == nil {
			_ = resp.Body.Close()
		}
		return err
	}
	if err := get(context.Background()); err == nil || len(dialed) != 0 {
		t.Fatalf("unmarked request to a private host: err %v dialed %v", err, dialed)
	}
	if err := get(WithInstancePrivate(context.Background())); err != nil || len(dialed) != 1 || dialed[0] != "10.5.5.5:"+port {
		t.Fatalf("marked request: err %v dialed %v", err, dialed)
	}
}

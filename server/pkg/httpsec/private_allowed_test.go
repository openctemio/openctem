package httpsec

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"
)

// recordingDial records the address it was asked to connect to and refuses.
type recordingDial struct{ addrs []string }

func (r *recordingDial) dial(_ context.Context, _, addr string) (net.Conn, error) {
	r.addrs = append(r.addrs, addr)
	return nil, net.ErrClosed
}

func TestPrivateAllowedDialer_OnlyOpensRFC1918(t *testing.T) {
	cases := []struct {
		name      string
		host      string
		privateOK bool
		reached   bool
	}{
		{"private blocked by default", "10.1.2.3", false, false},
		{"private allowed when opened", "10.1.2.3", true, true},
		{"ula allowed when opened", "fd12:3456::1", true, true},
		{"loopback always blocked", "127.0.0.1", true, false},
		{"metadata always blocked", "169.254.169.254", true, false},
		{"link-local always blocked", "169.254.10.10", true, false},
		{"cgnat always blocked", "100.64.0.1", true, false},
		{"aws ipv6 metadata always blocked", "fd00:ec2::254", true, false},
		{"nat64-embedded metadata always blocked", "64:ff9b::a9fe:a9fe", true, false},
		{"public reachable", "93.184.216.34", false, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rec := &recordingDial{}
			d := guardedDialer{resolver: net.DefaultResolver, dial: rec.dial, privateOK: c.privateOK}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			_, err := d.dialContext(ctx, "tcp", net.JoinHostPort(c.host, "443"))
			if c.reached {
				if len(rec.addrs) != 1 {
					t.Fatalf("want one dial, got %v (err %v)", rec.addrs, err)
				}
				return
			}
			if len(rec.addrs) != 0 || err == nil || !strings.Contains(err.Error(), "ssrf guard") {
				t.Fatalf("want ssrf refusal without a dial, got dials=%v err=%v", rec.addrs, err)
			}
		})
	}
}

// A private-allowed client must not be fooled by DNS rebinding either: the
// vetted address is the one dialed, and a name that answers loopback second
// is refused or pinned to the first (private) answer, never loopback.
func TestPrivateAllowedDialer_RebindToLoopbackNeverDialed(t *testing.T) {
	dns := newRebindDNS(t, map[string][]net.IP{
		"llm.internal.test": {net.ParseIP("10.9.9.9"), net.ParseIP("127.0.0.1")},
	})
	res := resolverFor(dns)
	rec := &recordingDial{}
	d := guardedDialer{resolver: res, dial: rec.dial, privateOK: true}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, _ = d.dialContext(ctx, "tcp", "llm.internal.test:443")
	if len(rec.addrs) != 1 || rec.addrs[0] != "10.9.9.9:443" {
		t.Fatalf("must dial the vetted address only, got %v", rec.addrs)
	}
}

func TestValidateHostAllowPrivate(t *testing.T) {
	ctx := context.Background()
	if err := ValidateHostAllowPrivate(ctx, "10.0.0.5"); err != nil {
		t.Fatalf("private literal should pass: %v", err)
	}
	for _, h := range []string{"127.0.0.1", "169.254.169.254", "localhost", "metadata.google.internal"} {
		if err := ValidateHostAllowPrivate(ctx, h); err == nil {
			t.Fatalf("%s must stay blocked", h)
		}
	}
	if err := ValidateHost(ctx, "10.0.0.5"); err == nil {
		t.Fatal("the default policy must still block private addresses")
	}
}

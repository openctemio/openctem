package httpsec

import (
	"net/http/httptest"
	"testing"
)

func TestClientIP(t *testing.T) {
	// The gateway (10.0.0.10) and the web UI (10.0.0.11) are trusted proxies.
	trusted := NewTrustedProxySet([]string{"10.0.0.10", "10.0.0.11/32", "fd00::/64"})

	tests := []struct {
		name    string
		trusted *TrustedProxySet
		remote  string
		xff     []string
		xrealip string
		want    string
	}{
		// Untrusted peers: the headers are never read.
		{name: "no proxies configured, forged XFF ignored", trusted: nil, remote: "203.0.113.7:5555", xff: []string{"1.2.3.4"}, want: "203.0.113.7"},
		{name: "empty proxy set, forged X-Real-IP ignored", trusted: NewTrustedProxySet(nil), remote: "203.0.113.7:5555", xrealip: "1.2.3.4", want: "203.0.113.7"},
		{name: "untrusted peer, forged XFF and X-Real-IP ignored", trusted: trusted, remote: "203.0.113.7:5555", xff: []string{"1.2.3.4, 10.0.0.10"}, xrealip: "1.2.3.4", want: "203.0.113.7"},
		{name: "untrusted IPv6 peer, port stripped", trusted: trusted, remote: "[2001:db8::1]:443", xff: []string{"1.2.3.4"}, want: "2001:db8::1"},
		{name: "no headers at all", trusted: trusted, remote: "203.0.113.7:5555", want: "203.0.113.7"},

		// Trusted peer.
		{name: "trusted proxy, XFF wins over a passed-through X-Real-IP", trusted: trusted, remote: "10.0.0.10:40000", xff: []string{"198.51.100.9"}, xrealip: "198.51.100.1", want: "198.51.100.9"},
		{name: "trusted proxy, malformed X-Real-IP ignored when XFF is present", trusted: trusted, remote: "10.0.0.10:40000", xff: []string{"198.51.100.9"}, xrealip: "not-an-ip", want: "198.51.100.9"},
		{name: "trusted proxy, X-Real-IP used only without XFF", trusted: trusted, remote: "10.0.0.10:40000", xrealip: "198.51.100.1", want: "198.51.100.1"},
		{name: "trusted proxy, malformed XFF does not fall back to X-Real-IP", trusted: trusted, remote: "10.0.0.10:40000", xff: []string{"garbage"}, xrealip: "1.2.3.4", want: "10.0.0.10"},
		{name: "trusted proxy, single XFF entry", trusted: trusted, remote: "10.0.0.10:40000", xff: []string{"198.51.100.9"}, want: "198.51.100.9"},
		{
			// An appending proxy keeps whatever the client sent on the left.
			// The left-most entry is the client's choice; the right-most
			// untrusted one is what the trusted proxy actually saw.
			name: "appending proxy, client-forged left entry ignored", trusted: trusted, remote: "10.0.0.10:40000",
			xff: []string{"1.2.3.4, 198.51.100.9"}, want: "198.51.100.9",
		},
		{
			name: "two trusted hops are skipped", trusted: trusted, remote: "10.0.0.11:40000",
			xff: []string{"1.2.3.4, 198.51.100.9, 10.0.0.10"}, want: "198.51.100.9",
		},
		{
			name: "multiple XFF header lines are one list", trusted: trusted, remote: "10.0.0.11:40000",
			xff: []string{"1.2.3.4", "198.51.100.9, 10.0.0.10"}, want: "198.51.100.9",
		},
		{
			name: "malformed right-most entry, falls back to peer", trusted: trusted, remote: "10.0.0.10:40000",
			xff: []string{"198.51.100.9, garbage"}, want: "10.0.0.10",
		},
		{
			name: "malformed entry behind a trusted hop stops the walk", trusted: trusted, remote: "10.0.0.11:40000",
			xff: []string{"1.2.3.4, garbage, 10.0.0.10"}, want: "10.0.0.10",
		},
		{name: "all entries trusted, left-most returned", trusted: trusted, remote: "10.0.0.11:40000", xff: []string{"10.0.0.10"}, want: "10.0.0.10"},
		{name: "trusted proxy without headers, peer returned", trusted: trusted, remote: "10.0.0.10:40000", want: "10.0.0.10"},
		{name: "trusted IPv6 proxy, IPv6 client", trusted: trusted, remote: "[fd00::5]:40000", xff: []string{"2001:db8::9"}, want: "2001:db8::9"},
		{name: "header value with port is not an IP", trusted: trusted, remote: "10.0.0.10:40000", xrealip: "198.51.100.1:1234", want: "10.0.0.10"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest("GET", "/", nil)
			r.RemoteAddr = tt.remote
			for _, v := range tt.xff {
				r.Header.Add("X-Forwarded-For", v)
			}
			if tt.xrealip != "" {
				r.Header.Set("X-Real-IP", tt.xrealip)
			}
			if got := ClientIP(r, tt.trusted); got != tt.want {
				t.Fatalf("ClientIP() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestClientIP_UnparseableRemoteAddr(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = " @unix "
	r.Header.Set("X-Forwarded-For", "1.2.3.4")
	if got := ClientIP(r, NewTrustedProxySet([]string{"0.0.0.0/0"})); got != "@unix" {
		t.Fatalf("ClientIP() = %q, want the trimmed RemoteAddr", got)
	}
}

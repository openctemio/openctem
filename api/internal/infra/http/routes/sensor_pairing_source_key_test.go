package routes

import (
	"net/http/httptest"
	"testing"
)

// The pairing start budget groups an IPv6 caller by its /64 (sensor →
// platform review, M11): addresses in one /64 share one budget, IPv4
// addresses keep one each.
func TestPairingSourceKey(t *testing.T) {
	key := func(remote string) string {
		r := httptest.NewRequest("POST", "/api/v2/sensor/pairings", nil)
		r.RemoteAddr = remote
		return pairingSourceKey(r)
	}
	if a, b := key("[2001:db8:1:2::1]:4000"), key("[2001:db8:1:2:ffff:ffff:ffff:fffe]:4000"); a != b || a != "2001:db8:1:2::/64" {
		t.Fatalf("one /64 must share a key: %q %q", a, b)
	}
	if a, b := key("[2001:db8:1:2::1]:4000"), key("[2001:db8:1:3::1]:4000"); a == b {
		t.Fatalf("different /64s must not share a key: %q", a)
	}
	if a, b := key("203.0.113.7:4000"), key("203.0.113.8:4000"); a == b || a != "203.0.113.7" {
		t.Fatalf("IPv4 keys per address: %q %q", a, b)
	}
	if k := key("[::ffff:203.0.113.7]:4000"); k != "203.0.113.7" {
		t.Fatalf("a mapped IPv4 address is IPv4: %q", k)
	}
}

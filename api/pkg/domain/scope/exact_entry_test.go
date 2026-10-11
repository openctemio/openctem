package scope

import "testing"

func TestExactEntryFor(t *testing.T) {
	cases := []struct {
		in, typ, pattern string
		ok               bool
	}{
		{"API.Example.com.", "domain", "api.example.com", true},
		{"https://shop.example.com:8443/login", "domain", "shop.example.com", true},
		{"mail.example.com:25:tcp", "domain", "mail.example.com", true},
		{"203.0.113.9", "ip_address", "203.0.113.9", true},
		{"203.0.113.9:443/tcp", "ip_address", "203.0.113.9", true},
		{"[2001:db8::1]:443", "ip_address", "2001:db8::1", true},
		{"198.51.100.7/24", "cidr", "198.51.100.0/24", true},
		{"203.0.113.9/32", "ip_address", "203.0.113.9", true},
		{"*.example.com", "", "", false},
		{"10.0.0.5", "", "", false},
		{"192.168.0.0/16", "", "", false},
		{"db.internal", "", "", false},
		{"github.com/acme/web", "domain", "github.com", true},
		{"acme-repo", "", "", false},
		{"", "", "", false},
	}
	for _, c := range cases {
		typ, p, ok := ExactEntryFor(c.in)
		if ok != c.ok || string(typ) != c.typ || p != c.pattern {
			t.Errorf("ExactEntryFor(%q) = %q %q %v, want %q %q %v", c.in, typ, p, ok, c.typ, c.pattern, c.ok)
		}
	}
}

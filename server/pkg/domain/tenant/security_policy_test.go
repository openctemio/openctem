package tenant

import "testing"

func TestEmailDomainAllowed(t *testing.T) {
	cases := []struct {
		name    string
		allowed []string
		email   string
		want    bool
	}{
		{"empty list allows any", nil, "a@anything.io", true},
		{"exact match", []string{"corp.com"}, "alice@corp.com", true},
		{"case insensitive", []string{"Corp.COM"}, "Alice@CORP.com", true},
		{"surrounding spaces in list", []string{" corp.com "}, "alice@corp.com", true},
		{"other domain refused", []string{"corp.com"}, "alice@evil.com", false},
		{"subdomain is not the domain", []string{"corp.com"}, "alice@eu.corp.com", false},
		{"suffix trick refused", []string{"corp.com"}, "alice@evilcorp.com", false},
		{"no at sign refused", []string{"corp.com"}, "corp.com", false},
		{"empty email refused", []string{"corp.com"}, "", false},
		{"one of many", []string{"a.com", "corp.com"}, "bob@corp.com", true},
		{"last at sign wins", []string{"corp.com"}, "x@evil.com@corp.com", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := SecuritySettings{AllowedDomains: tc.allowed}
			if got := s.EmailDomainAllowed(tc.email); got != tc.want {
				t.Fatalf("EmailDomainAllowed(%q) with %v = %v, want %v", tc.email, tc.allowed, got, tc.want)
			}
		})
	}
}

func TestIPAllowed(t *testing.T) {
	cases := []struct {
		name string
		list []string
		ip   string
		want bool
	}{
		{"empty list allows any", nil, "203.0.113.9", true},
		{"exact ipv4", []string{"203.0.113.9"}, "203.0.113.9", true},
		{"cidr ipv4", []string{"10.0.0.0/8"}, "10.20.30.40", true},
		{"outside cidr", []string{"10.0.0.0/8"}, "11.0.0.1", false},
		{"ipv4-mapped ipv6 matches ipv4 entry", []string{"203.0.113.0/24"}, "::ffff:203.0.113.7", true},
		{"ipv6 cidr", []string{"2001:db8::/32"}, "2001:db8::1", true},
		{"ipv6 outside", []string{"2001:db8::/32"}, "2001:db9::1", false},
		{"unparseable ip refused", []string{"10.0.0.0/8"}, "not-an-ip", false},
		{"empty ip refused", []string{"10.0.0.0/8"}, "", false},
		{"ip with port refused", []string{"10.0.0.0/8"}, "10.0.0.1:443", false},
		{"invalid entry ignored", []string{"garbage", "10.0.0.1"}, "10.0.0.1", true},
		{"only invalid entries deny", []string{"garbage"}, "10.0.0.1", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := SecuritySettings{IPWhitelist: tc.list}
			if got := s.IPAllowed(tc.ip); got != tc.want {
				t.Fatalf("IPAllowed(%q) with %v = %v, want %v", tc.ip, tc.list, got, tc.want)
			}
		})
	}
}

func TestIPAllowlistActive(t *testing.T) {
	if (SecuritySettings{}).IPAllowlistActive() {
		t.Fatal("empty list must be inactive")
	}
	if !(SecuritySettings{IPWhitelist: []string{"10.0.0.1"}}).IPAllowlistActive() {
		t.Fatal("non-empty list must be active")
	}
}

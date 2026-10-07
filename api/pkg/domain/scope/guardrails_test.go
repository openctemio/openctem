package scope

import (
	"errors"
	"testing"
)

func TestGuardrails_CheckPattern(t *testing.T) {
	g, bad := NewGuardrails(0, 0, []string{"203.0.113.0/24", "platform.example", "not a thing!"})
	if len(bad) != 1 || bad[0] != "not a thing!" {
		t.Fatalf("bad extras = %v", bad)
	}
	cases := []struct {
		typ     TargetType
		pattern string
		want    error
	}{
		// Public suffixes (embedded PSL).
		{TargetTypeDomain, "*.com.vn", ErrPublicSuffix},
		{TargetTypeDomain, "com.vn", ErrPublicSuffix},
		{TargetTypeDomain, "*.com", ErrPublicSuffix},
		{TargetTypeDomain, "com", ErrPublicSuffix},
		{TargetTypeDomain, "*.co.uk", ErrPublicSuffix},
		{TargetTypeDomain, "github.io", ErrPublicSuffix}, // private PSL section
		{TargetTypeDomain, "*.github.io", ErrPublicSuffix},
		{TargetTypeDomain, "*.amazonaws.com", ErrPublicSuffix},
		{TargetTypeDomain, "*.azurewebsites.net", ErrPublicSuffix},
		{TargetTypeURL, "https://*.com.vn/", ErrPublicSuffix},
		// A tenant's own name at a provider stays allowed.
		{TargetTypeDomain, "myapp.azurewebsites.net", nil},
		{TargetTypeDomain, "*.myapp.herokuapp.com", nil},
		{TargetTypeDomain, "*.vndirect.com.vn", nil},
		{TargetTypeDomain, "vndirect.com.vn", nil},
		// Government and military, and the operator's own names.
		{TargetTypeDomain, "*.gov.vn", ErrDenyList},
		{TargetTypeDomain, "portal.gov.vn", ErrDenyList},
		{TargetTypeDomain, "*.army.mil", ErrDenyList},
		{TargetTypeDomain, "whitehouse.gov", ErrDenyList},
		{TargetTypeDomain, "*.service.gov.uk", ErrDenyList},
		{TargetTypeDomain, "*.go.jp", ErrDenyList},
		{TargetTypeDomain, "*.canada.gc.ca", ErrDenyList},
		{TargetTypeDomain, "api.platform.example", ErrDenyList},
		{TargetTypeURL, "https://portal.gov.vn/login", ErrDenyList},
		// Addresses: the whole space, metadata, link-local, the operator's range.
		{TargetTypeCIDR, "0.0.0.0/0", ErrDenyList},
		{TargetTypeCIDR, "::/0", ErrDenyList},
		{TargetTypeIPAddress, "169.254.169.254", ErrDenyList},
		{TargetTypeIPAddress, "fe80::1", ErrDenyList},
		{TargetTypeIPRange, "203.0.113.10-203.0.113.20", ErrDenyList},
		{TargetTypeURL, "http://169.254.169.254/latest/meta-data", ErrDenyList},
		// CIDR caps on public space; private space is gated by zones.
		{TargetTypeCIDR, "198.51.0.0/16", nil},
		{TargetTypeCIDR, "8.0.0.0/15", ErrCIDRTooLarge},
		{TargetTypeIPRange, "8.0.0.0-8.1.255.255", ErrCIDRTooLarge},
		{TargetTypeCIDR, "2001:db8::/32", nil},
		{TargetTypeCIDR, "2001:db8::/31", ErrCIDRTooLarge},
		{TargetTypeCIDR, "10.0.0.0/8", nil},
		{TargetTypeIPAddress, "8.8.8.8", nil},
		// Other types are not checked here.
		{TargetTypeRepository, "github.com/org/*", nil},
	}
	for _, c := range cases {
		err := g.CheckPattern(c.typ, c.pattern)
		if (c.want == nil) != (err == nil) || (c.want != nil && !errors.Is(err, c.want)) {
			t.Errorf("CheckPattern(%s, %q) = %v, want %v", c.typ, c.pattern, err, c.want)
		}
	}
}

func TestGuardrails_Denies(t *testing.T) {
	g, _ := NewGuardrails(0, 0, []string{"203.0.113.0/24", "platform.example"})
	for _, target := range []string{
		"portal.gov.vn", "https://portal.gov.vn/x", "portal.gov.vn:443", "x.army.mil",
		"169.254.169.254", "http://169.254.169.254/latest", "[fe80::1]:80", "203.0.113.5", "203.0.113.0/28",
		"api.platform.example", "0.0.0.0/0",
	} {
		if !g.Denies(target) {
			t.Errorf("Denies(%q) = false", target)
		}
	}
	for _, target := range []string{
		"vndirect.com.vn", "https://app.vndirect.com.vn/", "8.8.8.8", "198.51.100.0/24", "gov.example.com", "govern.vn",
		"10.0.0.5", "example.com:8443",
	} {
		if g.Denies(target) {
			t.Errorf("Denies(%q) = true", target)
		}
	}
}

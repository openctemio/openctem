package stage

import "testing"

func TestRegistrableDomain(t *testing.T) {
	for in, want := range map[string]string{
		"example.com":           "example.com",
		"WWW.Example.COM.":      "example.com",
		"a.b.example.com":       "example.com",
		"www.example.co.uk":     "example.co.uk",
		"example.com.vn":        "example.com.vn",
		"portal.example.com.vn": "example.com.vn",
		"x.y.github.io":         "github.io",
	} {
		if got, ok := RegistrableDomain(in); !ok || got != want {
			t.Errorf("%s = %q %v, want %q", in, got, ok, want)
		}
	}
	for _, bad := range []string{"", "com", "co.uk", "com.vn", "localhost", "192.0.2.1", "2001:db8::1", "a..com", "*.example.com", "https://example.com", "example.com:443"} {
		if got, ok := RegistrableDomain(bad); ok {
			t.Errorf("%q = %q, want no registrable domain", bad, got)
		}
	}
}

func TestRegistryLevel(t *testing.T) {
	if !RegistryLevel(LookupRDAP) || RegistryLevel(LookupASN) || RegistryLevel(ResolveDNS) {
		t.Fatal("only the registration lookup answers for the registered domain")
	}
}

package asset

import "testing"

func TestNormalizeName_DiscoveredDNSNames(t *testing.T) {
	for in, want := range map[string]string{
		"%2Fwww.example.com":          "www.example.com",
		"%252Fwww.example.com":        "www.example.com",
		"%2fWWW.Example.COM.":         "www.example.com",
		"/www.example.com":            "www.example.com",
		"\"www.example.com\",":        "www.example.com",
		"'api.example.com'":           "api.example.com",
		"*.example.com":               "*.example.com",
		"_dmarc.example.com":          "_dmarc.example.com",
		"https://www.example.com/a?b": "www.example.com",
		"www.example.com%":            "www.example.com",
		"bücher.example":              "bücher.example",
		"2fwww.example.com":           "2fwww.example.com", // a remnant is a caller's decision (EncodedRemnant)
	} {
		for _, typ := range []AssetType{AssetTypeDomain, AssetTypeSubdomain} {
			got := NormalizeName(in, typ, "")
			if got != want {
				t.Errorf("NormalizeName(%q, %s) = %q, want %q", in, typ, got, want)
			}
			if again := NormalizeName(got, typ, ""); again != got {
				t.Errorf("not idempotent: %q -> %q -> %q", in, got, again)
			}
		}
	}
}

func TestValidHostname(t *testing.T) {
	for name, want := range map[string]bool{
		"www.example.com":       true,
		"*.example.com":         true,
		"_dmarc.example.com":    true,
		"bücher.example":        true,
		"xn--bcher-kva.example": true,
		"3ds.example.com":       true,
		"example":               false,
		"":                      false,
		"*":                     false,
		"a.*.example.com":       false,
		"exa mple.example.com":  false,
		"bad-.example.com":      false,
		"-bad.example.com":      false,
		"a..example.com":        false,
		"a/b.example.com":       false,
		"www.example.com:443":   false,
		string(make([]byte, 64)) + ".example.com": false,
	} {
		if got := ValidHostname(name); got != want {
			t.Errorf("ValidHostname(%q) = %v, want %v", name, got, want)
		}
	}
	long := ""
	for range 5 {
		long += "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz0123456789a."
	}
	if ValidHostname(long + "com") {
		t.Error("a name over 253 characters is valid")
	}
}

func TestEncodedRemnant(t *testing.T) {
	for name, want := range map[string]string{
		"2fwww.example.com":  "www.example.com",
		"3aapi.example.com":  "api.example.com",
		"40mail.example.com": "mail.example.com",
		"3ds.example.com":    "s.example.com", // a candidate only: the caller checks the name is known
		"2f.example.com":     "",
		"www.example.com":    "",
		"2fexample":          "",
		"2f-x.example.com":   "",
	} {
		got, ok := EncodedRemnant(name)
		if got != want || ok != (want != "") {
			t.Errorf("EncodedRemnant(%q) = %q %v, want %q", name, got, ok, want)
		}
	}
}

func TestIsRegistrableDomain(t *testing.T) {
	for name, want := range map[string]bool{
		"example.com":     true,
		"Example.COM.":    true,
		"example.co.uk":   true,
		"www.example.com": false,
		"mb.balu88.com":   false,
		"com":             false,
		"*.example.com":   false,
		"":                false,
		"co.uk":           false,
	} {
		if got := IsRegistrableDomain(name); got != want {
			t.Errorf("IsRegistrableDomain(%q) = %v, want %v", name, got, want)
		}
	}
}

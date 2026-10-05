package easmseed

import (
	"errors"
	"strings"
	"testing"
)

func TestNormalizeRootDomain(t *testing.T) {
	ok := map[string]string{
		"Acme.COM.":       "acme.com",
		" eu.acme.co.uk ": "eu.acme.co.uk",
		"*.acme.io":       "acme.io",
		"bücher.de":       "xn--bcher-kva.de",
	}
	for in, want := range ok {
		got, err := Normalize(KindRootDomain, in)
		if err != nil || got != want {
			t.Errorf("%q = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, in := range []string{
		"", "com", "co.uk", // public suffixes: would claim everyone's names
		"azurewebsites.net", "shop.azurewebsites.net", "x.github.io", // provider shared domains
		"acme.local", "intranet", // no ICANN suffix
		"https://acme.com", "acme.com/path", "user@acme.com", "acme .com",
		strings.Repeat("a", 250) + ".com",
	} {
		if _, err := Normalize(KindRootDomain, in); !errors.Is(err, ErrInvalid) {
			t.Errorf("%q accepted", in)
		}
	}
	if _, err := Normalize("cidr", "203.0.113.0/24"); !errors.Is(err, ErrInvalid) {
		t.Error("a kind with no consumer yet was accepted")
	}
}

func TestCleanLabel(t *testing.T) {
	if s, err := CleanLabel("  Main brand "); err != nil || s != "Main brand" {
		t.Fatalf("%q %v", s, err)
	}
	for _, in := range []string{"a\nb", "x\x00", strings.Repeat("é", MaxLabelLength+1)} {
		if _, err := CleanLabel(in); err == nil {
			t.Errorf("%q accepted", in)
		}
	}
}

func TestCoversName(t *testing.T) {
	if !CoversName("acme.com", "api.acme.com") || !CoversName("acme.com", "ACME.com.") {
		t.Fatal("subdomain/self not covered")
	}
	if CoversName("acme.com", "notacme.com") || CoversName("acme.com", "acme.com.evil.net") {
		t.Fatal("a look-alike is covered")
	}
}

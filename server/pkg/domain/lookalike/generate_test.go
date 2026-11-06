package lookalike

import (
	"errors"
	"strings"
	"testing"
)

func TestRootDomain(t *testing.T) {
	for in, want := range map[string]string{"Example.COM.": "example.com", "example.co.uk": "example.co.uk", "bücher.de": "xn--bcher-kva.de"} {
		if got, err := RootDomain(in); err != nil || got != want {
			t.Errorf("RootDomain(%q) = %q, %v", in, got, err)
		}
	}
	for _, bad := range []string{"", "www.example.com", "co.uk", "com", "exa mple.com", "github.io"} {
		if _, err := RootDomain(bad); !errors.Is(err, ErrInvalid) {
			t.Errorf("RootDomain(%q) accepted", bad)
		}
	}
}

func TestGenerate(t *testing.T) {
	cands := Generate("example.com", nil, MaxCandidates)
	by := map[string]Technique{}
	for _, c := range cands {
		if c.Domain == "example.com" {
			t.Fatal("the root itself was generated")
		}
		if _, dup := by[c.Domain]; dup {
			t.Fatalf("duplicate %s", c.Domain)
		}
		if _, ok := validName(c.Domain); !ok {
			t.Fatalf("invalid name %s", c.Domain)
		}
		by[c.Domain] = c.Technique
	}
	for name, tech := range map[string]Technique{
		"exmple.com":   TechOmission,
		"exxample.com": TechRepetition,
		"examlpe.com":  TechTransposition,
		"exampke.com":  TechReplacement,
		"ex-ample.com": TechHyphenation,
		"exarnple.com": TechHomoglyph,
		"example.net":  TechTLD,
	} {
		if by[name] != tech {
			t.Errorf("%s: technique %q, want %q", name, by[name], tech)
		}
	}
	// A Cyrillic "а" homoglyph comes out as punycode.
	found := false
	for d, tech := range by {
		if tech == TechHomoglyph && strings.HasPrefix(d, "xn--") && Display(d) != d {
			found = true
		}
	}
	if !found {
		t.Error("no IDN homoglyph generated")
	}
}

func TestGenerateLimits(t *testing.T) {
	if got := Generate("example.com", []Technique{TechTLD}, 5); len(got) != 5 {
		t.Fatalf("cap: %d", len(got))
	}
	for _, c := range Generate("example.com", []Technique{TechBitflip}, 1000) {
		if c.Technique != TechBitflip {
			t.Fatalf("technique filter: %+v", c)
		}
	}
	if got := Generate("a.com", []Technique{TechOmission}, 10); len(got) != 0 {
		t.Fatalf("empty label generated: %+v", got)
	}
}

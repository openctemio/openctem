package vulnmatch

import (
	"strings"
	"testing"
)

func TestParseVersion_Refuses(t *testing.T) {
	for _, s := range []string{
		"", " ", "abc", "latest", "rr24", "r", "v", "-1.0", ".1", "1.0 (Ubuntu)", "1.0/2", "1;rm", "1:2.3",
		"1\x00", strings.Repeat("1", 65),
		strings.Repeat("1.", 17) + "1", // 18 segments
		"1." + strings.Repeat("9", 19), // overflow
		"１.0",                          // full-width digit
	} {
		if _, ok := ParseVersion(s); ok {
			t.Errorf("ParseVersion(%q) accepted", s)
		}
	}
}

func TestParseVersion_Accepts(t *testing.T) {
	for _, s := range []string{
		"1", "1.0", "v1.2.3", "V2.0", "8.2p1", "1.1.1w", "2.4.58-rc1", "10.0.17763",
		"1.0.0-beta.2", "3.0.0+build.5", "1_2_3", "2.0~rc1", "0001.002", "r24", "R30p1",
		strings.Repeat("1.", 15) + "1",
	} {
		if _, ok := ParseVersion(s); !ok {
			t.Errorf("ParseVersion(%q) refused", s)
		}
	}
}

func TestVersionCompare(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"1", "1", 0},
		{"1.0", "1.0.0", 0},
		{"1.0.0.0", "1", 0},
		{"v1.2.3", "1.2.3", 0},
		{"01.02", "1.2", 0},
		{"1.2", "1.10", -1},
		{"1.10", "1.9", 1},
		{"2.4.41", "2.4.62", -1},
		{"2.4.62", "2.4.41", 1},
		{"1.18.0", "1.20.1", -1},
		{"1.25.3", "1.20.1", 1},
		{"10.0", "9.99", 1},
		{"0.9", "1.0", -1},
		// pre-releases sort before the release
		{"1.0rc1", "1.0", -1},
		{"1.0-rc1", "1.0", -1},
		{"1.0.0-beta.2", "1.0.0", -1},
		{"1.0.0-alpha", "1.0.0-beta", -1},
		{"1.0.0-beta", "1.0.0-rc", -1},
		{"1.0.0-rc.1", "1.0.0-rc.2", -1},
		{"1.0.0-dev", "1.0.0-alpha", -1},
		{"1.0a1", "1.0", -1},
		{"2.0b3", "2.0", -1},
		{"1.0a1", "1.0b1", -1},
		{"1.0.1", "1.0rc1", 1},
		{"2.0~rc1", "2.0", -1},
		{"1.0-preview", "1.0", -1},
		// patch letters sort after the release
		{"8.2p1", "8.2", 1},
		{"8.2p1", "8.2p2", -1},
		{"8.2p1", "8.3", -1},
		{"8.9p1", "9.0", -1},
		{"9.3p2", "9.3p1", 1},
		{"1.1.1a", "1.1.1", 1},
		{"1.1.1w", "1.1.1v", 1},
		{"1.1.1w", "1.1.2", -1},
		{"1.0.2u", "1.1.0", -1},
		{"0.9.8zh", "0.9.8zg", 1},
		// trailing zero vs nothing
		{"2.0.0", "2", 0},
		{"2.0.1", "2", 1},
		// build metadata after a separator is just more segments
		{"3.0.0+build.5", "3.0.0", 1},
		// separators are equivalent
		{"1_2_3", "1.2.3", 0},
		{"1-2-3", "1.2.3", 0},
		// big numbers
		{"10.0.17763", "10.0.20348", -1},
		{"2023.1", "2022.12", 1},
		// release trains
		{"r24", "r25", -1},
		{"r30p1", "r30", 1},
	}
	for _, c := range cases {
		a, ok := ParseVersion(c.a)
		if !ok {
			t.Fatalf("parse %q", c.a)
		}
		b, ok := ParseVersion(c.b)
		if !ok {
			t.Fatalf("parse %q", c.b)
		}
		if got := a.Compare(b); got != c.want {
			t.Errorf("Compare(%q, %q) = %d, want %d", c.a, c.b, got, c.want)
		}
		if got := b.Compare(a); got != -c.want {
			t.Errorf("Compare(%q, %q) = %d, want %d (antisymmetry)", c.b, c.a, got, -c.want)
		}
	}
}

func TestVersionSegments(t *testing.T) {
	for s, want := range map[string]int{"2.4": 2, "2.4.41": 3, "8.2p1": 4, "1": 1} {
		v, _ := ParseVersion(s)
		if v.Segments() != want {
			t.Errorf("Segments(%q) = %d, want %d", s, v.Segments(), want)
		}
		if v.String() != s {
			t.Errorf("String(%q) = %q", s, v.String())
		}
	}
}

func TestVersionNormalized(t *testing.T) {
	for in, want := range map[string]string{
		"v1.18.0": "1.18", "1.18": "1.18", "1.0.0": "1", "0": "0", "0.0": "0",
		"8.2p1": "8.2.p.1", "1.0RC1": "1.0.~rc.1", "01.002": "1.2", "1_2_3": "1.2.3",
		"2.4.58-rc1": "2.4.58.~rc.1", "1.0.0-beta.2": "1.0.0.~beta.2", "1.1.1a": "1.1.1.a", "1.0a1": "1.0.~a.1",
	} {
		v, ok := ParseVersion(in)
		if !ok {
			t.Fatalf("parse %q", in)
		}
		if got := v.Normalized(); got != want {
			t.Errorf("Normalized(%q) = %q, want %q", in, got, want)
		}
	}
}

// Equal versions have the same canonical form and different ones do not.
func FuzzNormalizedMatchesCompare(f *testing.F) {
	for _, s := range []string{"1.0", "1", "1.0rc1", "8.2p1", "1.0.0.1", "2.a"} {
		f.Add(s, "1.0.0")
	}
	f.Fuzz(func(t *testing.T, a, b string) {
		va, oka := ParseVersion(a)
		vb, okb := ParseVersion(b)
		if !oka || !okb {
			return
		}
		if (va.Compare(vb) == 0) != (va.Normalized() == vb.Normalized()) {
			t.Fatalf("%q vs %q: compare=%d normalized %q %q", a, b, va.Compare(vb), va.Normalized(), vb.Normalized())
		}
	})
}

func FuzzParseVersion(f *testing.F) {
	for _, s := range []string{"1.2.3", "8.2p1", "1.0rc1", "v2", "1.1.1w", "", "x"} {
		f.Add(s, "1.0")
	}
	f.Fuzz(func(t *testing.T, a, b string) {
		va, oka := ParseVersion(a)
		vb, okb := ParseVersion(b)
		if !oka || !okb {
			return
		}
		if va.Compare(vb) != -vb.Compare(va) {
			t.Fatalf("not antisymmetric: %q %q", a, b)
		}
		if va.Compare(va) != 0 {
			t.Fatalf("not reflexive: %q", a)
		}
	})
}

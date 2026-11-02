package mcpoauth

import (
	"strings"
	"testing"
)

func TestNewUserCodeShapeAndAlphabet(t *testing.T) {
	seen := map[string]bool{}
	for range 200 {
		c, err := NewUserCode()
		if err != nil {
			t.Fatal(err)
		}
		if len(c) != 9 || c[4] != '-' {
			t.Fatalf("code %q is not XXXX-XXXX", c)
		}
		if NormalizeUserCode(c) != strings.ReplaceAll(c, "-", "") {
			t.Fatalf("code %q does not normalize to itself", c)
		}
		seen[c] = true
	}
	if len(seen) < 195 {
		t.Fatalf("only %d distinct codes out of 200", len(seen))
	}
}

func TestNormalizeUserCode(t *testing.T) {
	cases := map[string]string{
		"BCDF-GHJK":             "BCDFGHJK",
		"bcdf ghjk":             "BCDFGHJK",
		" bcdfghjk ":            "BCDFGHJK",
		"BCDF-GHJ":              "", // too short
		"BCDF-GHJKL":            "", // too long
		"ABCD-GHJK":             "", // vowel, not in the alphabet
		"BCDF-GH0K":             "", // digit
		"BCDF_GHJK":             "", // other separator
		"":                      "",
		"BCDF\nGHJK":            "",
		strings.Repeat("B", 40): "",
	}
	for in, want := range cases {
		if got := NormalizeUserCode(in); got != want {
			t.Errorf("NormalizeUserCode(%q) = %q, want %q", in, got, want)
		}
	}
}

package sensorkey

import (
	"math/big"
	"regexp"
	"strings"
	"testing"
)

// The patterns published for secret scanners (.betterleaks.toml and
// docs/architecture/agent-identity.md). Every issued token must match them.
var (
	scannerSensorKey  = regexp.MustCompile(`\bocts_[0-9A-Za-z]{49}\b`)
	scannerEnrollment = regexp.MustCompile(`\bocte_[0-9A-Za-z]{49}\b`)
)

func TestNew_Format(t *testing.T) {
	for _, tc := range []struct {
		prefix string
		re     *regexp.Regexp
	}{
		{PrefixSensorKey, scannerSensorKey},
		{PrefixEnrollmentToken, scannerEnrollment},
	} {
		seen := map[string]bool{}
		for range 200 {
			tok, err := New(tc.prefix)
			if err != nil {
				t.Fatalf("New(%q): %v", tc.prefix, err)
			}
			if len(tok) != len(tc.prefix)+RandomLen+ChecksumLen {
				t.Fatalf("%q: length %d, want %d", tok, len(tok), len(tc.prefix)+RandomLen+ChecksumLen)
			}
			if !tc.re.MatchString(tok) {
				t.Fatalf("%q does not match the published scanner pattern", tok)
			}
			if p, ok := Valid(tok); !ok || p != tc.prefix {
				t.Fatalf("Valid(%q) = %q, %v", tok, p, ok)
			}
			if seen[tok] {
				t.Fatalf("duplicate token %q", tok)
			}
			seen[tok] = true
		}
	}
}

func TestNew_UnknownPrefix(t *testing.T) {
	for _, p := range []string{"", "oct_", "rda_", "octx_", "OCTS_"} {
		if _, err := New(p); err == nil {
			t.Errorf("New(%q) issued a token", p)
		}
	}
}

func TestValid_RejectsBadChecksum(t *testing.T) {
	tok, err := New(PrefixSensorKey)
	if err != nil {
		t.Fatal(err)
	}
	flip := func(s string, i int) string {
		b := []byte(s)
		if b[i] == 'a' {
			b[i] = 'b'
		} else {
			b[i] = 'a'
		}
		return string(b)
	}
	cases := map[string]string{
		"random char changed":   flip(tok, len(PrefixSensorKey)+3),
		"checksum char changed": flip(tok, len(tok)-1),
		"truncated":             tok[:len(tok)-1],
		"extended":              tok + "0",
		"non-base62 char":       tok[:len(tok)-2] + "_" + tok[len(tok)-1:],
		"wrong prefix":          "octx_" + tok[len(PrefixSensorKey):],
		"prefix only":           PrefixSensorKey,
		"empty":                 "",
	}
	for name, bad := range cases {
		if _, ok := Valid(bad); ok {
			t.Errorf("%s: Valid(%q) = true", name, bad)
		}
	}
}

// A checksum is bound to its own prefix's body only through the random part;
// moving a valid body to the other prefix still validates, so callers must
// check the returned prefix (AcceptableSensorKey does).
func TestAcceptableSensorKey(t *testing.T) {
	key, _ := New(PrefixSensorKey)
	enroll, _ := New(PrefixEnrollmentToken)
	cases := []struct {
		name string
		key  string
		want bool
	}{
		{"valid octs_", key, true},
		{"octs_ with a broken checksum", key[:len(key)-1] + string(otherChar(key[len(key)-1])), false},
		{"octs_ truncated", key[:20], false},
		{"enrollment token presented as a key", enroll, false},
		{"enrollment body under the sensor prefix is fine", PrefixSensorKey + enroll[len(PrefixEnrollmentToken):], true},
		{"legacy rda_ key goes on to the lookup", "rda_" + strings.Repeat("ab", 32), true},
		{"unknown format goes on to the lookup", "something-else", true},
	}
	for _, tc := range cases {
		if got := AcceptableSensorKey(tc.key); got != tc.want {
			t.Errorf("%s: AcceptableSensorKey = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// The HTTP layer sends every "oct_" bearer token to user / MCP API-key auth.
// No sensor credential may ever look like one.
func TestPrefixesAreNeverUserAPIKeys(t *testing.T) {
	for _, p := range []string{PrefixSensorKey, PrefixEnrollmentToken, PrefixLegacySensorKey} {
		if strings.HasPrefix(p, "oct_") {
			t.Errorf("prefix %q starts with oct_", p)
		}
	}
	for range 50 {
		tok, _ := New(PrefixSensorKey)
		if strings.HasPrefix(tok, "oct_") {
			t.Fatalf("issued sensor key %q starts with oct_", tok)
		}
	}
}

func TestIsLegacy(t *testing.T) {
	key, _ := New(PrefixSensorKey)
	for in, want := range map[string]bool{
		"rda_" + strings.Repeat("0f", 32): true,
		"rda_1a2b3c4d":                    true, // a stored display prefix
		key:                               false,
		DisplayPrefix(key):                false,
		"":                                false,
	} {
		if got := IsLegacy(in); got != want {
			t.Errorf("IsLegacy(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestDisplayPrefix(t *testing.T) {
	key, _ := New(PrefixSensorKey)
	got := DisplayPrefix(key)
	if len(got) != DisplayPrefixLen || !strings.HasPrefix(key, got) || !strings.HasPrefix(got, PrefixSensorKey) {
		t.Fatalf("DisplayPrefix(%q) = %q", key, got)
	}
	if DisplayPrefixLen > 12 {
		t.Fatalf("DisplayPrefixLen %d does not fit the VARCHAR(12) prefix columns", DisplayPrefixLen)
	}
	// The SDK logs at most 8 characters of a key; that hint must be a prefix
	// of what the UI shows, so an operator can match the two.
	if hint := key[:8]; !strings.HasPrefix(got, hint) {
		t.Errorf("log hint %q is not a prefix of the display prefix %q", hint, got)
	}
}

// Leading zero bytes must not shorten the encoding.
func TestEncodeBase62_FixedWidth(t *testing.T) {
	if got := checksum(""); len(got) != ChecksumLen {
		t.Errorf("checksum width %d", len(got))
	}
	zero := encodeBase62(newInt(0), RandomLen)
	if zero != strings.Repeat("0", RandomLen) {
		t.Errorf("zero encodes as %q", zero)
	}
	top := encodeBase62(maxRandom(), RandomLen)
	if len(top) != RandomLen || top[0] == '0' {
		t.Errorf("2^256-1 encodes as %q", top)
	}
}

func FuzzValid(f *testing.F) {
	k, _ := New(PrefixSensorKey)
	f.Add(k)
	f.Add("rda_00")
	f.Add("octs_")
	f.Fuzz(func(t *testing.T, s string) {
		p, ok := Valid(s)
		if ok && !strings.HasPrefix(s, p) {
			t.Fatalf("Valid(%q) returned prefix %q", s, p)
		}
		_ = AcceptableSensorKey(s)
	})
}

func newInt(v int64) *big.Int { return big.NewInt(v) }

func maxRandom() *big.Int {
	return new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 8*RandomBytes), big.NewInt(1))
}

func otherChar(c byte) byte {
	if c == 'a' {
		return 'b'
	}
	return 'a'
}

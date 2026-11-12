package totp

import (
	"encoding/base32"
	"strings"
	"testing"
	"time"
)

// RFC 6238 Appendix B test vectors for the SHA-1 key "12345678901234567890".
// The RFC lists 8-digit values; codeAt is checked with 8 digits against them,
// and the 6-digit public API against their last six digits.
var rfcVectors = []struct {
	unix int64
	code string
}{
	{59, "94287082"},
	{1111111109, "07081804"},
	{1111111111, "14050471"},
	{1234567890, "89005924"},
	{2000000000, "69279037"},
	{20000000000, "65353130"},
}

func rfcSecret() string {
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString([]byte("12345678901234567890"))
}

func TestCodeAtMatchesRFC6238(t *testing.T) {
	key := []byte("12345678901234567890")
	for _, v := range rfcVectors {
		if got := codeAt(key, Step(time.Unix(v.unix, 0)), 8); got != v.code {
			t.Errorf("t=%d: got %s, want %s", v.unix, got, v.code)
		}
	}
}

func TestCodeMatchesRFC6238SixDigits(t *testing.T) {
	for _, v := range rfcVectors {
		got, err := Code(rfcSecret(), time.Unix(v.unix, 0))
		if err != nil {
			t.Fatal(err)
		}
		if want := v.code[2:]; got != want {
			t.Errorf("t=%d: got %s, want %s", v.unix, got, want)
		}
	}
}

func TestVerifyAcceptsSkewAndReturnsStep(t *testing.T) {
	now := time.Unix(1234567890, 0)
	secret := rfcSecret()
	for _, delta := range []time.Duration{-Period, 0, Period} {
		code, _ := Code(secret, now.Add(delta))
		step, ok := Verify(secret, code, now)
		if !ok {
			t.Fatalf("delta %v: expected accept", delta)
		}
		if step != Step(now.Add(delta)) {
			t.Fatalf("delta %v: step %d, want %d", delta, step, Step(now.Add(delta)))
		}
	}
}

func TestVerifyRejects(t *testing.T) {
	now := time.Unix(1234567890, 0)
	secret := rfcSecret()
	old, _ := Code(secret, now.Add(-3*Period))
	cases := map[string]string{
		"outside window": old,
		"too short":      "12345",
		"not digits":     "abcdef",
		"empty":          "",
	}
	for name, code := range cases {
		if _, ok := Verify(secret, code, now); ok {
			t.Errorf("%s: expected reject", name)
		}
	}
	if _, ok := Verify("not base32!!", "123456", now); ok {
		t.Error("invalid secret: expected reject")
	}
}

func TestGenerateSecretIsUsable(t *testing.T) {
	s1, err := GenerateSecret()
	if err != nil {
		t.Fatal(err)
	}
	s2, _ := GenerateSecret()
	if s1 == s2 {
		t.Fatal("secrets must be random")
	}
	if len(s1) != 32 { // 20 bytes -> 32 base32 chars without padding
		t.Fatalf("secret length %d, want 32", len(s1))
	}
	code, err := Code(s1, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := Verify(s1, code, time.Now()); !ok {
		t.Fatal("a freshly generated secret must verify its own code")
	}
}

func TestURI(t *testing.T) {
	u := URI("ABC", "OpenCTEM", "ops@acme.io")
	for _, want := range []string{"otpauth://totp/OpenCTEM:ops@acme.io?", "secret=ABC", "issuer=OpenCTEM", "digits=6", "period=30"} {
		if !strings.Contains(u, want) {
			t.Errorf("uri %q missing %q", u, want)
		}
	}
}

package crypto

import (
	"errors"
	"strings"
	"testing"
)

const (
	testOldHex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	testNewHex = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"
)

func TestParseKey_Formats(t *testing.T) {
	for name, tc := range map[string]struct{ key, format string }{
		"hex auto":    {testOldHex, ""},
		"hex":         {testOldHex, "hex"},
		"raw auto":    {strings.Repeat("k", 32), ""},
		"base64 auto": {"MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=", ""},
	} {
		b, err := ParseKey(tc.key, tc.format)
		if err != nil || len(b) != 32 {
			t.Errorf("%s: len=%d err=%v", name, len(b), err)
		}
	}
	for _, bad := range []string{"", "short", strings.Repeat("z", 64)} {
		if _, err := ParseKey(bad, ""); !errors.Is(err, ErrInvalidKey) {
			t.Errorf("ParseKey(%q) err=%v, want ErrInvalidKey", bad, err)
		}
	}
}

func TestKeyRing_EncryptsWithCurrentDecryptsBoth(t *testing.T) {
	oldC, _ := NewCipherFromKey(testOldHex, "")
	newC, _ := NewCipherFromKey(testNewHex, "")
	ring := NewKeyRing(newC, oldC)

	underOld, _ := oldC.EncryptString("old-secret")
	if got, err := ring.DecryptString(underOld); err != nil || got != "old-secret" {
		t.Fatalf("ring must read values under the previous key: %q %v", got, err)
	}
	enc, _ := ring.EncryptString("fresh")
	if _, err := oldC.DecryptString(enc); err == nil {
		t.Fatal("ring must encrypt with the current key, not the previous one")
	}
	if got, err := newC.DecryptString(enc); err != nil || got != "fresh" {
		t.Fatalf("current key must read what the ring wrote: %q %v", got, err)
	}

	other, _ := NewCipherFromKey(strings.Repeat("ab", 32), "")
	underOther, _ := other.EncryptString("x")
	if _, err := ring.DecryptString(underOther); !errors.Is(err, ErrDecryptionFailed) {
		t.Fatalf("a value under neither key must fail with ErrDecryptionFailed, got %v", err)
	}
}

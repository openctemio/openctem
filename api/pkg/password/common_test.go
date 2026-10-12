package password

import (
	"errors"
	"strings"
	"testing"
)

func TestIsCommon(t *testing.T) {
	for _, p := range []string{"password123", "PASSWORD123", "qwertyuiop", "iloveyou12"} {
		if !IsCommon(p) {
			t.Errorf("%q must be on the breached list", p)
		}
	}
	for _, p := range []string{"Zr7!uq-Lake-Tunnel-41", "correct-horse-battery-staple-9", ""} {
		if IsCommon(p) {
			t.Errorf("%q must not be on the list", p)
		}
	}
}

// A breached password is refused whatever the composition rules, and the
// default minimum is 12.
func TestValidate_BreachedAndLength(t *testing.T) {
	h := New(WithPolicy(Policy{MinLength: 8}))
	if err := h.Validate("password123"); !errors.Is(err, ErrPasswordCommon) {
		t.Fatalf("expected ErrPasswordCommon, got %v", err)
	}
	if err := h.Validate("Zr7uqLakeTunnel"); err != nil {
		t.Fatalf("a strong password must pass, got %v", err)
	}
	def := New()
	if err := def.Validate("Ab1cdefghij"); !errors.Is(err, ErrPasswordTooShort) {
		t.Fatalf("11 characters is below the default minimum of 12, got %v", err)
	}
	if err := def.Validate("Ab1cdefghijk"); err != nil {
		t.Fatalf("12 characters passes, got %v", err)
	}
}

// bcrypt hashes at most 72 bytes: a longer password is a validation error,
// never a hashing failure. The minimum counts characters, not bytes.
func TestValidate_ByteLimitAndCharacterMinimum(t *testing.T) {
	h := New(WithPolicy(Policy{MinLength: 12}))
	at := strings.Repeat("Zr7uqLakeTun", 6) // 72 bytes
	if err := h.Validate(at); err != nil {
		t.Fatalf("72 bytes must pass, got %v", err)
	}
	if _, err := h.Hash(at); err != nil {
		t.Fatalf("a password that passes validation must hash, got %v", err)
	}
	if err := h.Validate(at + "x"); !errors.Is(err, ErrPasswordTooLong) {
		t.Fatalf("73 bytes must be ErrPasswordTooLong, got %v", err)
	}
	// 30 Vietnamese characters, 3 bytes each: 90 bytes.
	if err := h.Validate(strings.Repeat("ữ", 30)); !errors.Is(err, ErrPasswordTooLong) {
		t.Fatalf("90 bytes of accented letters must be ErrPasswordTooLong, got %v", err)
	}
	// 6 accented characters are 18 bytes but only 6 characters.
	if err := h.Validate("ữữữữữữ"); !errors.Is(err, ErrPasswordTooShort) {
		t.Fatalf("6 characters is below 12 whatever their byte length, got %v", err)
	}
}

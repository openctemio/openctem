package password

import (
	"errors"
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

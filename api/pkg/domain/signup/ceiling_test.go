package signup

import (
	"errors"
	"testing"
)

func TestParseCeiling(t *testing.T) {
	for in, want := range map[string]Ceiling{
		"": CeilingDisabled, "disabled": CeilingDisabled, " Domain ": CeilingDomain, "OPEN": CeilingOpen,
	} {
		got, err := ParseCeiling(in)
		if err != nil || got != want {
			t.Fatalf("ParseCeiling(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, bad := range []string{"self_service", "admin_only", "on", "true"} {
		if _, err := ParseCeiling(bad); !errors.Is(err, ErrInvalidCeiling) {
			t.Fatalf("ParseCeiling(%q) must fail, got %v", bad, err)
		}
	}
}

// The console can never open more than SIGNUP_MODE: the policy in force is
// the stored one clamped to the ceiling, and the zero/unknown ceiling is
// disabled.
func TestCeilingClampsPolicy(t *testing.T) {
	self := Policy{Mode: ModeSelfService, RequestAccess: true}
	admin := Policy{Mode: ModeAdminOnly, RequestAccess: true}
	cases := []struct {
		c       Ceiling
		permits bool
	}{
		{CeilingOpen, true},
		{CeilingDomain, false},
		{CeilingDisabled, false},
		{"", false},
		{"bogus", false},
	}
	for _, tc := range cases {
		if got := tc.c.Permits(self); got != tc.permits {
			t.Fatalf("%q.Permits(self_service) = %v, want %v", tc.c, got, tc.permits)
		}
		clamped := tc.c.Clamp(self)
		if clamped.AllowsSelfService() != tc.permits {
			t.Fatalf("%q.Clamp(self_service) = %+v", tc.c, clamped)
		}
		if !clamped.RequestAccess {
			t.Fatalf("%q: request access is allowed under every ceiling", tc.c)
		}
		if !tc.c.Permits(admin) || tc.c.Clamp(admin) != admin {
			t.Fatalf("%q: admin_only is always permitted unchanged", tc.c)
		}
	}
	if Ceiling("").String() != "disabled" || Ceiling("bogus").AllowsPublicSignup() {
		t.Fatal("the zero or unknown ceiling is disabled")
	}
	if !CeilingDomain.AllowsPublicSignup() || !CeilingOpen.AllowsPublicSignup() || CeilingDisabled.AllowsPublicSignup() {
		t.Fatal("AllowsPublicSignup")
	}
	if CeilingOpen.SeedPolicy().Mode != ModeSelfService || CeilingDomain.SeedPolicy().Mode != ModeAdminOnly || CeilingDisabled.SeedPolicy().Mode != ModeAdminOnly {
		t.Fatal("SeedPolicy")
	}
}

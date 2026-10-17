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
		if !tc.c.Permits(admin) || tc.c.Clamp(admin) != admin.Normalized() {
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

// Account sign-up is clamped to the ceiling separately from organization
// self-service: domain allows domain sign-up but never open sign-up or
// organizations.
func TestCeilingClampsAccounts(t *testing.T) {
	open := Policy{Mode: ModeAdminOnly, Accounts: AccountsOpen}
	domain := Policy{Mode: ModeAdminOnly, Accounts: AccountsDomain}
	cases := []struct {
		c               Ceiling
		permitsOpen     bool
		permitsDomain   bool
		openClampedTo   Accounts
		domainClampedTo Accounts
	}{
		{CeilingOpen, true, true, AccountsOpen, AccountsDomain},
		{CeilingDomain, false, true, AccountsDomain, AccountsDomain},
		{CeilingDisabled, false, false, AccountsClosed, AccountsClosed},
		{"", false, false, AccountsClosed, AccountsClosed},
	}
	for _, tc := range cases {
		if tc.c.Permits(open) != tc.permitsOpen || tc.c.Permits(domain) != tc.permitsDomain {
			t.Fatalf("%q: Permits open=%v domain=%v", tc.c, tc.c.Permits(open), tc.c.Permits(domain))
		}
		if got := tc.c.Clamp(open).Accounts; got != tc.openClampedTo {
			t.Fatalf("%q: Clamp(open) = %s, want %s", tc.c, got, tc.openClampedTo)
		}
		if got := tc.c.Clamp(domain).Accounts; got != tc.domainClampedTo {
			t.Fatalf("%q: Clamp(domain) = %s, want %s", tc.c, got, tc.domainClampedTo)
		}
	}
	// Organization self-service follows account sign-up down: under domain
	// a stored self_service with open accounts becomes admin_only + domain.
	got := CeilingDomain.Clamp(Policy{Mode: ModeSelfService, Accounts: AccountsOpen})
	if got.Mode != ModeAdminOnly || got.Accounts != AccountsDomain || got.AllowsSelfService() {
		t.Fatalf("domain clamp of self_service: %+v", got)
	}
	if CeilingDomain.SeedPolicy().Accounts != AccountsDomain || CeilingOpen.SeedPolicy().Accounts != AccountsOpen ||
		CeilingDisabled.SeedPolicy().Accounts != AccountsClosed {
		t.Fatal("SeedPolicy accounts")
	}
}

// A stored policy from before the accounts field keeps its meaning.
func TestDecodeLegacyPolicy(t *testing.T) {
	p, err := Decode([]byte(`{"mode":"self_service","request_access":false}`))
	if err != nil || p.Accounts != AccountsOpen || !p.AllowsSelfService() {
		t.Fatalf("legacy self_service: %+v %v", p, err)
	}
	p, err = Decode([]byte(`{"mode":"admin_only","request_access":true}`))
	if err != nil || p.Accounts != AccountsClosed || p.AllowsPublicSignup() || !p.RequestAccess {
		t.Fatalf("legacy admin_only: %+v %v", p, err)
	}
	if _, err := Decode([]byte(`{"mode":"self_service","accounts":"domain"}`)); err == nil {
		t.Fatal("self_service needs open accounts")
	}
	if _, err := Decode([]byte(`{"mode":"admin_only","accounts":"everyone"}`)); err == nil {
		t.Fatal("unknown accounts value must fail")
	}
}

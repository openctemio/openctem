package email

import (
	"errors"
	"testing"
)

func TestValidateTenantRelay(t *testing.T) {
	t.Cleanup(func() { SetManagedTenantRelay(false) })
	tests := []struct {
		name         string
		managed      bool
		port         int
		tls, starttl bool
		user, pass   string
		want         error
	}{
		{"self-managed keeps port 25 without auth or TLS", false, 25, false, false, "", "", nil},
		{"self-managed still refuses other ports", false, 6379, false, false, "", "", ErrTenantPortNotAllowed},
		{"managed refuses port 25", true, 25, true, true, "u", "p", ErrTenantRelayPort25},
		{"managed requires AUTH", true, 587, false, true, "", "", ErrTenantRelayNeedsAuth},
		{"managed requires the password too", true, 587, false, true, "u", "", ErrTenantRelayNeedsAuth},
		{"managed requires TLS or STARTTLS", true, 587, false, false, "u", "p", ErrTenantRelayNeedsTLS},
		{"managed accepts 587 with STARTTLS and AUTH", true, 587, false, true, "u", "p", nil},
		{"managed accepts 465 with TLS and AUTH", true, 465, true, false, "u", "p", nil},
		{"managed accepts 2525 with STARTTLS and AUTH", true, 2525, false, true, "u", "p", nil},
		{"managed still refuses other ports", true, 6379, true, true, "u", "p", ErrTenantPortNotAllowed},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			SetManagedTenantRelay(tc.managed)
			err := ValidateTenantRelay(tc.port, tc.tls, tc.starttl, tc.user, tc.pass)
			if !errors.Is(err, tc.want) || (tc.want == nil) != (err == nil) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
			if tc.managed && err != nil && tc.want != ErrTenantPortNotAllowed && !errors.Is(err, ErrTenantRelayPolicy) {
				t.Fatalf("a managed refusal must wrap ErrTenantRelayPolicy: %v", err)
			}
		})
	}
}

func TestParseRelayModeAndDefaults(t *testing.T) {
	if m, ok := ParseRelayMode(" ON "); !ok || m != RelayModeOn {
		t.Fatalf("got %q %v", m, ok)
	}
	if _, ok := ParseRelayMode("maybe"); ok {
		t.Fatal("an unknown mode was accepted")
	}
	if DefaultRelayMode(true) != RelayModeVerifiedSender || DefaultRelayMode(false) != RelayModeOn {
		t.Fatal("defaults: managed verified_sender, self-managed on")
	}
}

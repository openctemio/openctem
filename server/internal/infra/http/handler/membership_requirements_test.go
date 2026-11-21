package handler

import (
	"reflect"
	"testing"

	tenantdom "github.com/openctemio/openctem/server/pkg/domain/tenant"
)

// The memberships listing names what an organization asks of a member's
// sign-in, from its settings and the member's role.
func TestMembershipRequirements(t *testing.T) {
	newTenant := func(t *testing.T, mfa, mfaAdmins, sso bool) *tenantdom.Tenant {
		t.Helper()
		tn, err := tenantdom.NewTenant("Acme", "req-acme", "creator")
		if err != nil {
			t.Fatal(err)
		}
		st := tn.TypedSettings()
		st.Security.MFARequired = mfa
		st.Security.MFARequiredForAdmins = mfaAdmins
		st.Security.SSOEnforced = sso
		if err := tn.UpdateSettings(st); err != nil {
			t.Fatal(err)
		}
		return tn
	}
	cases := []struct {
		name             string
		mfa, admins, sso bool
		role             string
		want             []string
	}{
		{"nothing required", false, false, false, "member", []string{}},
		{"2FA for everyone", true, false, false, "member", []string{"two_factor"}},
		{"2FA for admins, a member", false, true, false, "member", []string{}},
		{"2FA for admins, an admin", false, true, false, "admin", []string{"two_factor"}},
		{"SSO enforced, a member", false, false, true, "member", []string{"identity_provider"}},
		{"SSO enforced, the owner keeps break-glass", false, false, true, "owner", []string{}},
		{"both", true, false, true, "member", []string{"two_factor", "identity_provider"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := membershipRequirements(newTenant(t, c.mfa, c.admins, c.sso), c.role)
			if !reflect.DeepEqual(got, c.want) {
				t.Fatalf("got %v, want %v", got, c.want)
			}
		})
	}
}

package tenant

import (
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

func TestTenantWithRole_BlockedReason(t *testing.T) {
	org := func(policy PersonalAccountsPolicy) *Tenant {
		tn := Reconstitute(shared.NewID(), "Host", "host", "", "", map[string]any{}, "c", time.Now(), time.Now())
		st := tn.TypedSettings()
		st.Security.PersonalAccounts = policy
		_ = tn.UpdateSettings(st)
		return tn
	}
	home := shared.NewID()
	for _, tc := range []struct {
		name string
		twr  TenantWithRole
		want string
	}{
		{"active internal", TenantWithRole{Tenant: org(PersonalAccountsBlocked), MemberStatus: MemberStatusActive, Kind: MemberKindInternal}, ""},
		{"suspended with reason", TenantWithRole{Tenant: org(""), MemberStatus: MemberStatusSuspended, SuspendedReason: SuspendedReasonExpired}, "expired"},
		{"suspended without reason", TenantWithRole{Tenant: org(""), MemberStatus: MemberStatusSuspended}, "suspended"},
		{"personal, blocked", TenantWithRole{Tenant: org(PersonalAccountsBlocked), MemberStatus: MemberStatusActive, Kind: MemberKindExternal, HomeDomain: "gmail.com"}, "personal_accounts_blocked"},
		{"personal, allowed with MFA", TenantWithRole{Tenant: org(PersonalAccountsAllowedWithMFA), MemberStatus: MemberStatusActive, Kind: MemberKindExternal, HomeDomain: "gmail.com"}, ""},
		{"managed external, blocked policy", TenantWithRole{Tenant: org(PersonalAccountsBlocked), MemberStatus: MemberStatusActive, Kind: MemberKindExternal, HomeDomain: "partner.example", HomeTenantID: &home}, ""},
	} {
		if got := tc.twr.BlockedReason(); got != tc.want {
			t.Errorf("%s: got %q, want %q", tc.name, got, tc.want)
		}
	}
}

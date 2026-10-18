package signup

import "testing"

func TestPolicyOpensBeyond(t *testing.T) {
	adminClosed := Policy{Mode: ModeAdminOnly, Accounts: AccountsClosed}
	cases := []struct {
		next, prev Policy
		want       bool
	}{
		{Policy{Mode: ModeSelfService, Accounts: AccountsOpen}, adminClosed, true},
		{Policy{Mode: ModeAdminOnly, Accounts: AccountsDomain}, adminClosed, true},
		{Policy{Mode: ModeAdminOnly, Accounts: AccountsOpen}, Policy{Mode: ModeAdminOnly, Accounts: AccountsDomain}, true},
		{adminClosed, Policy{Mode: ModeSelfService, Accounts: AccountsOpen}, false},
		{Policy{Mode: ModeSelfService, Accounts: AccountsOpen}, Policy{Mode: ModeSelfService, Accounts: AccountsOpen}, false},
		{Policy{Mode: ModeAdminOnly, Accounts: AccountsDomain, RequestAccess: true}, Policy{Mode: ModeAdminOnly, Accounts: AccountsDomain}, false},
	}
	for i, c := range cases {
		if got := c.next.OpensBeyond(c.prev); got != c.want {
			t.Errorf("case %d: OpensBeyond = %v, want %v", i, got, c.want)
		}
	}
}

package signup

import "testing"

// The one admission rule, path-independent: every sign-up path maps its
// situation to an Identity and calls Admit.
func TestAdmit(t *testing.T) {
	admin := Policy{Mode: ModeAdminOnly}
	self := Policy{Mode: ModeSelfService}
	domainP := Policy{Mode: ModeAdminOnly, Accounts: AccountsDomain}
	openAccounts := Policy{Mode: ModeAdminOnly, Accounts: AccountsOpen}
	cases := []struct {
		name   string
		policy Policy
		id     Identity
		want   Outcome
	}{
		// Creating an organization (create-first-team, POST /tenants).
		{"org, admin_only", admin, Identity{Intent: IntentOrganization}, OutcomeNotSetUp},
		{"org, admin_only, even invited", admin, Identity{Intent: IntentOrganization, InvitedPending: true}, OutcomeNotSetUp},
		{"org, admin_only, even JIT", admin, Identity{Intent: IntentOrganization, JITEligible: true}, OutcomeNotSetUp},
		{"org, self_service", self, Identity{Intent: IntentOrganization}, OutcomeSelfService},

		// Creating an account (register, first social / SSO sign-in).
		{"account, admin_only, stranger", admin, Identity{Intent: IntentAccount}, OutcomeNotSetUp},
		{"account, admin_only, invited", admin, Identity{Intent: IntentAccount, InvitedPending: true}, OutcomeAcceptInvitation},
		{"account, admin_only, SSO JIT", admin, Identity{Intent: IntentAccount, JITEligible: true}, OutcomeJITMember},
		{"account, self_service, stranger", self, Identity{Intent: IntentAccount}, OutcomeSelfService},
		{"account, self_service, invited", self, Identity{Intent: IntentAccount, InvitedPending: true}, OutcomeAcceptInvitation},
		{"account, self_service, SSO JIT", self, Identity{Intent: IntentAccount, JITEligible: true}, OutcomeJITMember},
		{"account, self_service, disposable email", self, Identity{Intent: IntentAccount, DisposableEmail: true}, OutcomeNotSetUp},
		{"account, self_service, disposable but invited", self, Identity{Intent: IntentAccount, DisposableEmail: true, InvitedPending: true}, OutcomeAcceptInvitation},

		// Domain sign-up (accounts=domain): only a joinable verified domain,
		// never an organization.
		{"account, domain, stranger", domainP, Identity{Intent: IntentAccount}, OutcomeNotSetUp},
		{"account, domain, joinable domain", domainP, Identity{Intent: IntentAccount, DomainJoinable: true}, OutcomeDomainAccount},
		{"account, domain, joinable but disposable", domainP, Identity{Intent: IntentAccount, DomainJoinable: true, DisposableEmail: true}, OutcomeNotSetUp},
		{"account, domain, invited", domainP, Identity{Intent: IntentAccount, InvitedPending: true}, OutcomeAcceptInvitation},
		{"org, domain", domainP, Identity{Intent: IntentOrganization, DomainJoinable: true}, OutcomeNotSetUp},
		{"account, closed, joinable domain", admin, Identity{Intent: IntentAccount, DomainJoinable: true}, OutcomeNotSetUp},
		{"account, open, joinable domain", self, Identity{Intent: IntentAccount, DomainJoinable: true}, OutcomeSelfService},
		{"account, open accounts, admin_only orgs", openAccounts, Identity{Intent: IntentAccount}, OutcomeSelfService},
		{"org, open accounts, admin_only orgs", openAccounts, Identity{Intent: IntentOrganization}, OutcomeNotSetUp},

		// A domain whose organization requires its SSO: no password or
		// social account, in any policy, even with an invitation; the SSO
		// path itself (JIT) still admits.
		{"account, open, SSO required", self, Identity{Intent: IntentAccount, SSORequired: true}, OutcomeSSORequired},
		{"account, domain, SSO required and joinable", domainP, Identity{Intent: IntentAccount, SSORequired: true, DomainJoinable: true}, OutcomeSSORequired},
		{"account, closed, SSO required and invited", admin, Identity{Intent: IntentAccount, SSORequired: true, InvitedPending: true}, OutcomeSSORequired},
		{"account, SSO required, JIT", admin, Identity{Intent: IntentAccount, SSORequired: true, JITEligible: true}, OutcomeJITMember},

		// Unknown intent or mode: refused (fail-closed).
		{"unknown intent", self, Identity{Intent: "delete-everything"}, OutcomeNotSetUp},
		{"unknown mode", Policy{Mode: "open"}, Identity{Intent: IntentAccount}, OutcomeNotSetUp},
		{"zero policy", Policy{}, Identity{Intent: IntentOrganization}, OutcomeNotSetUp},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := Admit(c.policy, c.id)
			if got != c.want {
				t.Fatalf("Admit = %s, want %s", got, c.want)
			}
			if got.Admitted() != (c.want != OutcomeNotSetUp && c.want != OutcomeSSORequired) {
				t.Fatal("Admitted must be false only for not_set_up and sso_required")
			}
		})
	}
}

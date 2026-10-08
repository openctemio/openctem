package signup

import "testing"

// The one admission rule, path-independent: every sign-up path maps its
// situation to an Identity and calls Admit.
func TestAdmit(t *testing.T) {
	admin := Policy{Mode: ModeAdminOnly}
	self := Policy{Mode: ModeSelfService}
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
			if got.Admitted() != (c.want != OutcomeNotSetUp) {
				t.Fatal("Admitted must be false only for not_set_up")
			}
		})
	}
}

package signup

// Intent is what a sign-up path is about to create.
type Intent string

const (
	// IntentAccount: a users row for someone who has none (local register,
	// the first social sign-in, the first SSO/SAML sign-in).
	IntentAccount Intent = "account"
	// IntentOrganization: a new organization (create-first-team,
	// POST /tenants).
	IntentOrganization Intent = "organization"
)

// Identity is what the path knows about the person, all of it already
// verified by the path (the invitation token or the IdP).
type Identity struct {
	Intent Intent
	// InvitedPending: a pending invitation is addressed to this exact email.
	InvitedPending bool
	// JITEligible: an organization's SSO admits this identity just-in-time
	// (auto-provision on, DNS-verified SSO domain, allowed domains).
	JITEligible bool
	// DisposableEmail: the email is on a disposable-address service
	// (pkg/emaildomain). Self-service sign-up refuses it; an invitation or an
	// organization's SSO is the organization choosing the person.
	DisposableEmail bool
}

// Outcome is the admission decision.
type Outcome string

const (
	// OutcomeAcceptInvitation: create the account to accept an invitation.
	OutcomeAcceptInvitation Outcome = "accept_invitation"
	// OutcomeJITMember: create the account and join the organization by SSO.
	OutcomeJITMember Outcome = "jit_member"
	// OutcomeSelfService: self-service sign-up; the person may create an
	// account and their own organization.
	OutcomeSelfService Outcome = "self_service"
	// OutcomeNotSetUp: refused. The caller writes nothing (no account, no
	// session, no organization) and answers the same "not set up" response
	// whatever the reason, so the answer does not enumerate.
	OutcomeNotSetUp Outcome = "not_set_up"
)

// Admitted reports whether the outcome lets the path go on.
func (o Outcome) Admitted() bool { return o != OutcomeNotSetUp }

// Admit is the one admission rule every sign-up path applies, so the paths
// cannot drift apart (docs/architecture/user-onboarding.md, "Admission"):
//
//	creating an organization          → self_service mode only
//	creating an account:
//	  an organization's SSO admits it  → jit_member     (either mode)
//	  a pending invitation for it      → accept_invitation (either mode)
//	  self_service mode, not a disposable email → self_service
//	otherwise                          → not_set_up (write nothing)
//
// An existing account signing in is never refused here: a mode change never
// locks anyone out.
func Admit(p Policy, id Identity) Outcome {
	switch id.Intent {
	case IntentOrganization:
		if p.AllowsSelfService() {
			return OutcomeSelfService
		}
		return OutcomeNotSetUp
	case IntentAccount:
		switch {
		case id.JITEligible:
			return OutcomeJITMember
		case id.InvitedPending:
			return OutcomeAcceptInvitation
		case p.AllowsSelfService() && !id.DisposableEmail:
			return OutcomeSelfService
		}
	}
	return OutcomeNotSetUp
}

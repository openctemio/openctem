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
	// IntentPersonalOrganization: the organization the platform creates on
	// its own for a person who signed up and has no other way in
	// ("Create a personal organization on sign-up").
	IntentPersonalOrganization Intent = "personal_organization"
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
	// DomainJoinable: the (verified) email is on a domain an organization
	// verified and opened to joining (join policy approval or auto).
	DomainJoinable bool
	// SSORequired: the email is on a domain whose organization requires its
	// SSO for every account on it. Password and social sign-up are refused
	// and the person is sent to the identity provider.
	SSORequired bool
	// WorkspacesBlocked: the person's email is on a domain whose organization
	// blocks new organizations for accounts on it.
	WorkspacesBlocked bool
	// DisposableEmail: the email is on a disposable-address service
	// (pkg/emaildomain). Self-service sign-up refuses it; an invitation or an
	// organization's SSO is the organization choosing the person.
	DisposableEmail bool
	// EmailVerified: the address is verified (by the link we sent, or by a
	// provider that vouches for it).
	EmailVerified bool
	// DomainClaimed: an organization verified the address's domain. The
	// person belongs with that organization (join, SSO or an invitation),
	// so no personal organization is made for them.
	DomainClaimed bool
}

// Outcome is the admission decision.
type Outcome string

const (
	// OutcomeAcceptInvitation: create the account to accept an invitation.
	OutcomeAcceptInvitation Outcome = "accept_invitation"
	// OutcomeJITMember: create the account and join the organization by SSO.
	OutcomeJITMember Outcome = "jit_member"
	// OutcomeSelfService: self-service sign-up; the person may create an
	// account (and, when the policy allows it, their own organization).
	OutcomeSelfService Outcome = "self_service"
	// OutcomeDomainAccount: create the account; it joins the organization
	// of its verified domain by that organization's join policy and never
	// creates an organization.
	OutcomeDomainAccount Outcome = "domain_account"
	// OutcomeSSORequired: refused here; the person must sign in through the
	// SSO of the organization that claims the domain. Nothing is written.
	OutcomeSSORequired Outcome = "sso_required"
	// OutcomeNotSetUp: refused. The caller writes nothing (no account, no
	// session, no organization) and answers the same "not set up" response
	// whatever the reason, so the answer does not enumerate.
	OutcomeNotSetUp Outcome = "not_set_up"
	// OutcomePersonalOrganization: create the person's own organization
	// now (IntentPersonalOrganization). Every other answer for that intent
	// is not_set_up: nothing is created and the person keeps the normal
	// "create or join an organization" step.
	OutcomePersonalOrganization Outcome = "personal_organization"
)

// Admitted reports whether the outcome lets the path go on.
func (o Outcome) Admitted() bool { return o != OutcomeNotSetUp && o != OutcomeSSORequired }

// Admit is the one admission rule every sign-up path applies, so the paths
// cannot drift apart (docs/architecture/user-onboarding.md, "Admission"):
//
//	creating an organization              → self-service policy, and the
//	                                         person's domain does not block it
//	creating an account:
//	  an organization's SSO admits it      → jit_member        (any policy)
//	  its domain requires the org's SSO    → sso_required      (write nothing)
//	  a pending invitation for it          → accept_invitation (any policy)
//	  accounts open, not disposable        → self_service
//	  accounts domain, joinable domain, not disposable → domain_account
//	otherwise                              → not_set_up (write nothing)
//	the personal organization at sign-up:
//	  switch on, self-service, verified email, no invitation, no SSO
//	  admission, no claimed domain, not blocked, not disposable
//	                                       → personal_organization
//	  anything else                        → not_set_up (create nothing)
//
// The policy passed in is the policy in force (clamped to the ceiling). An
// existing account signing in is never refused here: a policy change never
// locks anyone out.
func Admit(p Policy, id Identity) Outcome {
	switch id.Intent {
	case IntentOrganization:
		if p.AllowsSelfService() && !id.WorkspacesBlocked {
			return OutcomeSelfService
		}
		return OutcomeNotSetUp
	case IntentPersonalOrganization:
		if p.CreatesPersonalOrganization() && id.EmailVerified && !id.InvitedPending && !id.JITEligible &&
			!id.SSORequired && !id.DomainJoinable && !id.DomainClaimed && !id.WorkspacesBlocked && !id.DisposableEmail {
			return OutcomePersonalOrganization
		}
		return OutcomeNotSetUp
	case IntentAccount:
		switch {
		case id.JITEligible:
			return OutcomeJITMember
		case id.SSORequired:
			return OutcomeSSORequired
		case id.InvitedPending:
			return OutcomeAcceptInvitation
		case p.AccountSignup() == AccountsOpen && !id.DisposableEmail:
			return OutcomeSelfService
		case p.AccountSignup() == AccountsDomain && id.DomainJoinable && !id.DisposableEmail:
			return OutcomeDomainAccount
		}
	}
	return OutcomeNotSetUp
}

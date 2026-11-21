//go:build authscenarios

package authscenarios

import "slices"

// The scenario model: how a person signed in, what the organization
// requires, how they relate to it, and what must happen next. The full
// state space and the reasoning behind each expected outcome are in
// server/docs/development/auth-scenarios.md.

type methodKind int

const (
	kindPassword methodKind = iota
	kindSocial
	kindOrgOIDC
	kindOrgSAML
	kindOtherIdP
)

// method is how the person signed in.
type method struct {
	name     string
	kind     methodKind
	provider string // social provider
	factor   bool   // the account has an enabled authenticator (and, for a password session, passed it)
	// mfaEvidence: the organization's identity provider proved a second
	// factor in this sign-in (amr / authentication context).
	mfaEvidence bool
}

func (m method) federated() bool { return m.kind != kindPassword }

// hasPassword: the account can sign in with a password (social and IdP
// accounts are created without one; the other-IdP person has their own).
func (m method) hasPassword() bool { return m.kind == kindPassword || m.kind == kindOtherIdP }

var methods = []method{
	{name: "password", kind: kindPassword},
	{name: "password-totp", kind: kindPassword, factor: true},
	{name: "google", kind: kindSocial, provider: "google"},
	{name: "google-totp", kind: kindSocial, provider: "google", factor: true},
	{name: "microsoft", kind: kindSocial, provider: "microsoft"},
	{name: "github", kind: kindSocial, provider: "github"},
	{name: "org-oidc", kind: kindOrgOIDC},
	{name: "org-oidc-mfa", kind: kindOrgOIDC, mfaEvidence: true},
	{name: "org-saml", kind: kindOrgSAML},
	{name: "other-org-idp", kind: kindOtherIdP},
}

// rule is what the organization requires.
type rule struct {
	name  string
	set   rules
	admin bool // the person's role is administrator (rules aimed at admins)
}

var orgRules = []rule{
	{name: "open"},
	{name: "2fa-required", set: rules{MFARequired: true}},
	{name: "2fa-admins", set: rules{MFARequiredForAdmins: true}, admin: true},
	{name: "2fa-admins-member", set: rules{MFARequiredForAdmins: true}},
	{name: "idp-required", set: rules{SSOEnforced: true}},
	{name: "idp-mfa-proof", set: rules{MFARequired: true, SSORequireMFAEvidence: true}},
	{name: "ip-allowlist", set: rules{IPAllowList: []string{"203.0.113.0/24"}}},
	{name: "suspended", set: rules{Suspended: true}},
}

// membership is how the person relates to the organization when the
// scenario starts.
type membership string

const (
	// invited: first time; the invitation is pending and accepted with the
	// session the sign-in just opened.
	invited membership = "first-time-invited"
	// member: a returning member signing in again.
	member membership = "returning-member"
	// twoOrgs: a returning member of an open organization and of this one.
	twoOrgs membership = "member-of-two"
)

var memberships = []membership{invited, member, twoOrgs}

// remedy is the next step the person is offered when the organization
// refuses the session.
type remedy int

const (
	remedyNone remedy = iota
	// remedySecondFactor: our second step inside this session (verify an
	// authenticator, or set one up), then the organization opens.
	remedySecondFactor
	// remedyPassword: sign in again with the account's own password (and the
	// second step it then asks).
	remedyPassword
	// remedyOrgIdP: sign in through the organization's identity provider
	// (proving a second factor when the organization asks for that proof).
	remedyOrgIdP
	// remedyExternal: nothing the person can do here (an administrator or
	// the platform decides); the session must still land somewhere.
	remedyExternal
)

func (r remedy) String() string {
	return [...]string{"none", "second factor in this session", "sign in again with the password",
		"sign in through the organization's identity provider", "outside the product"}[r]
}

// expectation is the outcome the scenario must produce.
type expectation struct {
	admit  bool     // the first answer opens the organization
	codes  []string // refusal codes that name the reason (nil: any non-empty code)
	remedy remedy
	// final: the organization opens after the remedy.
	final bool
}

// expect is the specification: the outcome every (method, rule) pair must
// produce. The membership changes how the person gets there, never the
// outcome, except that a suspended organization takes no new member.
func expect(m method, r rule) expectation {
	mfa := []string{"MFA_ENROLLMENT_REQUIRED"}
	own := []string{"OWN_SIGN_IN_REQUIRED", "MFA_ENROLLMENT_REQUIRED"}
	sso := []string{"SSO_REQUIRED"}
	ownIdP := m.kind == kindOrgOIDC || m.kind == kindOrgSAML
	if m.kind == kindOtherIdP {
		// Another organization's provider never opens an organization that
		// did not choose it; the person signs in with their own account, and
		// the organization then applies its own rules to that sign-in.
		final := r.name != "idp-required" && r.name != "ip-allowlist" && r.name != "suspended"
		codes := own
		switch r.name {
		case "idp-required":
			codes = append(slices.Clone(own), "SSO_REQUIRED")
		case "suspended":
			// A suspended organization refuses the acceptance itself, before
			// the sign-in method is looked at (it takes no new member).
			codes = append(slices.Clone(own), "ORGANIZATION_SUSPENDED")
		}
		return expectation{codes: codes, remedy: remedyPassword, final: final}
	}
	switch r.name {
	case "open", "2fa-admins-member":
		return expectation{admit: true}
	case "2fa-required", "2fa-admins":
		switch {
		case ownIdP:
			return expectation{admit: true}
		case m.kind == kindPassword && m.factor:
			return expectation{admit: true}
		default:
			// A password session without a factor, or any social session: our
			// second step in this session, then the organization opens.
			return expectation{codes: mfa, remedy: remedySecondFactor, final: true}
		}
	case "idp-required":
		if ownIdP {
			return expectation{admit: true}
		}
		return expectation{codes: sso, remedy: remedyOrgIdP, final: true}
	case "idp-mfa-proof":
		switch {
		case ownIdP && m.mfaEvidence:
			return expectation{admit: true}
		case ownIdP:
			return expectation{codes: []string{"MFA_IDP_EVIDENCE_REQUIRED"}, remedy: remedyOrgIdP, final: true}
		case m.kind == kindPassword && m.factor:
			return expectation{admit: true}
		default:
			return expectation{codes: mfa, remedy: remedySecondFactor, final: true}
		}
	case "ip-allowlist":
		return expectation{remedy: remedyExternal}
	case "suspended":
		return expectation{codes: []string{"ORGANIZATION_SUSPENDED", "TENANT_ACCESS_DENIED", "FORBIDDEN"}, remedy: remedyExternal}
	}
	panic("unknown rule " + r.name)
}

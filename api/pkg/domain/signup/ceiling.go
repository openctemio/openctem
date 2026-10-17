package signup

import (
	"fmt"
	"strings"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Ceiling is the deployment's sign-up ceiling, SIGNUP_MODE in the server
// environment. No API can change it. The console sign-up policy is a runtime
// switch below it: the policy in force is the stored policy clamped to the
// ceiling, so a console session (stolen or not) can never open more than the
// server configuration allows (docs/architecture/user-onboarding.md,
// "Sign-up ceiling").
type Ceiling string

const (
	// CeilingDisabled: no public account creation of any kind. Accounts come
	// from the platform administrator, invitations and organization SSO;
	// organizations from the platform administrator. The default.
	CeilingDisabled Ceiling = "disabled"
	// CeilingDomain: public sign-up only for addresses on a domain an
	// organization verified; such a person joins that organization and never
	// creates one. Organizations from the platform administrator only.
	CeilingDomain Ceiling = "domain"
	// CeilingOpen: anyone may sign up and create an organization, subject to
	// the console policy and the limits.
	CeilingOpen Ceiling = "open"
)

// ErrInvalidCeiling is returned for an unknown SIGNUP_MODE value.
var ErrInvalidCeiling = fmt.Errorf("%w: SIGNUP_MODE must be disabled, domain or open", shared.ErrValidation)

// ParseCeiling parses SIGNUP_MODE. Empty is the default, disabled.
func ParseCeiling(s string) (Ceiling, error) {
	switch c := Ceiling(strings.ToLower(strings.TrimSpace(s))); c {
	case "":
		return CeilingDisabled, nil
	case CeilingDisabled, CeilingDomain, CeilingOpen:
		return c, nil
	default:
		return "", ErrInvalidCeiling
	}
}

// normalized maps the zero value and anything unknown to disabled
// (fail-closed).
func (c Ceiling) normalized() Ceiling {
	switch c {
	case CeilingDomain, CeilingOpen:
		return c
	default:
		return CeilingDisabled
	}
}

// String returns the SIGNUP_MODE value; the zero value is disabled.
func (c Ceiling) String() string { return string(c.normalized()) }

// AllowsPublicSignup reports whether the deployment allows any public account
// creation (domain or open). Such deployments need e-mail to verify every
// self-registered address.
func (c Ceiling) AllowsPublicSignup() bool { return c.normalized() != CeilingDisabled }

// MaxAccounts is the widest account sign-up the ceiling allows.
func (c Ceiling) MaxAccounts() Accounts {
	switch c.normalized() {
	case CeilingOpen:
		return AccountsOpen
	case CeilingDomain:
		return AccountsDomain
	default:
		return AccountsClosed
	}
}

// Permits reports whether the console may store p under this ceiling:
// account sign-up at or below the ceiling, organization self-service only
// under open. Asking for access (which creates nothing until an
// administrator approves) is allowed under every ceiling.
func (c Ceiling) Permits(p Policy) bool {
	if p.AccountSignup().rank() > c.MaxAccounts().rank() {
		return false
	}
	if p.Mode == ModeSelfService {
		return c.normalized() == CeilingOpen
	}
	return true
}

// Clamp returns the policy in force: p limited to what the ceiling allows.
// Lowering SIGNUP_MODE therefore closes sign-up at the next start without a
// console change. An unknown account value is closed.
func (c Ceiling) Clamp(p Policy) Policy {
	p = p.Normalized()
	if max := c.MaxAccounts(); p.Accounts.rank() > max.rank() {
		p.Accounts = max
	}
	if !p.AllowsSelfService() {
		p.Mode = ModeAdminOnly
	}
	return p
}

// SeedPolicy is the policy stored at the first start when none exists: the
// widest the ceiling allows.
func (c Ceiling) SeedPolicy() Policy {
	switch c.normalized() {
	case CeilingOpen:
		return Policy{Mode: ModeSelfService, Accounts: AccountsOpen}
	case CeilingDomain:
		return Policy{Mode: ModeAdminOnly, Accounts: AccountsDomain}
	default:
		return Default()
	}
}

// ErrLockedByDeployment is returned when the console asks for more than the
// ceiling allows.
var ErrLockedByDeployment = fmt.Errorf("%w: sign-up is limited by this deployment's server configuration (SIGNUP_MODE)", shared.ErrConflict)

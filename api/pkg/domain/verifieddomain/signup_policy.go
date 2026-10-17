package verifieddomain

import (
	"fmt"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Sign-up policy of a verified SSO domain (docs/rfcs/RFC-104).

// JoinPolicy says how a verified holder of an address on the domain may join
// the organization that claims it.
type JoinPolicy string

const (
	// JoinOff: only by invitation or SSO. The default.
	JoinOff JoinPolicy = "off"
	// JoinApproval: the person may ask to join; an administrator decides.
	JoinApproval JoinPolicy = "approval"
	// JoinAuto: the person joins at once.
	JoinAuto JoinPolicy = "auto"
)

// IsValid reports whether p is a known value.
func (p JoinPolicy) IsValid() bool { return p == JoinOff || p == JoinApproval || p == JoinAuto }

// SignupPolicy is what a domain claim does to accounts on the domain. Every
// field is off by default.
type SignupPolicy struct {
	Join JoinPolicy
	// JoinRole is "viewer" or "member": people never join as administrators
	// by domain.
	JoinRole           string
	Discoverable       bool
	SSORequired        bool
	BlockNewWorkspaces bool
	IncludeSubdomains  bool
}

// DefaultSignupPolicy is the policy of a new claim: nothing.
func DefaultSignupPolicy() SignupPolicy { return SignupPolicy{Join: JoinOff, JoinRole: "viewer"} }

// Validate checks the policy.
func (p SignupPolicy) Validate() error {
	if !p.Join.IsValid() {
		return fmt.Errorf("%w: join_policy must be off, approval or auto", shared.ErrValidation)
	}
	if p.JoinRole != "viewer" && p.JoinRole != "member" {
		return fmt.Errorf("%w: join_role must be viewer or member", shared.ErrValidation)
	}
	return nil
}

// Manages reports whether the policy takes over accounts on the domain
// (existing account holders are told once when it starts to).
func (p SignupPolicy) Manages() bool { return p.SSORequired || p.BlockNewWorkspaces }

// ErrPolicyNeedsSSOClaim is returned for a policy on a domain that is not a
// verified SSO claim of the organization.
var ErrPolicyNeedsSSOClaim = fmt.Errorf("%w: only a verified SSO domain has a sign-up policy", shared.ErrValidation)

// SignupPolicy returns the domain's sign-up policy.
func (d *VerifiedDomain) SignupPolicy() SignupPolicy {
	if d.signup.Join == "" {
		return DefaultSignupPolicy()
	}
	return d.signup
}

// CaptureNotifiedAt is when existing accounts on the domain were told the
// organization manages it; nil when not yet.
func (d *VerifiedDomain) CaptureNotifiedAt() *time.Time { return d.captureNotifiedAt }

// ChangeSignupPolicy sets the sign-up policy. Only a verified SSO claim has
// one; it reports whether existing account holders must now be told the
// organization manages the domain (first time sso_required or
// block_new_workspaces turns on).
func (d *VerifiedDomain) ChangeSignupPolicy(p SignupPolicy) (notifyCapture bool, err error) {
	if err := p.Validate(); err != nil {
		return false, err
	}
	if !d.AdmitsSSO() || d.claimConflict {
		return false, ErrPolicyNeedsSSOClaim
	}
	d.signup = p
	d.updatedAt = time.Now().UTC()
	return p.Manages() && d.captureNotifiedAt == nil, nil
}

// MarkCaptureNotified records that existing account holders were told.
func (d *VerifiedDomain) MarkCaptureNotified(t time.Time) {
	t = t.UTC()
	d.captureNotifiedAt = &t
}

// WithSignupPolicy restores the sign-up policy from persistence.
func (d *VerifiedDomain) WithSignupPolicy(p SignupPolicy, captureNotifiedAt *time.Time) *VerifiedDomain {
	d.signup = p
	d.captureNotifiedAt = captureNotifiedAt
	return d
}

// EmailPolicy is the sign-up policy that governs an email address: the
// organization holding the address's domain (or a parent domain claimed with
// subdomains) and that claim's policy.
type EmailPolicy struct {
	OrganizationID shared.ID
	DomainID       shared.ID
	Domain         string
	Policy         SignupPolicy
}

// Joinable reports whether a verified holder of the address may join the
// organization by domain (approval or auto).
func (e EmailPolicy) Joinable() bool {
	return e.Policy.Join == JoinApproval || e.Policy.Join == JoinAuto
}

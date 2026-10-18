// Package signup holds the platform sign-up policy: who may create an account
// and who may create an organization on this deployment. It is one platform setting, edited in the
// admin console (docs/architecture/user-onboarding.md, "Sign-up policy").
package signup

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Mode says who may create an organization.
type Mode string

const (
	// ModeAdminOnly: only a platform administrator creates organizations.
	// People sign in only to organizations that exist (membership,
	// invitation or SSO just-in-time).
	ModeAdminOnly Mode = "admin_only"
	// ModeSelfService: anyone may sign up and create their own organization.
	ModeSelfService Mode = "self_service"
)

// IsValid reports whether m is a known mode.
func (m Mode) IsValid() bool { return m == ModeAdminOnly || m == ModeSelfService }

// Accounts says who may create an account by public sign-up. Invitations,
// organization SSO and SCIM are not public sign-up: the organization chose
// those people, under every value.
type Accounts string

const (
	// AccountsClosed: no public sign-up.
	AccountsClosed Accounts = "closed"
	// AccountsDomain: public sign-up only for an address on a domain an
	// organization verified and opened to joining; the account joins that
	// organization and never creates one.
	AccountsDomain Accounts = "domain"
	// AccountsOpen: anyone may sign up (not a disposable address).
	AccountsOpen Accounts = "open"
)

// rank orders the values: closed < domain < open. Unknown is below closed.
func (a Accounts) rank() int {
	switch a {
	case AccountsClosed:
		return 1
	case AccountsDomain:
		return 2
	case AccountsOpen:
		return 3
	default:
		return 0
	}
}

// IsValid reports whether a is a known value.
func (a Accounts) IsValid() bool { return a.rank() > 0 }

// OpensBeyond reports whether p lets more people in than prev: self-service
// organizations where prev had none, or a wider account sign-up.
func (p Policy) OpensBeyond(prev Policy) bool {
	return (p.Mode == ModeSelfService && prev.Mode != ModeSelfService) || p.Accounts.rank() > prev.Accounts.rank()
}

// Source records where the stored policy came from.
type Source string

const (
	// SourceEnvironment: seeded from SIGNUP_MODE at first start.
	SourceEnvironment Source = "environment"
	// SourceConsole: set by a platform administrator in the console.
	SourceConsole Source = "console"
	// SourceDefault: nothing stored or the read failed; the fail-closed
	// default (admin_only) is in force.
	SourceDefault Source = "default"
)

// Policy is the sign-up policy: two decisions.
type Policy struct {
	// Mode says who may create an organization (admin_only or
	// self_service). self_service needs Accounts open.
	Mode Mode `json:"mode"`
	// Accounts says who may create an account by public sign-up. Empty (a
	// policy stored before this field) reads as open with self_service and
	// as closed otherwise: see AccountSignup.
	Accounts Accounts `json:"accounts,omitempty"`
	// RequestAccess lets people who cannot sign up ask the platform
	// administrators for an organization (admin_only mode).
	RequestAccess bool `json:"request_access"`
}

// PolicySource answers the policy in force. Implementations are fail-closed:
// when the policy cannot be read, they answer Default (admin_only).
type PolicySource interface {
	Current(ctx context.Context) Policy
}

// Static is a PolicySource with a fixed policy (tests, and a server built
// without the database-backed setting).
type Static Policy

// Current returns the fixed policy.
func (s Static) Current(context.Context) Policy { return Policy(s) }

// Default is the fail-closed policy: no public sign-up, admin_only, no
// request-access form.
func Default() Policy { return Policy{Mode: ModeAdminOnly, Accounts: AccountsClosed} }

// ErrInvalidPolicy is returned for an unknown mode.
var ErrInvalidPolicy = fmt.Errorf("%w: invalid sign-up policy", shared.ErrValidation)

// ErrSelfServiceNeedsOpenAccounts is returned for organization self-service
// without open account sign-up (nobody could reach it).
var ErrSelfServiceNeedsOpenAccounts = fmt.Errorf("%w: organization self-service needs open account sign-up", shared.ErrValidation)

// AccountSignup is who may create an account by public sign-up. An empty
// Accounts follows Mode: self_service meant anyone may sign up, admin_only
// meant nobody. An unknown value is closed.
func (p Policy) AccountSignup() Accounts {
	switch {
	case p.Accounts == "" && p.Mode == ModeSelfService:
		return AccountsOpen
	case p.Accounts.IsValid():
		return p.Accounts
	default:
		return AccountsClosed
	}
}

// Validate checks the policy.
func (p Policy) Validate() error {
	if !p.Mode.IsValid() || (p.Accounts != "" && !p.Accounts.IsValid()) {
		return ErrInvalidPolicy
	}
	if p.Mode == ModeSelfService && p.AccountSignup() != AccountsOpen {
		return ErrSelfServiceNeedsOpenAccounts
	}
	return nil
}

// Normalized returns p with Accounts spelled out.
func (p Policy) Normalized() Policy {
	p.Accounts = p.AccountSignup()
	return p
}

// AllowsSelfService reports whether people may create their own organization.
func (p Policy) AllowsSelfService() bool {
	return p.Mode == ModeSelfService && p.AccountSignup() == AccountsOpen
}

// AllowsPublicSignup reports whether some public account sign-up is open
// (domain or open): the web then offers "Sign up".
func (p Policy) AllowsPublicSignup() bool {
	a := p.AccountSignup()
	return a == AccountsDomain || a == AccountsOpen
}

// Encode serializes the policy for storage.
func (p Policy) Encode() ([]byte, error) { return json.Marshal(p) }

// Decode parses a stored policy; anything malformed is an error (the caller
// falls back to Default).
func Decode(raw []byte) (Policy, error) {
	var p Policy
	if err := json.Unmarshal(raw, &p); err != nil {
		return Policy{}, fmt.Errorf("decode sign-up policy: %w", err)
	}
	if err := p.Validate(); err != nil {
		return Policy{}, err
	}
	return p.Normalized(), nil
}

// State is the stored policy with its bookkeeping.
type State struct {
	Policy    Policy
	Version   int
	Source    Source
	UpdatedBy *shared.ID // administrator id; nil when seeded from the environment
	UpdatedAt time.Time
}

// SettingKey is the platform_settings key of the sign-up policy.
const SettingKey = "signup_policy"

// ErrVersionConflict is returned when the stored version moved on since the
// caller read it (optimistic concurrency: If-Match).
var ErrVersionConflict = fmt.Errorf("%w: the sign-up policy was changed by someone else; reload and try again", shared.ErrConflict)

// ErrNotFound is returned when no policy is stored yet.
var ErrNotFound = fmt.Errorf("%w: sign-up policy not stored", shared.ErrNotFound)

// Repository persists the policy (one row of platform_settings).
type Repository interface {
	// Get returns the stored state, or ErrNotFound.
	Get(ctx context.Context) (State, error)
	// CreateIfAbsent stores the first state; it reports false when a row
	// already exists (the stored value wins).
	CreateIfAbsent(ctx context.Context, s State) (bool, error)
	// Update stores p when the stored version is expectedVersion, bumping the
	// version; ErrVersionConflict otherwise.
	Update(ctx context.Context, p Policy, expectedVersion int, by shared.ID, at time.Time) (State, error)
}

// IsNotFound reports whether err is ErrNotFound.
func IsNotFound(err error) bool { return errors.Is(err, ErrNotFound) }

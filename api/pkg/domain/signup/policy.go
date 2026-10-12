// Package signup holds the platform sign-up policy: who may create an
// organization on this deployment. It is one platform setting, edited in the
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

// Source records where the stored policy came from.
type Source string

const (
	// SourceEnvironment: seeded from TENANT_CREATION_MODE at first start.
	SourceEnvironment Source = "environment"
	// SourceConsole: set by a platform administrator in the console.
	SourceConsole Source = "console"
	// SourceDefault: nothing stored or the read failed; the fail-closed
	// default (admin_only) is in force.
	SourceDefault Source = "default"
)

// Policy is the sign-up policy.
type Policy struct {
	Mode Mode `json:"mode"`
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

// Default is the fail-closed policy: admin_only, no request-access form.
func Default() Policy { return Policy{Mode: ModeAdminOnly} }

// ErrInvalidPolicy is returned for an unknown mode.
var ErrInvalidPolicy = fmt.Errorf("%w: invalid sign-up policy", shared.ErrValidation)

// Validate checks the policy.
func (p Policy) Validate() error {
	if !p.Mode.IsValid() {
		return ErrInvalidPolicy
	}
	return nil
}

// AllowsSelfService reports whether people may create their own organization.
func (p Policy) AllowsSelfService() bool { return p.Mode == ModeSelfService }

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
	return p, nil
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

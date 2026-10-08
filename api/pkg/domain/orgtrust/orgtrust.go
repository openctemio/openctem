// Package orgtrust holds trusts between organizations (RFC-058): a host
// organization trusts a named home organization, and the home organization
// accepts. External members from that home may then satisfy the host's SSO
// and 2FA policy with a session from their home identity provider, within a
// role ceiling the host sets.
package orgtrust

import (
	"context"
	"fmt"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Status of a trust.
type Status string

const (
	// StatusRequested: the host asked; the home has not accepted yet. A
	// requested trust grants nothing.
	StatusRequested Status = "requested"
	// StatusActive: the home accepted.
	StatusActive Status = "active"
)

// MaxRole is the highest role an external member from the home may hold in
// the host. Administrators and owners are never external.
type MaxRole string

const (
	MaxRoleViewer MaxRole = "viewer"
	MaxRoleMember MaxRole = "member"
)

// IsValid reports whether r is a known ceiling.
func (r MaxRole) IsValid() bool { return r == MaxRoleViewer || r == MaxRoleMember }

var (
	// ErrNotFound: no such trust visible to the caller.
	ErrNotFound = fmt.Errorf("%w: trust not found", shared.ErrNotFound)
	// ErrExists: the host already trusts (or asked to trust) that home.
	ErrExists = fmt.Errorf("%w: this organization is already trusted or asked", shared.ErrConflict)
	// ErrSelf: an organization cannot trust itself.
	ErrSelf = fmt.Errorf("%w: an organization cannot trust itself", shared.ErrValidation)
)

// Settings are what the host decides for members from the home.
type Settings struct {
	MaxRole            MaxRole
	AcceptHomeSSO      bool
	RequireMFAEvidence bool
	AllowAPIKeys       bool
	// DefaultExpiryDays proposes an end of access for new external members
	// from the home (nil: none).
	DefaultExpiryDays *int
}

// DefaultSettings are a new trust's settings.
func DefaultSettings() Settings {
	return Settings{MaxRole: MaxRoleMember, AcceptHomeSSO: true}
}

// Validate checks the settings.
func (s Settings) Validate() error {
	if !s.MaxRole.IsValid() {
		return fmt.Errorf("%w: max_role must be viewer or member", shared.ErrValidation)
	}
	if s.DefaultExpiryDays != nil && (*s.DefaultExpiryDays < 1 || *s.DefaultExpiryDays > 365) {
		return fmt.Errorf("%w: default_expiry_days must be between 1 and 365", shared.ErrValidation)
	}
	return nil
}

// Trust is host → home.
type Trust struct {
	ID             shared.ID
	HostTenantID   shared.ID
	HomeTenantID   shared.ID
	Status         Status
	Settings       Settings
	HomeAttestsMFA bool
	RequestedBy    *shared.ID
	AcceptedBy     *shared.ID
	CreatedAt      time.Time
	UpdatedAt      time.Time
	AcceptedAt     *time.Time
}

// New builds a requested trust.
func New(host, home shared.ID, settings Settings, requestedBy shared.ID) (*Trust, error) {
	if host == home {
		return nil, ErrSelf
	}
	if err := settings.Validate(); err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	by := requestedBy
	return &Trust{
		ID: shared.NewID(), HostTenantID: host, HomeTenantID: home, Status: StatusRequested,
		Settings: settings, RequestedBy: &by, CreatedAt: now, UpdatedAt: now,
	}, nil
}

// IsActive reports whether the home accepted.
func (t *Trust) IsActive() bool { return t != nil && t.Status == StatusActive }

// Accept records the home's acceptance; attestsMFA is the home owner's
// statement that its identity provider enforces MFA for everyone.
func (t *Trust) Accept(by shared.ID, attestsMFA bool, now time.Time) error {
	if t.Status != StatusRequested {
		return fmt.Errorf("%w: the trust is not waiting for acceptance", shared.ErrValidation)
	}
	t.Status = StatusActive
	t.AcceptedBy = &by
	t.AcceptedAt = &now
	t.HomeAttestsMFA = attestsMFA
	t.UpdatedAt = now
	return nil
}

// Repository stores trusts. Every read names the organization asking (host
// or home); a trust is visible only to its two organizations.
type Repository interface {
	Create(ctx context.Context, t *Trust) error
	Update(ctx context.Context, t *Trust) error
	// GetForTenant returns the trust when tenantID is its host or its home.
	GetForTenant(ctx context.Context, tenantID, id shared.ID) (*Trust, error)
	// GetPair returns host → home, or ErrNotFound.
	GetPair(ctx context.Context, host, home shared.ID) (*Trust, error)
	// ListForTenant returns the trusts tenantID is host or home of.
	ListForTenant(ctx context.Context, tenantID shared.ID) ([]*Trust, error)
	// Delete removes the trust when tenantID is its host or its home.
	Delete(ctx context.Context, tenantID, id shared.ID) error
}

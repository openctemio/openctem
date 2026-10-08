package orgtrust

import (
	"context"
	"errors"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/orgtrust"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	tenantdom "github.com/openctemio/openctem/api/pkg/domain/tenant"
)

// MembershipReader reads one membership.
type MembershipReader interface {
	GetMembership(ctx context.Context, userID, tenantID shared.ID) (*tenantdom.Membership, error)
}

// Policy answers per-member questions from the trusts (RFC-058): the role
// ceiling of an external member and whether they may create API keys.
type Policy struct {
	trusts  orgtrust.Repository
	members MembershipReader
}

// NewPolicy builds the policy.
func NewPolicy(trusts orgtrust.Repository, members MembershipReader) *Policy {
	return &Policy{trusts: trusts, members: members}
}

// activeTrust returns host → home when it is active, nil otherwise.
func (p *Policy) activeTrust(ctx context.Context, host, home shared.ID) (*orgtrust.Trust, error) {
	t, err := p.trusts.GetPair(ctx, host, home)
	if errors.Is(err, orgtrust.ErrNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if !t.IsActive() {
		return nil, nil
	}
	return t, nil
}

// MaxRoleFor returns the role ceiling for external members homed in home:
// the trust's, or member when there is no active trust.
func (p *Policy) MaxRoleFor(ctx context.Context, host, home shared.ID) (orgtrust.MaxRole, error) {
	t, err := p.activeTrust(ctx, host, home)
	if err != nil {
		return "", err
	}
	if t == nil {
		return orgtrust.MaxRoleMember, nil
	}
	return t.Settings.MaxRole, nil
}

// APIKeyAllowance implements apikey.ExternalKeyPolicy: an internal member is
// always allowed; an external member only when the trust with their home
// allows keys, and never past the end of their access.
func (p *Policy) APIKeyAllowance(ctx context.Context, tenantID, userID shared.ID) (bool, *time.Time, error) {
	m, err := p.members.GetMembership(ctx, userID, tenantID)
	if err != nil {
		return false, nil, err
	}
	if !m.IsExternal() {
		return true, nil, nil
	}
	if m.HomeTenantID() == nil {
		return false, nil, nil
	}
	t, err := p.activeTrust(ctx, tenantID, *m.HomeTenantID())
	if err != nil {
		return false, nil, err
	}
	if t == nil || !t.Settings.AllowAPIKeys {
		return false, nil, nil
	}
	return true, m.ExpiresAt(), nil
}

// DefaultExpiryFor returns the trust's proposed end of access for a new
// external member homed in home (nil when none).
func (p *Policy) DefaultExpiryFor(ctx context.Context, host, home shared.ID, now time.Time) (*time.Time, error) {
	t, err := p.activeTrust(ctx, host, home)
	if err != nil || t == nil || t.Settings.DefaultExpiryDays == nil {
		return nil, err
	}
	at := now.Add(time.Duration(*t.Settings.DefaultExpiryDays) * 24 * time.Hour).UTC()
	return &at, nil
}

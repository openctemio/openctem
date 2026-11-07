package entitlement

// Grants: things that are off unless granted (pkg/domain/limits/grants.go).
// Every gate on a grant calls Addon or RequireAddon here, never a provider
// directly. The Community build registers no provider, so every grant is
// none and there are no notices. Nothing that is not a grant ever depends on
// this: a Community feature, a limit or a security control cannot be
// switched off by it.

import (
	"context"

	"github.com/openctemio/openctem/api/pkg/domain/limits"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// AddonState is the state of one grant key for an organization.
type AddonState struct {
	limits.Grant
	// Unavailable: the provider could not answer; the grant is treated as
	// off.
	Unavailable bool
}

// SetGrantProvider sets the grant provider (nil: none, every grant off).
// Called once at start, before the service is used.
func (s *Service) SetGrantProvider(p limits.GrantProvider) { s.grants = p }

// Addon returns the state of grant key for the organization. Without a
// provider it is none. A provider error, or an answer for another key or
// with an unknown status, is none (fail-closed, for grants only).
func (s *Service) Addon(ctx context.Context, tenantID shared.ID, key limits.GrantKey) AddonState {
	none := AddonState{Grant: limits.Grant{Key: key, Status: limits.GrantNone}}
	if s.grants == nil || key == "" {
		return none
	}
	g, err := s.grants.Grant(ctx, tenantID, key)
	if err != nil {
		s.log.Warn("grant provider unavailable", "key", string(key), "error", err)
		none.Unavailable = true
		return none
	}
	if g.Key != key || !g.Better(limits.Grant{Status: limits.GrantNone}) {
		return none
	}
	return AddonState{Grant: g}
}

// RequireAddon returns nil when grant key is on (active, expiring or in
// grace) for the organization, and a *limits.ErrGrantRequired otherwise
// (code ADDON_NOT_LICENSED, or ADDON_LICENSE_EXPIRED once it has ended).
func (s *Service) RequireAddon(ctx context.Context, tenantID shared.ID, key limits.GrantKey) error {
	st := s.Addon(ctx, tenantID, key)
	if st.Status.Granting() {
		return nil
	}
	return &limits.ErrGrantRequired{Key: key, Expired: st.Status == limits.GrantExpired, Unavailable: st.Unavailable}
}

// Notices returns the installation notices for platform administrators
// (none without a provider). They are informational: a provider error is
// logged and yields none.
func (s *Service) Notices(ctx context.Context) []limits.Notice {
	if s.grants == nil {
		return nil
	}
	n, err := s.grants.Notices(ctx)
	if err != nil {
		s.log.Warn("grant provider notices unavailable", "error", err)
		return nil
	}
	return n
}

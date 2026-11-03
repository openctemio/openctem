package entitlement

// Grants: things that are off unless granted (pkg/domain/limits/grants.go),
// the other half of the entitlement answer next to limits and denies. A
// self-managed installation is granted keys by its signed license
// (internal/app/subscription); a hosted service by its control plane. Every
// gate on a granted extra calls Addon or RequireAddon here, never a license
// or a source directly. Nothing that is not a grant key ever depends on
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
	// Unavailable: no source could be read; the grant is treated as off.
	Unavailable bool
}

// SetGrantSources replaces the grant sources (none: every grant is off).
func (s *Service) SetGrantSources(src ...limits.GrantSource) { s.grants = src }

// Addon returns the state of grant key for the organization: the most
// granting answer of all sources. A source that fails contributes nothing;
// when every source fails the state is none and Unavailable (fail-closed,
// for granted extras only). An unregistered key is never granted.
func (s *Service) Addon(ctx context.Context, tenantID shared.ID, key limits.GrantKey) AddonState {
	best := AddonState{Grant: limits.Grant{Key: key, Status: limits.GrantNone}}
	if !limits.IsGrantKey(key) {
		return best
	}
	failed := 0
	for _, src := range s.grants {
		grants, err := src.Grants(ctx, tenantID)
		if err != nil {
			failed++
			s.log.Warn("grant source unavailable", "key", string(key), "error", err)
			continue
		}
		if g, ok := grants[key]; ok && g.Key == key && g.Better(best.Grant) {
			best.Grant = g
		}
	}
	best.Unavailable = failed > 0 && failed == len(s.grants)
	return best
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

package scope

// Exclusions on the paths that discover or dispatch outside a scan trigger:
// ingest, Certificate Transparency discovery, pipeline runs and the coverage
// dispatcher. Design: docs/rfcs/RFC-042-asset-inventory-v2.md (§3.3 F16 and
// §6.13).

import (
	"context"
	"fmt"

	"github.com/openctemio/openctem/api/pkg/domain/asset"
	scopedom "github.com/openctemio/openctem/api/pkg/domain/scope"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// ExclusionMatcher tests values against one tenant's exclusions in effect
// (approved, active, unexpired), loaded once. It uses the same matching as
// scan dispatch (ExcludedTargets): a URL or host:port is also tested by its
// host.
type ExclusionMatcher struct {
	s          *Service
	exclusions []*scopedom.Exclusion
}

// LoadExclusionMatcher loads the tenant's exclusions in effect. A failed
// lookup is returned; callers do not discover or dispatch without it
// (fail closed).
func (s *Service) LoadExclusionMatcher(ctx context.Context, tenantID shared.ID) (*ExclusionMatcher, error) {
	exclusions, err := s.effectiveExclusions(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("list active scope exclusions: %w", err)
	}
	return &ExclusionMatcher{s: s, exclusions: exclusions}, nil
}

// Empty reports whether the tenant has no exclusion in effect.
func (m *ExclusionMatcher) Empty() bool { return m == nil || len(m.exclusions) == 0 }

// Excluded reports whether any of the values matches an exclusion.
func (m *ExclusionMatcher) Excluded(values ...string) bool {
	if m.Empty() {
		return false
	}
	return m.s.isAssetExcluded(values, m.exclusions)
}

// ExcludedAsset reports whether an asset matches an exclusion by its name,
// by its repository URLs, or by an address it is known to have (its IP
// properties and the addresses it resolved to). A hostname whose address is
// in an excluded range is excluded too.
func (m *ExclusionMatcher) ExcludedAsset(a *asset.Asset) bool {
	if m.Empty() || a == nil {
		return false
	}
	values := m.s.getAssetValues(a)
	values = append(values, asset.IPAddresses(a.Properties())...)
	return m.Excluded(values...)
}

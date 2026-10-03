package certmonitor

// Scope exclusions apply to CT discovery: an excluded name is not queried
// and nothing is discovered from it. Design:
// docs/rfcs/RFC-042-asset-inventory-v2.md (§3.3 F16, §6.13 "Discovery").

import (
	"context"

	scopeapp "github.com/openctemio/openctem/api/internal/app/scope"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// ExclusionSource loads a tenant's scope exclusions in effect. Satisfied by
// *scope.Service.
type ExclusionSource interface {
	LoadExclusionMatcher(ctx context.Context, tenantID shared.ID) (*scopeapp.ExclusionMatcher, error)
}

// SetExclusions makes the sweep apply scope exclusions. When set, a failed
// exclusion lookup skips the tenant's sweep (fail closed).
func (s *Service) SetExclusions(src ExclusionSource) { s.exclusions = src }

// withoutExcludedRoots drops the watched domains that match an exclusion:
// they are not queried.
func withoutExcludedRoots(roots []rootDomain, m *scopeapp.ExclusionMatcher) (kept []rootDomain, dropped int) {
	if m.Empty() {
		return roots, 0
	}
	kept = roots[:0:0]
	for _, r := range roots {
		if m.Excluded(r.name) {
			dropped++
			continue
		}
		kept = append(kept, r)
	}
	return kept, dropped
}

// withoutExcluded removes every excluded host from one domain's discoveries,
// so no exposure (and no asset) is created for it.
func withoutExcluded(d discoveries, m *scopeapp.ExclusionMatcher) (discoveries, int) {
	if m.Empty() {
		return d, 0
	}
	dropped := 0
	subs := d.subdomains[:0:0]
	for _, h := range d.subdomains {
		if m.Excluded(h) {
			dropped++
			continue
		}
		subs = append(subs, h)
	}
	keepCerts := func(in []expiringCert) []expiringCert {
		out := in[:0:0]
		for _, c := range in {
			if !m.Excluded(c.Host) {
				out = append(out, c)
			}
		}
		return out
	}
	d.subdomains = subs
	d.expiring = keepCerts(d.expiring)
	d.expired = keepCerts(d.expired)
	return d, dropped
}

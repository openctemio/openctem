package scope

// Which exclusions left a run's targets out (docs/rfcs/RFC-054-scope-model.md
// §6.5): the run page and the scan preview list them next to the count.

import (
	"context"
	"fmt"

	scopedom "github.com/openctemio/openctem/api/pkg/domain/scope"
	"github.com/openctemio/openctem/api/pkg/domain/scope/ipset"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// maxRulesPerTarget bounds the exclusions named for one range target.
const maxRulesPerTarget = 5

// ExclusionsMatching names, for each target, the tenant's exclusions in
// effect that remove it or part of it: the first exclusion that matches the
// target (as a run matches it), or for a range target the address-kind
// exclusions that overlap it (up to five). Targets nothing matches are
// absent. Only the tenant's own exclusions are read.
func (s *Service) ExclusionsMatching(ctx context.Context, tenantID string, targets []string) (map[string][]scopedom.RuleRef, error) {
	id, err := shared.IDFromString(tenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}
	out := map[string][]scopedom.RuleRef{}
	if len(targets) == 0 {
		return out, nil
	}
	excl, err := s.effectiveExclusions(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("list scope exclusions: %w", err)
	}
	ref := func(x *scopedom.Exclusion) scopedom.RuleRef {
		return scopedom.RuleRef{Kind: scopedom.RuleExclusion, ID: x.ID().String(), Pattern: x.Pattern()}
	}
	for _, t := range targets {
		if r, ok := ipset.Parse(t); ok && r.Lo != r.Hi {
			set := ipset.Of(r)
			for _, x := range excl {
				if x == nil || len(out[t]) >= maxRulesPerTarget {
					continue
				}
				switch x.ExclusionType() {
				case scopedom.ExclusionTypeIPAddress, scopedom.ExclusionTypeIPRange, scopedom.ExclusionTypeCIDR:
					if xr, ok := ipset.Parse(x.Pattern()); ok && set.Overlaps(ipset.Of(xr)) {
						out[t] = append(out[t], ref(x))
					}
				}
			}
			if len(out[t]) > 0 {
				continue
			}
		}
	match:
		for _, f := range exclusionMatchForms(t) {
			for _, x := range excl {
				if x != nil && x.Matches(f) {
					out[t] = []scopedom.RuleRef{ref(x)}
					break match
				}
			}
		}
	}
	return out, nil
}

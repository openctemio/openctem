package scan

// Which exclusions left a run's targets out (docs/rfcs/RFC-054-scope-model.md
// §6.5): a run records the targets its exclusions removed, whole or cut
// (a range split around excluded addresses), with the matching rules, so
// the run page and the scan preview can show "N targets left out by
// exclusions" and why. Informational: a failed rule lookup leaves the rules
// out, never the run.

import (
	"context"

	scopedom "github.com/openctemio/openctem/api/pkg/domain/scope"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// RunContextKeyExcludedTargets is the run-context key of the excluded
// targets ([]ExcludedTarget).
const RunContextKeyExcludedTargets = "excluded_targets"

// MaxListedExcluded bounds the excluded targets a run records.
const MaxListedExcluded = 50

// ExcludedTarget is a target exclusions left out of a run: whole, or cut
// (a range whose excluded addresses were removed; RemovedAddresses counts
// them). Rules are the tenant's own exclusions that matched.
type ExcludedTarget struct {
	Target           string             `json:"target"`
	Rules            []scopedom.RuleRef `json:"rules,omitempty"`
	RemovedAddresses uint64             `json:"removed_addresses,omitempty"`
	Cut              bool               `json:"cut,omitempty"`
}

// ExclusionExplainer names the exclusions matching targets (*scope.Service).
type ExclusionExplainer interface {
	ExclusionsMatching(ctx context.Context, tenantID string, targets []string) (map[string][]scopedom.RuleRef, error)
}

// ExplainExcluded lists the targets d's exclusions removed (whole ones
// first, then cut ranges), at most MaxListedExcluded, with the matching
// rules of the tenant when the exclusion filter can name them.
func (s *Service) ExplainExcluded(ctx context.Context, tenantID shared.ID, d *DispatchTargets) []ExcludedTarget {
	if d == nil || (len(d.Excluded) == 0 && len(d.Split) == 0) {
		return nil
	}
	out := make([]ExcludedTarget, 0, min(len(d.Excluded)+len(d.Split), MaxListedExcluded))
	for _, t := range d.Excluded {
		if len(out) >= MaxListedExcluded {
			break
		}
		out = append(out, ExcludedTarget{Target: t})
	}
	for _, sp := range d.Split {
		if len(out) >= MaxListedExcluded {
			break
		}
		if sp.Removed == 0 {
			continue
		}
		out = append(out, ExcludedTarget{Target: sp.Target, Cut: true, RemovedAddresses: sp.Removed})
	}
	ex, ok := s.scopeExclusions.(ExclusionExplainer)
	if !ok || len(out) == 0 {
		return out
	}
	names := make([]string, 0, len(out))
	for _, e := range out {
		names = append(names, e.Target)
	}
	rules, err := ex.ExclusionsMatching(ctx, tenantID.String(), names)
	if err != nil {
		if s.logger != nil {
			s.logger.Warn("cannot name the exclusions that left targets out", "tenant_id", tenantID.String(), "error", logger.SanitizeError(err))
		}
		return out
	}
	for i := range out {
		out[i].Rules = rules[out[i].Target]
	}
	return out
}

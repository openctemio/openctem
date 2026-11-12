package scope

// A not_ours or retired exclusion closes the open findings of every asset it
// matches (effects.go). A member whose data scope is limited may say that
// only about assets they can see: a rule that also matches assets outside
// their scope is refused, with the count, so they ask someone who can see
// them (research/320 D9). Exclusions that only stop scanning (do_not_scan,
// or any temporary one) keep today's rule: narrowing scanning is allowed
// whatever the data scope.

import (
	"context"
	"fmt"
	"net/netip"
	"strings"

	scopedom "github.com/openctemio/openctem/api/pkg/domain/scope"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// ErrClosingReachOutsideScope: a closing exclusion would close findings on
// assets the caller cannot see.
var ErrClosingReachOutsideScope = shared.NewDomainError("EXCLUSION_REACHES_OUTSIDE_SCOPE",
	"This rule also matches assets you cannot see; ask someone with access to them, or mark only the assets you see",
	shared.ErrForbidden)

// ErrClosingRuleNeedsFullAccess: a member with limited data access asked for
// a closing rule that is not exact.
var ErrClosingRuleNeedsFullAccess = shared.NewDomainError("CLOSING_RULE_NEEDS_FULL_ACCESS",
	"With limited data access you can only close findings with a rule for one exact hostname or IP address (no wildcard, range or network); "+
		"a broader rule needs full data access, because it also reaches assets you cannot see later",
	shared.ErrForbidden)

// isExactClosingRule reports whether the rule names one hostname or one IP
// address: a domain or subdomain rule without a wildcard, or an ip_address
// rule that is a single address (not a network or a range).
func isExactClosingRule(t scopedom.ExclusionType, pattern string) bool {
	p := strings.TrimSpace(pattern)
	if p == "" || strings.ContainsAny(p, "*?/ ,") {
		return false
	}
	switch t {
	case scopedom.ExclusionTypeDomain, scopedom.ExclusionTypeSubdomain:
		return true
	case scopedom.ExclusionTypeIPAddress:
		_, err := netip.ParseAddr(p)
		return err == nil
	}
	return false
}

// checkClosingReach refuses a closing exclusion whose pattern matches assets
// outside the caller's data scope. Without a data scope resolver or a match
// counter it refuses (fail closed) unless the exclusion closes nothing.
func (s *Service) checkClosingReach(ctx context.Context, tenantID shared.ID, kind scopedom.ExclusionKind,
	exclusionType scopedom.ExclusionType, pattern string, permanent bool,
) error {
	if !kind.ClosesFindings() || !permanent {
		return nil
	}
	if s.dataScope == nil || s.exclusionMatches == nil {
		return fmt.Errorf("%w: closing exclusions need the data scope check", ErrClosingReachOutsideScope)
	}
	ds, err := s.dataScope.Resolve(ctx, tenantID)
	if err != nil {
		return fmt.Errorf("resolve data scope: %w", err)
	}
	if !ds.Restricted() {
		return nil
	}
	// A pass re-matches the rule every few minutes, so it reaches assets that
	// appear later, outside what the creator sees now. A limited member may
	// therefore only close with an exact rule; a broader one needs full access.
	if !isExactClosingRule(exclusionType, pattern) {
		return ErrClosingRuleNeedsFullAccess
	}
	item := []BulkExclusionItem{{ExclusionType: string(exclusionType), Pattern: pattern}}
	visible, err := s.exclusionMatches.ExclusionMatches(ctx, tenantID, ds, item)
	if err != nil {
		return err
	}
	all, err := s.exclusionMatches.ExclusionMatches(ctx, tenantID, nil, item)
	if err != nil {
		return err
	}
	if len(all) == 1 && len(visible) == 1 && all[0].Matched > visible[0].Matched {
		return ErrClosingReachOutsideScope
	}
	return nil
}

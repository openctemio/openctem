package scope

// Explanations for the dry run (RFC-054 §6.4): which of the caller's own
// rules refused a target. Tenant-scoped reads only.

import (
	"context"
	"fmt"
	"time"

	scopedom "github.com/openctemio/openctem/api/pkg/domain/scope"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/pagination"
)

// maxExplainTargets bounds the entries one explanation reads.
const maxExplainTargets = 1000

// Explainer answers the dry run's "why" for one tenant, reading its entries
// and exclusions once.
type Explainer struct {
	targets    []*scopedom.Target
	exclusions []*scopedom.Exclusion
	now        time.Time
	oneOffDays int
}

// NewExplainer loads the tenant's scope entries (every status) and
// exclusions in effect.
func (s *Service) NewExplainer(ctx context.Context, tenantID string) (*Explainer, error) {
	id, err := shared.IDFromString(tenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}
	page, err := s.targetRepo.List(ctx, scopedom.TargetFilter{TenantID: &tenantID}, pagination.New(1, maxExplainTargets))
	if err != nil {
		return nil, fmt.Errorf("list scope targets: %w", err)
	}
	excl, err := s.effectiveExclusions(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("list scope exclusions: %w", err)
	}
	e := &Explainer{targets: page.Data, exclusions: excl, now: time.Now(), oneOffDays: scopedom.DefaultOneOffDays}
	if p, err := s.loadPolicy(ctx, id); err == nil {
		e.oneOffDays = p.settings.DefaultDays()
	}
	return e, nil
}

// OneOffDays is the organization's default one-off duration.
func (e *Explainer) OneOffDays() int { return e.oneOffDays }

// Uncovered refines no_entry: a pending, deactivated or expired entry of the
// tenant that would cover the target (entry_pending, entry_inactive,
// entry_expired), else no_entry with no rule.
func (e *Explainer) Uncovered(target string) (string, *scopedom.RuleRef) {
	code := scopedom.RefusalNoEntry
	var rule *scopedom.RuleRef
	rank := map[string]int{scopedom.RefusalEntryPending: 3, scopedom.RefusalEntryExpired: 2, scopedom.RefusalEntryInactive: 1}
	for _, t := range e.targets {
		if t == nil || !matchesAny(t, target) {
			continue
		}
		c := ""
		switch {
		case t.Status() == scopedom.StatusPending:
			c = scopedom.RefusalEntryPending
		case t.Status() == scopedom.StatusExpired || (t.Status() == scopedom.StatusActive && t.ExpiredAt(e.now)):
			c = scopedom.RefusalEntryExpired
		case t.Status() == scopedom.StatusInactive:
			c = scopedom.RefusalEntryInactive
		default:
			continue
		}
		if rank[c] > rank[code] {
			code = c
			rule = &scopedom.RuleRef{Kind: scopedom.RuleScopeTarget, ID: t.ID().String(), Pattern: t.Pattern()}
		}
	}
	return code, rule
}

// Exclusion names the tenant's exclusion in effect that matches the target.
func (e *Explainer) Exclusion(target string) *scopedom.RuleRef {
	for _, f := range exclusionMatchForms(target) {
		for _, x := range e.exclusions {
			if x != nil && x.Matches(f) {
				return &scopedom.RuleRef{Kind: scopedom.RuleExclusion, ID: x.ID().String(), Pattern: x.Pattern()}
			}
		}
	}
	return nil
}

// Covering names an entry in effect that covers the target (nil: a seed or
// verified domain covers it, or nothing).
func (e *Explainer) Covering(target string) *scopedom.Target {
	for _, t := range e.targets {
		if t != nil && t.InEffect(e.now) && matchesAny(t, target) {
			return t
		}
	}
	return nil
}

func matchesAny(t *scopedom.Target, target string) bool {
	for _, f := range exclusionMatchForms(target) {
		if t.Matches(f) {
			return true
		}
	}
	return false
}

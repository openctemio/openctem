package finding

// Attribution gate on priority (RFC-036 §6.8, decision T5): a finding on an
// asset the platform has not established is the tenant's is capped at P2
// until a person confirms the asset. See vulnerability.ApplyAttributionCap.

import (
	"context"

	"github.com/openctemio/openctem/api/pkg/domain/attribution"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

// AttributionLookup returns, for the given assets of the tenant, the stored
// attribution states other than confirmed. Assets without a record (legacy,
// confirmed) are absent. Tenant-scoped.
type AttributionLookup interface {
	ActiveCheckBlocked(ctx context.Context, tenantID shared.ID, assetIDs []string) (map[string]attribution.State, error)
}

// SetAttributionLookup wires the attribution gate. Nil keeps it off (no cap).
func (s *PriorityClassificationService) SetAttributionLookup(l AttributionLookup) {
	s.attribution = l
}

// capsPriority reports whether an attribution state caps priority: the
// automatic states below confirmed and a rejection. dependency and
// monitor_only are a person's decision that the name is the tenant's, so they
// are not capped (a takeover of a dependency is the tenant's problem).
func capsPriority(st attribution.State) bool {
	switch st {
	case attribution.StateNeedsReview, attribution.StateCandidate, attribution.StateRejected:
		return true
	}
	return false
}

// unconfirmedAssets returns the assets whose attribution caps priority, with
// their state. One tenant-scoped query. A lookup error is logged and yields
// no cap (the previous behavior), never a failed classification.
func (s *PriorityClassificationService) unconfirmedAssets(ctx context.Context, tenantID shared.ID, assetIDs []shared.ID) map[shared.ID]string {
	if s.attribution == nil || len(assetIDs) == 0 {
		return nil
	}
	ids := make([]string, 0, len(assetIDs))
	for _, id := range assetIDs {
		if !id.IsZero() {
			ids = append(ids, id.String())
		}
	}
	if len(ids) == 0 {
		return nil
	}
	states, err := s.attribution.ActiveCheckBlocked(ctx, tenantID, ids)
	if err != nil {
		s.logger.Warn("priority: attribution lookup failed; no attribution cap applied", "error", err)
		return nil
	}
	out := make(map[shared.ID]string, len(states))
	for raw, st := range states {
		if !capsPriority(st) {
			continue
		}
		if id, err := shared.IDFromString(raw); err == nil {
			out[id] = string(st)
		}
	}
	return out
}

// ruleClassification is the result of a matched override rule, with the
// attribution cap applied: a rule may not page anyone for an asset that is
// not confirmed either.
func ruleClassification(rule *vulnerability.PriorityOverrideRule, pctx vulnerability.PriorityContext, withID bool) vulnerability.PriorityClassification {
	c := vulnerability.PriorityClassification{
		Class:  rule.PriorityClass(),
		Reason: "Rule: " + rule.Name(),
		Source: "rule",
	}
	if withID {
		id := rule.ID()
		c.RuleID = &id
	}
	return vulnerability.ApplyAttributionCap(c, pctx)
}

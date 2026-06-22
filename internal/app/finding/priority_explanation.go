package finding

import (
	"context"
	"fmt"

	"github.com/openctemio/api/pkg/domain/asset"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/domain/vulnerability"
)

// PriorityExplanation is a read-only, human-auditable breakdown of WHY a
// finding holds its priority class — the factors that fed the classifier and
// the decision it reached. It mirrors what ClassifyFinding would compute but
// persists nothing and emits no events.
type PriorityExplanation struct {
	FindingID string `json:"finding_id"`
	// Decision
	Class    string  `json:"priority_class"`
	Reason   string  `json:"reason"`
	Source   string  `json:"source"` // "auto" | "rule"
	RuleName *string `json:"rule_name,omitempty"`

	// Factors that fed the decision (so an operator can audit/tune).
	Factors PriorityFactors `json:"factors"`
}

// PriorityFactors are the inputs to the classifier, plus the two derived
// booleans the rules actually gate on (reachable, critical_asset), so the
// explanation is self-contained.
type PriorityFactors struct {
	Severity             string   `json:"severity"`
	CVEID                string   `json:"cve_id,omitempty"`
	EPSSScore            *float64 `json:"epss_score,omitempty"`
	EPSSPercentile       *float64 `json:"epss_percentile,omitempty"`
	IsInKEV              bool     `json:"is_in_kev"`
	IsReachable          bool     `json:"is_reachable"`
	IsInternetAccessible bool     `json:"is_internet_accessible"`
	IsNetworkAccessible  bool     `json:"is_network_accessible"`
	ReachableFromCount   int      `json:"reachable_from_count"`
	AssetCriticality     string   `json:"asset_criticality,omitempty"`
	AssetExposure        string   `json:"asset_exposure,omitempty"`
	AssetIsCrownJewel    bool     `json:"asset_is_crown_jewel"`
	IsProtected          bool     `json:"is_protected"`
	ControlReductionPct  float64  `json:"control_reduction_pct"`

	// Derived gates (computed exactly as ClassifyPriority does).
	Reachable     bool `json:"reachable"`
	CriticalAsset bool `json:"critical_asset"`
}

// ExplainFinding computes the priority explanation for a single finding without
// mutating it. It loads the finding and its asset, applies compensating-control
// reduction, evaluates tenant override rules, and reports the resulting class
// alongside every contributing factor.
func (s *PriorityClassificationService) ExplainFinding(ctx context.Context, tenantID, findingID shared.ID) (*PriorityExplanation, error) {
	f, err := s.findingRepo.GetByID(ctx, tenantID, findingID)
	if err != nil {
		return nil, fmt.Errorf("get finding: %w", err)
	}

	var a *asset.Asset
	if !f.AssetID().IsZero() {
		// Asset is best-effort: pentest findings may have no inventory asset.
		if loaded, aerr := s.assetRepo.GetByID(ctx, tenantID, f.AssetID()); aerr == nil {
			a = loaded
		}
	}

	pctx := s.buildPriorityContext(f, a)

	// Compensating-control reduction (same as the live classify path).
	if s.controlLookup != nil && !f.AssetID().IsZero() {
		if reductions, lerr := s.controlLookup.GetEffectiveForAssets(ctx, tenantID, []shared.ID{f.AssetID()}); lerr == nil {
			if r, ok := reductions[f.AssetID()]; ok && r > 0 {
				pctx.IsProtected = true
				pctx.ControlReductionFactor = r
			}
		}
	}

	// Evaluate override rules first, then fall back to the default classifier —
	// identical precedence to ClassifyFinding, but read-only.
	classification, ruleName := s.classifyWithRules(ctx, tenantID, pctx)

	exp := &PriorityExplanation{
		FindingID: findingID.String(),
		Class:     string(classification.Class),
		Reason:    classification.Reason,
		Source:    classification.Source,
		RuleName:  ruleName,
		Factors: PriorityFactors{
			Severity:             string(pctx.Severity),
			CVEID:                pctx.CVEID,
			EPSSScore:            pctx.EPSSScore,
			EPSSPercentile:       pctx.EPSSPercentile,
			IsInKEV:              pctx.IsInKEV,
			IsReachable:          pctx.IsReachable,
			IsInternetAccessible: pctx.IsInternetAccessible,
			IsNetworkAccessible:  pctx.IsNetworkAccessible,
			ReachableFromCount:   pctx.ReachableFromCount,
			AssetCriticality:     pctx.AssetCriticality,
			AssetExposure:        pctx.AssetExposure,
			AssetIsCrownJewel:    pctx.AssetIsCrownJewel,
			IsProtected:          pctx.IsProtected,
			ControlReductionPct:  pctx.ControlReductionFactor * 100,
			Reachable:            pctx.IsReachable || pctx.IsInternetAccessible,
			CriticalAsset:        pctx.AssetCriticality == "critical" || pctx.AssetCriticality == "high",
		},
	}
	return exp, nil
}

// classifyWithRules applies tenant override rules (first match wins) then the
// default classifier. Returns the classification and the matched rule name (if
// any). Read-only — no audit, no event.
func (s *PriorityClassificationService) classifyWithRules(
	ctx context.Context,
	tenantID shared.ID,
	pctx vulnerability.PriorityContext,
) (vulnerability.PriorityClassification, *string) {
	rules, err := s.ruleRepo.ListActiveByTenant(ctx, tenantID)
	if err != nil {
		s.logger.Warn("explain: failed to load override rules, using defaults", "error", err)
		rules = nil
	}
	for _, rule := range rules {
		if rule.Matches(pctx) {
			name := rule.Name()
			ruleID := rule.ID()
			return vulnerability.PriorityClassification{
				Class:  rule.PriorityClass(),
				Reason: fmt.Sprintf("Rule: %s", rule.Name()),
				Source: "rule",
				RuleID: &ruleID,
			}, &name
		}
	}
	return vulnerability.ClassifyPriority(pctx), nil
}

package asset

// Likelihood-impact risk model (docs/architecture/asset-risk-score.md).
//
//	risk = findings score × exposure factor × criticality factor × (1 − control reduction)
//
//   - findings score (0-100): the worst severity tier sets it. The first open
//     finding of a tier scores the tier's base; each further finding of the
//     same tier closes RiskTierRepeat of the gap to the tier's ceiling, so the
//     score rises with diminishing returns and a tier can never pass its
//     ceiling: 500 low findings stay below one high finding.
//     A finding with an exploitation signal (KEV, EPSS ≥ ExploitEPSSThreshold,
//     known exploit) counts one severity up; an exploitable critical counts
//     twice.
//   - exposure factor: the organization's exposure score of the asset's
//     exposure, as a percentage. "unknown" has its own value (90% by
//     default): an asset whose exposure nobody established is not assumed
//     to be safe.
//   - criticality factor: the organization's criticality score of the
//     asset's effective criticality (own, business units, services, control
//     plane), as a percentage. A crown jewel counts as critical; "not rated"
//     counts as medium.
//   - control reduction: the strongest active, effective compensating
//     control on the asset, capped at MaxControlReduction (a control lowers
//     the likelihood, it does not remove the weakness).
//
// No open finding means a risk of 0: exposure and criticality scale risk,
// they are not risk on their own.

import "math"

// ScoreCompositionLikelihoodImpact selects the likelihood-impact model.
const ScoreCompositionLikelihoodImpact = "likelihood_impact"

// ExploitEPSSThreshold is the EPSS probability from which a finding counts as
// likely exploited (the same threshold the dashboard's EPSS counts use).
const ExploitEPSSThreshold = 0.5

// MaxControlReduction caps the effect of compensating controls.
const MaxControlReduction = 0.75

// RiskTierRepeat is the share of the remaining gap to a tier's ceiling that
// each further finding of the tier closes.
const RiskTierRepeat = 0.35

// riskTier is one severity tier of the findings score.
type riskTier struct {
	severity string
	base     float64
	ceiling  float64
}

// riskTiers, worst first.
var riskTiers = []riskTier{
	{"critical", 70, 100},
	{"high", 50, 85},
	{"medium", 25, 55},
	{"low", 10, 25},
}

// RiskInputs are the inputs of a score that do not live on the asset row.
type RiskInputs struct {
	// EffectiveCriticality is the business-aligned criticality; empty = the
	// asset's own.
	EffectiveCriticality Criticality
	// ControlReduction is the strongest compensating-control reduction
	// (0-1) on the asset.
	ControlReduction float64
}

// RiskTierContribution explains one severity tier.
type RiskTierContribution struct {
	Severity    string `json:"severity"`
	Count       int    `json:"count"`       // open findings of this severity
	Exploitable int    `json:"exploitable"` // of which with an exploitation signal
	Effective   int    `json:"effective"`   // findings counted in this tier after the exploit lift
	Score       int    `json:"score"`       // the tier's score (0-100)
}

// RiskBreakdown explains a score.
type RiskBreakdown struct {
	Model                string                 `json:"model"`
	Score                int                    `json:"score"`
	FindingsScore        int                    `json:"findings_score"`
	Tiers                []RiskTierContribution `json:"tiers"`
	Exposure             string                 `json:"exposure"`
	ExposureFactor       int                    `json:"exposure_factor"` // percent
	Criticality          string                 `json:"criticality"`
	EffectiveCriticality string                 `json:"effective_criticality"`
	CrownJewel           bool                   `json:"crown_jewel"`
	CriticalityFactor    int                    `json:"criticality_factor"` // percent
	ControlReduction     int                    `json:"control_reduction"`  // percent, after the cap
}

// tierScore is the score of n findings in a tier.
func tierScore(t riskTier, n int) float64 {
	if n <= 0 {
		return 0
	}
	return t.ceiling - (t.ceiling-t.base)*math.Pow(1-RiskTierRepeat, float64(n-1))
}

// effectiveTierCounts applies the exploit lift: an exploitable finding moves
// one tier up, and an exploitable critical counts twice.
func effectiveTierCounts(c *FindingSeverityCounts) [4]int {
	if c == nil {
		return [4]int{}
	}
	clamp := func(x, max int) int {
		if x < 0 {
			return 0
		}
		if x > max {
			return max
		}
		return x
	}
	cx := clamp(c.CriticalExploitable, c.Critical)
	hx := clamp(c.HighExploitable, c.High)
	mx := clamp(c.MediumExploitable, c.Medium)
	lx := clamp(c.LowExploitable, c.Low)
	return [4]int{
		c.Critical + cx + hx,
		c.High - hx + mx,
		c.Medium - mx + lx,
		c.Low - lx,
	}
}

func (e *RiskScoringEngine) explainLikelihoodImpact(a *Asset, in RiskInputs) RiskBreakdown {
	crit := in.EffectiveCriticality
	if crit == "" {
		crit = a.criticality
	}
	b := RiskBreakdown{
		Model:                ScoreCompositionLikelihoodImpact,
		Exposure:             a.exposure.String(),
		Criticality:          a.criticality.String(),
		EffectiveCriticality: crit.String(),
		CrownJewel:           a.isCrownJewel,
	}

	counts := a.findingSeverityCounts
	eff := effectiveTierCounts(counts)
	raw := [4]int{}
	exp := [4]int{}
	if counts != nil {
		raw = [4]int{counts.Critical, counts.High, counts.Medium, counts.Low}
		exp = [4]int{counts.CriticalExploitable, counts.HighExploitable, counts.MediumExploitable, counts.LowExploitable}
	}
	findings := 0.0
	b.Tiers = make([]RiskTierContribution, 0, len(riskTiers))
	for i, t := range riskTiers {
		s := tierScore(t, eff[i])
		if s > findings {
			findings = s
		}
		b.Tiers = append(b.Tiers, RiskTierContribution{
			Severity: t.severity, Count: raw[i], Exploitable: exp[i], Effective: eff[i],
			Score: int(math.Round(s)),
		})
	}
	b.FindingsScore = int(math.Round(findings))

	b.ExposureFactor = clampPercent(e.exposureScore(a.exposure))
	critForFactor := crit
	if a.isCrownJewel {
		critForFactor = CriticalityCritical
	}
	if critForFactor == "" || critForFactor == CriticalityNone {
		critForFactor = CriticalityMedium
	}
	b.CriticalityFactor = clampPercent(e.criticalityScore(critForFactor))

	reduction := in.ControlReduction
	if reduction < 0 {
		reduction = 0
	}
	if reduction > MaxControlReduction {
		reduction = MaxControlReduction
	}
	b.ControlReduction = int(math.Round(reduction * 100))

	score := findings * float64(b.ExposureFactor) / 100 * float64(b.CriticalityFactor) / 100 * (1 - reduction)
	b.Score = clampPercent(int(math.Round(score)))
	return b
}

func clampPercent(v int) int {
	if v < 0 {
		return 0
	}
	if v > 100 {
		return 100
	}
	return v
}

// CalculateScoreWithInputs computes the score (0-100) from the asset and the
// inputs that do not live on it.
func (e *RiskScoringEngine) CalculateScoreWithInputs(a *Asset, in RiskInputs) int {
	if e.config.ScoreCompositionMode == ScoreCompositionLikelihoodImpact {
		return e.explainLikelihoodImpact(a, in).Score
	}
	return e.weightedScore(a, in.EffectiveCriticality)
}

// Explain returns the breakdown of the score. The weighted models report
// their components in the same shape (no tiers).
func (e *RiskScoringEngine) Explain(a *Asset, in RiskInputs) RiskBreakdown {
	if e.config.ScoreCompositionMode == ScoreCompositionLikelihoodImpact {
		return e.explainLikelihoodImpact(a, in)
	}
	crit := in.EffectiveCriticality
	if crit == "" {
		crit = a.criticality
	}
	mode := e.config.ScoreCompositionMode
	if mode == "" {
		mode = ScoreCompositionMultiply
	}
	return RiskBreakdown{
		Model:                mode,
		Score:                e.weightedScore(a, in.EffectiveCriticality),
		FindingsScore:        e.findingScore(a),
		Exposure:             a.exposure.String(),
		ExposureFactor:       e.exposureScore(a.exposure),
		Criticality:          a.criticality.String(),
		EffectiveCriticality: crit.String(),
		CrownJewel:           a.isCrownJewel,
		CriticalityFactor:    e.criticalityScore(crit),
		Tiers:                []RiskTierContribution{},
	}
}

// LikelihoodImpactRiskScoringConfig is the default configuration: the
// likelihood-impact model with its default factors.
func LikelihoodImpactRiskScoringConfig() RiskScoringConfig {
	c := LegacyRiskScoringConfig()
	c.ScoreCompositionMode = ScoreCompositionLikelihoodImpact
	c.ExposureScores = ExposureScoreMap{Public: 100, Restricted: 90, Private: 75, Isolated: 50, Unknown: 90}
	c.CriticalityScores = CriticalityScoreMap{Critical: 100, High: 90, Medium: 80, Low: 60, None: 80}
	c.RiskLevels = RiskLevelMap{CriticalMin: 80, HighMin: 60, MediumMin: 40, LowMin: 20}
	return c
}

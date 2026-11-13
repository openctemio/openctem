package asset

import "testing"

func liAsset(exp Exposure, crit Criticality, c FindingSeverityCounts) *Asset {
	return &Asset{exposure: exp, criticality: crit, findingSeverityCounts: &c}
}

func TestLikelihoodImpactModel(t *testing.T) {
	e := NewRiskScoringEngine(LikelihoodImpactRiskScoringConfig())
	type tc struct {
		name string
		a    *Asset
		in   RiskInputs
		want int
	}
	cases := []tc{
		{"no findings is zero risk, even public and critical",
			liAsset(ExposurePublic, CriticalityCritical, FindingSeverityCounts{}), RiskInputs{}, 0},
		{"info findings carry no risk",
			liAsset(ExposurePublic, CriticalityCritical, FindingSeverityCounts{Info: 40}), RiskInputs{}, 0},
		{"one critical, public, critical asset",
			liAsset(ExposurePublic, CriticalityCritical, FindingSeverityCounts{Critical: 1}), RiskInputs{}, 70},
		{"two criticals close 35% of the gap",
			liAsset(ExposurePublic, CriticalityCritical, FindingSeverityCounts{Critical: 2}), RiskInputs{}, 81},
		{"500 lows stay at the low ceiling",
			liAsset(ExposurePublic, CriticalityCritical, FindingSeverityCounts{Low: 500}), RiskInputs{}, 25},
		{"one high outranks 500 lows",
			liAsset(ExposurePublic, CriticalityCritical, FindingSeverityCounts{High: 1}), RiskInputs{}, 50},
		{"a KEV high counts as critical",
			liAsset(ExposurePublic, CriticalityCritical, FindingSeverityCounts{High: 1, HighExploitable: 1}), RiskInputs{}, 70},
		{"a KEV critical counts twice",
			liAsset(ExposurePublic, CriticalityCritical, FindingSeverityCounts{Critical: 1, CriticalExploitable: 1}), RiskInputs{}, 81},
		{"exploitable count above the total is clamped",
			liAsset(ExposurePublic, CriticalityCritical, FindingSeverityCounts{Low: 1, LowExploitable: 9}), RiskInputs{}, 25},
		// 5 crit / 10 high / 59 medium / 7 low: critical tier 95; unknown
		// exposure 90%, not rated = medium 80% -> 68.
		{"the reported repository (unknown exposure, not rated)",
			liAsset(ExposureUnknown, CriticalityNone, FindingSeverityCounts{Critical: 5, High: 10, Medium: 59, Low: 7}), RiskInputs{}, 68},
		{"unknown exposure is not treated as isolated",
			liAsset(ExposureIsolated, CriticalityNone, FindingSeverityCounts{Critical: 5, High: 10, Medium: 59, Low: 7}), RiskInputs{}, 38},
		{"business criticality raises the factor",
			liAsset(ExposureUnknown, CriticalityLow, FindingSeverityCounts{Critical: 1}), RiskInputs{EffectiveCriticality: CriticalityCritical}, 63},
		{"compensating control is capped at 75%",
			liAsset(ExposurePublic, CriticalityCritical, FindingSeverityCounts{Critical: 1}), RiskInputs{ControlReduction: 1}, 18},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := e.CalculateScoreWithInputs(c.a, c.in); got != c.want {
				t.Fatalf("score = %d, want %d (%+v)", got, c.want, e.Explain(c.a, c.in))
			}
		})
	}
}

func TestLikelihoodImpactCrownJewelCountsAsCritical(t *testing.T) {
	e := NewRiskScoringEngine(LikelihoodImpactRiskScoringConfig())
	a := liAsset(ExposurePublic, CriticalityLow, FindingSeverityCounts{Critical: 1})
	plain := e.CalculateScoreWithInputs(a, RiskInputs{})
	a.isCrownJewel = true
	if got := e.CalculateScoreWithInputs(a, RiskInputs{}); got != 70 || got <= plain {
		t.Fatalf("crown jewel score = %d (plain %d), want 70", got, plain)
	}
}

func TestLikelihoodImpactMonotonic(t *testing.T) {
	e := NewRiskScoringEngine(LikelihoodImpactRiskScoringConfig())
	prev := -1
	for n := 0; n <= 50; n++ {
		got := e.CalculateScoreWithInputs(liAsset(ExposurePublic, CriticalityHigh, FindingSeverityCounts{Medium: n}), RiskInputs{})
		if got < prev {
			t.Fatalf("score fell from %d to %d at %d mediums", prev, got, n)
		}
		prev = got
	}
}

func TestExplainTiers(t *testing.T) {
	e := NewRiskScoringEngine(LikelihoodImpactRiskScoringConfig())
	b := e.Explain(liAsset(ExposurePublic, CriticalityCritical, FindingSeverityCounts{High: 3, HighExploitable: 1, Low: 2}), RiskInputs{})
	if b.Model != ScoreCompositionLikelihoodImpact || len(b.Tiers) != 4 {
		t.Fatalf("breakdown = %+v", b)
	}
	if b.Tiers[0].Effective != 1 || b.Tiers[1].Effective != 2 || b.Tiers[1].Exploitable != 1 || b.Tiers[3].Count != 2 {
		t.Fatalf("tiers = %+v", b.Tiers)
	}
	if b.FindingsScore != 70 || b.Score != 70 || b.ExposureFactor != 100 || b.CriticalityFactor != 100 {
		t.Fatalf("breakdown = %+v", b)
	}
}

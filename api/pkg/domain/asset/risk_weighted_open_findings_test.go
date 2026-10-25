package asset

import "testing"

// customWeightedConfig is a weighted configuration of the shape organizations
// save: exposure 40, findings 35, criticality 25, composed with
// amplify_headroom.
func customWeightedConfig() RiskScoringConfig {
	c := LegacyRiskScoringConfig()
	c.ScoreCompositionMode = ScoreCompositionAmplifyHeadroom
	return c
}

// An asset without an open actionable finding scores 0 in every model:
// exposure, criticality and data context scale the risk of findings, they
// are not risk on their own.
func TestWeightedModels_NothingOpenScoresZero(t *testing.T) {
	ctem := LegacyRiskScoringConfig()
	ctem.Weights = ComponentWeights{Exposure: 25, Criticality: 25, Findings: 25, CTEM: 25}
	ctem.CTEMPoints = CTEMPointsConfig{Enabled: true, InternetAccessible: 30, PIIExposed: 30, RestrictedData: 40}

	configs := map[string]RiskScoringConfig{
		"multiply":         LegacyRiskScoringConfig(),
		"amplify_headroom": customWeightedConfig(),
		"ctem points":      ctem,
	}
	assets := map[string]*Asset{
		"public critical, no findings":  liAsset(ExposurePublic, CriticalityCritical, FindingSeverityCounts{}),
		"public medium, no findings":    liAsset(ExposurePublic, CriticalityMedium, FindingSeverityCounts{}),
		"unknown medium, no findings":   liAsset(ExposureUnknown, CriticalityMedium, FindingSeverityCounts{}),
		"informational findings only":   {exposure: ExposurePublic, criticality: CriticalityHigh, findingCount: 12, findingSeverityCounts: &FindingSeverityCounts{Info: 12}},
		"no counts loaded, no findings": {exposure: ExposurePublic, criticality: CriticalityHigh},
		"internet facing with personal data, no findings": {
			exposure: ExposurePublic, criticality: CriticalityCritical, isInternetAccessible: true,
			piiDataExposed: true, dataClassification: DataClassificationRestricted,
			findingSeverityCounts: &FindingSeverityCounts{},
		},
	}
	for cn, cfg := range configs {
		e := NewRiskScoringEngine(cfg)
		for an, a := range assets {
			t.Run(cn+"/"+an, func(t *testing.T) {
				if got := e.CalculateScoreWithInputs(a, RiskInputs{}); got != 0 {
					t.Fatalf("score = %d, want 0", got)
				}
				if b := e.Explain(a, RiskInputs{}); b.Score != 0 {
					t.Fatalf("explained score = %d, want 0", b.Score)
				}
				if lvl := cfg.Level(e.CalculateScoreWithInputs(a, RiskInputs{})); lvl != RiskLevelNone {
					t.Fatalf("level = %s, want %s", lvl, RiskLevelNone)
				}
			})
		}
	}
}

// With open findings the weighted models keep their formula.
func TestWeightedModels_OpenFindingsKeepTheFormula(t *testing.T) {
	cases := []struct {
		name string
		cfg  RiskScoringConfig
		a    *Asset
		want int
	}{
		// raw = 100*0.40 + 48*0.25 + 14*0.35 = 56.9; 56.9 + 0.5*43.1 = 78.45
		{"amplify_headroom, public medium, one medium finding", customWeightedConfig(),
			&Asset{exposure: ExposurePublic, criticality: CriticalityMedium, findingCount: 1, findingSeverityCounts: &FindingSeverityCounts{Medium: 1}}, 78},
		// raw = 50*0.40 + 48*0.25 + 28*0.35 = 41.8; multiplier 1.0
		{"amplify_headroom, unknown medium, two findings", customWeightedConfig(),
			&Asset{exposure: ExposureUnknown, criticality: CriticalityMedium, findingCount: 2, findingSeverityCounts: &FindingSeverityCounts{High: 1, Low: 1}}, 42},
		// raw = 37*0.40 + 48*0.25 + 14*0.35 = 31.7; multiplier 1.0
		{"multiply, private medium, one finding without loaded counts", LegacyRiskScoringConfig(),
			&Asset{exposure: ExposurePrivate, criticality: CriticalityMedium, findingCount: 1}, 32},
		// informational findings do not count: one low among them
		{"multiply, info findings do not add points", LegacyRiskScoringConfig(),
			&Asset{exposure: ExposurePrivate, criticality: CriticalityMedium, findingCount: 9, findingSeverityCounts: &FindingSeverityCounts{Low: 1, Info: 8}}, 32},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := NewRiskScoringEngine(c.cfg)
			if got := e.CalculateScoreWithInputs(c.a, RiskInputs{}); got != c.want {
				t.Fatalf("score = %d, want %d", got, c.want)
			}
		})
	}
}

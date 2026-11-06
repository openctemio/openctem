package asset

import "testing"

// A stored configuration that weighs only CTEM while CTEM points are off has
// nothing to share the CTEM weight with. The engine scores with the platform
// weights instead of giving every asset 0.
func TestRiskScoring_CTEMOnlyWeightsWithCTEMOffNeverZero(t *testing.T) {
	cfg := LegacyRiskScoringConfig()
	cfg.Weights = ComponentWeights{CTEM: 100}
	cfg.CTEMPoints.Enabled = false
	a := liAsset(ExposurePublic, CriticalityCritical, FindingSeverityCounts{Critical: 3, High: 4})
	got := NewRiskScoringEngine(cfg).CalculateScore(a)
	want := NewRiskScoringEngine(LegacyRiskScoringConfig()).CalculateScore(a)
	if got == 0 || got != want {
		t.Fatalf("score = %d, want the platform-weight score %d (never 0 for a critical public asset with findings)", got, want)
	}
}

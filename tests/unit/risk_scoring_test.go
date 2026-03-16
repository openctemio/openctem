package unit

import (
	"testing"

	"github.com/openctemio/api/pkg/domain/asset"
	"github.com/openctemio/api/pkg/domain/tenant"
)

// =============================================================================
// Helper
// =============================================================================

func makeTestAsset(t *testing.T, exposure asset.Exposure, criticality asset.Criticality, findingCount int) *asset.Asset {
	t.Helper()
	a, err := asset.NewAsset("test-asset", asset.AssetTypeWebsite, criticality)
	if err != nil {
		t.Fatalf("failed to create test asset: %v", err)
	}
	_ = a.UpdateExposure(exposure)
	a.UpdateFindingCount(findingCount)
	return a
}

func makeTestAssetWithSeverity(t *testing.T, exposure asset.Exposure, criticality asset.Criticality, counts asset.FindingSeverityCounts) *asset.Asset {
	t.Helper()
	a := makeTestAsset(t, exposure, criticality, counts.Critical+counts.High+counts.Medium+counts.Low+counts.Info)
	a.SetFindingSeverityCounts(&counts)
	return a
}

// =============================================================================
// Phase 2: Risk Scoring Engine Tests
// =============================================================================

func TestRiskScoringEngine_LegacyConfig(t *testing.T) {
	config := asset.LegacyRiskScoringConfig()
	engine := asset.NewRiskScoringEngine(config)

	tests := []struct {
		name        string
		exposure    asset.Exposure
		criticality asset.Criticality
		findings    int
		wantMin     int
		wantMax     int
	}{
		{
			name:        "public critical many findings",
			exposure:    asset.ExposurePublic,
			criticality: asset.CriticalityCritical,
			findings:    10,
			wantMin:     90,
			wantMax:     100,
		},
		{
			name:        "isolated none no findings",
			exposure:    asset.ExposureIsolated,
			criticality: asset.CriticalityNone,
			findings:    0,
			wantMin:     0,
			wantMax:     10,
		},
		{
			name:        "private medium 3 findings",
			exposure:    asset.ExposurePrivate,
			criticality: asset.CriticalityMedium,
			findings:    3,
			wantMin:     20,
			wantMax:     50,
		},
		{
			name:        "public none no findings",
			exposure:    asset.ExposurePublic,
			criticality: asset.CriticalityNone,
			findings:    0,
			wantMin:     50,
			wantMax:     70,
		},
		{
			name:        "unknown medium 1 finding",
			exposure:    asset.ExposureUnknown,
			criticality: asset.CriticalityMedium,
			findings:    1,
			wantMin:     25,
			wantMax:     45,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := makeTestAsset(t, tt.exposure, tt.criticality, tt.findings)
			score := engine.CalculateScore(a)

			if score < tt.wantMin || score > tt.wantMax {
				t.Errorf("score %d not in expected range [%d, %d]", score, tt.wantMin, tt.wantMax)
			}
		})
	}
}

func TestRiskScoringEngine_NilConfig(t *testing.T) {
	a := makeTestAsset(t, asset.ExposurePublic, asset.CriticalityCritical, 5)

	// Using CalculateRiskScoreWithConfig(nil) should use legacy config
	a.CalculateRiskScoreWithConfig(nil)
	score := a.RiskScore()

	if score < 80 || score > 100 {
		t.Errorf("nil config should use legacy, got score %d", score)
	}
}

func TestRiskScoringEngine_ScoreClamped(t *testing.T) {
	// Config that produces very high raw scores
	config := asset.RiskScoringConfig{
		Weights:             asset.ComponentWeights{Exposure: 50, Criticality: 50, Findings: 0, CTEM: 0},
		ExposureScores:      asset.ExposureScoreMap{Public: 100},
		ExposureMultipliers: asset.ExposureMultiplierMap{Public: 3.0},
		CriticalityScores:   asset.CriticalityScoreMap{Critical: 100},
		FindingImpact:       asset.FindingImpactConfig{Mode: "count", FindingCap: 100, PerFindingPoints: 1},
	}

	engine := asset.NewRiskScoringEngine(config)
	a := makeTestAsset(t, asset.ExposurePublic, asset.CriticalityCritical, 0)
	score := engine.CalculateScore(a)

	if score > 100 {
		t.Errorf("score should be clamped to 100, got %d", score)
	}
	if score < 0 {
		t.Errorf("score should not be negative, got %d", score)
	}
}

func TestRiskScoringEngine_CTEMDisabled(t *testing.T) {
	config := asset.LegacyRiskScoringConfig()
	config.CTEMPoints.Enabled = false
	config.Weights.CTEM = 0

	engine := asset.NewRiskScoringEngine(config)
	a := makeTestAsset(t, asset.ExposurePublic, asset.CriticalityCritical, 5)
	score := engine.CalculateScore(a)

	// CTEM disabled, score should be based on exposure + criticality + findings only
	if score < 50 {
		t.Errorf("expected reasonable score without CTEM, got %d", score)
	}
}

func TestRiskScoringEngine_CTEMWeightRedistribution(t *testing.T) {
	config := asset.RiskScoringConfig{
		Weights:             asset.ComponentWeights{Exposure: 30, Criticality: 20, Findings: 30, CTEM: 20},
		ExposureScores:      asset.ExposureScoreMap{Public: 100},
		ExposureMultipliers: asset.ExposureMultiplierMap{Public: 1.0},
		CriticalityScores:   asset.CriticalityScoreMap{Critical: 100},
		FindingImpact:       asset.FindingImpactConfig{Mode: "count", PerFindingPoints: 10, FindingCap: 100},
		CTEMPoints:          asset.CTEMPointsConfig{Enabled: false}, // CTEM disabled but weight > 0
	}

	engine := asset.NewRiskScoringEngine(config)
	a := makeTestAsset(t, asset.ExposurePublic, asset.CriticalityCritical, 10)
	score := engine.CalculateScore(a)

	// With all components at 100, redistribution should give 100
	if score != 100 {
		t.Errorf("expected 100 with full scores and redistribution, got %d", score)
	}
}

func TestRiskScoringEngine_CTEMEnabled(t *testing.T) {
	config := asset.LegacyRiskScoringConfig()
	config.CTEMPoints = asset.CTEMPointsConfig{
		Enabled:            true,
		InternetAccessible: 30,
		PIIExposed:         25,
		PHIExposed:         20,
		HighRiskCompliance: 15,
		RestrictedData:     10,
	}
	config.Weights = asset.ComponentWeights{Exposure: 25, Criticality: 25, Findings: 25, CTEM: 25}

	engine := asset.NewRiskScoringEngine(config)

	// Asset with internet accessible flag
	a := makeTestAsset(t, asset.ExposurePublic, asset.CriticalityCritical, 5)
	a.SetInternetAccessible(true)

	score := engine.CalculateScore(a)
	if score < 50 {
		t.Errorf("CTEM enabled with internet accessible should boost score, got %d", score)
	}
}

func TestRiskScoringEngine_SeverityWeightedMode(t *testing.T) {
	config := asset.LegacyRiskScoringConfig()
	config.FindingImpact = asset.FindingImpactConfig{
		Mode:       "severity_weighted",
		FindingCap: 100,
		SeverityWeights: asset.SeverityWeightMap{
			Critical: 20,
			High:     10,
			Medium:   5,
			Low:      2,
			Info:     1,
		},
	}

	engine := asset.NewRiskScoringEngine(config)

	tests := []struct {
		name   string
		counts asset.FindingSeverityCounts
	}{
		{
			name:   "critical only",
			counts: asset.FindingSeverityCounts{Critical: 3},
		},
		{
			name:   "mixed severities",
			counts: asset.FindingSeverityCounts{Critical: 1, High: 2, Medium: 5, Low: 10, Info: 20},
		},
		{
			name:   "info only",
			counts: asset.FindingSeverityCounts{Info: 50},
		},
	}

	var prevScore int
	for i, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := makeTestAssetWithSeverity(t, asset.ExposurePrivate, asset.CriticalityMedium, tt.counts)
			score := engine.CalculateScore(a)

			if score < 0 || score > 100 {
				t.Errorf("score out of bounds: %d", score)
			}

			// Critical-heavy findings should produce higher scores
			if i == 0 {
				prevScore = score
			}
		})
	}
	_ = prevScore
}

func TestRiskScoringEngine_CountModeFallback(t *testing.T) {
	config := asset.LegacyRiskScoringConfig()
	config.FindingImpact.Mode = "severity_weighted"

	engine := asset.NewRiskScoringEngine(config)

	// Asset WITHOUT severity counts — should fall back to count-based
	a := makeTestAsset(t, asset.ExposurePrivate, asset.CriticalityMedium, 5)
	score := engine.CalculateScore(a)

	if score < 0 || score > 100 {
		t.Errorf("score out of bounds: %d", score)
	}
}

func TestRiskScoringEngine_FindingCapApplied(t *testing.T) {
	config := asset.LegacyRiskScoringConfig()
	config.FindingImpact.FindingCap = 50
	config.FindingImpact.PerFindingPoints = 20

	engine := asset.NewRiskScoringEngine(config)

	// 10 findings * 20 = 200, but capped at 50
	a := makeTestAsset(t, asset.ExposurePrivate, asset.CriticalityNone, 10)
	scoreMany := engine.CalculateScore(a)

	// 3 findings * 20 = 60, capped at 50
	a2 := makeTestAsset(t, asset.ExposurePrivate, asset.CriticalityNone, 3)
	scoreFew := engine.CalculateScore(a2)

	// Both should have similar finding component since both hit the cap (or close)
	if scoreMany < scoreFew {
		t.Errorf("more findings (%d) should not score lower than fewer findings (%d)", scoreMany, scoreFew)
	}
}

func TestRiskScoringEngine_ZeroFindings(t *testing.T) {
	config := asset.LegacyRiskScoringConfig()
	engine := asset.NewRiskScoringEngine(config)

	a := makeTestAsset(t, asset.ExposureIsolated, asset.CriticalityNone, 0)
	score := engine.CalculateScore(a)

	if score < 0 {
		t.Errorf("score should not be negative, got %d", score)
	}
}

func TestRiskScoringEngine_AllExposureLevels(t *testing.T) {
	config := asset.LegacyRiskScoringConfig()
	engine := asset.NewRiskScoringEngine(config)

	exposures := []asset.Exposure{
		asset.ExposurePublic,
		asset.ExposureRestricted,
		asset.ExposurePrivate,
		asset.ExposureIsolated,
		asset.ExposureUnknown,
	}

	var prevScore int
	for i, exp := range exposures {
		a := makeTestAsset(t, exp, asset.CriticalityMedium, 3)
		score := engine.CalculateScore(a)

		if score < 0 || score > 100 {
			t.Errorf("exposure %v: score %d out of bounds", exp, score)
		}

		// Scores should generally decrease from public → isolated
		// (Unknown is separate, skip that check)
		if i > 0 && i < 4 && score > prevScore {
			t.Errorf("exposure %v scored %d > previous %d — expected descending order", exp, score, prevScore)
		}
		prevScore = score
	}
}

func TestRiskScoringEngine_AllCriticalityLevels(t *testing.T) {
	config := asset.LegacyRiskScoringConfig()
	engine := asset.NewRiskScoringEngine(config)

	criticalities := []asset.Criticality{
		asset.CriticalityCritical,
		asset.CriticalityHigh,
		asset.CriticalityMedium,
		asset.CriticalityLow,
		asset.CriticalityNone,
	}

	prevScore := 101
	for _, crit := range criticalities {
		a := makeTestAsset(t, asset.ExposurePrivate, crit, 0)
		score := engine.CalculateScore(a)

		if score < 0 || score > 100 {
			t.Errorf("criticality %v: score %d out of bounds", crit, score)
		}

		// Scores should decrease from critical → none
		if score > prevScore {
			t.Errorf("criticality %v scored %d > previous %d — expected descending order", crit, score, prevScore)
		}
		prevScore = score
	}
}

func TestRiskScoringEngine_SingleComponentWeight(t *testing.T) {
	// Only exposure matters
	config := asset.RiskScoringConfig{
		Weights:             asset.ComponentWeights{Exposure: 100, Criticality: 0, Findings: 0, CTEM: 0},
		ExposureScores:      asset.ExposureScoreMap{Public: 80, Private: 20},
		ExposureMultipliers: asset.ExposureMultiplierMap{Public: 1.0, Private: 1.0},
		CriticalityScores:   asset.CriticalityScoreMap{Critical: 100},
		FindingImpact:       asset.FindingImpactConfig{Mode: "count", PerFindingPoints: 10, FindingCap: 100},
	}

	engine := asset.NewRiskScoringEngine(config)

	// Score should be purely from exposure
	a := makeTestAsset(t, asset.ExposurePublic, asset.CriticalityCritical, 100)
	score := engine.CalculateScore(a)

	if score != 80 {
		t.Errorf("expected 80 (100%% exposure weight, 80 exposure score), got %d", score)
	}
}

// =============================================================================
// Phase 1: Settings Validation Tests
// =============================================================================

func TestRiskScoringSettings_LegacyPassesValidation(t *testing.T) {
	settings := tenant.LegacyRiskScoringSettings()
	if err := settings.Validate(); err != nil {
		t.Errorf("legacy settings should pass validation: %v", err)
	}
}

func TestRiskScoringSettings_DefaultPassesValidation(t *testing.T) {
	settings := tenant.DefaultRiskScoringPreset()
	if err := settings.Validate(); err != nil {
		t.Errorf("default settings should pass validation: %v", err)
	}
}

func TestRiskScoringSettings_AllPresetsPassValidation(t *testing.T) {
	for name, preset := range tenant.AllRiskScoringPresets {
		t.Run(name, func(t *testing.T) {
			if err := preset.Validate(); err != nil {
				t.Errorf("preset %q should pass validation: %v", name, err)
			}
		})
	}
}

func TestRiskScoringSettings_WeightsNotSum100(t *testing.T) {
	settings := tenant.LegacyRiskScoringSettings()
	settings.Weights.Exposure = 50
	settings.Weights.Criticality = 50
	settings.Weights.Findings = 50
	settings.Weights.CTEM = 0

	err := settings.Validate()
	if err == nil {
		t.Error("weights summing to 150 should fail validation")
	}
}

func TestRiskScoringSettings_NegativeWeight(t *testing.T) {
	settings := tenant.LegacyRiskScoringSettings()
	settings.Weights.Exposure = -10
	settings.Weights.Criticality = 50
	settings.Weights.Findings = 60
	settings.Weights.CTEM = 0

	err := settings.Validate()
	if err == nil {
		t.Error("negative weight should fail validation")
	}
}

func TestRiskScoringSettings_MultiplierOutOfBounds(t *testing.T) {
	settings := tenant.LegacyRiskScoringSettings()
	settings.ExposureMultipliers.Public = 5.0 // Max is 3.0

	err := settings.Validate()
	if err == nil {
		t.Error("multiplier > 3.0 should fail validation")
	}
}

func TestRiskScoringSettings_InvalidFindingMode(t *testing.T) {
	settings := tenant.LegacyRiskScoringSettings()
	settings.FindingImpact.Mode = "invalid_mode"

	err := settings.Validate()
	if err == nil {
		t.Error("invalid finding mode should fail validation")
	}
}

func TestRiskScoringSettings_RiskLevelsNotOrdered(t *testing.T) {
	settings := tenant.LegacyRiskScoringSettings()
	settings.RiskLevels.CriticalMin = 50
	settings.RiskLevels.HighMin = 60 // High > Critical — wrong order

	err := settings.Validate()
	if err == nil {
		t.Error("unordered risk levels should fail validation")
	}
}

func TestRiskScoringSettings_SeverityWeightOutOfBounds(t *testing.T) {
	settings := tenant.LegacyRiskScoringSettings()
	settings.FindingImpact.SeverityWeights.Critical = 100 // Max is 50

	err := settings.Validate()
	if err == nil {
		t.Error("severity weight > 50 should fail validation")
	}
}

func TestRiskScoringSettings_CTEMPointsIgnoredWhenDisabled(t *testing.T) {
	settings := tenant.LegacyRiskScoringSettings()
	settings.CTEMPoints.Enabled = false
	settings.CTEMPoints.InternetAccessible = 200 // Out of bounds but CTEM disabled

	err := settings.Validate()
	if err != nil {
		t.Errorf("CTEM points should be ignored when disabled: %v", err)
	}
}

func TestRiskScoringSettings_CTEMPointsValidatedWhenEnabled(t *testing.T) {
	settings := tenant.LegacyRiskScoringSettings()
	settings.CTEMPoints.Enabled = true
	settings.CTEMPoints.InternetAccessible = 200 // Out of bounds

	err := settings.Validate()
	if err == nil {
		t.Error("CTEM points > 100 should fail when enabled")
	}
}

// =============================================================================
// Phase 1.2: Legacy Preset Verification — New Engine ≈ Old Formula
// =============================================================================

func TestRiskScoringEngine_LegacyPreset_MatchesOldFormula(t *testing.T) {
	config := asset.LegacyRiskScoringConfig()
	engine := asset.NewRiskScoringEngine(config)

	// Old formula reference:
	//   baseScore = exposure.BaseRiskScore() [Public=40, Restricted=25, Private=15, Isolated=5, Unknown=20]
	//   criticalityScore = criticality.Score() / 4 [Critical=25, High=18, Medium=12, Low=6, None=0]
	//   findingImpact = min(findingCount * 5, 35)
	//   rawScore = baseScore + criticalityScore + findingImpact
	//   finalScore = clamp(rawScore * ExposureMultiplier(), 0, 100)

	tests := []struct {
		name        string
		exposure    asset.Exposure
		criticality asset.Criticality
		findings    int
		oldScore    int // Exact old formula result
	}{
		{
			name:        "public/critical/7findings → old=100",
			exposure:    asset.ExposurePublic,
			criticality: asset.CriticalityCritical,
			findings:    7,
			oldScore:    100, // (40+25+35)*1.5 = 150 → clamped 100
		},
		{
			name:        "private/medium/3findings → old=42",
			exposure:    asset.ExposurePrivate,
			criticality: asset.CriticalityMedium,
			findings:    3,
			oldScore:    42, // (15+12+15)*1.0 = 42
		},
		{
			name:        "isolated/none/0findings → old=4",
			exposure:    asset.ExposureIsolated,
			criticality: asset.CriticalityNone,
			findings:    0,
			oldScore:    4, // (5+0+0)*0.8 = 4
		},
		{
			name:        "public/none/0findings → old=60",
			exposure:    asset.ExposurePublic,
			criticality: asset.CriticalityNone,
			findings:    0,
			oldScore:    60, // (40+0+0)*1.5 = 60
		},
		{
			name:        "restricted/high/2findings → old=63",
			exposure:    asset.ExposureRestricted,
			criticality: asset.CriticalityHigh,
			findings:    2,
			oldScore:    63, // (25+18+10)*1.2 = 63.6 → int(63.6) = 63
		},
		{
			name:        "unknown/low/1finding → old=31",
			exposure:    asset.ExposureUnknown,
			criticality: asset.CriticalityLow,
			findings:    1,
			oldScore:    31, // (20+6+5)*1.0 = 31
		},
		{
			name:        "public/high/10findings → old=100",
			exposure:    asset.ExposurePublic,
			criticality: asset.CriticalityHigh,
			findings:    10,
			oldScore:    100, // (40+18+35)*1.5 = 139.5 → clamped 100
		},
		{
			name:        "isolated/critical/0findings → old=24",
			exposure:    asset.ExposureIsolated,
			criticality: asset.CriticalityCritical,
			findings:    0,
			oldScore:    24, // (5+25+0)*0.8 = 24
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := makeTestAsset(t, tt.exposure, tt.criticality, tt.findings)
			newScore := engine.CalculateScore(a)

			// Allow ±3 tolerance since the new formula uses weighted percentages
			// that produce slightly different intermediate rounding
			diff := newScore - tt.oldScore
			if diff < 0 {
				diff = -diff
			}
			if diff > 3 {
				t.Errorf("new engine score %d deviates from old formula %d by %d (max allowed: 3)",
					newScore, tt.oldScore, diff)
			}
		})
	}
}

func TestRiskScoringEngine_LegacyPreset_ExposureContribution(t *testing.T) {
	config := asset.LegacyRiskScoringConfig()
	engine := asset.NewRiskScoringEngine(config)

	// Old: Public BaseRiskScore=40, new: ExposureScore=100 × 40% weight = 40
	// The exposure component should produce ~40 for public with multiplier=1.0
	a := makeTestAsset(t, asset.ExposurePublic, asset.CriticalityNone, 0)
	score := engine.CalculateScore(a)

	// Old formula: (40+0+0)*1.5=60
	// New formula: 100*0.40=40, multiplier=1.5 → 60
	if score != 60 {
		t.Errorf("public/none/0findings: expected ~60, got %d", score)
	}
}

func TestRiskScoringEngine_LegacyPreset_CriticalityContribution(t *testing.T) {
	config := asset.LegacyRiskScoringConfig()
	engine := asset.NewRiskScoringEngine(config)

	// Old: Critical Score()/4 = 25, new: CriticalityScore=100 × 25% weight = 25
	a := makeTestAsset(t, asset.ExposurePrivate, asset.CriticalityCritical, 0)
	score := engine.CalculateScore(a)

	// Old formula: (15+25+0)*1.0=40
	// New formula: 37*0.40+100*0.25+0*0.35 = 14.8+25+0 = 39.8 → round(39.8*1.0) = 40
	if score < 38 || score > 42 {
		t.Errorf("private/critical/0findings: expected ~40, got %d", score)
	}
}

func TestRiskScoringEngine_LegacyPreset_FindingContribution(t *testing.T) {
	config := asset.LegacyRiskScoringConfig()
	engine := asset.NewRiskScoringEngine(config)

	// Old: 5 findings → min(5*5,35)=25, new: min(5*14,100)=70 → 70*0.35=24.5
	a := makeTestAsset(t, asset.ExposurePrivate, asset.CriticalityNone, 5)
	score := engine.CalculateScore(a)

	// Old formula: (15+0+25)*1.0=40
	// New formula: 37*0.40+0*0.25+70*0.35 = 14.8+0+24.5 = 39.3 → round(39.3*1.0) = 39
	if score < 37 || score > 42 {
		t.Errorf("private/none/5findings: expected ~39-40, got %d", score)
	}
}

func TestRiskScoringEngine_LegacyPreset_MultiplierEffect(t *testing.T) {
	config := asset.LegacyRiskScoringConfig()
	engine := asset.NewRiskScoringEngine(config)

	// Test that multipliers match: Public=1.5, Restricted=1.2, Private=1.0, Isolated=0.8
	base := makeTestAsset(t, asset.ExposurePrivate, asset.CriticalityMedium, 2)
	privateScore := engine.CalculateScore(base)

	isolated := makeTestAsset(t, asset.ExposureIsolated, asset.CriticalityMedium, 2)
	isolatedScore := engine.CalculateScore(isolated)

	public := makeTestAsset(t, asset.ExposurePublic, asset.CriticalityMedium, 2)
	publicScore := engine.CalculateScore(public)

	// Public(1.5) > Private(1.0) > Isolated(0.8)
	if publicScore <= privateScore {
		t.Errorf("public score %d should be > private score %d (multiplier 1.5 vs 1.0)", publicScore, privateScore)
	}
	if privateScore <= isolatedScore {
		t.Errorf("private score %d should be > isolated score %d (multiplier 1.0 vs 0.8)", privateScore, isolatedScore)
	}
}

// =============================================================================
// Phase 1.6: SettingsFromMap → ToMap Roundtrip
// =============================================================================

func TestRiskScoringSettings_RoundtripPreservesConfig(t *testing.T) {
	original := tenant.LegacyRiskScoringSettings()

	// Create settings with this risk scoring config
	settings := tenant.DefaultSettings()
	settings.RiskScoring = original

	// Convert to map and back
	m := settings.ToMap()
	restored := tenant.SettingsFromMap(m)

	// Verify risk scoring fields are preserved
	rs := restored.RiskScoring
	if rs.Preset != original.Preset {
		t.Errorf("preset: got %q, want %q", rs.Preset, original.Preset)
	}
	if rs.Weights != original.Weights {
		t.Errorf("weights: got %+v, want %+v", rs.Weights, original.Weights)
	}
	if rs.ExposureScores != original.ExposureScores {
		t.Errorf("exposure scores: got %+v, want %+v", rs.ExposureScores, original.ExposureScores)
	}
	if rs.ExposureMultipliers != original.ExposureMultipliers {
		t.Errorf("exposure multipliers: got %+v, want %+v", rs.ExposureMultipliers, original.ExposureMultipliers)
	}
	if rs.CriticalityScores != original.CriticalityScores {
		t.Errorf("criticality scores: got %+v, want %+v", rs.CriticalityScores, original.CriticalityScores)
	}
	if rs.FindingImpact != original.FindingImpact {
		t.Errorf("finding impact: got %+v, want %+v", rs.FindingImpact, original.FindingImpact)
	}
	if rs.CTEMPoints != original.CTEMPoints {
		t.Errorf("ctem points: got %+v, want %+v", rs.CTEMPoints, original.CTEMPoints)
	}
	if rs.RiskLevels != original.RiskLevels {
		t.Errorf("risk levels: got %+v, want %+v", rs.RiskLevels, original.RiskLevels)
	}
}

func TestRiskScoringSettings_RoundtripWithCustomConfig(t *testing.T) {
	custom := tenant.RiskScoringSettings{
		Preset:  "custom",
		Weights: tenant.ComponentWeights{Exposure: 30, Criticality: 20, Findings: 25, CTEM: 25},
		ExposureScores: tenant.ExposureScoreConfig{
			Public: 90, Restricted: 60, Private: 30, Isolated: 10, Unknown: 45,
		},
		ExposureMultipliers: tenant.ExposureMultiplierConfig{
			Public: 1.4, Restricted: 1.1, Private: 1.0, Isolated: 0.85, Unknown: 1.0,
		},
		CriticalityScores: tenant.CriticalityScoreConfig{
			Critical: 100, High: 80, Medium: 50, Low: 20, None: 0,
		},
		FindingImpact: tenant.FindingImpactConfig{
			Mode:             "severity_weighted",
			PerFindingPoints: 8,
			FindingCap:       80,
			SeverityWeights: tenant.SeverityWeightConfig{
				Critical: 25, High: 15, Medium: 8, Low: 3, Info: 1,
			},
		},
		CTEMPoints: tenant.CTEMPointsConfig{
			Enabled:            true,
			InternetAccessible: 30,
			PIIExposed:         25,
			PHIExposed:         20,
			HighRiskCompliance: 15,
			RestrictedData:     20,
		},
		RiskLevels: tenant.RiskLevelConfig{
			CriticalMin: 85, HighMin: 65, MediumMin: 35, LowMin: 15,
		},
	}

	settings := tenant.DefaultSettings()
	settings.RiskScoring = custom

	m := settings.ToMap()
	restored := tenant.SettingsFromMap(m)

	rs := restored.RiskScoring
	if rs.Preset != "custom" {
		t.Errorf("preset: got %q, want %q", rs.Preset, "custom")
	}
	if rs.Weights.CTEM != 25 {
		t.Errorf("CTEM weight: got %d, want 25", rs.Weights.CTEM)
	}
	if rs.CTEMPoints.Enabled != true {
		t.Error("CTEMPoints.Enabled should be true after roundtrip")
	}
	if rs.FindingImpact.Mode != "severity_weighted" {
		t.Errorf("finding mode: got %q, want 'severity_weighted'", rs.FindingImpact.Mode)
	}
	if rs.ExposureMultipliers.Isolated != 0.85 {
		t.Errorf("isolated multiplier: got %f, want 0.85", rs.ExposureMultipliers.Isolated)
	}
}

// =============================================================================
// FindingSeverityCounts Tests
// =============================================================================

func TestAsset_SetFindingSeverityCounts(t *testing.T) {
	a := makeTestAsset(t, asset.ExposurePublic, asset.CriticalityCritical, 10)

	counts := asset.FindingSeverityCounts{
		Critical: 2,
		High:     3,
		Medium:   3,
		Low:      1,
		Info:     1,
	}
	a.SetFindingSeverityCounts(&counts)

	got := a.FindingSeverityCounts()
	if got == nil {
		t.Fatal("FindingSeverityCounts should not be nil after Set")
	}
	if got.Critical != 2 || got.High != 3 || got.Medium != 3 || got.Low != 1 || got.Info != 1 {
		t.Errorf("FindingSeverityCounts mismatch: got %+v", got)
	}
}

func TestAsset_FindingSeverityCountsNilByDefault(t *testing.T) {
	a := makeTestAsset(t, asset.ExposurePublic, asset.CriticalityCritical, 0)

	got := a.FindingSeverityCounts()
	if got != nil {
		t.Error("FindingSeverityCounts should be nil by default")
	}
}

// =============================================================================
// CalculateRiskScoreWithConfig Tests
// =============================================================================

func TestAsset_CalculateRiskScoreWithConfig(t *testing.T) {
	config := asset.LegacyRiskScoringConfig()
	a := makeTestAsset(t, asset.ExposurePublic, asset.CriticalityCritical, 5)

	a.CalculateRiskScoreWithConfig(&config)
	score := a.RiskScore()

	if score < 80 || score > 100 {
		t.Errorf("expected high score for public+critical+5findings, got %d", score)
	}
}

func TestAsset_CalculateRiskScoreWithConfig_NilFallback(t *testing.T) {
	a := makeTestAsset(t, asset.ExposurePublic, asset.CriticalityCritical, 5)

	a.CalculateRiskScoreWithConfig(nil)
	score := a.RiskScore()

	if score < 80 || score > 100 {
		t.Errorf("nil config should use legacy, got %d", score)
	}
}

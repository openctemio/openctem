package asset

import (
	"context"
	"math"
	"time"

	"github.com/openctemio/api/pkg/domain/shared"
)

// RiskScoringConfig contains the scoring configuration.
// This mirrors tenant.RiskScoringSettings but lives in the asset package
// to avoid circular dependencies. The service layer maps between them.
type RiskScoringConfig struct {
	Weights             ComponentWeights
	ExposureScores      ExposureScoreMap
	ExposureMultipliers ExposureMultiplierMap
	CriticalityScores   CriticalityScoreMap
	FindingImpact       FindingImpactConfig
	CTEMPoints          CTEMPointsConfig
}

// ComponentWeights defines the percentage weights for each risk component.
type ComponentWeights struct {
	Exposure    int
	Criticality int
	Findings    int
	CTEM        int
}

// ExposureScoreMap maps exposure levels to base scores (0-100).
type ExposureScoreMap struct {
	Public     int
	Restricted int
	Private    int
	Isolated   int
	Unknown    int
}

// ExposureMultiplierMap maps exposure levels to score multipliers.
type ExposureMultiplierMap struct {
	Public     float64
	Restricted float64
	Private    float64
	Isolated   float64
	Unknown    float64
}

// CriticalityScoreMap maps criticality levels to base scores (0-100).
type CriticalityScoreMap struct {
	Critical int
	High     int
	Medium   int
	Low      int
	None     int
}

// FindingImpactConfig configures how findings affect the risk score.
type FindingImpactConfig struct {
	Mode             string // "count" or "severity_weighted"
	PerFindingPoints int
	FindingCap       int
	SeverityWeights  SeverityWeightMap
}

// SeverityWeightMap maps finding severities to point values.
type SeverityWeightMap struct {
	Critical int
	High     int
	Medium   int
	Low      int
	Info     int
}

// CTEMPointsConfig configures CTEM-specific risk point additions.
type CTEMPointsConfig struct {
	Enabled            bool
	InternetAccessible int
	PIIExposed         int
	PHIExposed         int
	HighRiskCompliance int
	RestrictedData     int
}

// ScoringConfigProvider provides risk scoring configuration for a tenant.
// This interface lives in the asset package to avoid circular dependencies.
// The service layer implements it by reading from tenant settings.
type ScoringConfigProvider interface {
	GetScoringConfig(ctx context.Context, tenantID shared.ID) (*RiskScoringConfig, error)
}

// LegacyRiskScoringConfig returns the config that reproduces the exact
// current hardcoded formula in CalculateRiskScore().
func LegacyRiskScoringConfig() RiskScoringConfig {
	return RiskScoringConfig{
		Weights: ComponentWeights{
			Exposure: 40, Criticality: 25, Findings: 35, CTEM: 0,
		},
		ExposureScores: ExposureScoreMap{
			Public: 100, Restricted: 62, Private: 37, Isolated: 12, Unknown: 50,
		},
		ExposureMultipliers: ExposureMultiplierMap{
			Public: 1.5, Restricted: 1.2, Private: 1.0, Isolated: 0.8, Unknown: 1.0,
		},
		CriticalityScores: CriticalityScoreMap{
			Critical: 100, High: 72, Medium: 48, Low: 24, None: 0,
		},
		FindingImpact: FindingImpactConfig{
			Mode:             "count",
			PerFindingPoints: 14,
			FindingCap:       100,
			SeverityWeights: SeverityWeightMap{
				Critical: 20, High: 10, Medium: 5, Low: 2, Info: 1,
			},
		},
		CTEMPoints: CTEMPointsConfig{Enabled: false},
	}
}

// RiskScoringEngine calculates risk scores using configurable weights.
type RiskScoringEngine struct {
	config RiskScoringConfig
}

// NewRiskScoringEngine creates a new scoring engine with the given config.
func NewRiskScoringEngine(config RiskScoringConfig) *RiskScoringEngine {
	return &RiskScoringEngine{config: config}
}

// CalculateScore computes the risk score for an asset (0-100).
func (e *RiskScoringEngine) CalculateScore(a *Asset) int {
	w := e.effectiveWeights()

	exposureScore := e.exposureScore(a.exposure)
	criticalityScore := e.criticalityScore(a.criticality)
	findingScore := e.findingScore(a)
	ctemScore := e.ctemScore(a)

	raw := float64(exposureScore)*float64(w.Exposure)/100.0 +
		float64(criticalityScore)*float64(w.Criticality)/100.0 +
		float64(findingScore)*float64(w.Findings)/100.0 +
		float64(ctemScore)*float64(w.CTEM)/100.0

	multiplier := e.exposureMultiplier(a.exposure)
	final := int(math.Round(raw * multiplier))

	if final > 100 {
		final = 100
	}
	if final < 0 {
		final = 0
	}

	return final
}

// effectiveWeights redistributes CTEM weight when CTEM is disabled.
func (e *RiskScoringEngine) effectiveWeights() ComponentWeights {
	w := e.config.Weights
	if !e.config.CTEMPoints.Enabled && w.CTEM > 0 {
		remaining := w.Exposure + w.Criticality + w.Findings
		if remaining > 0 {
			factor := 100.0 / float64(remaining)
			w.Exposure = int(math.Round(float64(w.Exposure) * factor))
			w.Criticality = int(math.Round(float64(w.Criticality) * factor))
			w.Findings = 100 - w.Exposure - w.Criticality
			w.CTEM = 0
		}
	}
	return w
}

func (e *RiskScoringEngine) exposureScore(exp Exposure) int {
	switch exp {
	case ExposurePublic:
		return e.config.ExposureScores.Public
	case ExposureRestricted:
		return e.config.ExposureScores.Restricted
	case ExposurePrivate:
		return e.config.ExposureScores.Private
	case ExposureIsolated:
		return e.config.ExposureScores.Isolated
	default:
		return e.config.ExposureScores.Unknown
	}
}

func (e *RiskScoringEngine) criticalityScore(c Criticality) int {
	switch c {
	case CriticalityCritical:
		return e.config.CriticalityScores.Critical
	case CriticalityHigh:
		return e.config.CriticalityScores.High
	case CriticalityMedium:
		return e.config.CriticalityScores.Medium
	case CriticalityLow:
		return e.config.CriticalityScores.Low
	default:
		return e.config.CriticalityScores.None
	}
}

func (e *RiskScoringEngine) findingScore(a *Asset) int {
	cfg := e.config.FindingImpact

	if cfg.Mode == "severity_weighted" && a.findingSeverityCounts != nil {
		w := cfg.SeverityWeights
		weighted := a.findingSeverityCounts.Critical*w.Critical +
			a.findingSeverityCounts.High*w.High +
			a.findingSeverityCounts.Medium*w.Medium +
			a.findingSeverityCounts.Low*w.Low +
			a.findingSeverityCounts.Info*w.Info

		if weighted > cfg.FindingCap {
			return cfg.FindingCap
		}
		return weighted
	}

	// Fallback: count-based
	score := a.findingCount * cfg.PerFindingPoints
	if score > cfg.FindingCap {
		return cfg.FindingCap
	}
	return score
}

func (e *RiskScoringEngine) ctemScore(a *Asset) int {
	if !e.config.CTEMPoints.Enabled {
		return 0
	}

	score := 0
	pts := e.config.CTEMPoints

	if a.isInternetAccessible {
		score += pts.InternetAccessible
	}
	if a.piiDataExposed {
		score += pts.PIIExposed
	}
	if a.phiDataExposed {
		score += pts.PHIExposed
	}
	if a.IsHighRiskCompliance() {
		score += pts.HighRiskCompliance
	}
	if a.dataClassification == DataClassificationRestricted ||
		a.dataClassification == DataClassificationSecret {
		score += pts.RestrictedData
	}

	if score > 100 {
		return 100
	}
	return score
}

func (e *RiskScoringEngine) exposureMultiplier(exp Exposure) float64 {
	switch exp {
	case ExposurePublic:
		return e.config.ExposureMultipliers.Public
	case ExposureRestricted:
		return e.config.ExposureMultipliers.Restricted
	case ExposurePrivate:
		return e.config.ExposureMultipliers.Private
	case ExposureIsolated:
		return e.config.ExposureMultipliers.Isolated
	default:
		return e.config.ExposureMultipliers.Unknown
	}
}

// CalculateRiskScoreWithConfig calculates risk using the provided scoring config.
func (a *Asset) CalculateRiskScoreWithConfig(config *RiskScoringConfig) {
	if config == nil {
		// Backward compatible: use legacy config
		legacy := LegacyRiskScoringConfig()
		config = &legacy
	}

	engine := NewRiskScoringEngine(*config)
	a.riskScore = engine.CalculateScore(a)
	a.updatedAt = time.Now().UTC()
}

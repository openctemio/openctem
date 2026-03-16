package app

import (
	"context"
	"fmt"

	"github.com/openctemio/api/pkg/domain/asset"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/domain/tenant"
)

// TenantScoringConfigProvider implements asset.ScoringConfigProvider
// by reading scoring settings from the tenant repository.
type TenantScoringConfigProvider struct {
	tenantRepo tenant.Repository
}

// NewTenantScoringConfigProvider creates a new scoring config provider.
func NewTenantScoringConfigProvider(tenantRepo tenant.Repository) *TenantScoringConfigProvider {
	return &TenantScoringConfigProvider{tenantRepo: tenantRepo}
}

// GetScoringConfig returns the risk scoring config for a tenant.
func (p *TenantScoringConfigProvider) GetScoringConfig(ctx context.Context, tenantID shared.ID) (*asset.RiskScoringConfig, error) {
	t, err := p.tenantRepo.GetByID(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to get tenant for scoring config: %w", err)
	}

	settings := t.TypedSettings()
	return MapTenantToAssetScoringConfig(&settings.RiskScoring), nil
}

// MapTenantToAssetScoringConfig maps tenant.RiskScoringSettings to asset.RiskScoringConfig.
func MapTenantToAssetScoringConfig(s *tenant.RiskScoringSettings) *asset.RiskScoringConfig {
	return &asset.RiskScoringConfig{
		Weights: asset.ComponentWeights{
			Exposure:    s.Weights.Exposure,
			Criticality: s.Weights.Criticality,
			Findings:    s.Weights.Findings,
			CTEM:        s.Weights.CTEM,
		},
		ExposureScores: asset.ExposureScoreMap{
			Public:     s.ExposureScores.Public,
			Restricted: s.ExposureScores.Restricted,
			Private:    s.ExposureScores.Private,
			Isolated:   s.ExposureScores.Isolated,
			Unknown:    s.ExposureScores.Unknown,
		},
		ExposureMultipliers: asset.ExposureMultiplierMap{
			Public:     s.ExposureMultipliers.Public,
			Restricted: s.ExposureMultipliers.Restricted,
			Private:    s.ExposureMultipliers.Private,
			Isolated:   s.ExposureMultipliers.Isolated,
			Unknown:    s.ExposureMultipliers.Unknown,
		},
		CriticalityScores: asset.CriticalityScoreMap{
			Critical: s.CriticalityScores.Critical,
			High:     s.CriticalityScores.High,
			Medium:   s.CriticalityScores.Medium,
			Low:      s.CriticalityScores.Low,
			None:     s.CriticalityScores.None,
		},
		FindingImpact: asset.FindingImpactConfig{
			Mode:             s.FindingImpact.Mode,
			PerFindingPoints: s.FindingImpact.PerFindingPoints,
			FindingCap:       s.FindingImpact.FindingCap,
			SeverityWeights: asset.SeverityWeightMap{
				Critical: s.FindingImpact.SeverityWeights.Critical,
				High:     s.FindingImpact.SeverityWeights.High,
				Medium:   s.FindingImpact.SeverityWeights.Medium,
				Low:      s.FindingImpact.SeverityWeights.Low,
				Info:     s.FindingImpact.SeverityWeights.Info,
			},
		},
		CTEMPoints: asset.CTEMPointsConfig{
			Enabled:            s.CTEMPoints.Enabled,
			InternetAccessible: s.CTEMPoints.InternetAccessible,
			PIIExposed:         s.CTEMPoints.PIIExposed,
			PHIExposed:         s.CTEMPoints.PHIExposed,
			HighRiskCompliance: s.CTEMPoints.HighRiskCompliance,
			RestrictedData:     s.CTEMPoints.RestrictedData,
		},
	}
}

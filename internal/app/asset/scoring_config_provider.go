package asset

import (
	"context"
	"fmt"

	assetdom "github.com/openctemio/api/pkg/domain/asset"
	"github.com/openctemio/api/pkg/domain/shared"
	tenantdom "github.com/openctemio/api/pkg/domain/tenant"
)

// TenantScoringConfigProvider implements assetdom.ScoringConfigProvider
// by reading scoring settings from the tenant repository.
type TenantScoringConfigProvider struct {
	tenantRepo tenantdom.Repository
}

// NewTenantScoringConfigProvider creates a new scoring config provider.
func NewTenantScoringConfigProvider(tenantRepo tenantdom.Repository) *TenantScoringConfigProvider {
	return &TenantScoringConfigProvider{tenantRepo: tenantRepo}
}

// GetScoringConfig returns the risk scoring config for a tenant.
func (p *TenantScoringConfigProvider) GetScoringConfig(ctx context.Context, tenantID shared.ID) (*assetdom.RiskScoringConfig, error) {
	t, err := p.tenantRepo.GetByID(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to get tenant for scoring config: %w", err)
	}

	settings := t.TypedSettings()
	return MapTenantToAssetScoringConfig(&settings.RiskScoring), nil
}

// MapTenantToAssetScoringConfig maps tenantdom.RiskScoringSettings to assetdom.RiskScoringConfig.
func MapTenantToAssetScoringConfig(s *tenantdom.RiskScoringSettings) *assetdom.RiskScoringConfig {
	return &assetdom.RiskScoringConfig{
		Weights: assetdom.ComponentWeights{
			Exposure:    s.Weights.Exposure,
			Criticality: s.Weights.Criticality,
			Findings:    s.Weights.Findings,
			CTEM:        s.Weights.CTEM,
		},
		ExposureScores: assetdom.ExposureScoreMap{
			Public:     s.ExposureScores.Public,
			Restricted: s.ExposureScores.Restricted,
			Private:    s.ExposureScores.Private,
			Isolated:   s.ExposureScores.Isolated,
			Unknown:    s.ExposureScores.Unknown,
		},
		ExposureMultipliers: assetdom.ExposureMultiplierMap{
			Public:     s.ExposureMultipliers.Public,
			Restricted: s.ExposureMultipliers.Restricted,
			Private:    s.ExposureMultipliers.Private,
			Isolated:   s.ExposureMultipliers.Isolated,
			Unknown:    s.ExposureMultipliers.Unknown,
		},
		CriticalityScores: assetdom.CriticalityScoreMap{
			Critical: s.CriticalityScores.Critical,
			High:     s.CriticalityScores.High,
			Medium:   s.CriticalityScores.Medium,
			Low:      s.CriticalityScores.Low,
			None:     s.CriticalityScores.None,
		},
		FindingImpact: assetdom.FindingImpactConfig{
			Mode:             s.FindingImpact.Mode,
			PerFindingPoints: s.FindingImpact.PerFindingPoints,
			FindingCap:       s.FindingImpact.FindingCap,
			SeverityWeights: assetdom.SeverityWeightMap{
				Critical: s.FindingImpact.SeverityWeights.Critical,
				High:     s.FindingImpact.SeverityWeights.High,
				Medium:   s.FindingImpact.SeverityWeights.Medium,
				Low:      s.FindingImpact.SeverityWeights.Low,
				Info:     s.FindingImpact.SeverityWeights.Info,
			},
		},
		CTEMPoints: assetdom.CTEMPointsConfig{
			Enabled:            s.CTEMPoints.Enabled,
			InternetAccessible: s.CTEMPoints.InternetAccessible,
			PIIExposed:         s.CTEMPoints.PIIExposed,
			PHIExposed:         s.CTEMPoints.PHIExposed,
			HighRiskCompliance: s.CTEMPoints.HighRiskCompliance,
			RestrictedData:     s.CTEMPoints.RestrictedData,
		},
	}
}

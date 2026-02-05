package app

import (
	"context"
	"time"

	"github.com/openctemio/api/pkg/domain/asset"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/logger"
	"github.com/openctemio/api/pkg/pagination"
)

// AttackSurfaceStats represents aggregated attack surface statistics.
type AttackSurfaceStats struct {
	// Summary stats
	TotalAssets       int     `json:"total_assets"`
	ExposedServices   int     `json:"exposed_services"`
	CriticalExposures int     `json:"critical_exposures"`
	RiskScore         float64 `json:"risk_score"`

	// Trends (week-over-week)
	TotalAssetsChange       int `json:"total_assets_change"`
	ExposedServicesChange   int `json:"exposed_services_change"`
	CriticalExposuresChange int `json:"critical_exposures_change"`

	// Asset breakdown by type with exposed count
	AssetBreakdown []AssetTypeBreakdown `json:"asset_breakdown"`

	// Top exposed services
	ExposedServicesList []ExposedService `json:"exposed_services_list"`

	// Recent changes
	RecentChanges []AssetChange `json:"recent_changes"`
}

// AssetTypeBreakdown represents asset count breakdown by type.
type AssetTypeBreakdown struct {
	Type    string `json:"type"`
	Total   int    `json:"total"`
	Exposed int    `json:"exposed"`
}

// ExposedService represents an exposed service/asset.
type ExposedService struct {
	ID           string    `json:"id"`
	Name         string    `json:"name"`
	Type         string    `json:"type"`
	Port         int       `json:"port,omitempty"`
	Exposure     string    `json:"exposure"`
	Criticality  string    `json:"criticality"`
	FindingCount int       `json:"finding_count"`
	LastSeen     time.Time `json:"last_seen"`
}

// AssetChange represents a recent asset change.
type AssetChange struct {
	Type      string    `json:"type"` // added, removed, changed
	AssetName string    `json:"asset_name"`
	AssetType string    `json:"asset_type"`
	Timestamp time.Time `json:"timestamp"`
}

// AttackSurfaceRepository defines the interface for attack surface data access.
type AttackSurfaceRepository interface {
	// GetStats returns attack surface statistics for a tenant
	GetStats(ctx context.Context, tenantID shared.ID) (*AttackSurfaceStatsData, error)
	// GetExposedServices returns top exposed services/assets
	GetExposedServices(ctx context.Context, tenantID shared.ID, limit int) ([]ExposedService, error)
	// GetRecentChanges returns recent asset changes
	GetRecentChanges(ctx context.Context, tenantID shared.ID, limit int) ([]AssetChange, error)
	// GetStatsWithTrends returns stats with week-over-week comparison
	GetStatsWithTrends(ctx context.Context, tenantID shared.ID) (*AttackSurfaceStatsData, error)
}

// AttackSurfaceStatsData holds raw attack surface statistics.
type AttackSurfaceStatsData struct {
	TotalAssets             int
	ExposedServices         int
	CriticalExposures       int
	AverageRiskScore        float64
	TotalAssetsChange       int
	ExposedServicesChange   int
	CriticalExposuresChange int
	ByType                  map[string]int
	ExposedByType           map[string]int
}

// AttackSurfaceService provides attack surface operations.
type AttackSurfaceService struct {
	assetRepo asset.Repository
	logger    *logger.Logger
}

// NewAttackSurfaceService creates a new AttackSurfaceService.
func NewAttackSurfaceService(assetRepo asset.Repository, log *logger.Logger) *AttackSurfaceService {
	return &AttackSurfaceService{
		assetRepo: assetRepo,
		logger:    log.With("service", "attack_surface"),
	}
}

// GetStats returns attack surface statistics for a tenant.
func (s *AttackSurfaceService) GetStats(ctx context.Context, tenantID shared.ID) (*AttackSurfaceStats, error) {
	tenantIDStr := tenantID.String()

	// Get total assets count
	totalAssets, err := s.assetRepo.Count(ctx, asset.Filter{
		TenantID: &tenantIDStr,
	})
	if err != nil {
		s.logger.Error("failed to count total assets", "error", err)
		totalAssets = 0
	}

	// Get exposed services count (exposure = public)
	exposedServices, err := s.assetRepo.Count(ctx, asset.Filter{
		TenantID:  &tenantIDStr,
		Exposures: []asset.Exposure{asset.ExposurePublic},
	})
	if err != nil {
		s.logger.Error("failed to count exposed services", "error", err)
		exposedServices = 0
	}

	// Get critical exposures count (exposure = public AND criticality = critical OR high)
	criticalExposures, err := s.assetRepo.Count(ctx, asset.Filter{
		TenantID:      &tenantIDStr,
		Exposures:     []asset.Exposure{asset.ExposurePublic},
		Criticalities: []asset.Criticality{asset.CriticalityCritical, asset.CriticalityHigh},
	})
	if err != nil {
		s.logger.Error("failed to count critical exposures", "error", err)
		criticalExposures = 0
	}

	// Get assets with risk score for average calculation
	avgRiskScore := s.calculateAverageRiskScore(ctx, tenantIDStr)

	// Get asset breakdown by type
	assetBreakdown := s.getAssetBreakdown(ctx, tenantIDStr)

	// Get exposed services list (limit to 5 for overview)
	exposedServicesList := s.getExposedServicesList(ctx, tenantIDStr, 5)

	// Get recent changes (limit to 5 for overview)
	recentChanges := s.getRecentChanges(ctx, tenantIDStr, 5)

	return &AttackSurfaceStats{
		TotalAssets:       int(totalAssets),
		ExposedServices:   int(exposedServices),
		CriticalExposures: int(criticalExposures),
		RiskScore:         avgRiskScore,
		// Trends - for now return 0, can be implemented with historical data
		TotalAssetsChange:       0,
		ExposedServicesChange:   0,
		CriticalExposuresChange: 0,
		AssetBreakdown:          assetBreakdown,
		ExposedServicesList:     exposedServicesList,
		RecentChanges:           recentChanges,
	}, nil
}

// calculateAverageRiskScore calculates the average risk score for all assets.
func (s *AttackSurfaceService) calculateAverageRiskScore(ctx context.Context, tenantID string) float64 {
	// Get all assets with their risk scores
	result, err := s.assetRepo.List(ctx, asset.Filter{
		TenantID: &tenantID,
	}, asset.ListOptions{}, pagination.Pagination{Page: 1, PerPage: 1000})
	if err != nil {
		s.logger.Error("failed to get assets for risk score calculation", "error", err)
		return 0
	}

	if len(result.Data) == 0 {
		return 0
	}

	totalRiskScore := 0
	for _, a := range result.Data {
		totalRiskScore += a.RiskScore()
	}

	return float64(totalRiskScore) / float64(len(result.Data))
}

// getAssetBreakdown returns asset count breakdown by type with exposed count.
func (s *AttackSurfaceService) getAssetBreakdown(ctx context.Context, tenantID string) []AssetTypeBreakdown {
	assetTypes := []asset.AssetType{
		asset.AssetTypeDomain,
		asset.AssetTypeWebsite,
		asset.AssetTypeService,
		asset.AssetTypeRepository,
		asset.AssetTypeCloudAccount,
		asset.AssetTypeServer,
	}

	breakdown := make([]AssetTypeBreakdown, 0, len(assetTypes))

	for _, assetType := range assetTypes {
		// Count total for this type
		total, err := s.assetRepo.Count(ctx, asset.Filter{
			TenantID: &tenantID,
			Types:    []asset.AssetType{assetType},
		})
		if err != nil {
			s.logger.Error("failed to count assets by type", "error", err, "type", assetType)
			total = 0
		}

		// Count exposed for this type
		exposed, err := s.assetRepo.Count(ctx, asset.Filter{
			TenantID:  &tenantID,
			Types:     []asset.AssetType{assetType},
			Exposures: []asset.Exposure{asset.ExposurePublic},
		})
		if err != nil {
			s.logger.Error("failed to count exposed assets by type", "error", err, "type", assetType)
			exposed = 0
		}

		breakdown = append(breakdown, AssetTypeBreakdown{
			Type:    assetType.String(),
			Total:   int(total),
			Exposed: int(exposed),
		})
	}

	return breakdown
}

// getExposedServicesList returns a list of exposed services/assets.
func (s *AttackSurfaceService) getExposedServicesList(ctx context.Context, tenantID string, limit int) []ExposedService {
	// Get exposed assets (public or restricted access)
	result, err := s.assetRepo.List(ctx, asset.Filter{
		TenantID:  &tenantID,
		Exposures: []asset.Exposure{asset.ExposurePublic, asset.ExposureRestricted},
	}, asset.ListOptions{}, pagination.Pagination{Page: 1, PerPage: limit})
	if err != nil {
		s.logger.Error("failed to get exposed services", "error", err)
		return []ExposedService{}
	}

	services := make([]ExposedService, 0, len(result.Data))
	for _, a := range result.Data {
		services = append(services, ExposedService{
			ID:           a.ID().String(),
			Name:         a.Name(),
			Type:         a.Type().String(),
			Exposure:     a.Exposure().String(),
			Criticality:  a.Criticality().String(),
			FindingCount: a.FindingCount(),
			LastSeen:     a.LastSeen(),
		})
	}

	return services
}

// getRecentChanges returns recent asset changes based on created/updated timestamps.
func (s *AttackSurfaceService) getRecentChanges(ctx context.Context, tenantID string, limit int) []AssetChange {
	// Get recently created or updated assets
	result, err := s.assetRepo.List(ctx, asset.Filter{
		TenantID: &tenantID,
	}, asset.ListOptions{}, pagination.Pagination{Page: 1, PerPage: limit})
	if err != nil {
		s.logger.Error("failed to get recent changes", "error", err)
		return []AssetChange{}
	}

	changes := make([]AssetChange, 0, len(result.Data))
	for _, a := range result.Data {
		// Determine change type based on timestamps
		changeType := "changed"
		timestamp := a.UpdatedAt()

		// If created recently (within last 24 hours of updated), consider it "added"
		if a.CreatedAt().Add(24 * time.Hour).After(a.UpdatedAt()) {
			changeType = "added"
			timestamp = a.CreatedAt()
		}

		changes = append(changes, AssetChange{
			Type:      changeType,
			AssetName: a.Name(),
			AssetType: a.Type().String(),
			Timestamp: timestamp,
		})
	}

	return changes
}

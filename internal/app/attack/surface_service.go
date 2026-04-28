package attack

import (
	"context"
	"time"

	"github.com/openctemio/api/pkg/domain/asset"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/logger"
	"github.com/openctemio/api/pkg/pagination"
)

// SurfaceStats represents aggregated attack surface statistics.
type SurfaceStats struct {
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

// SurfaceRepository defines the interface for attack surface data access.
type SurfaceRepository interface {
	// GetStats returns attack surface statistics for a tenant
	GetStats(ctx context.Context, tenantID shared.ID) (*SurfaceStatsData, error)
	// GetExposedServices returns top exposed services/assets
	GetExposedServices(ctx context.Context, tenantID shared.ID, limit int) ([]ExposedService, error)
	// GetRecentChanges returns recent asset changes
	GetRecentChanges(ctx context.Context, tenantID shared.ID, limit int) ([]AssetChange, error)
	// GetStatsWithTrends returns stats with week-over-week comparison
	GetStatsWithTrends(ctx context.Context, tenantID shared.ID) (*SurfaceStatsData, error)
}

// SurfaceStatsData holds raw attack surface statistics.
type SurfaceStatsData struct {
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

// SurfaceService provides attack surface operations.
type SurfaceService struct {
	assetRepo asset.Repository
	relRepo   asset.RelationshipRepository
	logger    *logger.Logger
}

// NewSurfaceService creates a new SurfaceService.
func NewSurfaceService(assetRepo asset.Repository, relRepo asset.RelationshipRepository, log *logger.Logger) *SurfaceService {
	return &SurfaceService{
		assetRepo: assetRepo,
		relRepo:   relRepo,
		logger:    log.With("service", "attack_surface"),
	}
}

// GetAttackPathScores computes attack path scoring for the tenant.
func (s *SurfaceService) GetAttackPathScores(ctx context.Context, tenantID shared.ID) (*PathScoringResult, error) {
	return s.ComputeAttackPathScores(ctx, tenantID, s.relRepo)
}

// GetStats returns attack surface statistics for a tenant.
func (s *SurfaceService) GetStats(ctx context.Context, tenantID shared.ID) (*SurfaceStats, error) {
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
	avgRiskScore := s.calculateAverageRiskScore(ctx, tenantID)

	// Get asset breakdown by type
	assetBreakdown := s.getAssetBreakdown(ctx, tenantID)

	// Get exposed services list (limit to 5 for overview)
	exposedServicesList := s.getExposedServicesList(ctx, tenantIDStr, 5)

	// Get recent changes (limit to 5 for overview)
	recentChanges := s.getRecentChanges(ctx, tenantIDStr, 5)

	return &SurfaceStats{
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

// calculateAverageRiskScore calculates the average risk score using a single AVG() query.
func (s *SurfaceService) calculateAverageRiskScore(ctx context.Context, tenantID shared.ID) float64 {
	avg, err := s.assetRepo.GetAverageRiskScore(ctx, tenantID)
	if err != nil {
		s.logger.Error("failed to get average risk score", "error", err)
		return 0
	}
	return avg
}

// getAssetBreakdown returns asset count breakdown by type using a single GROUP BY query.
func (s *SurfaceService) getAssetBreakdown(ctx context.Context, tenantID shared.ID) []AssetTypeBreakdown {
	assetTypes := []asset.AssetType{
		asset.AssetTypeDomain,
		asset.AssetTypeWebsite,
		asset.AssetTypeService,
		asset.AssetTypeRepository,
		asset.AssetTypeCloudAccount,
		asset.AssetTypeHost,
	}

	// Single query returns all types with total + exposed counts
	statsMap, err := s.assetRepo.GetAssetTypeBreakdown(ctx, tenantID)
	if err != nil {
		s.logger.Error("failed to get asset type breakdown", "error", err)
		statsMap = make(map[string]asset.AssetTypeStats)
	}

	breakdown := make([]AssetTypeBreakdown, 0, len(assetTypes))
	for _, assetType := range assetTypes {
		stats := statsMap[assetType.String()]
		breakdown = append(breakdown, AssetTypeBreakdown{
			Type:    assetType.String(),
			Total:   stats.Total,
			Exposed: stats.Exposed,
		})
	}

	return breakdown
}

// getExposedServicesList returns a list of exposed services/assets.
func (s *SurfaceService) getExposedServicesList(ctx context.Context, tenantID string, limit int) []ExposedService {
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
func (s *SurfaceService) getRecentChanges(ctx context.Context, tenantID string, limit int) []AssetChange {
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

package app

import (
	"context"
	"time"

	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/logger"
)

// DashboardStats represents aggregated dashboard statistics.
type DashboardStats struct {
	// Asset stats
	AssetCount       int
	AssetsByType     map[string]int
	AssetsByStatus   map[string]int
	AverageRiskScore float64

	// Finding stats
	FindingCount       int
	FindingsBySeverity map[string]int
	FindingsByStatus   map[string]int
	OverdueFindings    int
	AverageCVSS        float64

	// Repository stats (repositories are assets with type 'repository')
	RepositoryCount          int
	RepositoriesWithFindings int

	// Recent activity
	RecentActivity []ActivityItem
}

// ActivityItem represents a recent activity item.
type ActivityItem struct {
	Type        string
	Title       string
	Description string
	Timestamp   time.Time
}

// DashboardStatsRepository defines the interface for dashboard data access.
type DashboardStatsRepository interface {
	// GetAssetStats returns asset statistics for a tenant
	GetAssetStats(ctx context.Context, tenantID shared.ID) (AssetStatsData, error)
	// GetFindingStats returns finding statistics for a tenant
	GetFindingStats(ctx context.Context, tenantID shared.ID) (FindingStatsData, error)
	// GetRepositoryStats returns repository statistics for a tenant
	GetRepositoryStats(ctx context.Context, tenantID shared.ID) (RepositoryStatsData, error)
	// GetRecentActivity returns recent activity for a tenant
	GetRecentActivity(ctx context.Context, tenantID shared.ID, limit int) ([]ActivityItem, error)

	// Global stats (not tenant-scoped) - deprecated, use filtered versions
	GetGlobalAssetStats(ctx context.Context) (AssetStatsData, error)
	GetGlobalFindingStats(ctx context.Context) (FindingStatsData, error)
	GetGlobalRepositoryStats(ctx context.Context) (RepositoryStatsData, error)
	GetGlobalRecentActivity(ctx context.Context, limit int) ([]ActivityItem, error)

	// Filtered stats (by accessible tenant IDs) - for multi-tenant authorization
	GetFilteredAssetStats(ctx context.Context, tenantIDs []string) (AssetStatsData, error)
	GetFilteredFindingStats(ctx context.Context, tenantIDs []string) (FindingStatsData, error)
	GetFilteredRepositoryStats(ctx context.Context, tenantIDs []string) (RepositoryStatsData, error)
	GetFilteredRecentActivity(ctx context.Context, tenantIDs []string, limit int) ([]ActivityItem, error)
}

// AssetStatsData holds raw asset statistics from repository.
type AssetStatsData struct {
	Total            int
	ByType           map[string]int
	ByStatus         map[string]int
	AverageRiskScore float64
}

// FindingStatsData holds raw finding statistics from repository.
type FindingStatsData struct {
	Total       int
	BySeverity  map[string]int
	ByStatus    map[string]int
	Overdue     int
	AverageCVSS float64
}

// RepositoryStatsData holds raw repository statistics from repository.
type RepositoryStatsData struct {
	Total        int
	WithFindings int
}

// DashboardService provides dashboard-related operations.
type DashboardService struct {
	repo   DashboardStatsRepository
	logger *logger.Logger
}

// NewDashboardService creates a new DashboardService.
func NewDashboardService(repo DashboardStatsRepository, log *logger.Logger) *DashboardService {
	return &DashboardService{
		repo:   repo,
		logger: log,
	}
}

// GetStats returns dashboard statistics for a tenant.
func (s *DashboardService) GetStats(ctx context.Context, tenantID shared.ID) (*DashboardStats, error) {
	// Get asset stats
	assetStats, err := s.repo.GetAssetStats(ctx, tenantID)
	if err != nil {
		s.logger.Error("failed to get asset stats", "error", err, "tenant_id", tenantID)
		// Don't fail completely, use empty stats
		assetStats = AssetStatsData{ByType: make(map[string]int), ByStatus: make(map[string]int)}
	}

	// Get finding stats
	findingStats, err := s.repo.GetFindingStats(ctx, tenantID)
	if err != nil {
		s.logger.Error("failed to get finding stats", "error", err, "tenant_id", tenantID)
		findingStats = FindingStatsData{BySeverity: make(map[string]int), ByStatus: make(map[string]int)}
	}

	// Get repository stats
	repoStats, err := s.repo.GetRepositoryStats(ctx, tenantID)
	if err != nil {
		s.logger.Error("failed to get repository stats", "error", err, "tenant_id", tenantID)
		repoStats = RepositoryStatsData{}
	}

	// Get recent activity
	activity, err := s.repo.GetRecentActivity(ctx, tenantID, 10)
	if err != nil {
		s.logger.Error("failed to get recent activity", "error", err, "tenant_id", tenantID)
		activity = []ActivityItem{}
	}

	return &DashboardStats{
		AssetCount:               assetStats.Total,
		AssetsByType:             assetStats.ByType,
		AssetsByStatus:           assetStats.ByStatus,
		AverageRiskScore:         assetStats.AverageRiskScore,
		FindingCount:             findingStats.Total,
		FindingsBySeverity:       findingStats.BySeverity,
		FindingsByStatus:         findingStats.ByStatus,
		OverdueFindings:          findingStats.Overdue,
		AverageCVSS:              findingStats.AverageCVSS,
		RepositoryCount:          repoStats.Total,
		RepositoriesWithFindings: repoStats.WithFindings,
		RecentActivity:           activity,
	}, nil
}

// GetGlobalStats returns global dashboard statistics (not tenant-scoped).
// Deprecated: Use GetStatsForTenants for proper multi-tenant authorization.
func (s *DashboardService) GetGlobalStats(ctx context.Context) (*DashboardStats, error) {
	// Get global asset stats
	assetStats, err := s.repo.GetGlobalAssetStats(ctx)
	if err != nil {
		s.logger.Error("failed to get global asset stats", "error", err)
		assetStats = AssetStatsData{ByType: make(map[string]int), ByStatus: make(map[string]int)}
	}

	// Get global finding stats
	findingStats, err := s.repo.GetGlobalFindingStats(ctx)
	if err != nil {
		s.logger.Error("failed to get global finding stats", "error", err)
		findingStats = FindingStatsData{BySeverity: make(map[string]int), ByStatus: make(map[string]int)}
	}

	// Get global repository stats
	repoStats, err := s.repo.GetGlobalRepositoryStats(ctx)
	if err != nil {
		s.logger.Error("failed to get global repository stats", "error", err)
		repoStats = RepositoryStatsData{}
	}

	// Get global recent activity
	activity, err := s.repo.GetGlobalRecentActivity(ctx, 10)
	if err != nil {
		s.logger.Error("failed to get global recent activity", "error", err)
		activity = []ActivityItem{}
	}

	return &DashboardStats{
		AssetCount:               assetStats.Total,
		AssetsByType:             assetStats.ByType,
		AssetsByStatus:           assetStats.ByStatus,
		AverageRiskScore:         assetStats.AverageRiskScore,
		FindingCount:             findingStats.Total,
		FindingsBySeverity:       findingStats.BySeverity,
		FindingsByStatus:         findingStats.ByStatus,
		OverdueFindings:          findingStats.Overdue,
		AverageCVSS:              findingStats.AverageCVSS,
		RepositoryCount:          repoStats.Total,
		RepositoriesWithFindings: repoStats.WithFindings,
		RecentActivity:           activity,
	}, nil
}

// GetStatsForTenants returns dashboard statistics filtered by accessible tenant IDs.
// This should be used for multi-tenant authorization - only shows data from tenants
// the user has access to.
func (s *DashboardService) GetStatsForTenants(ctx context.Context, tenantIDs []string) (*DashboardStats, error) {
	// If no accessible tenants, return empty stats
	if len(tenantIDs) == 0 {
		return &DashboardStats{
			AssetsByType:       make(map[string]int),
			AssetsByStatus:     make(map[string]int),
			FindingsBySeverity: make(map[string]int),
			FindingsByStatus:   make(map[string]int),
			RecentActivity:     []ActivityItem{},
		}, nil
	}

	// Get asset stats filtered by accessible tenants
	assetStats, err := s.repo.GetFilteredAssetStats(ctx, tenantIDs)
	if err != nil {
		s.logger.Error("failed to get filtered asset stats", "error", err, "tenant_count", len(tenantIDs))
		assetStats = AssetStatsData{ByType: make(map[string]int), ByStatus: make(map[string]int)}
	}

	// Get finding stats filtered by accessible tenants
	findingStats, err := s.repo.GetFilteredFindingStats(ctx, tenantIDs)
	if err != nil {
		s.logger.Error("failed to get filtered finding stats", "error", err, "tenant_count", len(tenantIDs))
		findingStats = FindingStatsData{BySeverity: make(map[string]int), ByStatus: make(map[string]int)}
	}

	// Get repository stats filtered by accessible tenants
	repoStats, err := s.repo.GetFilteredRepositoryStats(ctx, tenantIDs)
	if err != nil {
		s.logger.Error("failed to get filtered repository stats", "error", err, "tenant_count", len(tenantIDs))
		repoStats = RepositoryStatsData{}
	}

	// Get recent activity filtered by accessible tenants
	activity, err := s.repo.GetFilteredRecentActivity(ctx, tenantIDs, 10)
	if err != nil {
		s.logger.Error("failed to get filtered recent activity", "error", err, "tenant_count", len(tenantIDs))
		activity = []ActivityItem{}
	}

	return &DashboardStats{
		AssetCount:               assetStats.Total,
		AssetsByType:             assetStats.ByType,
		AssetsByStatus:           assetStats.ByStatus,
		AverageRiskScore:         assetStats.AverageRiskScore,
		FindingCount:             findingStats.Total,
		FindingsBySeverity:       findingStats.BySeverity,
		FindingsByStatus:         findingStats.ByStatus,
		OverdueFindings:          findingStats.Overdue,
		AverageCVSS:              findingStats.AverageCVSS,
		RepositoryCount:          repoStats.Total,
		RepositoriesWithFindings: repoStats.WithFindings,
		RecentActivity:           activity,
	}, nil
}

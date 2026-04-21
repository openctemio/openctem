package module

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
	AssetsBySubType  map[string]int
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

	// Finding trend (monthly breakdown by severity)
	FindingTrend []FindingTrendPoint
}

// FindingTrendPoint represents one month's finding counts by severity.
type FindingTrendPoint struct {
	Date     string // "Jan", "Feb", etc.
	Critical int
	High     int
	Medium   int
	Low      int
	Info     int
}

// RiskVelocityPoint represents weekly new vs resolved finding counts.
type RiskVelocityPoint struct {
	Week          time.Time `json:"week"`
	NewCount      int       `json:"new_count"`
	ResolvedCount int       `json:"resolved_count"`
	Velocity      int       `json:"velocity"` // new - resolved (positive = losing ground)
}

// ActivityItem represents a recent activity item.
type ActivityItem struct {
	Type        string
	Title       string
	Description string
	Timestamp   time.Time
}

// DashboardAllStats holds all dashboard stats from the optimized batched query.
type DashboardAllStats struct {
	Assets   AssetStatsData
	Findings FindingStatsData
	Repos    RepositoryStatsData
	Activity []ActivityItem
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
	// GetFindingTrend returns monthly finding counts by severity for a tenant
	GetFindingTrend(ctx context.Context, tenantID shared.ID, months int) ([]FindingTrendPoint, error)
	// GetAllStats returns all dashboard stats in 2 optimized queries (replaces 10+ individual calls)
	GetAllStats(ctx context.Context, tenantID shared.ID) (*DashboardAllStats, error)

	// Global stats (not tenant-scoped) - deprecated, use filtered versions
	GetGlobalAssetStats(ctx context.Context) (AssetStatsData, error)
	GetGlobalFindingStats(ctx context.Context) (FindingStatsData, error)
	GetGlobalRepositoryStats(ctx context.Context) (RepositoryStatsData, error)
	GetGlobalRecentActivity(ctx context.Context, limit int) ([]ActivityItem, error)

	// MTTR & Trending
	GetMTTRMetrics(ctx context.Context, tenantID shared.ID) (map[string]float64, error)
	GetRiskVelocity(ctx context.Context, tenantID shared.ID, weeks int) ([]RiskVelocityPoint, error)

	// Filtered stats (by accessible tenant IDs) - for multi-tenant authorization
	GetFilteredAssetStats(ctx context.Context, tenantIDs []string) (AssetStatsData, error)
	GetFilteredFindingStats(ctx context.Context, tenantIDs []string) (FindingStatsData, error)
	GetFilteredRepositoryStats(ctx context.Context, tenantIDs []string) (RepositoryStatsData, error)
	GetFilteredRecentActivity(ctx context.Context, tenantIDs []string, limit int) ([]ActivityItem, error)

	// Data Quality Scorecard (RFC-005)
	GetDataQualityScorecard(ctx context.Context, tenantID shared.ID) (*DataQualityScorecard, error)
	// Risk Trend (RFC-005 Gap 4)
	GetRiskTrend(ctx context.Context, tenantID shared.ID, days int) ([]RiskTrendPoint, error)

	// Executive Summary (Phase 2)
	GetExecutiveSummary(ctx context.Context, tenantID shared.ID, days int) (*ExecutiveSummary, error)
	// MTTR Analytics (Phase 2)
	GetMTTRAnalytics(ctx context.Context, tenantID shared.ID, days int) (*MTTRAnalytics, error)
	// Process Metrics (Phase 2)
	GetProcessMetrics(ctx context.Context, tenantID shared.ID, days int) (*ProcessMetrics, error)
}

// DataQualityScorecard holds data quality metrics (RFC-005 Gap 5).
type DataQualityScorecard struct {
	AssetOwnershipPct  float64 `json:"asset_ownership_pct"`
	FindingEvidencePct float64 `json:"finding_evidence_pct"`
	MedianLastSeenDays float64 `json:"median_last_seen_days"`
	DeduplicationRate  float64 `json:"deduplication_rate"`
	TotalAssets        int     `json:"total_assets"`
	TotalFindings      int     `json:"total_findings"`
}

// AssetStatsData holds raw asset statistics from repository.
type AssetStatsData struct {
	Total            int
	ByType           map[string]int
	BySubType        map[string]int
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
// Uses optimized batched query (2 queries instead of 10+).
func (s *DashboardService) GetStats(ctx context.Context, tenantID shared.ID) (*DashboardStats, error) {
	// Batched query: all counts + activity in 2 queries
	all, err := s.repo.GetAllStats(ctx, tenantID)
	if err != nil {
		s.logger.Error("failed to get dashboard stats", "error", err, "tenant_id", tenantID)
		// Fallback to empty
		all = &DashboardAllStats{
			Assets:   AssetStatsData{ByType: make(map[string]int), ByStatus: make(map[string]int)},
			Findings: FindingStatsData{BySeverity: make(map[string]int), ByStatus: make(map[string]int)},
			Activity: []ActivityItem{},
		}
	}

	// Finding trend (separate query — different shape, efficient CTE)
	trend, err := s.repo.GetFindingTrend(ctx, tenantID, 6)
	if err != nil {
		s.logger.Error("failed to get finding trend", "error", err, "tenant_id", tenantID)
		trend = []FindingTrendPoint{}
	}

	return &DashboardStats{
		AssetCount:               all.Assets.Total,
		AssetsByType:             all.Assets.ByType,
		AssetsBySubType:          all.Assets.BySubType,
		AssetsByStatus:           all.Assets.ByStatus,
		AverageRiskScore:         all.Assets.AverageRiskScore,
		FindingCount:             all.Findings.Total,
		FindingsBySeverity:       all.Findings.BySeverity,
		FindingsByStatus:         all.Findings.ByStatus,
		OverdueFindings:          all.Findings.Overdue,
		AverageCVSS:              all.Findings.AverageCVSS,
		RepositoryCount:          all.Repos.Total,
		RepositoriesWithFindings: all.Repos.WithFindings,
		RecentActivity:           all.Activity,
		FindingTrend:             trend,
	}, nil
}

// GetMTTRMetrics returns MTTR (Mean Time To Remediate) in hours by severity.
func (s *DashboardService) GetMTTRMetrics(ctx context.Context, tenantID shared.ID) (map[string]float64, error) {
	return s.repo.GetMTTRMetrics(ctx, tenantID)
}

// GetRiskVelocity returns weekly new vs resolved finding counts.
func (s *DashboardService) GetRiskVelocity(ctx context.Context, tenantID shared.ID, weeks int) ([]RiskVelocityPoint, error) {
	return s.repo.GetRiskVelocity(ctx, tenantID, weeks)
}

// GetDataQualityScorecard returns data quality metrics (RFC-005 Gap 5).
func (s *DashboardService) GetDataQualityScorecard(ctx context.Context, tenantID shared.ID) (*DataQualityScorecard, error) {
	return s.repo.GetDataQualityScorecard(ctx, tenantID)
}

// GetRiskTrend returns risk snapshot time-series (RFC-005 Gap 4).
func (s *DashboardService) GetRiskTrend(ctx context.Context, tenantID shared.ID, days int) ([]RiskTrendPoint, error) {
	return s.repo.GetRiskTrend(ctx, tenantID, days)
}

// RiskTrendPoint represents a single point in a risk trend time-series.
type RiskTrendPoint struct {
	Date             string  `json:"date"`
	RiskScoreAvg     float64 `json:"risk_score_avg"`
	FindingsOpen     int     `json:"findings_open"`
	SLACompliancePct float64 `json:"sla_compliance_pct"`
	P0Open           int     `json:"p0_open"`
	P1Open           int     `json:"p1_open"`
	P2Open           int     `json:"p2_open"`
	P3Open           int     `json:"p3_open"`
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
		FindingTrend:             []FindingTrendPoint{},
	}, nil
}

// ExecutiveSummary holds executive-level metrics for a time period.
type ExecutiveSummary struct {
	Period            string    `json:"period"`
	RiskScoreCurrent  float64   `json:"risk_score_current"`
	RiskScoreChange   float64   `json:"risk_score_change"`
	FindingsTotal     int       `json:"findings_total"`
	FindingsResolved  int       `json:"findings_resolved_period"`
	FindingsNew       int       `json:"findings_new_period"`
	P0Open            int       `json:"p0_open"`
	P0Resolved        int       `json:"p0_resolved_period"`
	P1Open            int       `json:"p1_open"`
	P1Resolved        int       `json:"p1_resolved_period"`
	SLACompliancePct  float64   `json:"sla_compliance_pct"`
	SLABreached       int       `json:"sla_breached"`
	MTTRCriticalHrs   float64   `json:"mttr_critical_hours"`
	MTTRHighHrs       float64   `json:"mttr_high_hours"`
	CrownJewelsAtRisk int       `json:"crown_jewels_at_risk"`
	RegressionCount   int       `json:"regression_count"`
	RegressionRatePct float64   `json:"regression_rate_pct"`
	TopRisks          []TopRisk `json:"top_risks"`
}

// TopRisk represents a high-priority open finding for executive view.
type TopRisk struct {
	FindingTitle  string   `json:"title"`
	Severity      string   `json:"severity"`
	PriorityClass string   `json:"priority_class"`
	AssetName     string   `json:"asset_name"`
	EPSSScore     *float64 `json:"epss_score"`
	IsInKEV       bool     `json:"is_in_kev"`
}

// MTTRAnalytics holds MTTR breakdown by severity and priority class.
type MTTRAnalytics struct {
	BySeverity      map[string]float64 `json:"by_severity"`
	ByPriorityClass map[string]float64 `json:"by_priority_class"`
	Overall         float64            `json:"overall_hours"`
	SampleSize      int                `json:"sample_size"`
}

// ProcessMetrics holds process efficiency metrics.
type ProcessMetrics struct {
	ApprovalAvgHours     float64 `json:"approval_avg_hours"`
	ApprovalCount        int     `json:"approval_count"`
	RetestAvgHours       float64 `json:"retest_avg_hours"`
	RetestCount          int     `json:"retest_count"`
	StaleAssets          int     `json:"stale_assets"`
	StaleAssetsPct       float64 `json:"stale_assets_pct"`
	FindingsWithoutOwner int     `json:"findings_without_owner"`
	AvgTimeToAssignHours float64 `json:"avg_time_to_assign_hours"`
}

// GetProcessMetrics returns process efficiency metrics.
func (s *DashboardService) GetProcessMetrics(ctx context.Context, tenantID shared.ID, days int) (*ProcessMetrics, error) {
	return s.repo.GetProcessMetrics(ctx, tenantID, days)
}

// GetExecutiveSummary returns executive-level metrics for a time period.
func (s *DashboardService) GetExecutiveSummary(ctx context.Context, tenantID shared.ID, days int) (*ExecutiveSummary, error) {
	return s.repo.GetExecutiveSummary(ctx, tenantID, days)
}

// GetMTTRAnalytics returns MTTR breakdown by severity and priority class.
func (s *DashboardService) GetMTTRAnalytics(ctx context.Context, tenantID shared.ID, days int) (*MTTRAnalytics, error) {
	return s.repo.GetMTTRAnalytics(ctx, tenantID, days)
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
			FindingTrend:       []FindingTrendPoint{},
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
		FindingTrend:             []FindingTrendPoint{},
	}, nil
}

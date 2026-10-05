package unit

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/internal/app/module"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// =============================================================================
// Mock: DashboardStatsRepository
// =============================================================================

type mockDashboardRepo struct {
	// Error overrides
	getFindingStatsErr            error
	getRepositoryStatsErr         error
	getRecentActivityErr          error
	getFindingTrendErr            error
	getAllStatsErr                error
	getFilteredAssetStatsErr      error
	getFilteredFindingStatsErr    error
	getFilteredRepositoryStatsErr error
	getFilteredRecentActivityErr  error

	// Return data overrides
	findingStats   module.FindingStatsData
	repoStats      module.RepositoryStatsData
	recentActivity []module.ActivityItem
	findingTrend   []module.FindingTrendPoint
	allStats       *module.DashboardAllStats

	filteredAssetStats     module.AssetStatsData
	filteredFindingStats   module.FindingStatsData
	filteredRepoStats      module.RepositoryStatsData
	filteredRecentActivity []module.ActivityItem

	// Call tracking
	getAllStatsCalls               int
	getFindingTrendCalls           int
	getFilteredAssetStatsCalls     int
	getFilteredFindingStatsCalls   int
	getFilteredRepoStatsCalls      int
	getFilteredRecentActivityCalls int

	// Capture arguments
	lastTenantID  shared.ID
	lastTenantIDs []string
	lastLimit     int
	lastMonths    int
}

func newMockDashboardRepo() *mockDashboardRepo {
	return &mockDashboardRepo{}
}

func (m *mockDashboardRepo) GetFindingStats(_ context.Context, tenantID shared.ID) (module.FindingStatsData, error) {
	m.lastTenantID = tenantID
	if m.getFindingStatsErr != nil {
		return module.FindingStatsData{}, m.getFindingStatsErr
	}
	return m.findingStats, nil
}

func (m *mockDashboardRepo) GetRepositoryStats(_ context.Context, tenantID shared.ID) (module.RepositoryStatsData, error) {
	m.lastTenantID = tenantID
	if m.getRepositoryStatsErr != nil {
		return module.RepositoryStatsData{}, m.getRepositoryStatsErr
	}
	return m.repoStats, nil
}

func (m *mockDashboardRepo) GetRecentActivity(_ context.Context, tenantID shared.ID, _ *shared.DataScope, limit int) ([]module.ActivityItem, error) {
	m.lastTenantID = tenantID
	m.lastLimit = limit
	if m.getRecentActivityErr != nil {
		return nil, m.getRecentActivityErr
	}
	return m.recentActivity, nil
}

func (m *mockDashboardRepo) GetFindingTrend(_ context.Context, tenantID shared.ID, _ *shared.DataScope, months int) ([]module.FindingTrendPoint, error) {
	m.getFindingTrendCalls++
	m.lastTenantID = tenantID
	m.lastMonths = months
	if m.getFindingTrendErr != nil {
		return nil, m.getFindingTrendErr
	}
	return m.findingTrend, nil
}

func (m *mockDashboardRepo) GetAllStats(_ context.Context, tenantID shared.ID, _ *shared.DataScope) (*module.DashboardAllStats, error) {
	m.getAllStatsCalls++
	m.lastTenantID = tenantID
	if m.getAllStatsErr != nil {
		return nil, m.getAllStatsErr
	}
	return m.allStats, nil
}

func (m *mockDashboardRepo) GetFilteredAssetStats(_ context.Context, tenantIDs []string) (module.AssetStatsData, error) {
	m.getFilteredAssetStatsCalls++
	m.lastTenantIDs = tenantIDs
	if m.getFilteredAssetStatsErr != nil {
		return module.AssetStatsData{}, m.getFilteredAssetStatsErr
	}
	return m.filteredAssetStats, nil
}

func (m *mockDashboardRepo) GetFilteredFindingStats(_ context.Context, tenantIDs []string) (module.FindingStatsData, error) {
	m.getFilteredFindingStatsCalls++
	m.lastTenantIDs = tenantIDs
	if m.getFilteredFindingStatsErr != nil {
		return module.FindingStatsData{}, m.getFilteredFindingStatsErr
	}
	return m.filteredFindingStats, nil
}

func (m *mockDashboardRepo) GetFilteredRepositoryStats(_ context.Context, tenantIDs []string) (module.RepositoryStatsData, error) {
	m.getFilteredRepoStatsCalls++
	m.lastTenantIDs = tenantIDs
	if m.getFilteredRepositoryStatsErr != nil {
		return module.RepositoryStatsData{}, m.getFilteredRepositoryStatsErr
	}
	return m.filteredRepoStats, nil
}

func (m *mockDashboardRepo) GetFilteredRecentActivity(_ context.Context, tenantIDs, _ []string, _ string, limit int) ([]module.ActivityItem, error) {
	m.getFilteredRecentActivityCalls++
	m.lastTenantIDs = tenantIDs
	m.lastLimit = limit
	if m.getFilteredRecentActivityErr != nil {
		return nil, m.getFilteredRecentActivityErr
	}
	return m.filteredRecentActivity, nil
}

func (m *mockDashboardRepo) GetMTTRMetrics(_ context.Context, _ shared.ID, _ *shared.DataScope, _ int) (map[string]float64, error) {
	return map[string]float64{}, nil
}

func (m *mockDashboardRepo) GetRiskVelocity(_ context.Context, _ shared.ID, _ int) ([]module.RiskVelocityPoint, error) {
	return nil, nil
}

func (m *mockDashboardRepo) GetDataQualityScorecard(_ context.Context, _ shared.ID) (*module.DataQualityScorecard, error) {
	return &module.DataQualityScorecard{}, nil
}

func (m *mockDashboardRepo) GetRiskTrend(_ context.Context, _ shared.ID, _ int) ([]module.RiskTrendPoint, error) {
	return nil, nil
}

func (m *mockDashboardRepo) GetExecutiveSummary(_ context.Context, _ shared.ID, _ int) (*module.ExecutiveSummary, error) {
	return &module.ExecutiveSummary{}, nil
}

func (m *mockDashboardRepo) GetMTTRAnalytics(_ context.Context, _ shared.ID, _ *shared.DataScope, _ int) (*module.MTTRAnalytics, error) {
	return &module.MTTRAnalytics{BySeverity: map[string]float64{}, ByPriorityClass: map[string]float64{}}, nil
}

func (m *mockDashboardRepo) GetProcessMetrics(_ context.Context, _ shared.ID, _ int) (*module.ProcessMetrics, error) {
	return &module.ProcessMetrics{}, nil
}

func (m *mockDashboardRepo) GetProgramMetrics(_ context.Context, _ shared.ID, days int) (*module.ProgramMetrics, error) {
	return &module.ProgramMetrics{PeriodDays: days}, nil
}

// =============================================================================
// Helper functions
// =============================================================================

func newTestDashboardService(repo *mockDashboardRepo) *module.DashboardService {
	log := logger.NewNop()
	return module.NewDashboardService(repo, log)
}

func sampleAssetStats() module.AssetStatsData {
	return module.AssetStatsData{
		Total:            150,
		ByType:           map[string]int{"website": 50, "ip_address": 40, "domain": 60},
		ByStatus:         map[string]int{"active": 120, "inactive": 30},
		AverageRiskScore: 7.5,
	}
}

func sampleFindingStats() module.FindingStatsData {
	return module.FindingStatsData{
		Total:       300,
		BySeverity:  map[string]int{"critical": 10, "high": 40, "medium": 100, "low": 120, "info": 30},
		ByStatus:    map[string]int{"open": 200, "resolved": 80, "accepted": 20},
		Overdue:     15,
		AverageCVSS: 5.8,
	}
}

func sampleRepoStats() module.RepositoryStatsData {
	return module.RepositoryStatsData{
		Total:        25,
		WithFindings: 18,
	}
}

func sampleActivity() []module.ActivityItem {
	return []module.ActivityItem{
		{
			Type:        "finding_created",
			Title:       "New critical finding",
			Description: "SQL Injection in login",
			Timestamp:   time.Date(2026, 3, 9, 10, 0, 0, 0, time.UTC),
		},
		{
			Type:        "scan_completed",
			Title:       "Scan finished",
			Description: "Nuclei scan completed",
			Timestamp:   time.Date(2026, 3, 9, 9, 0, 0, 0, time.UTC),
		},
	}
}

func sampleTrend() []module.FindingTrendPoint {
	return []module.FindingTrendPoint{
		{Date: "Oct", Critical: 2, High: 5, Medium: 10, Low: 15, Info: 3},
		{Date: "Nov", Critical: 3, High: 7, Medium: 12, Low: 18, Info: 5},
		{Date: "Dec", Critical: 1, High: 4, Medium: 8, Low: 12, Info: 2},
		{Date: "Jan", Critical: 4, High: 8, Medium: 15, Low: 20, Info: 6},
		{Date: "Feb", Critical: 2, High: 6, Medium: 11, Low: 16, Info: 4},
		{Date: "Mar", Critical: 3, High: 9, Medium: 14, Low: 22, Info: 7},
	}
}

func sampleAllStats() *module.DashboardAllStats {
	return &module.DashboardAllStats{
		Assets:   sampleAssetStats(),
		Findings: sampleFindingStats(),
		Repos:    sampleRepoStats(),
		Activity: sampleActivity(),
	}
}

// =============================================================================
// Tests: GetStats (tenant-scoped, batched query)
// =============================================================================

func TestDashboardService_GetStats(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name            string
		setupRepo       func(*mockDashboardRepo)
		wantAssetCount  int
		wantFindCount   int
		wantRepoCount   int
		wantTrendLen    int
		wantActivityLen int
		wantAvgRisk     float64
		wantAvgCVSS     float64
		wantOverdue     int
		wantErr         bool
	}{
		{
			name: "happy path - all data returned",
			setupRepo: func(m *mockDashboardRepo) {
				m.allStats = sampleAllStats()
				m.findingTrend = sampleTrend()
			},
			wantAssetCount:  150,
			wantFindCount:   300,
			wantRepoCount:   25,
			wantTrendLen:    6,
			wantActivityLen: 2,
			wantAvgRisk:     7.5,
			wantAvgCVSS:     5.8,
			wantOverdue:     15,
		},
		{
			name: "GetAllStats error - returns empty stats with trend",
			setupRepo: func(m *mockDashboardRepo) {
				m.getAllStatsErr = errors.New("database connection lost")
				m.findingTrend = sampleTrend()
			},
			wantAssetCount:  0,
			wantFindCount:   0,
			wantRepoCount:   0,
			wantTrendLen:    6,
			wantActivityLen: 0,
			wantAvgRisk:     0,
			wantAvgCVSS:     0,
			wantOverdue:     0,
		},
		{
			name: "GetFindingTrend error - returns stats with empty trend",
			setupRepo: func(m *mockDashboardRepo) {
				m.allStats = sampleAllStats()
				m.getFindingTrendErr = errors.New("trend query timeout")
			},
			wantAssetCount:  150,
			wantFindCount:   300,
			wantRepoCount:   25,
			wantTrendLen:    0,
			wantActivityLen: 2,
			wantAvgRisk:     7.5,
			wantAvgCVSS:     5.8,
			wantOverdue:     15,
		},
		{
			name: "both queries fail - returns fully empty stats",
			setupRepo: func(m *mockDashboardRepo) {
				m.getAllStatsErr = errors.New("db down")
				m.getFindingTrendErr = errors.New("db down")
			},
			wantAssetCount:  0,
			wantFindCount:   0,
			wantRepoCount:   0,
			wantTrendLen:    0,
			wantActivityLen: 0,
			wantAvgRisk:     0,
			wantAvgCVSS:     0,
			wantOverdue:     0,
		},
		{
			name: "empty tenant - zero stats",
			setupRepo: func(m *mockDashboardRepo) {
				m.allStats = &module.DashboardAllStats{
					Assets:   module.AssetStatsData{ByType: make(map[string]int), ByStatus: make(map[string]int)},
					Findings: module.FindingStatsData{BySeverity: make(map[string]int), ByStatus: make(map[string]int)},
					Repos:    module.RepositoryStatsData{},
					Activity: []module.ActivityItem{},
				}
				m.findingTrend = []module.FindingTrendPoint{}
			},
			wantAssetCount:  0,
			wantFindCount:   0,
			wantRepoCount:   0,
			wantTrendLen:    0,
			wantActivityLen: 0,
			wantAvgRisk:     0,
			wantAvgCVSS:     0,
			wantOverdue:     0,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			repo := newMockDashboardRepo()
			tc.setupRepo(repo)
			svc := newTestDashboardService(repo)

			tenantID := shared.NewID()
			ctx := context.Background()

			stats, err := svc.GetStats(ctx, tenantID)

			if tc.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			// GetStats never returns an error (it falls back to empty)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if stats == nil {
				t.Fatal("expected non-nil stats")
			}

			if stats.AssetCount != tc.wantAssetCount {
				t.Errorf("AssetCount = %d, want %d", stats.AssetCount, tc.wantAssetCount)
			}
			if stats.FindingCount != tc.wantFindCount {
				t.Errorf("FindingCount = %d, want %d", stats.FindingCount, tc.wantFindCount)
			}
			if stats.RepositoryCount != tc.wantRepoCount {
				t.Errorf("RepositoryCount = %d, want %d", stats.RepositoryCount, tc.wantRepoCount)
			}
			if len(stats.FindingTrend) != tc.wantTrendLen {
				t.Errorf("FindingTrend length = %d, want %d", len(stats.FindingTrend), tc.wantTrendLen)
			}
			if len(stats.RecentActivity) != tc.wantActivityLen {
				t.Errorf("RecentActivity length = %d, want %d", len(stats.RecentActivity), tc.wantActivityLen)
			}
			if stats.AverageRiskScore != tc.wantAvgRisk {
				t.Errorf("AverageRiskScore = %f, want %f", stats.AverageRiskScore, tc.wantAvgRisk)
			}
			if stats.AverageCVSS != tc.wantAvgCVSS {
				t.Errorf("AverageCVSS = %f, want %f", stats.AverageCVSS, tc.wantAvgCVSS)
			}
			if stats.OverdueFindings != tc.wantOverdue {
				t.Errorf("OverdueFindings = %d, want %d", stats.OverdueFindings, tc.wantOverdue)
			}
		})
	}
}

func TestDashboardService_GetStats_TenantIsolation(t *testing.T) {
	t.Parallel()

	repo := newMockDashboardRepo()
	repo.allStats = sampleAllStats()
	repo.findingTrend = sampleTrend()
	svc := newTestDashboardService(repo)

	tenantID := shared.NewID()
	ctx := context.Background()

	_, err := svc.GetStats(ctx, tenantID)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify the correct tenant ID was passed to the repository
	if repo.lastTenantID != tenantID {
		t.Errorf("repo received tenantID = %v, want %v", repo.lastTenantID, tenantID)
	}

	// Verify both queries were called
	if repo.getAllStatsCalls != 1 {
		t.Errorf("GetAllStats called %d times, want 1", repo.getAllStatsCalls)
	}
	if repo.getFindingTrendCalls != 1 {
		t.Errorf("GetFindingTrend called %d times, want 1", repo.getFindingTrendCalls)
	}
}

func TestDashboardService_GetStats_TrendRequestsSixMonths(t *testing.T) {
	t.Parallel()

	repo := newMockDashboardRepo()
	repo.allStats = sampleAllStats()
	repo.findingTrend = sampleTrend()
	svc := newTestDashboardService(repo)

	_, err := svc.GetStats(context.Background(), shared.NewID())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if repo.lastMonths != 6 {
		t.Errorf("GetFindingTrend called with months = %d, want 6", repo.lastMonths)
	}
}

func TestDashboardService_GetStats_MapFields(t *testing.T) {
	t.Parallel()

	repo := newMockDashboardRepo()
	repo.allStats = sampleAllStats()
	repo.findingTrend = sampleTrend()
	svc := newTestDashboardService(repo)

	stats, err := svc.GetStats(context.Background(), shared.NewID())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify map fields are correctly propagated
	if stats.AssetsByType["website"] != 50 {
		t.Errorf("AssetsByType[website] = %d, want 50", stats.AssetsByType["website"])
	}
	if stats.AssetsByType["ip_address"] != 40 {
		t.Errorf("AssetsByType[ip_address] = %d, want 40", stats.AssetsByType["ip_address"])
	}
	if stats.AssetsByStatus["active"] != 120 {
		t.Errorf("AssetsByStatus[active] = %d, want 120", stats.AssetsByStatus["active"])
	}
	if stats.FindingsBySeverity["critical"] != 10 {
		t.Errorf("FindingsBySeverity[critical] = %d, want 10", stats.FindingsBySeverity["critical"])
	}
	if stats.FindingsByStatus["open"] != 200 {
		t.Errorf("FindingsByStatus[open] = %d, want 200", stats.FindingsByStatus["open"])
	}
	if stats.RepositoriesWithFindings != 18 {
		t.Errorf("RepositoriesWithFindings = %d, want 18", stats.RepositoriesWithFindings)
	}
}

// =============================================================================
// Tests: GetStatsForTenants (multi-tenant filtered)
// =============================================================================

func TestDashboardService_GetStatsForTenants(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name            string
		tenantIDs       []string
		setupRepo       func(*mockDashboardRepo)
		wantAssetCount  int
		wantFindCount   int
		wantRepoCount   int
		wantTrendLen    int
		wantActivityLen int
	}{
		{
			name:      "happy path - multiple tenants",
			tenantIDs: []string{"tenant-1", "tenant-2", "tenant-3"},
			setupRepo: func(m *mockDashboardRepo) {
				m.filteredAssetStats = sampleAssetStats()
				m.filteredFindingStats = sampleFindingStats()
				m.filteredRepoStats = sampleRepoStats()
				m.filteredRecentActivity = sampleActivity()
			},
			wantAssetCount:  150,
			wantFindCount:   300,
			wantRepoCount:   25,
			wantTrendLen:    0, // Filtered stats don't include trend
			wantActivityLen: 2,
		},
		{
			name:      "single tenant",
			tenantIDs: []string{"tenant-1"},
			setupRepo: func(m *mockDashboardRepo) {
				m.filteredAssetStats = module.AssetStatsData{
					Total:    10,
					ByType:   map[string]int{"website": 10},
					ByStatus: map[string]int{"active": 10},
				}
				m.filteredFindingStats = module.FindingStatsData{
					Total:      5,
					BySeverity: map[string]int{"high": 5},
					ByStatus:   map[string]int{"open": 5},
				}
				m.filteredRepoStats = module.RepositoryStatsData{Total: 2, WithFindings: 1}
				m.filteredRecentActivity = []module.ActivityItem{}
			},
			wantAssetCount:  10,
			wantFindCount:   5,
			wantRepoCount:   2,
			wantTrendLen:    0,
			wantActivityLen: 0,
		},
		{
			name:      "empty tenant IDs - returns empty stats immediately",
			tenantIDs: []string{},
			setupRepo: func(_ *mockDashboardRepo) {
				// No setup needed - should short-circuit
			},
			wantAssetCount:  0,
			wantFindCount:   0,
			wantRepoCount:   0,
			wantTrendLen:    0,
			wantActivityLen: 0,
		},
		{
			name:      "nil tenant IDs - returns empty stats immediately",
			tenantIDs: nil,
			setupRepo: func(_ *mockDashboardRepo) {
				// No setup needed - should short-circuit
			},
			wantAssetCount:  0,
			wantFindCount:   0,
			wantRepoCount:   0,
			wantTrendLen:    0,
			wantActivityLen: 0,
		},
		{
			name:      "all filtered queries fail - returns empty stats",
			tenantIDs: []string{"tenant-1"},
			setupRepo: func(m *mockDashboardRepo) {
				m.getFilteredAssetStatsErr = errors.New("db error")
				m.getFilteredFindingStatsErr = errors.New("db error")
				m.getFilteredRepositoryStatsErr = errors.New("db error")
				m.getFilteredRecentActivityErr = errors.New("db error")
			},
			wantAssetCount:  0,
			wantFindCount:   0,
			wantRepoCount:   0,
			wantTrendLen:    0,
			wantActivityLen: 0,
		},
		{
			name:      "partial failures - asset stats fail",
			tenantIDs: []string{"tenant-1", "tenant-2"},
			setupRepo: func(m *mockDashboardRepo) {
				m.getFilteredAssetStatsErr = errors.New("timeout")
				m.filteredFindingStats = sampleFindingStats()
				m.filteredRepoStats = sampleRepoStats()
				m.filteredRecentActivity = sampleActivity()
			},
			wantAssetCount:  0,
			wantFindCount:   300,
			wantRepoCount:   25,
			wantTrendLen:    0,
			wantActivityLen: 2,
		},
		{
			name:      "partial failures - finding stats fail",
			tenantIDs: []string{"tenant-1"},
			setupRepo: func(m *mockDashboardRepo) {
				m.filteredAssetStats = sampleAssetStats()
				m.getFilteredFindingStatsErr = errors.New("timeout")
				m.filteredRepoStats = sampleRepoStats()
				m.filteredRecentActivity = sampleActivity()
			},
			wantAssetCount:  150,
			wantFindCount:   0,
			wantRepoCount:   25,
			wantTrendLen:    0,
			wantActivityLen: 2,
		},
		{
			name:      "partial failures - repo stats fail",
			tenantIDs: []string{"tenant-1"},
			setupRepo: func(m *mockDashboardRepo) {
				m.filteredAssetStats = sampleAssetStats()
				m.filteredFindingStats = sampleFindingStats()
				m.getFilteredRepositoryStatsErr = errors.New("timeout")
				m.filteredRecentActivity = sampleActivity()
			},
			wantAssetCount:  150,
			wantFindCount:   300,
			wantRepoCount:   0,
			wantTrendLen:    0,
			wantActivityLen: 2,
		},
		{
			name:      "partial failures - activity fail",
			tenantIDs: []string{"tenant-1"},
			setupRepo: func(m *mockDashboardRepo) {
				m.filteredAssetStats = sampleAssetStats()
				m.filteredFindingStats = sampleFindingStats()
				m.filteredRepoStats = sampleRepoStats()
				m.getFilteredRecentActivityErr = errors.New("timeout")
			},
			wantAssetCount:  150,
			wantFindCount:   300,
			wantRepoCount:   25,
			wantTrendLen:    0,
			wantActivityLen: 0,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			repo := newMockDashboardRepo()
			tc.setupRepo(repo)
			svc := newTestDashboardService(repo)

			stats, err := svc.GetStatsForTenants(context.Background(), tc.tenantIDs)

			// GetStatsForTenants never returns an error
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if stats == nil {
				t.Fatal("expected non-nil stats")
			}

			if stats.AssetCount != tc.wantAssetCount {
				t.Errorf("AssetCount = %d, want %d", stats.AssetCount, tc.wantAssetCount)
			}
			if stats.FindingCount != tc.wantFindCount {
				t.Errorf("FindingCount = %d, want %d", stats.FindingCount, tc.wantFindCount)
			}
			if stats.RepositoryCount != tc.wantRepoCount {
				t.Errorf("RepositoryCount = %d, want %d", stats.RepositoryCount, tc.wantRepoCount)
			}
			if len(stats.FindingTrend) != tc.wantTrendLen {
				t.Errorf("FindingTrend length = %d, want %d", len(stats.FindingTrend), tc.wantTrendLen)
			}
			if len(stats.RecentActivity) != tc.wantActivityLen {
				t.Errorf("RecentActivity length = %d, want %d", len(stats.RecentActivity), tc.wantActivityLen)
			}
		})
	}
}

func TestDashboardService_GetStatsForTenants_EmptyTenantsSkipsRepo(t *testing.T) {
	t.Parallel()

	repo := newMockDashboardRepo()
	svc := newTestDashboardService(repo)

	stats, err := svc.GetStatsForTenants(context.Background(), []string{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify no repository calls were made when tenant list is empty
	if repo.getFilteredAssetStatsCalls != 0 {
		t.Errorf("GetFilteredAssetStats called %d times, want 0", repo.getFilteredAssetStatsCalls)
	}
	if repo.getFilteredFindingStatsCalls != 0 {
		t.Errorf("GetFilteredFindingStats called %d times, want 0", repo.getFilteredFindingStatsCalls)
	}
	if repo.getFilteredRepoStatsCalls != 0 {
		t.Errorf("GetFilteredRepositoryStats called %d times, want 0", repo.getFilteredRepoStatsCalls)
	}
	if repo.getFilteredRecentActivityCalls != 0 {
		t.Errorf("GetFilteredRecentActivity called %d times, want 0", repo.getFilteredRecentActivityCalls)
	}

	// Verify empty maps are initialized (not nil)
	if stats.AssetsByType == nil {
		t.Error("AssetsByType should be initialized, not nil")
	}
	if stats.AssetsByStatus == nil {
		t.Error("AssetsByStatus should be initialized, not nil")
	}
	if stats.FindingsBySeverity == nil {
		t.Error("FindingsBySeverity should be initialized, not nil")
	}
	if stats.FindingsByStatus == nil {
		t.Error("FindingsByStatus should be initialized, not nil")
	}
	if stats.RecentActivity == nil {
		t.Error("RecentActivity should be initialized, not nil")
	}
	if stats.FindingTrend == nil {
		t.Error("FindingTrend should be initialized, not nil")
	}
}

func TestDashboardService_GetStatsForTenants_PassesTenantIDs(t *testing.T) {
	t.Parallel()

	repo := newMockDashboardRepo()
	repo.filteredAssetStats = module.AssetStatsData{ByType: make(map[string]int), ByStatus: make(map[string]int)}
	repo.filteredFindingStats = module.FindingStatsData{BySeverity: make(map[string]int), ByStatus: make(map[string]int)}
	repo.filteredRepoStats = module.RepositoryStatsData{}
	repo.filteredRecentActivity = []module.ActivityItem{}
	svc := newTestDashboardService(repo)

	tenantIDs := []string{"aaa-111", "bbb-222", "ccc-333"}
	_, err := svc.GetStatsForTenants(context.Background(), tenantIDs)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify tenant IDs were passed correctly
	if len(repo.lastTenantIDs) != 3 {
		t.Fatalf("lastTenantIDs length = %d, want 3", len(repo.lastTenantIDs))
	}
	for i, want := range tenantIDs {
		if repo.lastTenantIDs[i] != want {
			t.Errorf("lastTenantIDs[%d] = %q, want %q", i, repo.lastTenantIDs[i], want)
		}
	}
}

func TestDashboardService_GetStatsForTenants_ActivityLimit(t *testing.T) {
	t.Parallel()

	repo := newMockDashboardRepo()
	repo.filteredAssetStats = module.AssetStatsData{ByType: make(map[string]int), ByStatus: make(map[string]int)}
	repo.filteredFindingStats = module.FindingStatsData{BySeverity: make(map[string]int), ByStatus: make(map[string]int)}
	repo.filteredRepoStats = module.RepositoryStatsData{}
	repo.filteredRecentActivity = []module.ActivityItem{}
	svc := newTestDashboardService(repo)

	_, err := svc.GetStatsForTenants(context.Background(), []string{"tenant-1"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if repo.lastLimit != 10 {
		t.Errorf("GetFilteredRecentActivity called with limit = %d, want 10", repo.lastLimit)
	}
}

func TestDashboardService_GetStatsForTenants_NoFindingTrend(t *testing.T) {
	t.Parallel()

	repo := newMockDashboardRepo()
	repo.filteredAssetStats = sampleAssetStats()
	repo.filteredFindingStats = sampleFindingStats()
	repo.filteredRepoStats = sampleRepoStats()
	repo.filteredRecentActivity = sampleActivity()
	svc := newTestDashboardService(repo)

	stats, err := svc.GetStatsForTenants(context.Background(), []string{"tenant-1"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// GetStatsForTenants always returns empty FindingTrend
	if stats.FindingTrend == nil {
		t.Error("FindingTrend should not be nil, expected empty slice")
	}
	if len(stats.FindingTrend) != 0 {
		t.Errorf("FindingTrend length = %d, want 0", len(stats.FindingTrend))
	}
}

// =============================================================================
// Tests: Cross-tenant isolation
// =============================================================================

func TestDashboardService_CrossTenantIsolation(t *testing.T) {
	t.Parallel()

	// Simulate two different tenants getting different stats
	tenantA := shared.NewID()
	tenantB := shared.NewID()

	// Tenant A service
	repoA := newMockDashboardRepo()
	repoA.allStats = &module.DashboardAllStats{
		Assets:   module.AssetStatsData{Total: 100, ByType: make(map[string]int), ByStatus: make(map[string]int)},
		Findings: module.FindingStatsData{Total: 50, BySeverity: make(map[string]int), ByStatus: make(map[string]int)},
		Repos:    module.RepositoryStatsData{Total: 10},
		Activity: []module.ActivityItem{},
	}
	repoA.findingTrend = []module.FindingTrendPoint{}
	svcA := newTestDashboardService(repoA)

	statsA, err := svcA.GetStats(context.Background(), tenantA)
	if err != nil {
		t.Fatalf("tenant A: unexpected error: %v", err)
	}

	// Tenant B service
	repoB := newMockDashboardRepo()
	repoB.allStats = &module.DashboardAllStats{
		Assets:   module.AssetStatsData{Total: 200, ByType: make(map[string]int), ByStatus: make(map[string]int)},
		Findings: module.FindingStatsData{Total: 500, BySeverity: make(map[string]int), ByStatus: make(map[string]int)},
		Repos:    module.RepositoryStatsData{Total: 30},
		Activity: []module.ActivityItem{},
	}
	repoB.findingTrend = []module.FindingTrendPoint{}
	svcB := newTestDashboardService(repoB)

	statsB, err := svcB.GetStats(context.Background(), tenantB)
	if err != nil {
		t.Fatalf("tenant B: unexpected error: %v", err)
	}

	// Verify different tenant IDs were passed
	if repoA.lastTenantID != tenantA {
		t.Errorf("repo A received tenantID = %v, want %v", repoA.lastTenantID, tenantA)
	}
	if repoB.lastTenantID != tenantB {
		t.Errorf("repo B received tenantID = %v, want %v", repoB.lastTenantID, tenantB)
	}

	// Verify different results
	if statsA.AssetCount == statsB.AssetCount {
		t.Error("tenant A and B should have different asset counts")
	}
	if statsA.FindingCount == statsB.FindingCount {
		t.Error("tenant A and B should have different finding counts")
	}
	if statsA.AssetCount != 100 {
		t.Errorf("tenant A AssetCount = %d, want 100", statsA.AssetCount)
	}
	if statsB.AssetCount != 200 {
		t.Errorf("tenant B AssetCount = %d, want 200", statsB.AssetCount)
	}
}

// =============================================================================
// Tests: NewDashboardService constructor
// =============================================================================

func TestNewDashboardService(t *testing.T) {
	t.Parallel()

	repo := newMockDashboardRepo()
	log := logger.NewNop()

	svc := module.NewDashboardService(repo, log)
	if svc == nil {
		t.Fatal("expected non-nil service")
	}
}

// =============================================================================
// Tests: Edge cases for map initialization on error fallback
// =============================================================================

func TestDashboardService_GetStats_ErrorFallbackMapsInitialized(t *testing.T) {
	t.Parallel()

	repo := newMockDashboardRepo()
	repo.getAllStatsErr = errors.New("total failure")
	repo.getFindingTrendErr = errors.New("trend failure")
	svc := newTestDashboardService(repo)

	stats, err := svc.GetStats(context.Background(), shared.NewID())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify maps are initialized (not nil) even on error fallback
	if stats.AssetsByType == nil {
		t.Error("AssetsByType should be initialized on error fallback")
	}
	if stats.AssetsByStatus == nil {
		t.Error("AssetsByStatus should be initialized on error fallback")
	}
	if stats.FindingsBySeverity == nil {
		t.Error("FindingsBySeverity should be initialized on error fallback")
	}
	if stats.FindingsByStatus == nil {
		t.Error("FindingsByStatus should be initialized on error fallback")
	}
	if stats.RecentActivity == nil {
		t.Error("RecentActivity should be initialized on error fallback")
	}
	if stats.FindingTrend == nil {
		t.Error("FindingTrend should be initialized on error fallback")
	}
}

// =============================================================================
// Tests: Large data sets
// =============================================================================

func TestDashboardService_GetStats_LargeDataSet(t *testing.T) {
	t.Parallel()

	// Simulate a tenant with many asset types and finding severities
	largeByType := make(map[string]int, 20)
	for i := 0; i < 20; i++ {
		largeByType["type_"+string(rune('a'+i))] = (i + 1) * 100
	}

	repo := newMockDashboardRepo()
	repo.allStats = &module.DashboardAllStats{
		Assets: module.AssetStatsData{
			Total:            100000,
			ByType:           largeByType,
			ByStatus:         map[string]int{"active": 80000, "inactive": 15000, "decommissioned": 5000},
			AverageRiskScore: 6.234,
		},
		Findings: module.FindingStatsData{
			Total:       500000,
			BySeverity:  map[string]int{"critical": 1000, "high": 10000, "medium": 100000, "low": 300000, "info": 89000},
			ByStatus:    map[string]int{"open": 200000, "resolved": 250000, "accepted": 50000},
			Overdue:     5000,
			AverageCVSS: 4.567,
		},
		Repos: module.RepositoryStatsData{
			Total:        5000,
			WithFindings: 3500,
		},
		Activity: make([]module.ActivityItem, 50),
	}
	repo.findingTrend = make([]module.FindingTrendPoint, 12) // 12 months
	svc := newTestDashboardService(repo)

	stats, err := svc.GetStats(context.Background(), shared.NewID())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if stats.AssetCount != 100000 {
		t.Errorf("AssetCount = %d, want 100000", stats.AssetCount)
	}
	if stats.FindingCount != 500000 {
		t.Errorf("FindingCount = %d, want 500000", stats.FindingCount)
	}
	if len(stats.AssetsByType) != 20 {
		t.Errorf("AssetsByType has %d entries, want 20", len(stats.AssetsByType))
	}
	if len(stats.RecentActivity) != 50 {
		t.Errorf("RecentActivity has %d entries, want 50", len(stats.RecentActivity))
	}
	if len(stats.FindingTrend) != 12 {
		t.Errorf("FindingTrend has %d entries, want 12", len(stats.FindingTrend))
	}
}

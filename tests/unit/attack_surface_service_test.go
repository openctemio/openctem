package unit

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/openctemio/api/internal/app"
	"github.com/openctemio/api/pkg/domain/asset"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/logger"
	"github.com/openctemio/api/pkg/pagination"
)

// =============================================================================
// Mock Asset Repository for Attack Surface Service
// =============================================================================

// mockAttackSurfaceRepo implements asset.Repository with configurable behavior
// specifically for AttackSurfaceService tests.
type mockAttackSurfaceRepo struct {
	// Count responses keyed by call index (0, 1, 2, ...)
	countResults []int64
	countErrors  []error
	countCall    int

	// List responses keyed by call index
	listResults []pagination.Result[*asset.Asset]
	listErrors  []error
	listCall    int

	// GetAverageRiskScore
	avgRiskScore    float64
	avgRiskScoreErr error

	// GetAssetTypeBreakdown
	breakdownResult map[string]asset.AssetTypeStats
	breakdownErr    error

	// Call tracking
	countFilters []asset.Filter
	listFilters  []asset.Filter
}

func newMockAttackSurfaceRepo() *mockAttackSurfaceRepo {
	return &mockAttackSurfaceRepo{
		countResults:    make([]int64, 0),
		countErrors:     make([]error, 0),
		listResults:     make([]pagination.Result[*asset.Asset], 0),
		listErrors:      make([]error, 0),
		countFilters:    make([]asset.Filter, 0),
		listFilters:     make([]asset.Filter, 0),
		breakdownResult: make(map[string]asset.AssetTypeStats),
	}
}

func (m *mockAttackSurfaceRepo) Count(_ context.Context, filter asset.Filter) (int64, error) {
	idx := m.countCall
	m.countCall++
	m.countFilters = append(m.countFilters, filter)

	if idx < len(m.countErrors) && m.countErrors[idx] != nil {
		return 0, m.countErrors[idx]
	}
	if idx < len(m.countResults) {
		return m.countResults[idx], nil
	}
	return 0, nil
}

func (m *mockAttackSurfaceRepo) List(
	_ context.Context,
	filter asset.Filter,
	_ asset.ListOptions,
	_ pagination.Pagination,
) (pagination.Result[*asset.Asset], error) {
	idx := m.listCall
	m.listCall++
	m.listFilters = append(m.listFilters, filter)

	if idx < len(m.listErrors) && m.listErrors[idx] != nil {
		return pagination.Result[*asset.Asset]{}, m.listErrors[idx]
	}
	if idx < len(m.listResults) {
		return m.listResults[idx], nil
	}
	return pagination.Result[*asset.Asset]{}, nil
}

func (m *mockAttackSurfaceRepo) GetAverageRiskScore(_ context.Context, _ shared.ID) (float64, error) {
	if m.avgRiskScoreErr != nil {
		return 0, m.avgRiskScoreErr
	}
	return m.avgRiskScore, nil
}

func (m *mockAttackSurfaceRepo) GetAssetTypeBreakdown(_ context.Context, _ shared.ID) (map[string]asset.AssetTypeStats, error) {
	if m.breakdownErr != nil {
		return nil, m.breakdownErr
	}
	return m.breakdownResult, nil
}

// Unused interface methods - return zero values.

func (m *mockAttackSurfaceRepo) Create(_ context.Context, _ *asset.Asset) error {
	return nil
}

func (m *mockAttackSurfaceRepo) GetByID(_ context.Context, _, _ shared.ID) (*asset.Asset, error) {
	return nil, shared.ErrNotFound
}

func (m *mockAttackSurfaceRepo) Update(_ context.Context, _ *asset.Asset) error {
	return nil
}

func (m *mockAttackSurfaceRepo) Delete(_ context.Context, _, _ shared.ID) error {
	return nil
}

func (m *mockAttackSurfaceRepo) ExistsByName(_ context.Context, _ shared.ID, _ string) (bool, error) {
	return false, nil
}

func (m *mockAttackSurfaceRepo) GetByExternalID(_ context.Context, _ shared.ID, _ asset.Provider, _ string) (*asset.Asset, error) {
	return nil, shared.ErrNotFound
}

func (m *mockAttackSurfaceRepo) GetByName(_ context.Context, _ shared.ID, _ string) (*asset.Asset, error) {
	return nil, shared.ErrNotFound
}

func (m *mockAttackSurfaceRepo) FindRepositoryByRepoName(_ context.Context, _ shared.ID, _ string) (*asset.Asset, error) {
	return nil, shared.ErrNotFound
}

func (m *mockAttackSurfaceRepo) FindRepositoryByFullName(_ context.Context, _ shared.ID, _ string) (*asset.Asset, error) {
	return nil, shared.ErrNotFound
}

func (m *mockAttackSurfaceRepo) FindByIP(_ context.Context, _ shared.ID, _ string) (*asset.Asset, error) {
	return nil, nil
}

func (m *mockAttackSurfaceRepo) FindByHostname(_ context.Context, _ shared.ID, _ string) (*asset.Asset, error) {
	return nil, nil
}

func (m *mockAttackSurfaceRepo) GetByNames(_ context.Context, _ shared.ID, _ []string) (map[string]*asset.Asset, error) {
	return make(map[string]*asset.Asset), nil
}

func (m *mockAttackSurfaceRepo) UpsertBatch(_ context.Context, _ []*asset.Asset) (int, int, error) {
	return 0, 0, nil
}

func (m *mockAttackSurfaceRepo) UpdateFindingCounts(_ context.Context, _ shared.ID, _ []shared.ID) error {
	return nil
}

func (m *mockAttackSurfaceRepo) ListDistinctTags(_ context.Context, _ shared.ID, _ string, _ []string, _ int) ([]string, error) {
	return []string{}, nil
}

func (m *mockAttackSurfaceRepo) BatchUpdateRiskScores(_ context.Context, _ shared.ID, _ []*asset.Asset) error {
	return nil
}

func (m *mockAttackSurfaceRepo) BulkUpdateStatus(_ context.Context, _ shared.ID, _ []shared.ID, _ asset.Status) (int64, error) {
	return 0, nil
}

func (m *mockAttackSurfaceRepo) GetAggregateStats(_ context.Context, _ shared.ID, _ []string, _ []string, _ string) (*asset.AggregateStats, error) {
	return &asset.AggregateStats{
		ByType:        make(map[string]int),
		ByStatus:      make(map[string]int),
		ByCriticality: make(map[string]int),
		ByScope:       make(map[string]int),
		ByExposure:    make(map[string]int),
	}, nil
}

func (m *mockAttackSurfaceRepo) GetPropertyFacets(_ context.Context, _ shared.ID, _ []string, _ string) ([]asset.PropertyFacet, error) {
	return nil, nil
}

func (m *mockAttackSurfaceRepo) ListAllNodes(_ context.Context, _ shared.ID) ([]asset.AssetNode, error) {
	return nil, nil
}

// =============================================================================
// Mock Relationship Repository for Attack Surface Service
// =============================================================================

type mockAttackSurfaceRelRepo struct{}

func (m *mockAttackSurfaceRelRepo) Create(_ context.Context, _ *asset.Relationship) error {
	return nil
}

func (m *mockAttackSurfaceRelRepo) GetByID(_ context.Context, _, _ shared.ID) (*asset.RelationshipWithAssets, error) {
	return nil, shared.ErrNotFound
}

func (m *mockAttackSurfaceRelRepo) Update(_ context.Context, _ *asset.Relationship) error {
	return nil
}

func (m *mockAttackSurfaceRelRepo) Delete(_ context.Context, _, _ shared.ID) error {
	return nil
}

func (m *mockAttackSurfaceRelRepo) ListByAsset(_ context.Context, _, _ shared.ID, _ asset.RelationshipFilter) ([]*asset.RelationshipWithAssets, int64, error) {
	return nil, 0, nil
}

func (m *mockAttackSurfaceRelRepo) Exists(_ context.Context, _, _, _ shared.ID, _ asset.RelationshipType) (bool, error) {
	return false, nil
}

func (m *mockAttackSurfaceRelRepo) CountByAsset(_ context.Context, _, _ shared.ID) (int64, error) {
	return 0, nil
}

func (m *mockAttackSurfaceRelRepo) CreateBatchIgnoreConflicts(_ context.Context, _ []*asset.Relationship) (int, error) {
	return 0, nil
}

func (m *mockAttackSurfaceRelRepo) CountByType(_ context.Context, _ shared.ID) (map[asset.RelationshipType]int64, error) {
	return nil, nil
}

func (m *mockAttackSurfaceRelRepo) ListAllEdges(_ context.Context, _ shared.ID) ([]asset.RelationshipEdge, error) {
	return nil, nil
}

// =============================================================================
// Helper Functions
// =============================================================================

func newTestAttackSurfaceService(repo *mockAttackSurfaceRepo) *app.AttackSurfaceService {
	log := logger.NewNop()
	relRepo := &mockAttackSurfaceRelRepo{}
	return app.NewAttackSurfaceService(repo, relRepo, log)
}

// makeAttackSurfaceAsset creates a test asset using Reconstitute with the given parameters.
func makeAttackSurfaceAsset(
	name string,
	assetType asset.AssetType,
	exposure asset.Exposure,
	criticality asset.Criticality,
	findingCount int,
	createdAt, updatedAt, lastSeen time.Time,
) *asset.Asset {
	return asset.Reconstitute(
		shared.NewID(),        // assetID
		serviceTenantID,       // tenantID
		nil,                   // parentID
		nil,                   // ownerID
		name,                  // name
		assetType,             // assetType
		criticality,           // criticality
		asset.StatusActive,    // status
		asset.ScopeExternal,   // scope
		exposure,              // exposure
		50,                    // riskScore
		findingCount,          // findingCount
		"test description",    // description
		nil,                   // tags
		nil,                   // metadata
		nil,                   // properties
		asset.ProviderManual,  // provider
		"",                    // externalID
		"",                    // classification
		asset.SyncStatusSynced, // syncStatus
		nil,                   // lastSyncedAt
		"",                    // syncError
		"",                    // discoverySource
		"",                    // discoveryTool
		nil,                   // discoveredAt
		nil,                   // complianceScope
		"",                    // dataClassification
		false,                 // piiDataExposed
		false,                 // phiDataExposed
		nil,                   // regulatoryOwnerID
		false,                 // isInternetAccessible
		nil,                   // exposureChangedAt
		asset.ExposureUnknown, // lastExposureLevel
		createdAt,             // firstSeen
		lastSeen,              // lastSeen
		createdAt,             // createdAt
		updatedAt,             // updatedAt
	)
}

// =============================================================================
// Tests
// =============================================================================

func TestAttackSurfaceService_GetStats_Success(t *testing.T) {
	repo := newMockAttackSurfaceRepo()
	repo.countResults = []int64{42, 10, 3}  // total, exposed, critical
	repo.countErrors = []error{nil, nil, nil}
	repo.avgRiskScore = 65.5
	repo.breakdownResult = map[string]asset.AssetTypeStats{
		"domain":  {Total: 15, Exposed: 5},
		"website": {Total: 10, Exposed: 3},
		"service": {Total: 8, Exposed: 2},
	}

	svc := newTestAttackSurfaceService(repo)
	stats, err := svc.GetStats(context.Background(), serviceTenantID)

	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if stats.TotalAssets != 42 {
		t.Errorf("expected TotalAssets=42, got %d", stats.TotalAssets)
	}
	if stats.ExposedServices != 10 {
		t.Errorf("expected ExposedServices=10, got %d", stats.ExposedServices)
	}
	if stats.CriticalExposures != 3 {
		t.Errorf("expected CriticalExposures=3, got %d", stats.CriticalExposures)
	}
	if stats.RiskScore != 65.5 {
		t.Errorf("expected RiskScore=65.5, got %f", stats.RiskScore)
	}
}

func TestAttackSurfaceService_GetStats_EmptyTenant(t *testing.T) {
	repo := newMockAttackSurfaceRepo()
	repo.countResults = []int64{0, 0, 0}
	repo.countErrors = []error{nil, nil, nil}
	repo.avgRiskScore = 0
	repo.breakdownResult = make(map[string]asset.AssetTypeStats)

	svc := newTestAttackSurfaceService(repo)
	stats, err := svc.GetStats(context.Background(), serviceTenantID)

	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if stats.TotalAssets != 0 {
		t.Errorf("expected TotalAssets=0, got %d", stats.TotalAssets)
	}
	if stats.ExposedServices != 0 {
		t.Errorf("expected ExposedServices=0, got %d", stats.ExposedServices)
	}
	if stats.CriticalExposures != 0 {
		t.Errorf("expected CriticalExposures=0, got %d", stats.CriticalExposures)
	}
	if stats.RiskScore != 0 {
		t.Errorf("expected RiskScore=0, got %f", stats.RiskScore)
	}
	if len(stats.ExposedServicesList) != 0 {
		t.Errorf("expected empty ExposedServicesList, got %d items", len(stats.ExposedServicesList))
	}
	if len(stats.RecentChanges) != 0 {
		t.Errorf("expected empty RecentChanges, got %d items", len(stats.RecentChanges))
	}
}

func TestAttackSurfaceService_GetStats_TotalCountError(t *testing.T) {
	repo := newMockAttackSurfaceRepo()
	repo.countResults = []int64{0, 5, 2}
	repo.countErrors = []error{errors.New("db connection error"), nil, nil}

	svc := newTestAttackSurfaceService(repo)
	stats, err := svc.GetStats(context.Background(), serviceTenantID)

	if err != nil {
		t.Fatalf("expected no error (graceful degradation), got %v", err)
	}
	if stats.TotalAssets != 0 {
		t.Errorf("expected TotalAssets=0 on error, got %d", stats.TotalAssets)
	}
	// Other counts should still work
	if stats.ExposedServices != 5 {
		t.Errorf("expected ExposedServices=5, got %d", stats.ExposedServices)
	}
	if stats.CriticalExposures != 2 {
		t.Errorf("expected CriticalExposures=2, got %d", stats.CriticalExposures)
	}
}

func TestAttackSurfaceService_GetStats_ExposedCountError(t *testing.T) {
	repo := newMockAttackSurfaceRepo()
	repo.countResults = []int64{100, 0, 5}
	repo.countErrors = []error{nil, errors.New("timeout"), nil}

	svc := newTestAttackSurfaceService(repo)
	stats, err := svc.GetStats(context.Background(), serviceTenantID)

	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if stats.TotalAssets != 100 {
		t.Errorf("expected TotalAssets=100, got %d", stats.TotalAssets)
	}
	if stats.ExposedServices != 0 {
		t.Errorf("expected ExposedServices=0 on error, got %d", stats.ExposedServices)
	}
	if stats.CriticalExposures != 5 {
		t.Errorf("expected CriticalExposures=5, got %d", stats.CriticalExposures)
	}
}

func TestAttackSurfaceService_GetStats_CriticalCountError(t *testing.T) {
	repo := newMockAttackSurfaceRepo()
	repo.countResults = []int64{100, 20, 0}
	repo.countErrors = []error{nil, nil, errors.New("query failed")}

	svc := newTestAttackSurfaceService(repo)
	stats, err := svc.GetStats(context.Background(), serviceTenantID)

	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if stats.TotalAssets != 100 {
		t.Errorf("expected TotalAssets=100, got %d", stats.TotalAssets)
	}
	if stats.ExposedServices != 20 {
		t.Errorf("expected ExposedServices=20, got %d", stats.ExposedServices)
	}
	if stats.CriticalExposures != 0 {
		t.Errorf("expected CriticalExposures=0 on error, got %d", stats.CriticalExposures)
	}
}

func TestAttackSurfaceService_GetStats_AverageRiskScoreError(t *testing.T) {
	repo := newMockAttackSurfaceRepo()
	repo.countResults = []int64{10, 5, 2}
	repo.countErrors = []error{nil, nil, nil}
	repo.avgRiskScoreErr = errors.New("avg calculation failed")

	svc := newTestAttackSurfaceService(repo)
	stats, err := svc.GetStats(context.Background(), serviceTenantID)

	if err != nil {
		t.Fatalf("expected no error (graceful degradation), got %v", err)
	}
	if stats.RiskScore != 0 {
		t.Errorf("expected RiskScore=0 on error, got %f", stats.RiskScore)
	}
	// Other fields should still be populated
	if stats.TotalAssets != 10 {
		t.Errorf("expected TotalAssets=10, got %d", stats.TotalAssets)
	}
}

func TestAttackSurfaceService_GetStats_BreakdownError(t *testing.T) {
	repo := newMockAttackSurfaceRepo()
	repo.countResults = []int64{10, 5, 2}
	repo.countErrors = []error{nil, nil, nil}
	repo.breakdownErr = errors.New("breakdown query failed")

	svc := newTestAttackSurfaceService(repo)
	stats, err := svc.GetStats(context.Background(), serviceTenantID)

	if err != nil {
		t.Fatalf("expected no error (graceful degradation), got %v", err)
	}

	// Breakdown should have 6 entries (all asset types) with zero values
	if len(stats.AssetBreakdown) != 6 {
		t.Fatalf("expected 6 breakdown entries, got %d", len(stats.AssetBreakdown))
	}
	for _, b := range stats.AssetBreakdown {
		if b.Total != 0 || b.Exposed != 0 {
			t.Errorf("expected zero counts for type %s on error, got total=%d exposed=%d",
				b.Type, b.Total, b.Exposed)
		}
	}
}

func TestAttackSurfaceService_GetStats_AssetBreakdownTypes(t *testing.T) {
	repo := newMockAttackSurfaceRepo()
	repo.countResults = []int64{50, 20, 5}
	repo.countErrors = []error{nil, nil, nil}
	repo.breakdownResult = map[string]asset.AssetTypeStats{
		"domain":        {Total: 10, Exposed: 3},
		"website":       {Total: 8, Exposed: 2},
		"service":       {Total: 12, Exposed: 7},
		"repository":    {Total: 5, Exposed: 0},
		"cloud_account": {Total: 3, Exposed: 1},
		"host":          {Total: 12, Exposed: 4},
	}

	svc := newTestAttackSurfaceService(repo)
	stats, err := svc.GetStats(context.Background(), serviceTenantID)

	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	expectedTypes := []string{"domain", "website", "service", "repository", "cloud_account", "host"}
	if len(stats.AssetBreakdown) != len(expectedTypes) {
		t.Fatalf("expected %d breakdown entries, got %d", len(expectedTypes), len(stats.AssetBreakdown))
	}

	for i, expected := range expectedTypes {
		if stats.AssetBreakdown[i].Type != expected {
			t.Errorf("breakdown[%d]: expected type=%s, got %s", i, expected, stats.AssetBreakdown[i].Type)
		}
	}

	// Verify specific values
	if stats.AssetBreakdown[0].Total != 10 || stats.AssetBreakdown[0].Exposed != 3 {
		t.Errorf("domain: expected total=10 exposed=3, got total=%d exposed=%d",
			stats.AssetBreakdown[0].Total, stats.AssetBreakdown[0].Exposed)
	}
	if stats.AssetBreakdown[2].Total != 12 || stats.AssetBreakdown[2].Exposed != 7 {
		t.Errorf("service: expected total=12 exposed=7, got total=%d exposed=%d",
			stats.AssetBreakdown[2].Total, stats.AssetBreakdown[2].Exposed)
	}
}

func TestAttackSurfaceService_GetStats_ExposedServicesList(t *testing.T) {
	now := time.Now().UTC()
	repo := newMockAttackSurfaceRepo()
	repo.countResults = []int64{10, 5, 2}
	repo.countErrors = []error{nil, nil, nil}

	testAsset1 := makeAttackSurfaceAsset("api.example.com", asset.AssetTypeService, asset.ExposurePublic,
		asset.CriticalityCritical, 5, now, now, now)
	testAsset2 := makeAttackSurfaceAsset("web.example.com", asset.AssetTypeWebsite, asset.ExposureRestricted,
		asset.CriticalityHigh, 3, now, now, now)

	// First List call is for exposed services, second is for recent changes
	repo.listResults = []pagination.Result[*asset.Asset]{
		{Data: []*asset.Asset{testAsset1, testAsset2}, Total: 2, Page: 1, PerPage: 5, TotalPages: 1},
		{Data: []*asset.Asset{}, Total: 0, Page: 1, PerPage: 5, TotalPages: 0},
	}

	svc := newTestAttackSurfaceService(repo)
	stats, err := svc.GetStats(context.Background(), serviceTenantID)

	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if len(stats.ExposedServicesList) != 2 {
		t.Fatalf("expected 2 exposed services, got %d", len(stats.ExposedServicesList))
	}

	svc1 := stats.ExposedServicesList[0]
	if svc1.Name != "api.example.com" {
		t.Errorf("expected name=api.example.com, got %s", svc1.Name)
	}
	if svc1.Type != "service" {
		t.Errorf("expected type=service, got %s", svc1.Type)
	}
	if svc1.Exposure != "public" {
		t.Errorf("expected exposure=public, got %s", svc1.Exposure)
	}
	if svc1.Criticality != "critical" {
		t.Errorf("expected criticality=critical, got %s", svc1.Criticality)
	}
	if svc1.FindingCount != 5 {
		t.Errorf("expected findingCount=5, got %d", svc1.FindingCount)
	}

	svc2 := stats.ExposedServicesList[1]
	if svc2.Exposure != "restricted" {
		t.Errorf("expected exposure=restricted, got %s", svc2.Exposure)
	}
}

func TestAttackSurfaceService_GetStats_ExposedServicesListError(t *testing.T) {
	repo := newMockAttackSurfaceRepo()
	repo.countResults = []int64{10, 5, 2}
	repo.countErrors = []error{nil, nil, nil}
	repo.listErrors = []error{errors.New("list failed"), nil}

	svc := newTestAttackSurfaceService(repo)
	stats, err := svc.GetStats(context.Background(), serviceTenantID)

	if err != nil {
		t.Fatalf("expected no error (graceful degradation), got %v", err)
	}
	if len(stats.ExposedServicesList) != 0 {
		t.Errorf("expected empty ExposedServicesList on error, got %d items", len(stats.ExposedServicesList))
	}
}

func TestAttackSurfaceService_GetStats_RecentChangesAdded(t *testing.T) {
	now := time.Now().UTC()
	// Asset created and updated at the same time = "added"
	addedAsset := makeAttackSurfaceAsset("new-service.example.com", asset.AssetTypeDomain, asset.ExposurePublic,
		asset.CriticalityMedium, 0, now, now, now)

	repo := newMockAttackSurfaceRepo()
	repo.countResults = []int64{1, 0, 0}
	repo.countErrors = []error{nil, nil, nil}
	// First List is for exposed services, second is for recent changes
	repo.listResults = []pagination.Result[*asset.Asset]{
		{Data: []*asset.Asset{}, Total: 0, Page: 1, PerPage: 5, TotalPages: 0},
		{Data: []*asset.Asset{addedAsset}, Total: 1, Page: 1, PerPage: 5, TotalPages: 1},
	}

	svc := newTestAttackSurfaceService(repo)
	stats, err := svc.GetStats(context.Background(), serviceTenantID)

	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if len(stats.RecentChanges) != 1 {
		t.Fatalf("expected 1 recent change, got %d", len(stats.RecentChanges))
	}
	if stats.RecentChanges[0].Type != "added" {
		t.Errorf("expected change type=added, got %s", stats.RecentChanges[0].Type)
	}
	if stats.RecentChanges[0].AssetName != "new-service.example.com" {
		t.Errorf("expected asset name=new-service.example.com, got %s", stats.RecentChanges[0].AssetName)
	}
	if stats.RecentChanges[0].AssetType != "domain" {
		t.Errorf("expected asset type=domain, got %s", stats.RecentChanges[0].AssetType)
	}
}

func TestAttackSurfaceService_GetStats_RecentChangesChanged(t *testing.T) {
	createdAt := time.Now().UTC().Add(-48 * time.Hour) // Created 2 days ago
	updatedAt := time.Now().UTC()                       // Updated now
	changedAsset := makeAttackSurfaceAsset("old-service.example.com", asset.AssetTypeHost, asset.ExposurePrivate,
		asset.CriticalityLow, 1, createdAt, updatedAt, updatedAt)

	repo := newMockAttackSurfaceRepo()
	repo.countResults = []int64{1, 0, 0}
	repo.countErrors = []error{nil, nil, nil}
	repo.listResults = []pagination.Result[*asset.Asset]{
		{Data: []*asset.Asset{}, Total: 0, Page: 1, PerPage: 5, TotalPages: 0},
		{Data: []*asset.Asset{changedAsset}, Total: 1, Page: 1, PerPage: 5, TotalPages: 1},
	}

	svc := newTestAttackSurfaceService(repo)
	stats, err := svc.GetStats(context.Background(), serviceTenantID)

	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if len(stats.RecentChanges) != 1 {
		t.Fatalf("expected 1 recent change, got %d", len(stats.RecentChanges))
	}
	if stats.RecentChanges[0].Type != "changed" {
		t.Errorf("expected change type=changed, got %s", stats.RecentChanges[0].Type)
	}
	if stats.RecentChanges[0].AssetType != "host" {
		t.Errorf("expected asset type=host, got %s", stats.RecentChanges[0].AssetType)
	}
}

func TestAttackSurfaceService_GetStats_RecentChangesError(t *testing.T) {
	repo := newMockAttackSurfaceRepo()
	repo.countResults = []int64{10, 5, 2}
	repo.countErrors = []error{nil, nil, nil}
	// Exposed services list succeeds, recent changes list fails
	repo.listErrors = []error{nil, errors.New("recent changes query failed")}
	repo.listResults = []pagination.Result[*asset.Asset]{
		{Data: []*asset.Asset{}, Total: 0, Page: 1, PerPage: 5, TotalPages: 0},
	}

	svc := newTestAttackSurfaceService(repo)
	stats, err := svc.GetStats(context.Background(), serviceTenantID)

	if err != nil {
		t.Fatalf("expected no error (graceful degradation), got %v", err)
	}
	if len(stats.RecentChanges) != 0 {
		t.Errorf("expected empty RecentChanges on error, got %d items", len(stats.RecentChanges))
	}
}

func TestAttackSurfaceService_GetStats_AllErrors(t *testing.T) {
	repo := newMockAttackSurfaceRepo()
	repo.countErrors = []error{
		errors.New("count total failed"),
		errors.New("count exposed failed"),
		errors.New("count critical failed"),
	}
	repo.avgRiskScoreErr = errors.New("avg risk failed")
	repo.breakdownErr = errors.New("breakdown failed")
	repo.listErrors = []error{
		errors.New("list exposed failed"),
		errors.New("list recent failed"),
	}

	svc := newTestAttackSurfaceService(repo)
	stats, err := svc.GetStats(context.Background(), serviceTenantID)

	// Should still return stats, not error
	if err != nil {
		t.Fatalf("expected no error even with all failures, got %v", err)
	}
	if stats.TotalAssets != 0 {
		t.Errorf("expected TotalAssets=0, got %d", stats.TotalAssets)
	}
	if stats.ExposedServices != 0 {
		t.Errorf("expected ExposedServices=0, got %d", stats.ExposedServices)
	}
	if stats.CriticalExposures != 0 {
		t.Errorf("expected CriticalExposures=0, got %d", stats.CriticalExposures)
	}
	if stats.RiskScore != 0 {
		t.Errorf("expected RiskScore=0, got %f", stats.RiskScore)
	}
	if len(stats.ExposedServicesList) != 0 {
		t.Errorf("expected empty ExposedServicesList, got %d items", len(stats.ExposedServicesList))
	}
	if len(stats.RecentChanges) != 0 {
		t.Errorf("expected empty RecentChanges, got %d items", len(stats.RecentChanges))
	}
	// Breakdown should still have 6 zero-value entries
	if len(stats.AssetBreakdown) != 6 {
		t.Errorf("expected 6 breakdown entries, got %d", len(stats.AssetBreakdown))
	}
}

func TestAttackSurfaceService_GetStats_CountFilterVerification(t *testing.T) {
	repo := newMockAttackSurfaceRepo()
	repo.countResults = []int64{100, 25, 5}
	repo.countErrors = []error{nil, nil, nil}

	svc := newTestAttackSurfaceService(repo)
	_, err := svc.GetStats(context.Background(), serviceTenantID)

	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	// Verify Count was called 3 times
	if repo.countCall != 3 {
		t.Fatalf("expected 3 Count calls, got %d", repo.countCall)
	}

	// First call: total assets (only tenantID filter)
	f0 := repo.countFilters[0]
	if f0.TenantID == nil {
		t.Error("first Count call should have TenantID set")
	}
	if len(f0.Exposures) != 0 {
		t.Error("first Count call should not have exposure filter")
	}

	// Second call: exposed services (tenantID + exposure=public)
	f1 := repo.countFilters[1]
	if f1.TenantID == nil {
		t.Error("second Count call should have TenantID set")
	}
	if len(f1.Exposures) != 1 || f1.Exposures[0] != asset.ExposurePublic {
		t.Errorf("second Count call should filter by ExposurePublic, got %v", f1.Exposures)
	}

	// Third call: critical exposures (tenantID + exposure=public + criticality=critical,high)
	f2 := repo.countFilters[2]
	if f2.TenantID == nil {
		t.Error("third Count call should have TenantID set")
	}
	if len(f2.Exposures) != 1 || f2.Exposures[0] != asset.ExposurePublic {
		t.Errorf("third Count call should filter by ExposurePublic, got %v", f2.Exposures)
	}
	if len(f2.Criticalities) != 2 {
		t.Fatalf("third Count call should filter by 2 criticalities, got %d", len(f2.Criticalities))
	}
	hasCritical := f2.Criticalities[0] == asset.CriticalityCritical || f2.Criticalities[1] == asset.CriticalityCritical
	hasHigh := f2.Criticalities[0] == asset.CriticalityHigh || f2.Criticalities[1] == asset.CriticalityHigh
	if !hasCritical || !hasHigh {
		t.Errorf("third Count call should filter by critical and high, got %v", f2.Criticalities)
	}
}

func TestAttackSurfaceService_GetStats_ListFilterVerification(t *testing.T) {
	repo := newMockAttackSurfaceRepo()
	repo.countResults = []int64{10, 5, 2}
	repo.countErrors = []error{nil, nil, nil}
	repo.listResults = []pagination.Result[*asset.Asset]{
		{Data: []*asset.Asset{}, Total: 0, Page: 1, PerPage: 5, TotalPages: 0},
		{Data: []*asset.Asset{}, Total: 0, Page: 1, PerPage: 5, TotalPages: 0},
	}

	svc := newTestAttackSurfaceService(repo)
	_, err := svc.GetStats(context.Background(), serviceTenantID)

	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	// Verify List was called 2 times
	if repo.listCall != 2 {
		t.Fatalf("expected 2 List calls, got %d", repo.listCall)
	}

	// First List call: exposed services (public + restricted)
	lf0 := repo.listFilters[0]
	if lf0.TenantID == nil {
		t.Error("first List call should have TenantID set")
	}
	if len(lf0.Exposures) != 2 {
		t.Fatalf("first List call should have 2 exposure filters, got %d", len(lf0.Exposures))
	}
	hasPublic := lf0.Exposures[0] == asset.ExposurePublic || lf0.Exposures[1] == asset.ExposurePublic
	hasRestricted := lf0.Exposures[0] == asset.ExposureRestricted || lf0.Exposures[1] == asset.ExposureRestricted
	if !hasPublic || !hasRestricted {
		t.Errorf("first List call should filter by public and restricted, got %v", lf0.Exposures)
	}

	// Second List call: recent changes (tenantID only)
	lf1 := repo.listFilters[1]
	if lf1.TenantID == nil {
		t.Error("second List call should have TenantID set")
	}
	if len(lf1.Exposures) != 0 {
		t.Errorf("second List call should not have exposure filter, got %v", lf1.Exposures)
	}
}

func TestAttackSurfaceService_GetStats_TrendsAreZero(t *testing.T) {
	repo := newMockAttackSurfaceRepo()
	repo.countResults = []int64{50, 15, 3}
	repo.countErrors = []error{nil, nil, nil}

	svc := newTestAttackSurfaceService(repo)
	stats, err := svc.GetStats(context.Background(), serviceTenantID)

	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if stats.TotalAssetsChange != 0 {
		t.Errorf("expected TotalAssetsChange=0, got %d", stats.TotalAssetsChange)
	}
	if stats.ExposedServicesChange != 0 {
		t.Errorf("expected ExposedServicesChange=0, got %d", stats.ExposedServicesChange)
	}
	if stats.CriticalExposuresChange != 0 {
		t.Errorf("expected CriticalExposuresChange=0, got %d", stats.CriticalExposuresChange)
	}
}

func TestAttackSurfaceService_GetStats_BreakdownMissingTypes(t *testing.T) {
	repo := newMockAttackSurfaceRepo()
	repo.countResults = []int64{5, 2, 1}
	repo.countErrors = []error{nil, nil, nil}
	// Only return data for "domain" - other types should have zero values
	repo.breakdownResult = map[string]asset.AssetTypeStats{
		"domain": {Total: 5, Exposed: 2},
	}

	svc := newTestAttackSurfaceService(repo)
	stats, err := svc.GetStats(context.Background(), serviceTenantID)

	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if len(stats.AssetBreakdown) != 6 {
		t.Fatalf("expected 6 breakdown entries, got %d", len(stats.AssetBreakdown))
	}

	// Domain should have values
	if stats.AssetBreakdown[0].Type != "domain" {
		t.Errorf("expected first breakdown type=domain, got %s", stats.AssetBreakdown[0].Type)
	}
	if stats.AssetBreakdown[0].Total != 5 {
		t.Errorf("expected domain total=5, got %d", stats.AssetBreakdown[0].Total)
	}

	// Other types should be zero
	for i := 1; i < 6; i++ {
		if stats.AssetBreakdown[i].Total != 0 {
			t.Errorf("expected %s total=0, got %d", stats.AssetBreakdown[i].Type, stats.AssetBreakdown[i].Total)
		}
		if stats.AssetBreakdown[i].Exposed != 0 {
			t.Errorf("expected %s exposed=0, got %d", stats.AssetBreakdown[i].Type, stats.AssetBreakdown[i].Exposed)
		}
	}
}

func TestAttackSurfaceService_GetStats_ExposedServiceConversion(t *testing.T) {
	now := time.Now().UTC()
	lastSeen := now.Add(-2 * time.Hour)

	testAsset := makeAttackSurfaceAsset("db.example.com", asset.AssetTypeService, asset.ExposurePublic,
		asset.CriticalityHigh, 12, now.Add(-24*time.Hour), now, lastSeen)

	repo := newMockAttackSurfaceRepo()
	repo.countResults = []int64{1, 1, 1}
	repo.countErrors = []error{nil, nil, nil}
	repo.listResults = []pagination.Result[*asset.Asset]{
		{Data: []*asset.Asset{testAsset}, Total: 1, Page: 1, PerPage: 5, TotalPages: 1},
		{Data: []*asset.Asset{}, Total: 0, Page: 1, PerPage: 5, TotalPages: 0},
	}

	svc := newTestAttackSurfaceService(repo)
	stats, err := svc.GetStats(context.Background(), serviceTenantID)

	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if len(stats.ExposedServicesList) != 1 {
		t.Fatalf("expected 1 exposed service, got %d", len(stats.ExposedServicesList))
	}

	es := stats.ExposedServicesList[0]
	if es.ID == "" {
		t.Error("expected non-empty ID")
	}
	if es.Name != "db.example.com" {
		t.Errorf("expected name=db.example.com, got %s", es.Name)
	}
	if es.Type != "service" {
		t.Errorf("expected type=service, got %s", es.Type)
	}
	if es.Exposure != "public" {
		t.Errorf("expected exposure=public, got %s", es.Exposure)
	}
	if es.Criticality != "high" {
		t.Errorf("expected criticality=high, got %s", es.Criticality)
	}
	if es.FindingCount != 12 {
		t.Errorf("expected findingCount=12, got %d", es.FindingCount)
	}
	if !es.LastSeen.Equal(lastSeen) {
		t.Errorf("expected lastSeen=%v, got %v", lastSeen, es.LastSeen)
	}
}

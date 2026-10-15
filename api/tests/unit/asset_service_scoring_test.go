package unit

import (
	"context"
	"errors"
	"testing"

	assetapp "github.com/openctemio/openctem/api/internal/app/asset"
	"github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/pagination"
)

// =============================================================================
// Mock ScoringConfigProvider
// =============================================================================

type mockScoringConfigProvider struct {
	config   *asset.RiskScoringConfig
	err      error
	getCalls int
}

func (m *mockScoringConfigProvider) GetScoringConfig(_ context.Context, _ shared.ID) (*asset.RiskScoringConfig, error) {
	m.getCalls++
	if m.err != nil {
		return nil, m.err
	}
	return m.config, nil
}

// =============================================================================
// Enhanced mock for batch updates
// =============================================================================

type mockBatchAssetRepository struct {
	MockAssetRepository
	batchUpdateCalls  int
	batchUpdateErr    error
	batchUpdatedCount int // tracks total assets sent to BatchUpdateRiskScores
}

func newMockBatchAssetRepository() *mockBatchAssetRepository {
	return &mockBatchAssetRepository{
		MockAssetRepository: MockAssetRepository{
			assets: make(map[string]*asset.Asset),
		},
	}
}

// GetByIDs lets the rescore path (UpdateRiskScores) read the mock's assets.
func (m *mockBatchAssetRepository) GetByIDs(_ context.Context, _ shared.ID, ids []shared.ID) (map[string]*asset.Asset, error) {
	out := make(map[string]*asset.Asset, len(ids))
	for _, id := range ids {
		if a, ok := m.assets[id.String()]; ok {
			out[id.String()] = a
		}
	}
	return out, nil
}

// rescoreAll scores every asset of the mock through the worker's path.
func rescoreAll(t *testing.T, svc *assetapp.AssetService, repo *mockBatchAssetRepository) {
	t.Helper()
	svc.SetRiskQueue(nil, repo)
	ids := make([]shared.ID, 0, len(repo.assets))
	for _, a := range repo.assets {
		ids = append(ids, a.ID())
	}
	if err := svc.UpdateRiskScores(context.Background(), serviceTenantID, ids); err != nil {
		t.Fatalf("rescore: %v", err)
	}
}

func (m *mockBatchAssetRepository) BatchUpdateRiskScores(_ context.Context, _ shared.ID, assets []*asset.Asset) error {
	m.batchUpdateCalls++
	if m.batchUpdateErr != nil {
		return m.batchUpdateErr
	}
	m.batchUpdatedCount += len(assets)
	return nil
}

// =============================================================================
// Helper
// =============================================================================

func newTestAssetService(repo asset.Repository) *assetapp.AssetService {
	log := logger.NewNop()
	return assetapp.NewAssetService(repo, log)
}

func makeTestAssetForService(exposure asset.Exposure, criticality asset.Criticality, findingCount int) *asset.Asset {
	a, _ := asset.NewAssetWithSubType("test-asset", asset.AssetTypeApplication, "website", criticality)
	_ = a.UpdateExposure(exposure)
	a.UpdateFindingCount(findingCount)
	a.SetTenantID(serviceTenantID)
	return a
}

// =============================================================================
// getScoringConfig Tests
// =============================================================================

func TestAssetService_ScoringConfig_NoProvider(t *testing.T) {
	repo := NewMockAssetRepository()
	svc := newTestAssetService(repo)

	// Without provider, CreateAsset should still work (uses legacy config)
	a := makeTestAssetForService(asset.ExposurePublic, asset.CriticalityCritical, 5)
	repo.assets[a.ID().String()] = a

	// Service should use legacy config internally — verify by checking the asset
	// can be created without a provider
	_, err := svc.CreateAsset(context.Background(), assetapp.CreateAssetInput{
		TenantID:    serviceTenantID.String(),
		Name:        "test-no-provider",
		Type:        "website",
		Criticality: "critical",
		Exposure:    "public",
	})
	if err != nil {
		t.Fatalf("CreateAsset without provider should work: %v", err)
	}
}

func TestAssetService_ScoringConfig_CacheMiss(t *testing.T) {
	repo := NewMockAssetRepository()
	svc := newTestAssetService(repo)

	customConfig := asset.LegacyRiskScoringConfig()
	customConfig.Weights.Exposure = 50
	customConfig.Weights.Criticality = 50
	customConfig.Weights.Findings = 0
	customConfig.Weights.CTEM = 0

	provider := &mockScoringConfigProvider{config: &customConfig}
	svc.SetScoringConfigProvider(provider)

	// CreateAsset triggers getScoringConfig — should be a cache miss
	_, err := svc.CreateAsset(context.Background(), assetapp.CreateAssetInput{
		TenantID:    serviceTenantID.String(),
		Name:        "test-cache-miss",
		Type:        "website",
		Criticality: "critical",
		Exposure:    "public",
	})
	if err != nil {
		t.Fatalf("CreateAsset with provider should work: %v", err)
	}
	if provider.getCalls != 1 {
		t.Errorf("expected 1 provider call (cache miss), got %d", provider.getCalls)
	}
}

func TestAssetService_ScoringConfig_CacheHit(t *testing.T) {
	repo := NewMockAssetRepository()
	svc := newTestAssetService(repo)

	customConfig := asset.LegacyRiskScoringConfig()
	provider := &mockScoringConfigProvider{config: &customConfig}
	svc.SetScoringConfigProvider(provider)

	// First call — cache miss
	_, _ = svc.CreateAsset(context.Background(), assetapp.CreateAssetInput{
		TenantID:    serviceTenantID.String(),
		Name:        "test-cache-hit-1",
		Type:        "website",
		Criticality: "critical",
		Exposure:    "public",
	})

	// Second call — should be cache hit
	_, _ = svc.CreateAsset(context.Background(), assetapp.CreateAssetInput{
		TenantID:    serviceTenantID.String(),
		Name:        "test-cache-hit-2",
		Type:        "website",
		Criticality: "critical",
		Exposure:    "public",
	})

	if provider.getCalls != 1 {
		t.Errorf("expected 1 provider call (second should be cache hit), got %d", provider.getCalls)
	}
}

func TestAssetService_ScoringConfig_CacheInvalidation(t *testing.T) {
	repo := NewMockAssetRepository()
	svc := newTestAssetService(repo)

	customConfig := asset.LegacyRiskScoringConfig()
	provider := &mockScoringConfigProvider{config: &customConfig}
	svc.SetScoringConfigProvider(provider)

	// First call — cache miss
	_, _ = svc.CreateAsset(context.Background(), assetapp.CreateAssetInput{
		TenantID:    serviceTenantID.String(),
		Name:        "test-invalidation-1",
		Type:        "website",
		Criticality: "critical",
		Exposure:    "public",
	})

	// Invalidate cache
	svc.InvalidateScoringConfigCache(serviceTenantID)

	// Next call — should be cache miss again
	_, _ = svc.CreateAsset(context.Background(), assetapp.CreateAssetInput{
		TenantID:    serviceTenantID.String(),
		Name:        "test-invalidation-2",
		Type:        "website",
		Criticality: "critical",
		Exposure:    "public",
	})

	if provider.getCalls != 2 {
		t.Errorf("expected 2 provider calls (after invalidation), got %d", provider.getCalls)
	}
}

func TestAssetService_ScoringConfig_ProviderError_FallbackToLegacy(t *testing.T) {
	repo := NewMockAssetRepository()
	svc := newTestAssetService(repo)

	provider := &mockScoringConfigProvider{err: errors.New("db error")}
	svc.SetScoringConfigProvider(provider)

	// Should not fail — falls back to legacy config
	_, err := svc.CreateAsset(context.Background(), assetapp.CreateAssetInput{
		TenantID:    serviceTenantID.String(),
		Name:        "test-provider-error",
		Type:        "website",
		Criticality: "critical",
		Exposure:    "public",
	})
	if err != nil {
		t.Fatalf("CreateAsset should work with provider error (legacy fallback): %v", err)
	}
}

// =============================================================================
// PreviewRiskImpact Tests
// =============================================================================

// The preview scores every asset with the new settings exactly as the worker
// will, counts band moves, and writes nothing.
func TestAssetService_PreviewRiskImpact(t *testing.T) {
	repo := newMockBatchAssetRepository()
	svc := newTestAssetService(repo)

	current := asset.LegacyRiskScoringConfig()
	svc.SetScoringConfigProvider(&mockScoringConfigProvider{config: &current})
	for i := range 5 {
		a := makeTestAssetForService(asset.ExposurePublic, asset.CriticalityCritical, i)
		a.SetTenantID(serviceTenantID)
		a.CalculateRiskScoreWithConfig(&current)
		repo.assets[a.ID().String()] = a
	}
	stored := map[string]int{}
	for id, a := range repo.assets {
		stored[id] = a.RiskScore()
	}

	newConfig := asset.LegacyRiskScoringConfig()
	newConfig.Weights = asset.ComponentWeights{Exposure: 10, Criticality: 10, Findings: 80, CTEM: 0}
	engine := asset.NewRiskScoringEngine(newConfig)

	impact, err := svc.PreviewRiskImpact(context.Background(), serviceTenantID, &newConfig)
	if err != nil {
		t.Fatalf("PreviewRiskImpact: %v", err)
	}
	if impact.TotalAssets != 5 {
		t.Fatalf("total = %d, want 5", impact.TotalAssets)
	}
	moved := 0
	for _, bc := range impact.BandChanges {
		moved += bc.Count
	}
	if moved != impact.ChangedBands {
		t.Fatalf("band changes sum %d != changed bands %d", moved, impact.ChangedBands)
	}
	for _, c := range impact.TopChanges {
		a := repo.assets[c.AssetID]
		if want := engine.CalculateScore(a); c.NewScore != want {
			t.Fatalf("preview score %d, engine %d", c.NewScore, want)
		}
		if c.CurrentLevel != current.Level(c.CurrentScore) || c.NewLevel != newConfig.Level(c.NewScore) {
			t.Fatalf("levels: %+v", c)
		}
	}
	if impact.Changed != len(impact.TopChanges) || impact.Raised+impact.Lowered != impact.Changed {
		t.Fatalf("counts: %+v", impact)
	}
	for id, a := range repo.assets {
		if a.RiskScore() != stored[id] {
			t.Fatal("the preview changed a stored score")
		}
	}
	if repo.batchUpdateCalls != 0 {
		t.Fatal("the preview wrote scores")
	}
}

// =============================================================================
// InvalidateScoringConfigCache Tests
// =============================================================================

func TestAssetService_InvalidateCache_NilCache(t *testing.T) {
	repo := NewMockAssetRepository()
	svc := newTestAssetService(repo)

	// No provider set — cache is nil. Should not panic.
	svc.InvalidateScoringConfigCache(serviceTenantID)
}

func TestAssetService_InvalidateCache_NonExistentTenant(t *testing.T) {
	repo := NewMockAssetRepository()
	svc := newTestAssetService(repo)

	customConfig := asset.LegacyRiskScoringConfig()
	provider := &mockScoringConfigProvider{config: &customConfig}
	svc.SetScoringConfigProvider(provider)

	// Invalidate a tenant that's not in cache — should not panic
	randomID := shared.NewID()
	svc.InvalidateScoringConfigCache(randomID)
}

// =============================================================================
// Config Provider Behavior
// =============================================================================

func TestAssetService_ScoringConfig_UsesCustomWeights(t *testing.T) {
	repo := NewMockAssetRepository()
	svc := newTestAssetService(repo)

	// Config with 100% exposure weight — should make exposure the dominant factor
	customConfig := asset.RiskScoringConfig{
		Weights:             asset.ComponentWeights{Exposure: 100, Criticality: 0, Findings: 0, CTEM: 0},
		ExposureScores:      asset.ExposureScoreMap{Public: 80, Private: 20},
		ExposureMultipliers: asset.ExposureMultiplierMap{Public: 1.0, Private: 1.0, Isolated: 1.0, Restricted: 1.0, Unknown: 1.0},
		CriticalityScores:   asset.CriticalityScoreMap{Critical: 100, High: 75, Medium: 50, Low: 25, None: 0},
		FindingImpact:       asset.FindingImpactConfig{Mode: "count", PerFindingPoints: 5, FindingCap: 100},
	}
	provider := &mockScoringConfigProvider{config: &customConfig}
	svc.SetScoringConfigProvider(provider)

	created, err := svc.CreateAsset(context.Background(), assetapp.CreateAssetInput{
		TenantID:    serviceTenantID.String(),
		Name:        "test-custom-weights",
		Type:        "website",
		Criticality: "critical",
		Exposure:    "public",
	})
	if err != nil {
		t.Fatalf("CreateAsset failed: %v", err)
	}

	// With 100% exposure weight and public=80, score should be 80
	if created.RiskScore() != 80 {
		t.Errorf("expected risk score 80 (100%% exposure, public=80), got %d", created.RiskScore())
	}
}

// Ensure timestamps are not from the future (basic sanity).
func TestAssetService_ScoringConfig_CacheTTLBehavior(t *testing.T) {
	// This test verifies the cache is initialized and behaves correctly
	repo := NewMockAssetRepository()
	svc := newTestAssetService(repo)

	customConfig := asset.LegacyRiskScoringConfig()
	provider := &mockScoringConfigProvider{config: &customConfig}
	svc.SetScoringConfigProvider(provider)

	// Trigger cache population
	_, _ = svc.CreateAsset(context.Background(), assetapp.CreateAssetInput{
		TenantID:    serviceTenantID.String(),
		Name:        "test-ttl-1",
		Type:        "website",
		Criticality: "medium",
	})

	// Within TTL — should use cache
	_, _ = svc.CreateAsset(context.Background(), assetapp.CreateAssetInput{
		TenantID:    serviceTenantID.String(),
		Name:        "test-ttl-2",
		Type:        "website",
		Criticality: "medium",
	})

	if provider.getCalls != 1 {
		t.Errorf("expected 1 provider call within TTL, got %d", provider.getCalls)
	}

	// We can't easily test TTL expiry without time manipulation,
	// but we can verify invalidation works as expected
	svc.InvalidateScoringConfigCache(serviceTenantID)

	_, _ = svc.CreateAsset(context.Background(), assetapp.CreateAssetInput{
		TenantID:    serviceTenantID.String(),
		Name:        "test-ttl-3",
		Type:        "website",
		Criticality: "medium",
	})

	if provider.getCalls != 2 {
		t.Errorf("expected 2 provider calls after invalidation, got %d", provider.getCalls)
	}
}

// =============================================================================
// Max Asset Count Limit Test
// =============================================================================

// mockLargeAssetRepo overrides List to return a large Total count without
// actually storing that many assets, to test the max asset limit.
type mockLargeAssetRepo struct {
	mockBatchAssetRepository
	overrideTotal int64 // if > 0, returned as Total in List result
}

func (m *mockLargeAssetRepo) List(
	ctx context.Context,
	f asset.Filter,
	opts asset.ListOptions,
	page pagination.Pagination,
) (pagination.Result[*asset.Asset], error) {
	result, err := m.mockBatchAssetRepository.MockAssetRepository.List(ctx, f, opts, page)
	if err != nil {
		return result, err
	}
	if m.overrideTotal > 0 {
		result.Total = m.overrideTotal
	}
	return result, nil
}

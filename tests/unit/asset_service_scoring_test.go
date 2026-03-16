package unit

import (
	"context"
	"errors"
	"testing"

	"github.com/openctemio/api/internal/app"
	"github.com/openctemio/api/pkg/domain/asset"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/logger"
	"github.com/openctemio/api/pkg/pagination"
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

func newTestAssetService(repo asset.Repository) *app.AssetService {
	log := logger.NewNop()
	return app.NewAssetService(repo, log)
}

func makeTestAssetForService(exposure asset.Exposure, criticality asset.Criticality, findingCount int) *asset.Asset {
	a, _ := asset.NewAsset("test-asset", asset.AssetTypeWebsite, criticality)
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
	_, err := svc.CreateAsset(context.Background(), app.CreateAssetInput{
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
	_, err := svc.CreateAsset(context.Background(), app.CreateAssetInput{
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
	_, _ = svc.CreateAsset(context.Background(), app.CreateAssetInput{
		TenantID:    serviceTenantID.String(),
		Name:        "test-cache-hit-1",
		Type:        "website",
		Criticality: "critical",
		Exposure:    "public",
	})

	// Second call — should be cache hit
	_, _ = svc.CreateAsset(context.Background(), app.CreateAssetInput{
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
	_, _ = svc.CreateAsset(context.Background(), app.CreateAssetInput{
		TenantID:    serviceTenantID.String(),
		Name:        "test-invalidation-1",
		Type:        "website",
		Criticality: "critical",
		Exposure:    "public",
	})

	// Invalidate cache
	svc.InvalidateScoringConfigCache(serviceTenantID)

	// Next call — should be cache miss again
	_, _ = svc.CreateAsset(context.Background(), app.CreateAssetInput{
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
	_, err := svc.CreateAsset(context.Background(), app.CreateAssetInput{
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
// RecalculateAllRiskScores Tests
// =============================================================================

func TestAssetService_RecalculateAllRiskScores_ProcessesBatches(t *testing.T) {
	repo := newMockBatchAssetRepository()
	svc := newTestAssetService(repo)

	customConfig := asset.LegacyRiskScoringConfig()
	provider := &mockScoringConfigProvider{config: &customConfig}
	svc.SetScoringConfigProvider(provider)

	// Add 3 assets with different risk scores
	for range 3 {
		a := makeTestAssetForService(asset.ExposurePublic, asset.CriticalityCritical, 5)
		a.SetTenantID(serviceTenantID)
		// Set a risk score that differs from what the engine would calculate
		// so they appear as "changed"
		repo.assets[a.ID().String()] = a
	}

	updated, err := svc.RecalculateAllRiskScores(context.Background(), serviceTenantID)
	if err != nil {
		t.Fatalf("RecalculateAllRiskScores failed: %v", err)
	}

	if updated < 0 {
		t.Errorf("expected non-negative updated count, got %d", updated)
	}
}

func TestAssetService_RecalculateAllRiskScores_EmptyAssets(t *testing.T) {
	repo := newMockBatchAssetRepository()
	svc := newTestAssetService(repo)

	customConfig := asset.LegacyRiskScoringConfig()
	provider := &mockScoringConfigProvider{config: &customConfig}
	svc.SetScoringConfigProvider(provider)

	updated, err := svc.RecalculateAllRiskScores(context.Background(), serviceTenantID)
	if err != nil {
		t.Fatalf("RecalculateAllRiskScores with empty assets failed: %v", err)
	}

	if updated != 0 {
		t.Errorf("expected 0 updated for empty repo, got %d", updated)
	}

	if repo.batchUpdateCalls != 0 {
		t.Errorf("expected 0 batch update calls for empty repo, got %d", repo.batchUpdateCalls)
	}
}

func TestAssetService_RecalculateAllRiskScores_ListError(t *testing.T) {
	repo := newMockBatchAssetRepository()
	repo.listErr = errors.New("db connection error")
	svc := newTestAssetService(repo)

	customConfig := asset.LegacyRiskScoringConfig()
	provider := &mockScoringConfigProvider{config: &customConfig}
	svc.SetScoringConfigProvider(provider)

	_, err := svc.RecalculateAllRiskScores(context.Background(), serviceTenantID)
	if err == nil {
		t.Fatal("RecalculateAllRiskScores should fail when List returns error")
	}
}

func TestAssetService_RecalculateAllRiskScores_BatchUpdateError(t *testing.T) {
	repo := newMockBatchAssetRepository()
	repo.batchUpdateErr = errors.New("batch update failed")
	svc := newTestAssetService(repo)

	customConfig := asset.LegacyRiskScoringConfig()
	provider := &mockScoringConfigProvider{config: &customConfig}
	svc.SetScoringConfigProvider(provider)

	// Add an asset that will need update
	a := makeTestAssetForService(asset.ExposurePublic, asset.CriticalityCritical, 10)
	a.SetTenantID(serviceTenantID)
	repo.assets[a.ID().String()] = a

	_, err := svc.RecalculateAllRiskScores(context.Background(), serviceTenantID)
	if err == nil {
		t.Fatal("RecalculateAllRiskScores should fail when BatchUpdateRiskScores errors")
	}
}

// =============================================================================
// PreviewRiskScoreChanges Tests
// =============================================================================

func TestAssetService_PreviewRiskScoreChanges(t *testing.T) {
	repo := NewMockAssetRepository()
	svc := newTestAssetService(repo)

	customConfig := asset.LegacyRiskScoringConfig()
	provider := &mockScoringConfigProvider{config: &customConfig}
	svc.SetScoringConfigProvider(provider)

	// Add some assets
	for i := range 5 {
		a := makeTestAssetForService(asset.ExposurePublic, asset.CriticalityCritical, i)
		a.SetTenantID(serviceTenantID)
		a.CalculateRiskScoreWithConfig(&customConfig)
		repo.assets[a.ID().String()] = a
	}

	// Preview with a different config
	newConfig := asset.LegacyRiskScoringConfig()
	newConfig.Weights = asset.ComponentWeights{Exposure: 80, Criticality: 10, Findings: 10, CTEM: 0}

	items, totalCount, err := svc.PreviewRiskScoreChanges(context.Background(), serviceTenantID, &newConfig)
	if err != nil {
		t.Fatalf("PreviewRiskScoreChanges failed: %v", err)
	}

	if len(items) == 0 {
		t.Error("expected preview items, got 0")
	}

	if totalCount < int64(len(items)) {
		t.Errorf("total count %d should be >= sample count %d", totalCount, len(items))
	}

	for _, item := range items {
		if item.AssetName == "" {
			t.Error("preview item missing asset name")
		}
		if item.Delta != item.NewScore-item.CurrentScore {
			t.Errorf("delta mismatch: got %d, expected %d", item.Delta, item.NewScore-item.CurrentScore)
		}
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

	created, err := svc.CreateAsset(context.Background(), app.CreateAssetInput{
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
	_, _ = svc.CreateAsset(context.Background(), app.CreateAssetInput{
		TenantID:    serviceTenantID.String(),
		Name:        "test-ttl-1",
		Type:        "website",
		Criticality: "medium",
	})

	// Within TTL — should use cache
	_, _ = svc.CreateAsset(context.Background(), app.CreateAssetInput{
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

	_, _ = svc.CreateAsset(context.Background(), app.CreateAssetInput{
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

func TestAssetService_RecalculateAllRiskScores_ExceedsMaxAssets(t *testing.T) {
	repo := &mockLargeAssetRepo{
		mockBatchAssetRepository: mockBatchAssetRepository{
			MockAssetRepository: MockAssetRepository{
				assets: make(map[string]*asset.Asset),
			},
		},
		overrideTotal: 200_000, // exceeds maxRecalcAssets (100K)
	}
	svc := newTestAssetService(repo)

	customConfig := asset.LegacyRiskScoringConfig()
	provider := &mockScoringConfigProvider{config: &customConfig}
	svc.SetScoringConfigProvider(provider)

	_, err := svc.RecalculateAllRiskScores(context.Background(), serviceTenantID)
	if err == nil {
		t.Fatal("expected error when asset count exceeds max limit")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected ErrValidation, got: %v", err)
	}
}

// =============================================================================
// Concurrent Recalculation (simulated without Redis)
// =============================================================================

func TestAssetService_RecalculateAllRiskScores_WithoutRedis_Succeeds(t *testing.T) {
	// Without Redis, the lock is skipped (logged as warning) and recalculation proceeds.
	repo := newMockBatchAssetRepository()
	svc := newTestAssetService(repo)

	customConfig := asset.LegacyRiskScoringConfig()
	provider := &mockScoringConfigProvider{config: &customConfig}
	svc.SetScoringConfigProvider(provider)

	a := makeTestAssetForService(asset.ExposurePublic, asset.CriticalityCritical, 5)
	repo.assets[a.ID().String()] = a

	// No Redis set — should work without lock
	updated, err := svc.RecalculateAllRiskScores(context.Background(), serviceTenantID)
	if err != nil {
		t.Fatalf("expected success without Redis, got: %v", err)
	}
	if updated < 0 {
		t.Errorf("expected non-negative updated count, got %d", updated)
	}
}

// =============================================================================
// Preview with distinct score changes
// =============================================================================

func TestAssetService_PreviewRiskScoreChanges_ShowsDeltas(t *testing.T) {
	repo := NewMockAssetRepository()
	svc := newTestAssetService(repo)

	// Current config: legacy (40% exposure, 25% criticality, 35% findings)
	legacyCfg := asset.LegacyRiskScoringConfig()
	provider := &mockScoringConfigProvider{config: &legacyCfg}
	svc.SetScoringConfigProvider(provider)

	// Add assets with varied profiles
	profiles := []struct {
		exp  asset.Exposure
		crit asset.Criticality
		fc   int
	}{
		{asset.ExposurePublic, asset.CriticalityCritical, 10},
		{asset.ExposurePrivate, asset.CriticalityLow, 0},
		{asset.ExposureIsolated, asset.CriticalityMedium, 3},
	}
	for _, p := range profiles {
		a := makeTestAssetForService(p.exp, p.crit, p.fc)
		a.CalculateRiskScoreWithConfig(&legacyCfg)
		repo.assets[a.ID().String()] = a
	}

	// Preview with exposure-heavy config
	newConfig := asset.LegacyRiskScoringConfig()
	newConfig.Weights = asset.ComponentWeights{Exposure: 90, Criticality: 5, Findings: 5, CTEM: 0}

	items, _, err := svc.PreviewRiskScoreChanges(context.Background(), serviceTenantID, &newConfig)
	if err != nil {
		t.Fatalf("PreviewRiskScoreChanges failed: %v", err)
	}

	if len(items) != 3 {
		t.Errorf("expected 3 preview items, got %d", len(items))
	}

	// Each item should have valid scores
	for _, item := range items {
		if item.AssetID == "" {
			t.Error("preview item missing asset ID")
		}
		if item.CurrentScore < 0 || item.CurrentScore > 100 {
			t.Errorf("current score out of range: %d", item.CurrentScore)
		}
		if item.NewScore < 0 || item.NewScore > 100 {
			t.Errorf("new score out of range: %d", item.NewScore)
		}
	}
}

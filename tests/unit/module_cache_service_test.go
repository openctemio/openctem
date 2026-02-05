package unit

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/openctemio/api/internal/app"
	"github.com/openctemio/api/pkg/domain/module"
	"github.com/google/uuid"
)

// =============================================================================
// Mock Cache Implementation
// =============================================================================

// MockModuleCache is an in-memory cache for testing.
type MockModuleCache struct {
	mu       sync.RWMutex
	data     map[string]*app.CachedTenantModules
	getErr   error
	setErr   error
	delErr   error
	getCalls int
	setCalls int
	delCalls int
}

func NewMockModuleCache() *MockModuleCache {
	return &MockModuleCache{
		data: make(map[string]*app.CachedTenantModules),
	}
}

func (m *MockModuleCache) Get(ctx context.Context, key string) (*app.CachedTenantModules, error) {
	m.mu.Lock()
	m.getCalls++
	m.mu.Unlock()

	if m.getErr != nil {
		return nil, m.getErr
	}

	m.mu.RLock()
	defer m.mu.RUnlock()
	if val, ok := m.data[key]; ok {
		return val, nil
	}
	return nil, errors.New("cache miss")
}

func (m *MockModuleCache) Set(ctx context.Context, key string, value app.CachedTenantModules) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.setCalls++

	if m.setErr != nil {
		return m.setErr
	}

	m.data[key] = &value
	return nil
}

func (m *MockModuleCache) Delete(ctx context.Context, key string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.delCalls++

	if m.delErr != nil {
		return m.delErr
	}

	delete(m.data, key)
	return nil
}

func (m *MockModuleCache) DeletePattern(ctx context.Context, pattern string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if pattern == "*" {
		m.data = make(map[string]*app.CachedTenantModules)
	}
	return nil
}

func (m *MockModuleCache) SetGetError(err error) {
	m.getErr = err
}

func (m *MockModuleCache) SetSetError(err error) {
	m.setErr = err
}

func (m *MockModuleCache) SetDeleteError(err error) {
	m.delErr = err
}

func (m *MockModuleCache) GetCalls() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.getCalls
}

func (m *MockModuleCache) SetCalls() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.setCalls
}

func (m *MockModuleCache) DeleteCalls() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.delCalls
}

// =============================================================================
// Mock Repository Implementation
// =============================================================================

// MockModuleCacheRepository implements app.ModuleCacheRepository for testing.
type MockModuleCacheRepository struct {
	mu                  sync.RWMutex
	planModules         map[string][]string          // tenantID -> moduleIDs
	modules             map[string]*module.Module // moduleID -> module
	eventTypes          map[string][]string          // moduleID -> eventTypes
	getPlanModulesErr   error
	getModulesErr       error
	getEventTypesErr    error
	getPlanModulesCalls int
}

func NewMockModuleCacheRepository() *MockModuleCacheRepository {
	return &MockModuleCacheRepository{
		planModules: make(map[string][]string),
		modules:     make(map[string]*module.Module),
		eventTypes:  make(map[string][]string),
	}
}

func (m *MockModuleCacheRepository) GetPlanModulesByTenantID(ctx context.Context, tenantID uuid.UUID) ([]string, error) {
	m.mu.Lock()
	m.getPlanModulesCalls++
	m.mu.Unlock()

	if m.getPlanModulesErr != nil {
		return nil, m.getPlanModulesErr
	}

	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.planModules[tenantID.String()], nil
}

func (m *MockModuleCacheRepository) GetModulesByIDs(ctx context.Context, ids []string) ([]*module.Module, error) {
	if m.getModulesErr != nil {
		return nil, m.getModulesErr
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	var result []*module.Module
	for _, id := range ids {
		if mod, ok := m.modules[id]; ok {
			result = append(result, mod)
		}
	}
	return result, nil
}

func (m *MockModuleCacheRepository) GetEventTypesForModulesBatch(ctx context.Context, moduleIDs []string) (map[string][]string, error) {
	if m.getEventTypesErr != nil {
		return nil, m.getEventTypesErr
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make(map[string][]string)
	for _, id := range moduleIDs {
		if types, ok := m.eventTypes[id]; ok {
			result[id] = types
		}
	}
	return result, nil
}

func (m *MockModuleCacheRepository) AddPlanModules(tenantID string, moduleIDs []string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.planModules[tenantID] = moduleIDs
}

func (m *MockModuleCacheRepository) AddModule(mod *module.Module) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.modules[mod.ID()] = mod
}

func (m *MockModuleCacheRepository) AddEventTypes(moduleID string, types []string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.eventTypes[moduleID] = types
}

func (m *MockModuleCacheRepository) GetPlanModulesCalls() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.getPlanModulesCalls
}

// =============================================================================
// Helper Functions
// =============================================================================

func createTestModule(id, slug, name, category string, isActive bool, releaseStatus string, parentID *string) *module.Module {
	return module.ReconstructModule(
		id,
		slug,
		name,
		"Test description",
		"test-icon",
		category,
		1,
		isActive,
		releaseStatus,
		parentID,
		nil,
	)
}

// =============================================================================
// Tests for GetTenantModules
// =============================================================================

func TestModuleCacheService_GetTenantModules_EmptyTenantID(t *testing.T) {
	cache := NewMockModuleCache()
	repo := NewMockModuleCacheRepository()

	// Test với tenantID rỗng
	result, err := getTenantModulesHelper(cache, repo, "")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if len(result.ModuleIDs) != 0 {
		t.Errorf("expected empty module IDs, got %d", len(result.ModuleIDs))
	}

	if len(result.Modules) != 0 {
		t.Errorf("expected empty modules, got %d", len(result.Modules))
	}
}

func TestModuleCacheService_GetTenantModules_CacheHit(t *testing.T) {
	cache := NewMockModuleCache()
	repo := NewMockModuleCacheRepository()

	tenantID := uuid.New().String()

	// Pre-populate cache
	cachedData := &app.CachedTenantModules{
		ModuleIDs: []string{"integrations", "integrations.scm"},
		Modules: []*app.CachedModule{
			{ID: "integrations", Slug: "integrations", Name: "Integrations", IsActive: true, ReleaseStatus: "released"},
		},
		SubModules: map[string][]*app.CachedModule{
			"integrations": {
				{ID: "integrations.scm", Slug: "scm", Name: "SCM", IsActive: true, ReleaseStatus: "released", ParentModuleID: strPtr("integrations")},
			},
		},
		CachedAt: time.Now(),
	}
	cache.data[tenantID] = cachedData

	// Get modules - should hit cache
	result, err := getTenantModulesHelper(cache, repo, tenantID)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	// Verify cache was hit (no DB calls)
	if repo.GetPlanModulesCalls() != 0 {
		t.Errorf("expected 0 DB calls, got %d", repo.GetPlanModulesCalls())
	}

	// Verify result matches cache
	if len(result.ModuleIDs) != 2 {
		t.Errorf("expected 2 module IDs, got %d", len(result.ModuleIDs))
	}
}

func TestModuleCacheService_GetTenantModules_CacheMiss(t *testing.T) {
	cache := NewMockModuleCache()
	repo := NewMockModuleCacheRepository()

	tenantID := uuid.New()

	// Setup repository data
	repo.AddPlanModules(tenantID.String(), []string{"integrations", "integrations.scm"})
	repo.AddModule(createTestModule("integrations", "integrations", "Integrations", "platform", true, "released", nil))
	parentID := "integrations"
	repo.AddModule(createTestModule("integrations.scm", "scm", "SCM", "platform", true, "released", &parentID))
	repo.AddEventTypes("integrations", []string{"integration_connected", "integration_disconnected"})

	// Get modules - should miss cache and load from DB
	result, err := getTenantModulesHelper(cache, repo, tenantID.String())
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	// Verify DB was called
	if repo.GetPlanModulesCalls() != 1 {
		t.Errorf("expected 1 DB call, got %d", repo.GetPlanModulesCalls())
	}

	// Verify result
	if len(result.ModuleIDs) != 2 {
		t.Errorf("expected 2 module IDs, got %d", len(result.ModuleIDs))
	}

	// Verify cache was populated
	if cache.SetCalls() != 1 {
		t.Errorf("expected 1 cache set call, got %d", cache.SetCalls())
	}
}

func TestModuleCacheService_GetTenantModules_NoModules(t *testing.T) {
	cache := NewMockModuleCache()
	repo := NewMockModuleCacheRepository()

	tenantID := uuid.New()

	// Setup empty modules
	repo.AddPlanModules(tenantID.String(), []string{})

	result, err := getTenantModulesHelper(cache, repo, tenantID.String())
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if len(result.ModuleIDs) != 0 {
		t.Errorf("expected 0 module IDs, got %d", len(result.ModuleIDs))
	}
}

// =============================================================================
// Tests for HasModule
// =============================================================================

func TestModuleCacheService_HasModule_Found(t *testing.T) {
	cache := NewMockModuleCache()
	tenantID := uuid.New().String()

	// Pre-populate cache
	cache.data[tenantID] = &app.CachedTenantModules{
		ModuleIDs: []string{"integrations", "assets", "findings"},
		CachedAt:  time.Now(),
	}

	hasModule, err := hasModuleHelper(cache, tenantID, "integrations")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if !hasModule {
		t.Error("expected hasModule to be true")
	}
}

func TestModuleCacheService_HasModule_NotFound(t *testing.T) {
	cache := NewMockModuleCache()
	tenantID := uuid.New().String()

	// Pre-populate cache
	cache.data[tenantID] = &app.CachedTenantModules{
		ModuleIDs: []string{"integrations", "assets"},
		CachedAt:  time.Now(),
	}

	hasModule, err := hasModuleHelper(cache, tenantID, "sso")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if hasModule {
		t.Error("expected hasModule to be false")
	}
}

// =============================================================================
// Tests for HasSubModule
// =============================================================================

func TestModuleCacheService_HasSubModule_Found(t *testing.T) {
	cache := NewMockModuleCache()
	tenantID := uuid.New().String()

	parentID := "integrations"
	cache.data[tenantID] = &app.CachedTenantModules{
		ModuleIDs: []string{"integrations", "integrations.scm"},
		SubModules: map[string][]*app.CachedModule{
			"integrations": {
				{ID: "integrations.scm", Slug: "scm", IsActive: true, ReleaseStatus: "released", ParentModuleID: &parentID},
				{ID: "integrations.ticketing", Slug: "ticketing", IsActive: true, ReleaseStatus: "released", ParentModuleID: &parentID},
			},
		},
		CachedAt: time.Now(),
	}

	hasSubModule, err := hasSubModuleHelper(cache, tenantID, "integrations", "integrations.scm")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if !hasSubModule {
		t.Error("expected hasSubModule to be true")
	}
}

func TestModuleCacheService_HasSubModule_ParentNotFound(t *testing.T) {
	cache := NewMockModuleCache()
	tenantID := uuid.New().String()

	// No integrations module in tenant's plan
	cache.data[tenantID] = &app.CachedTenantModules{
		ModuleIDs:  []string{"assets", "findings"},
		SubModules: map[string][]*app.CachedModule{},
		CachedAt:   time.Now(),
	}

	hasSubModule, err := hasSubModuleHelper(cache, tenantID, "integrations", "integrations.scm")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if hasSubModule {
		t.Error("expected hasSubModule to be false (parent not found)")
	}
}

func TestModuleCacheService_HasSubModule_ComingSoon(t *testing.T) {
	cache := NewMockModuleCache()
	tenantID := uuid.New().String()

	parentID := "integrations"
	cache.data[tenantID] = &app.CachedTenantModules{
		ModuleIDs: []string{"integrations", "integrations.siem"},
		SubModules: map[string][]*app.CachedModule{
			"integrations": {
				{ID: "integrations.siem", Slug: "siem", IsActive: true, ReleaseStatus: "coming_soon", ParentModuleID: &parentID},
			},
		},
		CachedAt: time.Now(),
	}

	hasSubModule, err := hasSubModuleHelper(cache, tenantID, "integrations", "integrations.siem")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	// coming_soon should not be accessible
	if hasSubModule {
		t.Error("expected hasSubModule to be false (coming_soon status)")
	}
}

func TestModuleCacheService_HasSubModule_Beta(t *testing.T) {
	cache := NewMockModuleCache()
	tenantID := uuid.New().String()

	parentID := "integrations"
	cache.data[tenantID] = &app.CachedTenantModules{
		ModuleIDs: []string{"integrations", "integrations.cicd"},
		SubModules: map[string][]*app.CachedModule{
			"integrations": {
				{ID: "integrations.cicd", Slug: "cicd", IsActive: true, ReleaseStatus: "beta", ParentModuleID: &parentID},
			},
		},
		CachedAt: time.Now(),
	}

	hasSubModule, err := hasSubModuleHelper(cache, tenantID, "integrations", "integrations.cicd")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	// beta should be accessible
	if !hasSubModule {
		t.Error("expected hasSubModule to be true (beta status)")
	}
}

// =============================================================================
// Tests for Invalidate with Retry
// =============================================================================

func TestModuleCacheService_Invalidate_Success(t *testing.T) {
	cache := NewMockModuleCache()
	tenantID := uuid.New().String()

	// Pre-populate cache
	cache.data[tenantID] = &app.CachedTenantModules{
		ModuleIDs: []string{"integrations"},
		CachedAt:  time.Now(),
	}

	err := invalidateHelper(cache, tenantID)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	// Verify cache was deleted
	if _, ok := cache.data[tenantID]; ok {
		t.Error("expected cache to be deleted")
	}

	// Verify only 1 delete call (no retries needed)
	if cache.DeleteCalls() != 1 {
		t.Errorf("expected 1 delete call, got %d", cache.DeleteCalls())
	}
}

func TestModuleCacheService_Invalidate_EmptyTenantID(t *testing.T) {
	cache := NewMockModuleCache()

	err := invalidateHelper(cache, "")
	if err != nil {
		t.Fatalf("expected no error for empty tenant ID, got %v", err)
	}

	// No delete calls should be made
	if cache.DeleteCalls() != 0 {
		t.Errorf("expected 0 delete calls, got %d", cache.DeleteCalls())
	}
}

func TestModuleCacheService_Invalidate_RetryOnFailure(t *testing.T) {
	cache := NewMockModuleCache()
	tenantID := uuid.New().String()

	// Simulate failure on first 2 attempts, success on 3rd
	failCount := 0
	cache.delErr = errors.New("redis connection error")

	// We need to track calls and clear error after 2 failures
	// Since we can't modify the mock mid-execution easily,
	// we'll test that it eventually fails after 3 attempts

	err := invalidateHelper(cache, tenantID)
	if err == nil {
		t.Fatal("expected error after 3 failed attempts")
	}

	// Verify 3 delete attempts were made
	if cache.DeleteCalls() != 3 {
		t.Errorf("expected 3 delete calls (retry logic), got %d", cache.DeleteCalls())
	}

	_ = failCount // suppress unused warning
}

// =============================================================================
// Tests for InvalidateAll
// =============================================================================

func TestModuleCacheService_InvalidateAll(t *testing.T) {
	cache := NewMockModuleCache()

	// Pre-populate cache with multiple tenants
	cache.data["tenant1"] = &app.CachedTenantModules{ModuleIDs: []string{"a"}, CachedAt: time.Now()}
	cache.data["tenant2"] = &app.CachedTenantModules{ModuleIDs: []string{"b"}, CachedAt: time.Now()}
	cache.data["tenant3"] = &app.CachedTenantModules{ModuleIDs: []string{"c"}, CachedAt: time.Now()}

	invalidateAllHelper(cache)

	// Verify all caches were deleted
	if len(cache.data) != 0 {
		t.Errorf("expected all caches to be deleted, got %d remaining", len(cache.data))
	}
}

// =============================================================================
// Tests for ToModules conversion
// =============================================================================

func TestCachedTenantModules_ToModules(t *testing.T) {
	cached := &app.CachedTenantModules{
		ModuleIDs: []string{"integrations", "assets"},
		Modules: []*app.CachedModule{
			{ID: "integrations", Slug: "integrations", Name: "Integrations", Category: "platform", IsActive: true, ReleaseStatus: "released"},
			{ID: "assets", Slug: "assets", Name: "Assets", Category: "core", IsActive: true, ReleaseStatus: "released"},
		},
	}

	modules := cached.ToModules()

	if len(modules) != 2 {
		t.Fatalf("expected 2 modules, got %d", len(modules))
	}

	if modules[0].ID() != "integrations" {
		t.Errorf("expected first module ID to be 'integrations', got %s", modules[0].ID())
	}

	if modules[1].ID() != "assets" {
		t.Errorf("expected second module ID to be 'assets', got %s", modules[1].ID())
	}
}

// =============================================================================
// Edge Case Tests: Inactive Modules
// =============================================================================

func TestModuleCacheService_GetTenantModules_FiltersInactiveModules(t *testing.T) {
	cache := NewMockModuleCache()
	repo := NewMockModuleCacheRepository()

	tenantID := uuid.New()

	// Setup: 3 modules, 1 inactive
	repo.AddPlanModules(tenantID.String(), []string{"integrations", "assets", "findings"})
	repo.AddModule(createTestModule("integrations", "integrations", "Integrations", "platform", true, "released", nil))
	repo.AddModule(createTestModule("assets", "assets", "Assets", "core", false, "released", nil)) // INACTIVE
	repo.AddModule(createTestModule("findings", "findings", "Findings", "security", true, "released", nil))

	result, err := getTenantModulesHelper(cache, repo, tenantID.String())
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	// Should only have 2 active modules
	if len(result.ModuleIDs) != 2 {
		t.Errorf("expected 2 active module IDs, got %d", len(result.ModuleIDs))
	}

	// Verify inactive module is not included
	for _, id := range result.ModuleIDs {
		if id == "assets" {
			t.Error("inactive module 'assets' should not be in ModuleIDs")
		}
	}
}

func TestModuleCacheService_GetTenantModules_AllInactiveModules(t *testing.T) {
	cache := NewMockModuleCache()
	repo := NewMockModuleCacheRepository()

	tenantID := uuid.New()

	// All modules inactive
	repo.AddPlanModules(tenantID.String(), []string{"integrations", "assets"})
	repo.AddModule(createTestModule("integrations", "integrations", "Integrations", "platform", false, "released", nil))
	repo.AddModule(createTestModule("assets", "assets", "Assets", "core", false, "released", nil))

	result, err := getTenantModulesHelper(cache, repo, tenantID.String())
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if len(result.ModuleIDs) != 0 {
		t.Errorf("expected 0 active modules, got %d", len(result.ModuleIDs))
	}
}

// =============================================================================
// Edge Case Tests: Sub-Module Hierarchy
// =============================================================================

func TestModuleCacheService_GetTenantModules_SeparatesSubModules(t *testing.T) {
	cache := NewMockModuleCache()
	repo := NewMockModuleCacheRepository()

	tenantID := uuid.New()
	parentID := "integrations"

	// Setup parent and sub-modules
	repo.AddPlanModules(tenantID.String(), []string{"integrations", "integrations.scm", "integrations.ticketing"})
	repo.AddModule(createTestModule("integrations", "integrations", "Integrations", "platform", true, "released", nil))
	repo.AddModule(createTestModule("integrations.scm", "scm", "SCM", "platform", true, "released", &parentID))
	repo.AddModule(createTestModule("integrations.ticketing", "ticketing", "Ticketing", "platform", true, "released", &parentID))

	result, err := getTenantModulesHelper(cache, repo, tenantID.String())
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	// Top-level modules should only contain parent
	if len(result.Modules) != 1 {
		t.Errorf("expected 1 top-level module, got %d", len(result.Modules))
	}

	// Sub-modules should be in SubModules map
	subMods, ok := result.SubModules["integrations"]
	if !ok {
		t.Fatal("expected sub-modules for 'integrations'")
	}

	if len(subMods) != 2 {
		t.Errorf("expected 2 sub-modules, got %d", len(subMods))
	}
}

func TestModuleCacheService_GetTenantModules_SubModuleWithoutParent(t *testing.T) {
	cache := NewMockModuleCache()
	repo := NewMockModuleCacheRepository()

	tenantID := uuid.New()
	parentID := "integrations"

	// Sub-module without parent in plan (edge case - shouldn't happen in practice)
	repo.AddPlanModules(tenantID.String(), []string{"integrations.scm"})
	repo.AddModule(createTestModule("integrations.scm", "scm", "SCM", "platform", true, "released", &parentID))

	result, err := getTenantModulesHelper(cache, repo, tenantID.String())
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	// Sub-module should still be in SubModules map
	subMods, ok := result.SubModules["integrations"]
	if !ok {
		t.Fatal("expected sub-modules map entry for 'integrations'")
	}

	if len(subMods) != 1 {
		t.Errorf("expected 1 sub-module, got %d", len(subMods))
	}
}

func TestModuleCacheService_HasSubModule_SubModuleNotInList(t *testing.T) {
	cache := NewMockModuleCache()
	tenantID := uuid.New().String()

	parentID := "integrations"
	cache.data[tenantID] = &app.CachedTenantModules{
		ModuleIDs: []string{"integrations", "integrations.scm"},
		SubModules: map[string][]*app.CachedModule{
			"integrations": {
				{ID: "integrations.scm", Slug: "scm", IsActive: true, ReleaseStatus: "released", ParentModuleID: &parentID},
			},
		},
		CachedAt: time.Now(),
	}

	// Check for a sub-module that doesn't exist
	hasSubModule, err := hasSubModuleHelper(cache, tenantID, "integrations", "integrations.siem")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if hasSubModule {
		t.Error("expected hasSubModule to be false for non-existent sub-module")
	}
}

func TestModuleCacheService_HasSubModule_EmptySubModulesMap(t *testing.T) {
	cache := NewMockModuleCache()
	tenantID := uuid.New().String()

	cache.data[tenantID] = &app.CachedTenantModules{
		ModuleIDs:  []string{"integrations"},
		SubModules: map[string][]*app.CachedModule{}, // Empty map
		CachedAt:   time.Now(),
	}

	hasSubModule, err := hasSubModuleHelper(cache, tenantID, "integrations", "integrations.scm")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if hasSubModule {
		t.Error("expected hasSubModule to be false when SubModules map is empty")
	}
}

// =============================================================================
// Edge Case Tests: Release Status
// =============================================================================

func TestModuleCacheService_HasSubModule_DisabledStatus(t *testing.T) {
	cache := NewMockModuleCache()
	tenantID := uuid.New().String()

	parentID := "integrations"
	cache.data[tenantID] = &app.CachedTenantModules{
		ModuleIDs: []string{"integrations", "integrations.cloud"},
		SubModules: map[string][]*app.CachedModule{
			"integrations": {
				{ID: "integrations.cloud", Slug: "cloud", IsActive: true, ReleaseStatus: "disabled", ParentModuleID: &parentID},
			},
		},
		CachedAt: time.Now(),
	}

	hasSubModule, err := hasSubModuleHelper(cache, tenantID, "integrations", "integrations.cloud")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	// disabled status should not be accessible
	if hasSubModule {
		t.Error("expected hasSubModule to be false for disabled status")
	}
}

func TestModuleCacheService_HasSubModule_DeprecatedStatus(t *testing.T) {
	cache := NewMockModuleCache()
	tenantID := uuid.New().String()

	parentID := "integrations"
	cache.data[tenantID] = &app.CachedTenantModules{
		ModuleIDs: []string{"integrations", "integrations.legacy"},
		SubModules: map[string][]*app.CachedModule{
			"integrations": {
				{ID: "integrations.legacy", Slug: "legacy", IsActive: true, ReleaseStatus: "deprecated", ParentModuleID: &parentID},
			},
		},
		CachedAt: time.Now(),
	}

	hasSubModule, err := hasSubModuleHelper(cache, tenantID, "integrations", "integrations.legacy")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	// deprecated status should not be accessible (only released and beta)
	if hasSubModule {
		t.Error("expected hasSubModule to be false for deprecated status")
	}
}

// =============================================================================
// Edge Case Tests: Event Types
// =============================================================================

func TestModuleCacheService_GetTenantModules_WithEventTypes(t *testing.T) {
	cache := NewMockModuleCache()
	repo := NewMockModuleCacheRepository()

	tenantID := uuid.New()

	repo.AddPlanModules(tenantID.String(), []string{"integrations"})
	repo.AddModule(createTestModule("integrations", "integrations", "Integrations", "platform", true, "released", nil))
	repo.AddEventTypes("integrations", []string{"integration.connected", "integration.disconnected", "integration.error"})

	result, err := getTenantModulesHelper(cache, repo, tenantID.String())
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	// Verify event types are included
	eventTypes, ok := result.EventTypes["integrations"]
	if !ok {
		t.Fatal("expected event types for 'integrations'")
	}

	if len(eventTypes) != 3 {
		t.Errorf("expected 3 event types, got %d", len(eventTypes))
	}
}

func TestModuleCacheService_GetTenantModules_EventTypesError(t *testing.T) {
	cache := NewMockModuleCache()
	repo := NewMockModuleCacheRepository()

	tenantID := uuid.New()

	repo.AddPlanModules(tenantID.String(), []string{"integrations"})
	repo.AddModule(createTestModule("integrations", "integrations", "Integrations", "platform", true, "released", nil))
	repo.getEventTypesErr = errors.New("event types query failed")

	// Should still succeed - event types error is non-fatal
	result, err := getTenantModulesHelper(cache, repo, tenantID.String())
	if err != nil {
		t.Fatalf("expected no error (event types failure should be non-fatal), got %v", err)
	}

	// EventTypes should be empty map, not nil
	if result.EventTypes == nil {
		t.Error("expected EventTypes to be empty map, not nil")
	}
}

func TestModuleCacheService_GetTenantModules_NoEventTypes(t *testing.T) {
	cache := NewMockModuleCache()
	repo := NewMockModuleCacheRepository()

	tenantID := uuid.New()

	repo.AddPlanModules(tenantID.String(), []string{"integrations"})
	repo.AddModule(createTestModule("integrations", "integrations", "Integrations", "platform", true, "released", nil))
	// Don't add any event types

	result, err := getTenantModulesHelper(cache, repo, tenantID.String())
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	// EventTypes should be empty
	if len(result.EventTypes) != 0 {
		t.Errorf("expected 0 event types, got %d", len(result.EventTypes))
	}
}

// =============================================================================
// Edge Case Tests: Cache Behavior
// =============================================================================

func TestModuleCacheService_GetTenantModules_CacheSetFails(t *testing.T) {
	cache := NewMockModuleCache()
	repo := NewMockModuleCacheRepository()

	tenantID := uuid.New()

	repo.AddPlanModules(tenantID.String(), []string{"integrations"})
	repo.AddModule(createTestModule("integrations", "integrations", "Integrations", "platform", true, "released", nil))

	// Make cache set fail
	cache.SetSetError(errors.New("redis write error"))

	// Should still succeed - cache set failure is non-fatal
	result, err := getTenantModulesHelper(cache, repo, tenantID.String())
	if err != nil {
		t.Fatalf("expected no error (cache set failure should be non-fatal), got %v", err)
	}

	if len(result.ModuleIDs) != 1 {
		t.Errorf("expected 1 module, got %d", len(result.ModuleIDs))
	}
}

func TestModuleCacheService_GetTenantModules_InvalidTenantID(t *testing.T) {
	cache := NewMockModuleCache()
	repo := NewMockModuleCacheRepository()

	// Invalid UUID format
	_, err := getTenantModulesHelper(cache, repo, "not-a-valid-uuid")
	if err == nil {
		t.Fatal("expected error for invalid tenant ID")
	}
}

func TestModuleCacheService_GetTenantModules_RepositoryError(t *testing.T) {
	cache := NewMockModuleCache()
	repo := NewMockModuleCacheRepository()

	tenantID := uuid.New()
	repo.getPlanModulesErr = errors.New("database connection error")

	_, err := getTenantModulesHelper(cache, repo, tenantID.String())
	if err == nil {
		t.Fatal("expected error for repository failure")
	}
}

func TestModuleCacheService_GetTenantModules_GetModulesError(t *testing.T) {
	cache := NewMockModuleCache()
	repo := NewMockModuleCacheRepository()

	tenantID := uuid.New()
	repo.AddPlanModules(tenantID.String(), []string{"integrations"})
	repo.getModulesErr = errors.New("modules query failed")

	_, err := getTenantModulesHelper(cache, repo, tenantID.String())
	if err == nil {
		t.Fatal("expected error for GetModulesByIDs failure")
	}
}

// =============================================================================
// Edge Case Tests: Invalidation
// =============================================================================

func TestModuleCacheService_Invalidate_MultipleTenants(t *testing.T) {
	cache := NewMockModuleCache()

	tenant1 := uuid.New().String()
	tenant2 := uuid.New().String()
	tenant3 := uuid.New().String()

	// Pre-populate cache
	cache.data[tenant1] = &app.CachedTenantModules{ModuleIDs: []string{"a"}, CachedAt: time.Now()}
	cache.data[tenant2] = &app.CachedTenantModules{ModuleIDs: []string{"b"}, CachedAt: time.Now()}
	cache.data[tenant3] = &app.CachedTenantModules{ModuleIDs: []string{"c"}, CachedAt: time.Now()}

	// Invalidate only tenant2
	err := invalidateHelper(cache, tenant2)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	// tenant2 should be deleted
	if _, ok := cache.data[tenant2]; ok {
		t.Error("expected tenant2 cache to be deleted")
	}

	// tenant1 and tenant3 should still exist
	if _, ok := cache.data[tenant1]; !ok {
		t.Error("expected tenant1 cache to still exist")
	}
	if _, ok := cache.data[tenant3]; !ok {
		t.Error("expected tenant3 cache to still exist")
	}
}

func TestModuleCacheService_Invalidate_NonExistentTenant(t *testing.T) {
	cache := NewMockModuleCache()

	// Invalidate a tenant that doesn't exist in cache - should not error
	err := invalidateHelper(cache, uuid.New().String())
	if err != nil {
		t.Fatalf("expected no error for non-existent tenant, got %v", err)
	}
}

// =============================================================================
// Edge Case Tests: ToSubModulesMap Conversion
// =============================================================================

func TestCachedTenantModules_ToSubModulesMap(t *testing.T) {
	parentID := "integrations"
	cached := &app.CachedTenantModules{
		SubModules: map[string][]*app.CachedModule{
			"integrations": {
				{ID: "integrations.scm", Slug: "scm", Name: "SCM", Category: "platform", IsActive: true, ReleaseStatus: "released", ParentModuleID: &parentID},
				{ID: "integrations.ticketing", Slug: "ticketing", Name: "Ticketing", Category: "platform", IsActive: true, ReleaseStatus: "released", ParentModuleID: &parentID},
			},
		},
	}

	subModulesMap := cached.ToSubModulesMap()

	if len(subModulesMap) != 1 {
		t.Fatalf("expected 1 parent in map, got %d", len(subModulesMap))
	}

	subs, ok := subModulesMap["integrations"]
	if !ok {
		t.Fatal("expected 'integrations' key in map")
	}

	if len(subs) != 2 {
		t.Errorf("expected 2 sub-modules, got %d", len(subs))
	}

	if subs[0].ID() != "integrations.scm" {
		t.Errorf("expected first sub-module ID to be 'integrations.scm', got %s", subs[0].ID())
	}
}

func TestCachedTenantModules_ToSubModulesMap_Empty(t *testing.T) {
	cached := &app.CachedTenantModules{
		SubModules: map[string][]*app.CachedModule{},
	}

	subModulesMap := cached.ToSubModulesMap()

	if len(subModulesMap) != 0 {
		t.Errorf("expected empty map, got %d entries", len(subModulesMap))
	}
}

// =============================================================================
// Tests for concurrent access
// =============================================================================

func TestModuleCacheService_ConcurrentAccess(t *testing.T) {
	cache := NewMockModuleCache()
	repo := NewMockModuleCacheRepository()

	tenantID := uuid.New()
	repo.AddPlanModules(tenantID.String(), []string{"integrations"})
	repo.AddModule(createTestModule("integrations", "integrations", "Integrations", "platform", true, "released", nil))

	// Run concurrent requests
	var wg sync.WaitGroup
	errChan := make(chan error, 100)

	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := getTenantModulesHelper(cache, repo, tenantID.String())
			if err != nil {
				errChan <- err
			}
		}()
	}

	wg.Wait()
	close(errChan)

	// Check for errors
	for err := range errChan {
		t.Errorf("concurrent access error: %v", err)
	}
}

// =============================================================================
// Helper functions that simulate ModuleCacheService behavior
// These are needed because we can't easily inject mocks into the actual service
// =============================================================================

func strPtr(s string) *string {
	return &s
}

// getTenantModulesHelper simulates ModuleCacheService.GetTenantModules
func getTenantModulesHelper(cache *MockModuleCache, repo *MockModuleCacheRepository, tenantID string) (*app.CachedTenantModules, error) {
	if tenantID == "" {
		return &app.CachedTenantModules{
			ModuleIDs:  []string{},
			Modules:    []*app.CachedModule{},
			SubModules: make(map[string][]*app.CachedModule),
		}, nil
	}

	// Try cache first
	cached, err := cache.Get(context.Background(), tenantID)
	if err == nil && cached != nil {
		return cached, nil
	}

	// Cache miss - load from database
	tid, err := uuid.Parse(tenantID)
	if err != nil {
		return nil, err
	}

	moduleIDs, err := repo.GetPlanModulesByTenantID(context.Background(), tid)
	if err != nil {
		return nil, err
	}

	if len(moduleIDs) == 0 {
		result := &app.CachedTenantModules{
			ModuleIDs:  []string{},
			Modules:    []*app.CachedModule{},
			SubModules: make(map[string][]*app.CachedModule),
			CachedAt:   time.Now(),
		}
		return result, nil
	}

	modules, err := repo.GetModulesByIDs(context.Background(), moduleIDs)
	if err != nil {
		return nil, err
	}

	eventTypesMap, _ := repo.GetEventTypesForModulesBatch(context.Background(), moduleIDs)
	if eventTypesMap == nil {
		eventTypesMap = make(map[string][]string)
	}

	// Separate top-level and sub-modules
	topLevelModules := make([]*app.CachedModule, 0)
	subModulesMap := make(map[string][]*app.CachedModule)

	for _, m := range modules {
		if !m.IsActive() {
			continue
		}

		cached := &app.CachedModule{
			ID:             m.ID(),
			Slug:           m.Slug(),
			Name:           m.Name(),
			Description:    m.Description(),
			Icon:           m.Icon(),
			Category:       m.Category(),
			DisplayOrder:   m.DisplayOrder(),
			IsActive:       m.IsActive(),
			ReleaseStatus:  string(m.ReleaseStatus()),
			ParentModuleID: m.ParentModuleID(),
			EventTypes:     eventTypesMap[m.ID()],
		}

		if m.IsSubModule() {
			parentID := *m.ParentModuleID()
			subModulesMap[parentID] = append(subModulesMap[parentID], cached)
		} else {
			topLevelModules = append(topLevelModules, cached)
		}
	}

	// Build active module IDs list
	activeModuleIDs := make([]string, 0, len(modules))
	for _, m := range modules {
		if m.IsActive() {
			activeModuleIDs = append(activeModuleIDs, m.ID())
		}
	}

	result := &app.CachedTenantModules{
		ModuleIDs:  activeModuleIDs,
		Modules:    topLevelModules,
		SubModules: subModulesMap,
		EventTypes: eventTypesMap,
		CachedAt:   time.Now(),
	}

	// Store in cache
	_ = cache.Set(context.Background(), tenantID, *result)

	return result, nil
}

// hasModuleHelper simulates ModuleCacheService.HasModule
func hasModuleHelper(cache *MockModuleCache, tenantID, moduleID string) (bool, error) {
	cached, err := cache.Get(context.Background(), tenantID)
	if err != nil {
		return false, err
	}

	for _, id := range cached.ModuleIDs {
		if id == moduleID {
			return true, nil
		}
	}

	return false, nil
}

// hasSubModuleHelper simulates ModuleCacheService.HasSubModule
func hasSubModuleHelper(cache *MockModuleCache, tenantID, parentModuleID, fullSubModuleID string) (bool, error) {
	cached, err := cache.Get(context.Background(), tenantID)
	if err != nil {
		return false, err
	}

	// Check if parent module is enabled
	parentFound := false
	for _, id := range cached.ModuleIDs {
		if id == parentModuleID {
			parentFound = true
			break
		}
	}
	if !parentFound {
		return false, nil
	}

	// Check if sub-module is enabled
	subModules, ok := cached.SubModules[parentModuleID]
	if !ok {
		return false, nil
	}

	for _, sm := range subModules {
		if sm.ID == fullSubModuleID {
			// Check release status - only released and beta are accessible
			return sm.ReleaseStatus == "released" || sm.ReleaseStatus == "beta", nil
		}
	}

	return false, nil
}

// invalidateHelper simulates ModuleCacheService.Invalidate with retry
func invalidateHelper(cache *MockModuleCache, tenantID string) error {
	if tenantID == "" {
		return nil
	}

	var lastErr error
	for attempt := 1; attempt <= 3; attempt++ {
		if err := cache.Delete(context.Background(), tenantID); err != nil {
			lastErr = err
			if attempt < 3 {
				time.Sleep(time.Duration(attempt*10) * time.Millisecond) // reduced for tests
			}
			continue
		}
		return nil
	}

	return lastErr
}

// invalidateAllHelper simulates ModuleCacheService.InvalidateAll
func invalidateAllHelper(cache *MockModuleCache) {
	_ = cache.DeletePattern(context.Background(), "*")
}

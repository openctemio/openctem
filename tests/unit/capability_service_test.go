package unit

import (
	"context"
	"testing"

	"github.com/openctemio/api/internal/app"
	"github.com/openctemio/api/pkg/domain/capability"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/logger"
	"github.com/openctemio/api/pkg/pagination"
)

// ============================================================================
// Mock Repository
// ============================================================================

// MockCapabilityRepository implements capability.Repository for testing.
type MockCapabilityRepository struct {
	capabilities map[string]*capability.Capability
	usageStats   map[string]*capability.CapabilityUsageStats
}

func NewMockCapabilityRepository() *MockCapabilityRepository {
	return &MockCapabilityRepository{
		capabilities: make(map[string]*capability.Capability),
		usageStats:   make(map[string]*capability.CapabilityUsageStats),
	}
}

func (m *MockCapabilityRepository) Create(ctx context.Context, c *capability.Capability) error {
	m.capabilities[c.ID.String()] = c
	return nil
}

func (m *MockCapabilityRepository) GetByID(ctx context.Context, id shared.ID) (*capability.Capability, error) {
	c, ok := m.capabilities[id.String()]
	if !ok {
		return nil, shared.ErrNotFound
	}
	return c, nil
}

func (m *MockCapabilityRepository) GetByName(ctx context.Context, tenantID *shared.ID, name string) (*capability.Capability, error) {
	for _, c := range m.capabilities {
		if c.Name == name {
			// Platform capability
			if c.TenantID == nil && tenantID == nil {
				return c, nil
			}
			// Tenant capability
			if c.TenantID != nil && tenantID != nil && *c.TenantID == *tenantID {
				return c, nil
			}
		}
	}
	return nil, shared.ErrNotFound
}

func (m *MockCapabilityRepository) List(ctx context.Context, filter capability.Filter, page pagination.Pagination) (pagination.Result[*capability.Capability], error) {
	var result []*capability.Capability
	for _, c := range m.capabilities {
		// Include platform capabilities
		if c.IsBuiltin {
			result = append(result, c)
			continue
		}
		// Include tenant's custom capabilities
		if filter.TenantID != nil && c.TenantID != nil && *filter.TenantID == *c.TenantID {
			result = append(result, c)
		}
	}
	total := int64(len(result))
	return pagination.Result[*capability.Capability]{
		Data:       result,
		Total:      total,
		Page:       page.Page,
		PerPage:    page.PerPage,
		TotalPages: int((total + int64(page.PerPage) - 1) / int64(page.PerPage)),
	}, nil
}

func (m *MockCapabilityRepository) ListAll(ctx context.Context, tenantID *shared.ID) ([]*capability.Capability, error) {
	var result []*capability.Capability
	for _, c := range m.capabilities {
		if c.IsBuiltin || (tenantID != nil && c.TenantID != nil && *tenantID == *c.TenantID) {
			result = append(result, c)
		}
	}
	return result, nil
}

func (m *MockCapabilityRepository) ListByNames(ctx context.Context, tenantID *shared.ID, names []string) ([]*capability.Capability, error) {
	var result []*capability.Capability
	nameSet := make(map[string]bool)
	for _, n := range names {
		nameSet[n] = true
	}
	for _, c := range m.capabilities {
		if !nameSet[c.Name] {
			continue
		}
		if c.IsBuiltin || (tenantID != nil && c.TenantID != nil && *tenantID == *c.TenantID) {
			result = append(result, c)
		}
	}
	return result, nil
}

func (m *MockCapabilityRepository) ListByCategory(ctx context.Context, tenantID *shared.ID, category string) ([]*capability.Capability, error) {
	var result []*capability.Capability
	for _, c := range m.capabilities {
		if c.Category != category {
			continue
		}
		if c.IsBuiltin || (tenantID != nil && c.TenantID != nil && *tenantID == *c.TenantID) {
			result = append(result, c)
		}
	}
	return result, nil
}

func (m *MockCapabilityRepository) Update(ctx context.Context, c *capability.Capability) error {
	if _, ok := m.capabilities[c.ID.String()]; !ok {
		return shared.ErrNotFound
	}
	m.capabilities[c.ID.String()] = c
	return nil
}

func (m *MockCapabilityRepository) Delete(ctx context.Context, id shared.ID) error {
	if _, ok := m.capabilities[id.String()]; !ok {
		return shared.ErrNotFound
	}
	delete(m.capabilities, id.String())
	return nil
}

func (m *MockCapabilityRepository) ExistsByName(ctx context.Context, tenantID *shared.ID, name string) (bool, error) {
	for _, c := range m.capabilities {
		if c.Name == name {
			// Platform capability
			if c.TenantID == nil && tenantID == nil {
				return true, nil
			}
			// Check tenant scope
			if c.TenantID != nil && tenantID != nil && *c.TenantID == *tenantID {
				return true, nil
			}
			// Platform capability accessible to all tenants
			if c.TenantID == nil {
				return true, nil
			}
		}
	}
	return false, nil
}

func (m *MockCapabilityRepository) CountByTenant(ctx context.Context, tenantID shared.ID) (int64, error) {
	var count int64
	for _, c := range m.capabilities {
		if c.TenantID != nil && *c.TenantID == tenantID {
			count++
		}
	}
	return count, nil
}

func (m *MockCapabilityRepository) GetCategories(ctx context.Context) ([]string, error) {
	categorySet := make(map[string]bool)
	for _, c := range m.capabilities {
		if c.Category != "" {
			categorySet[c.Category] = true
		}
	}
	var categories []string
	for cat := range categorySet {
		categories = append(categories, cat)
	}
	return categories, nil
}

func (m *MockCapabilityRepository) GetUsageStats(ctx context.Context, capabilityID shared.ID) (*capability.CapabilityUsageStats, error) {
	c, ok := m.capabilities[capabilityID.String()]
	if !ok {
		return nil, shared.ErrNotFound
	}

	stats, ok := m.usageStats[c.Name]
	if !ok {
		return &capability.CapabilityUsageStats{
			ToolCount:  0,
			AgentCount: 0,
		}, nil
	}
	return stats, nil
}

func (m *MockCapabilityRepository) GetUsageStatsBatch(ctx context.Context, capabilityIDs []shared.ID) (map[shared.ID]*capability.CapabilityUsageStats, error) {
	result := make(map[shared.ID]*capability.CapabilityUsageStats)
	for _, id := range capabilityIDs {
		c, ok := m.capabilities[id.String()]
		if !ok {
			continue
		}
		stats, ok := m.usageStats[c.Name]
		if !ok {
			result[id] = &capability.CapabilityUsageStats{ToolCount: 0, AgentCount: 0}
		} else {
			result[id] = stats
		}
	}
	return result, nil
}

// SetUsageStats sets the usage stats for a capability name (for testing)
func (m *MockCapabilityRepository) SetUsageStats(name string, stats *capability.CapabilityUsageStats) {
	m.usageStats[name] = stats
}

// AddCapability adds a capability directly to the mock (for test setup)
func (m *MockCapabilityRepository) AddCapability(c *capability.Capability) {
	m.capabilities[c.ID.String()] = c
}

// ============================================================================
// Test Helpers
// ============================================================================

func newCapabilityTestService() (*app.CapabilityService, *MockCapabilityRepository) {
	repo := NewMockCapabilityRepository()
	log := logger.NewDevelopment()
	svc := app.NewCapabilityService(repo, nil, log)
	return svc, repo
}

func createPlatformCapability(name, displayName, category string) *capability.Capability {
	c, _ := capability.NewPlatformCapability(name, displayName, "", "zap", "blue", category, 0)
	return c
}

func createTenantCapability(tenantID shared.ID, name, displayName string) *capability.Capability {
	createdBy := shared.NewID()
	c, _ := capability.NewTenantCapability(tenantID, createdBy, name, displayName, "", "zap", "blue", "security")
	return c
}

// ============================================================================
// Tests: GetCapabilityUsageStats
// ============================================================================

func TestCapabilityService_GetUsageStats_Success(t *testing.T) {
	svc, repo := newCapabilityTestService()
	tenantID := shared.NewID()

	// Create a platform capability
	cap := createPlatformCapability("sast", "SAST", "security")
	repo.AddCapability(cap)

	// Set usage stats
	repo.SetUsageStats("sast", &capability.CapabilityUsageStats{
		ToolCount:  3,
		AgentCount: 2,
		ToolNames:  []string{"Tool1", "Tool2", "Tool3"},
		AgentNames: []string{"Agent1", "Agent2"},
	})

	// Get usage stats
	stats, err := svc.GetCapabilityUsageStats(context.Background(), tenantID.String(), cap.ID.String())
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if stats.ToolCount != 3 {
		t.Errorf("expected ToolCount 3, got %d", stats.ToolCount)
	}
	if stats.AgentCount != 2 {
		t.Errorf("expected AgentCount 2, got %d", stats.AgentCount)
	}
	if len(stats.ToolNames) != 3 {
		t.Errorf("expected 3 tool names, got %d", len(stats.ToolNames))
	}
}

func TestCapabilityService_GetUsageStats_ZeroUsage(t *testing.T) {
	svc, repo := newCapabilityTestService()
	tenantID := shared.NewID()

	// Create a platform capability with no usage
	cap := createPlatformCapability("sca", "SCA", "security")
	repo.AddCapability(cap)

	// Get usage stats (no stats set = zero usage)
	stats, err := svc.GetCapabilityUsageStats(context.Background(), tenantID.String(), cap.ID.String())
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if stats.ToolCount != 0 {
		t.Errorf("expected ToolCount 0, got %d", stats.ToolCount)
	}
	if stats.AgentCount != 0 {
		t.Errorf("expected AgentCount 0, got %d", stats.AgentCount)
	}
}

func TestCapabilityService_GetUsageStats_NotFound(t *testing.T) {
	svc, _ := newCapabilityTestService()
	tenantID := shared.NewID()

	// Try to get stats for non-existent capability
	_, err := svc.GetCapabilityUsageStats(context.Background(), tenantID.String(), shared.NewID().String())
	if err == nil {
		t.Fatal("expected error for non-existent capability")
	}
}

func TestCapabilityService_GetUsageStats_InvalidCapabilityID(t *testing.T) {
	svc, _ := newCapabilityTestService()
	tenantID := shared.NewID()

	_, err := svc.GetCapabilityUsageStats(context.Background(), tenantID.String(), "invalid-uuid")
	if err == nil {
		t.Fatal("expected error for invalid capability ID")
	}
}

func TestCapabilityService_GetUsageStats_InvalidTenantID(t *testing.T) {
	svc, repo := newCapabilityTestService()

	cap := createPlatformCapability("sast", "SAST", "security")
	repo.AddCapability(cap)

	_, err := svc.GetCapabilityUsageStats(context.Background(), "invalid-tenant-id", cap.ID.String())
	if err == nil {
		t.Fatal("expected error for invalid tenant ID")
	}
}

// Security test: Tenant cannot access another tenant's custom capability stats
func TestCapabilityService_GetUsageStats_TenantIsolation(t *testing.T) {
	svc, repo := newCapabilityTestService()

	tenant1 := shared.NewID()
	tenant2 := shared.NewID()

	// Create a custom capability for tenant1
	cap := createTenantCapability(tenant1, "custom-scan", "Custom Scan")
	repo.AddCapability(cap)

	repo.SetUsageStats("custom-scan", &capability.CapabilityUsageStats{
		ToolCount:  5,
		AgentCount: 3,
	})

	// Tenant2 tries to access tenant1's capability
	_, err := svc.GetCapabilityUsageStats(context.Background(), tenant2.String(), cap.ID.String())
	if err == nil {
		t.Fatal("expected error when accessing another tenant's capability")
	}

	// Tenant1 can access their own capability
	stats, err := svc.GetCapabilityUsageStats(context.Background(), tenant1.String(), cap.ID.String())
	if err != nil {
		t.Fatalf("tenant should be able to access their own capability: %v", err)
	}
	if stats.ToolCount != 5 {
		t.Errorf("expected ToolCount 5, got %d", stats.ToolCount)
	}
}

// Security test: All tenants can access platform capabilities
func TestCapabilityService_GetUsageStats_PlatformCapabilityAccessible(t *testing.T) {
	svc, repo := newCapabilityTestService()

	tenant1 := shared.NewID()
	tenant2 := shared.NewID()

	// Create a platform capability
	cap := createPlatformCapability("sast", "SAST", "security")
	repo.AddCapability(cap)

	repo.SetUsageStats("sast", &capability.CapabilityUsageStats{
		ToolCount:  10,
		AgentCount: 5,
	})

	// Both tenants should be able to access platform capability
	stats1, err := svc.GetCapabilityUsageStats(context.Background(), tenant1.String(), cap.ID.String())
	if err != nil {
		t.Fatalf("tenant1 should access platform capability: %v", err)
	}
	if stats1.ToolCount != 10 {
		t.Errorf("expected ToolCount 10, got %d", stats1.ToolCount)
	}

	stats2, err := svc.GetCapabilityUsageStats(context.Background(), tenant2.String(), cap.ID.String())
	if err != nil {
		t.Fatalf("tenant2 should access platform capability: %v", err)
	}
	if stats2.ToolCount != 10 {
		t.Errorf("expected ToolCount 10, got %d", stats2.ToolCount)
	}
}

// ============================================================================
// Tests: GetCapabilitiesUsageStatsBatch
// ============================================================================

func TestCapabilityService_GetUsageStatsBatch_Success(t *testing.T) {
	svc, repo := newCapabilityTestService()
	tenantID := shared.NewID()

	// Create multiple platform capabilities
	cap1 := createPlatformCapability("sast", "SAST", "security")
	cap2 := createPlatformCapability("sca", "SCA", "security")
	cap3 := createPlatformCapability("dast", "DAST", "security")
	repo.AddCapability(cap1)
	repo.AddCapability(cap2)
	repo.AddCapability(cap3)

	// Set different usage stats
	repo.SetUsageStats("sast", &capability.CapabilityUsageStats{ToolCount: 5, AgentCount: 2})
	repo.SetUsageStats("sca", &capability.CapabilityUsageStats{ToolCount: 3, AgentCount: 1})
	repo.SetUsageStats("dast", &capability.CapabilityUsageStats{ToolCount: 0, AgentCount: 0})

	// Get batch stats
	ids := []string{cap1.ID.String(), cap2.ID.String(), cap3.ID.String()}
	stats, err := svc.GetCapabilitiesUsageStatsBatch(context.Background(), tenantID.String(), ids)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if len(stats) != 3 {
		t.Errorf("expected 3 stats entries, got %d", len(stats))
	}

	if stats[cap1.ID.String()].ToolCount != 5 {
		t.Errorf("expected cap1 ToolCount 5, got %d", stats[cap1.ID.String()].ToolCount)
	}
	if stats[cap2.ID.String()].ToolCount != 3 {
		t.Errorf("expected cap2 ToolCount 3, got %d", stats[cap2.ID.String()].ToolCount)
	}
	if stats[cap3.ID.String()].ToolCount != 0 {
		t.Errorf("expected cap3 ToolCount 0, got %d", stats[cap3.ID.String()].ToolCount)
	}
}

func TestCapabilityService_GetUsageStatsBatch_EmptyInput(t *testing.T) {
	svc, _ := newCapabilityTestService()
	tenantID := shared.NewID()

	stats, err := svc.GetCapabilitiesUsageStatsBatch(context.Background(), tenantID.String(), []string{})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if len(stats) != 0 {
		t.Errorf("expected empty map, got %d entries", len(stats))
	}
}

func TestCapabilityService_GetUsageStatsBatch_InvalidCapabilityID(t *testing.T) {
	svc, _ := newCapabilityTestService()
	tenantID := shared.NewID()

	_, err := svc.GetCapabilitiesUsageStatsBatch(context.Background(), tenantID.String(), []string{"invalid-uuid"})
	if err == nil {
		t.Fatal("expected error for invalid capability ID")
	}
}

func TestCapabilityService_GetUsageStatsBatch_PartialNotFound(t *testing.T) {
	svc, repo := newCapabilityTestService()
	tenantID := shared.NewID()

	// Create only one capability
	cap1 := createPlatformCapability("sast", "SAST", "security")
	repo.AddCapability(cap1)
	repo.SetUsageStats("sast", &capability.CapabilityUsageStats{ToolCount: 5, AgentCount: 2})

	// Request stats for existing + non-existing capabilities
	nonExistentID := shared.NewID()
	ids := []string{cap1.ID.String(), nonExistentID.String()}

	stats, err := svc.GetCapabilitiesUsageStatsBatch(context.Background(), tenantID.String(), ids)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	// Should return stats only for existing capability
	if len(stats) != 1 {
		t.Errorf("expected 1 stats entry, got %d", len(stats))
	}
	if stats[cap1.ID.String()].ToolCount != 5 {
		t.Errorf("expected cap1 ToolCount 5, got %d", stats[cap1.ID.String()].ToolCount)
	}
}

// Security test: Batch returns only accessible capabilities
func TestCapabilityService_GetUsageStatsBatch_TenantIsolation(t *testing.T) {
	svc, repo := newCapabilityTestService()

	tenant1 := shared.NewID()
	tenant2 := shared.NewID()

	// Create platform capability (accessible to all)
	platformCap := createPlatformCapability("sast", "SAST", "security")
	repo.AddCapability(platformCap)
	repo.SetUsageStats("sast", &capability.CapabilityUsageStats{ToolCount: 10, AgentCount: 5})

	// Create tenant1's custom capability
	tenant1Cap := createTenantCapability(tenant1, "custom-scan", "Custom Scan")
	repo.AddCapability(tenant1Cap)
	repo.SetUsageStats("custom-scan", &capability.CapabilityUsageStats{ToolCount: 3, AgentCount: 1})

	// Create tenant2's custom capability
	tenant2Cap := createTenantCapability(tenant2, "other-scan", "Other Scan")
	repo.AddCapability(tenant2Cap)
	repo.SetUsageStats("other-scan", &capability.CapabilityUsageStats{ToolCount: 7, AgentCount: 4})

	// Tenant1 requests all three
	ids := []string{platformCap.ID.String(), tenant1Cap.ID.String(), tenant2Cap.ID.String()}
	stats, err := svc.GetCapabilitiesUsageStatsBatch(context.Background(), tenant1.String(), ids)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	// Tenant1 should only see platform + their own capability
	if len(stats) != 2 {
		t.Errorf("expected 2 stats entries (platform + own), got %d", len(stats))
	}

	// Should have platform capability
	if _, ok := stats[platformCap.ID.String()]; !ok {
		t.Error("expected platform capability in results")
	}

	// Should have tenant1's own capability
	if _, ok := stats[tenant1Cap.ID.String()]; !ok {
		t.Error("expected tenant1's capability in results")
	}

	// Should NOT have tenant2's capability
	if _, ok := stats[tenant2Cap.ID.String()]; ok {
		t.Error("should not have tenant2's capability in results")
	}
}

// ============================================================================
// Tests: CreateCapability
// ============================================================================

func TestCapabilityService_CreateCapability_Success(t *testing.T) {
	svc, _ := newCapabilityTestService()
	tenantID := shared.NewID()
	userID := shared.NewID()

	input := app.CreateCapabilityInput{
		TenantID:    tenantID.String(),
		CreatedBy:   userID.String(),
		Name:        "custom-scan",
		DisplayName: "Custom Scan",
		Description: "A custom scanning capability",
		Icon:        "search",
		Color:       "purple",
		Category:    "security",
	}

	cap, err := svc.CreateCapability(context.Background(), input)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if cap.Name != "custom-scan" {
		t.Errorf("expected name custom-scan, got %s", cap.Name)
	}
	if cap.DisplayName != "Custom Scan" {
		t.Errorf("expected display name Custom Scan, got %s", cap.DisplayName)
	}
	if cap.IsBuiltin {
		t.Error("expected IsBuiltin to be false")
	}
}

func TestCapabilityService_CreateCapability_DuplicateName(t *testing.T) {
	svc, repo := newCapabilityTestService()
	tenantID := shared.NewID()
	userID := shared.NewID()

	// Add existing capability
	existing := createTenantCapability(tenantID, "existing-cap", "Existing")
	repo.AddCapability(existing)

	input := app.CreateCapabilityInput{
		TenantID:    tenantID.String(),
		CreatedBy:   userID.String(),
		Name:        "existing-cap", // Duplicate name
		DisplayName: "Another Name",
	}

	_, err := svc.CreateCapability(context.Background(), input)
	if err == nil {
		t.Fatal("expected error for duplicate name")
	}
}

func TestCapabilityService_CreateCapability_PlatformNameConflict(t *testing.T) {
	svc, repo := newCapabilityTestService()
	tenantID := shared.NewID()
	userID := shared.NewID()

	// Add platform capability
	platformCap := createPlatformCapability("sast", "SAST", "security")
	repo.AddCapability(platformCap)

	// Try to create tenant capability with same name as platform
	input := app.CreateCapabilityInput{
		TenantID:    tenantID.String(),
		CreatedBy:   userID.String(),
		Name:        "sast", // Conflicts with platform capability
		DisplayName: "My SAST",
	}

	_, err := svc.CreateCapability(context.Background(), input)
	if err == nil {
		t.Fatal("expected error for platform name conflict")
	}
}

func TestCapabilityService_CreateCapability_InvalidName(t *testing.T) {
	svc, _ := newCapabilityTestService()
	tenantID := shared.NewID()
	userID := shared.NewID()

	// Note: uppercase is converted to lowercase by the entity, so it's valid
	testCases := []struct {
		name        string
		invalidName string
	}{
		{"spaces", "my scan"},
		{"special chars", "scan@test"},
		{"unicode", "sаst"}, // Cyrillic 'а'
		{"too short", "a"},
		{"starts with number", "123scan"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			input := app.CreateCapabilityInput{
				TenantID:    tenantID.String(),
				CreatedBy:   userID.String(),
				Name:        tc.invalidName,
				DisplayName: "Test",
			}

			_, err := svc.CreateCapability(context.Background(), input)
			if err == nil {
				t.Errorf("expected error for invalid name: %s", tc.invalidName)
			}
		})
	}
}

func TestCapabilityService_CreateCapability_ReservedName(t *testing.T) {
	svc, _ := newCapabilityTestService()
	tenantID := shared.NewID()
	userID := shared.NewID()

	reservedNames := []string{"admin", "system", "platform", "root", "all", "any", "none", "null"}

	for _, name := range reservedNames {
		t.Run(name, func(t *testing.T) {
			input := app.CreateCapabilityInput{
				TenantID:    tenantID.String(),
				CreatedBy:   userID.String(),
				Name:        name,
				DisplayName: "Reserved Test",
			}

			_, err := svc.CreateCapability(context.Background(), input)
			if err == nil {
				t.Errorf("expected error for reserved name: %s", name)
			}
		})
	}
}

// ============================================================================
// Tests: UpdateCapability
// ============================================================================

func TestCapabilityService_UpdateCapability_Success(t *testing.T) {
	svc, repo := newCapabilityTestService()
	tenantID := shared.NewID()

	// Create capability
	cap := createTenantCapability(tenantID, "my-scan", "My Scan")
	repo.AddCapability(cap)

	input := app.UpdateCapabilityInput{
		TenantID:    tenantID.String(),
		ID:          cap.ID.String(),
		DisplayName: "Updated Name",
		Description: "Updated description",
		Icon:        "shield",
		Color:       "green",
		Category:    "analysis",
	}

	updated, err := svc.UpdateCapability(context.Background(), input)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if updated.DisplayName != "Updated Name" {
		t.Errorf("expected display name Updated Name, got %s", updated.DisplayName)
	}
	if updated.Description != "Updated description" {
		t.Errorf("expected description Updated description, got %s", updated.Description)
	}
}

// Security test: Cannot update another tenant's capability
func TestCapabilityService_UpdateCapability_TenantIsolation(t *testing.T) {
	svc, repo := newCapabilityTestService()

	tenant1 := shared.NewID()
	tenant2 := shared.NewID()

	// Create tenant1's capability
	cap := createTenantCapability(tenant1, "my-scan", "My Scan")
	repo.AddCapability(cap)

	// Tenant2 tries to update tenant1's capability
	input := app.UpdateCapabilityInput{
		TenantID:    tenant2.String(),
		ID:          cap.ID.String(),
		DisplayName: "Hacked Name",
	}

	_, err := svc.UpdateCapability(context.Background(), input)
	if err == nil {
		t.Fatal("expected error when updating another tenant's capability")
	}
}

// Security test: Cannot update platform capability
func TestCapabilityService_UpdateCapability_CannotUpdatePlatform(t *testing.T) {
	svc, repo := newCapabilityTestService()
	tenantID := shared.NewID()

	// Create platform capability
	cap := createPlatformCapability("sast", "SAST", "security")
	repo.AddCapability(cap)

	input := app.UpdateCapabilityInput{
		TenantID:    tenantID.String(),
		ID:          cap.ID.String(),
		DisplayName: "My Custom SAST",
	}

	_, err := svc.UpdateCapability(context.Background(), input)
	if err == nil {
		t.Fatal("expected error when updating platform capability")
	}
}

// ============================================================================
// Tests: DeleteCapability
// ============================================================================

func TestCapabilityService_DeleteCapability_Success(t *testing.T) {
	svc, repo := newCapabilityTestService()
	tenantID := shared.NewID()

	// Create capability
	cap := createTenantCapability(tenantID, "my-scan", "My Scan")
	repo.AddCapability(cap)

	input := app.DeleteCapabilityInput{
		TenantID:     tenantID.String(),
		CapabilityID: cap.ID.String(),
	}

	err := svc.DeleteCapability(context.Background(), input)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	// Verify deleted
	_, err = repo.GetByID(context.Background(), cap.ID)
	if err == nil {
		t.Error("expected capability to be deleted")
	}
}

func TestCapabilityService_DeleteCapability_InUse(t *testing.T) {
	svc, repo := newCapabilityTestService()
	tenantID := shared.NewID()

	// Create capability that is in use
	cap := createTenantCapability(tenantID, "my-scan", "My Scan")
	repo.AddCapability(cap)
	repo.SetUsageStats("my-scan", &capability.CapabilityUsageStats{
		ToolCount:  2,
		AgentCount: 1,
	})

	input := app.DeleteCapabilityInput{
		TenantID:     tenantID.String(),
		CapabilityID: cap.ID.String(),
		Force:        false,
	}

	err := svc.DeleteCapability(context.Background(), input)
	if err == nil {
		t.Fatal("expected error when deleting capability in use")
	}
}

func TestCapabilityService_DeleteCapability_ForceDelete(t *testing.T) {
	svc, repo := newCapabilityTestService()
	tenantID := shared.NewID()

	// Create capability that is in use
	cap := createTenantCapability(tenantID, "my-scan", "My Scan")
	repo.AddCapability(cap)
	repo.SetUsageStats("my-scan", &capability.CapabilityUsageStats{
		ToolCount:  2,
		AgentCount: 1,
	})

	input := app.DeleteCapabilityInput{
		TenantID:     tenantID.String(),
		CapabilityID: cap.ID.String(),
		Force:        true, // Force delete
	}

	err := svc.DeleteCapability(context.Background(), input)
	if err != nil {
		t.Fatalf("expected no error with force=true, got %v", err)
	}
}

// Security test: Cannot delete another tenant's capability
func TestCapabilityService_DeleteCapability_TenantIsolation(t *testing.T) {
	svc, repo := newCapabilityTestService()

	tenant1 := shared.NewID()
	tenant2 := shared.NewID()

	// Create tenant1's capability
	cap := createTenantCapability(tenant1, "my-scan", "My Scan")
	repo.AddCapability(cap)

	// Tenant2 tries to delete tenant1's capability
	input := app.DeleteCapabilityInput{
		TenantID:     tenant2.String(),
		CapabilityID: cap.ID.String(),
	}

	err := svc.DeleteCapability(context.Background(), input)
	if err == nil {
		t.Fatal("expected error when deleting another tenant's capability")
	}
}

// Security test: Cannot delete platform capability
func TestCapabilityService_DeleteCapability_CannotDeletePlatform(t *testing.T) {
	svc, repo := newCapabilityTestService()
	tenantID := shared.NewID()

	// Create platform capability
	cap := createPlatformCapability("sast", "SAST", "security")
	repo.AddCapability(cap)

	input := app.DeleteCapabilityInput{
		TenantID:     tenantID.String(),
		CapabilityID: cap.ID.String(),
	}

	err := svc.DeleteCapability(context.Background(), input)
	if err == nil {
		t.Fatal("expected error when deleting platform capability")
	}
}

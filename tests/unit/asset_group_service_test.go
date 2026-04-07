package unit

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/openctemio/api/internal/app"
	"github.com/openctemio/api/pkg/domain/assetgroup"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/logger"
	"github.com/openctemio/api/pkg/pagination"
)

// =============================================================================
// Mock Asset Group Repository
// =============================================================================

type mockAssetGroupServiceRepo struct {
	groups map[string]*assetgroup.AssetGroup

	// Asset membership tracking
	groupAssets map[string][]shared.ID // groupID -> assetIDs

	// Configurable errors
	createErr           error
	getByIDErr          error
	updateErr           error
	deleteErr           error
	listErr             error
	countErr            error
	existsByNameErr     error
	existsByNameResult  *bool
	getStatsErr         error
	addAssetsErr        error
	removeAssetsErr     error
	getGroupAssetsErr   error
	getGroupFindingsErr error
	recalculateErr      error

	// Configurable return values
	statsResult         *assetgroup.Stats
	groupAssetsResult   pagination.Result[*assetgroup.GroupAsset]
	groupFindingsResult pagination.Result[*assetgroup.GroupFinding]

	// Call tracking
	createCalls          int
	getByIDCalls         int
	updateCalls          int
	deleteCalls          int
	listCalls            int
	addAssetsCalls       int
	removeAssetsCalls    int
	recalculateCalls     int
	existsByNameCalls    int
	getStatsCalls        int
	getGroupAssetsCalls  int
	getGroupFindingCalls int
}

func newMockAssetGroupServiceRepo() *mockAssetGroupServiceRepo {
	return &mockAssetGroupServiceRepo{
		groups:      make(map[string]*assetgroup.AssetGroup),
		groupAssets: make(map[string][]shared.ID),
	}
}

func (m *mockAssetGroupServiceRepo) Create(_ context.Context, group *assetgroup.AssetGroup) error {
	m.createCalls++
	if m.createErr != nil {
		return m.createErr
	}
	m.groups[group.ID().String()] = group
	return nil
}

func (m *mockAssetGroupServiceRepo) GetByID(_ context.Context, id shared.ID) (*assetgroup.AssetGroup, error) {
	m.getByIDCalls++
	if m.getByIDErr != nil {
		return nil, m.getByIDErr
	}
	g, ok := m.groups[id.String()]
	if !ok {
		return nil, shared.ErrNotFound
	}
	return g, nil
}

func (m *mockAssetGroupServiceRepo) GetByTenantAndID(ctx context.Context, _, id shared.ID) (*assetgroup.AssetGroup, error) {
	return m.GetByID(ctx, id)
}

func (m *mockAssetGroupServiceRepo) Update(_ context.Context, group *assetgroup.AssetGroup) error {
	m.updateCalls++
	if m.updateErr != nil {
		return m.updateErr
	}
	if _, ok := m.groups[group.ID().String()]; !ok {
		return shared.ErrNotFound
	}
	m.groups[group.ID().String()] = group
	return nil
}

func (m *mockAssetGroupServiceRepo) Delete(_ context.Context, id shared.ID) error {
	m.deleteCalls++
	if m.deleteErr != nil {
		return m.deleteErr
	}
	if _, ok := m.groups[id.String()]; !ok {
		return shared.ErrNotFound
	}
	delete(m.groups, id.String())
	return nil
}

func (m *mockAssetGroupServiceRepo) List(
	_ context.Context,
	_ assetgroup.Filter,
	_ assetgroup.ListOptions,
	page pagination.Pagination,
) (pagination.Result[*assetgroup.AssetGroup], error) {
	m.listCalls++
	if m.listErr != nil {
		return pagination.Result[*assetgroup.AssetGroup]{}, m.listErr
	}
	result := make([]*assetgroup.AssetGroup, 0, len(m.groups))
	for _, g := range m.groups {
		result = append(result, g)
	}
	total := int64(len(result))
	totalPages := 1
	if total > 0 && page.PerPage > 0 {
		totalPages = int((total + int64(page.PerPage) - 1) / int64(page.PerPage))
	}
	return pagination.Result[*assetgroup.AssetGroup]{
		Data:       result,
		Total:      total,
		Page:       page.Page,
		PerPage:    page.PerPage,
		TotalPages: totalPages,
	}, nil
}

func (m *mockAssetGroupServiceRepo) Count(_ context.Context, _ assetgroup.Filter) (int64, error) {
	return int64(len(m.groups)), m.countErr
}

func (m *mockAssetGroupServiceRepo) ExistsByName(_ context.Context, tenantID shared.ID, name string) (bool, error) {
	m.existsByNameCalls++
	if m.existsByNameErr != nil {
		return false, m.existsByNameErr
	}
	if m.existsByNameResult != nil {
		return *m.existsByNameResult, nil
	}
	for _, g := range m.groups {
		if g.TenantID() == tenantID && g.Name() == name {
			return true, nil
		}
	}
	return false, nil
}

func (m *mockAssetGroupServiceRepo) GetStats(_ context.Context, _ shared.ID) (*assetgroup.Stats, error) {
	m.getStatsCalls++
	if m.getStatsErr != nil {
		return nil, m.getStatsErr
	}
	if m.statsResult != nil {
		return m.statsResult, nil
	}
	return &assetgroup.Stats{
		Total: int64(len(m.groups)),
	}, nil
}

func (m *mockAssetGroupServiceRepo) AddAssets(_ context.Context, groupID shared.ID, assetIDs []shared.ID) error {
	m.addAssetsCalls++
	if m.addAssetsErr != nil {
		return m.addAssetsErr
	}
	m.groupAssets[groupID.String()] = append(m.groupAssets[groupID.String()], assetIDs...)
	return nil
}

func (m *mockAssetGroupServiceRepo) RemoveAssets(_ context.Context, groupID shared.ID, assetIDs []shared.ID) error {
	m.removeAssetsCalls++
	if m.removeAssetsErr != nil {
		return m.removeAssetsErr
	}
	existing := m.groupAssets[groupID.String()]
	removeSet := make(map[string]bool, len(assetIDs))
	for _, id := range assetIDs {
		removeSet[id.String()] = true
	}
	filtered := make([]shared.ID, 0, len(existing))
	for _, id := range existing {
		if !removeSet[id.String()] {
			filtered = append(filtered, id)
		}
	}
	m.groupAssets[groupID.String()] = filtered
	return nil
}

func (m *mockAssetGroupServiceRepo) GetGroupAssets(_ context.Context, _ shared.ID, _ pagination.Pagination) (pagination.Result[*assetgroup.GroupAsset], error) {
	m.getGroupAssetsCalls++
	if m.getGroupAssetsErr != nil {
		return pagination.Result[*assetgroup.GroupAsset]{}, m.getGroupAssetsErr
	}
	return m.groupAssetsResult, nil
}

func (m *mockAssetGroupServiceRepo) GetGroupFindings(_ context.Context, _ shared.ID, _ pagination.Pagination) (pagination.Result[*assetgroup.GroupFinding], error) {
	m.getGroupFindingCalls++
	if m.getGroupFindingsErr != nil {
		return pagination.Result[*assetgroup.GroupFinding]{}, m.getGroupFindingsErr
	}
	return m.groupFindingsResult, nil
}

func (m *mockAssetGroupServiceRepo) GetGroupIDsByAssetID(_ context.Context, _ shared.ID) ([]shared.ID, error) {
	return nil, nil
}

func (m *mockAssetGroupServiceRepo) RecalculateCounts(_ context.Context, _ shared.ID) error {
	m.recalculateCalls++
	return m.recalculateErr
}

func (m *mockAssetGroupServiceRepo) GetDistinctAssetTypes(_ context.Context, _ shared.ID) ([]string, error) {
	return nil, nil
}

func (m *mockAssetGroupServiceRepo) GetDistinctAssetTypesMultiple(_ context.Context, _ []shared.ID) ([]string, error) {
	return nil, nil
}

func (m *mockAssetGroupServiceRepo) CountAssetsByType(_ context.Context, _ shared.ID) (map[string]int64, error) {
	return nil, nil
}

// =============================================================================
// Test Helpers
// =============================================================================

func newTestAssetGroupService(repo *mockAssetGroupServiceRepo) *app.AssetGroupService {
	log := logger.NewNop()
	return app.NewAssetGroupService(repo, log)
}

func seedAssetGroup(repo *mockAssetGroupServiceRepo, tenantID shared.ID, name string, env assetgroup.Environment, crit assetgroup.Criticality) *assetgroup.AssetGroup {
	now := time.Now().UTC()
	id := shared.NewID()
	g := assetgroup.Reconstitute(
		id, tenantID, name, "description for "+name,
		env, crit,
		"Engineering", "John Doe", "john@example.com",
		[]string{"tag1"},
		10, 2, 3, 1, 2, 1, 1,
		45, 5,
		now, now,
	)
	repo.groups[id.String()] = g
	return g
}

// =============================================================================
// Tests for CreateAssetGroup
// =============================================================================

func TestCreateAssetGroup(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		repo := newMockAssetGroupServiceRepo()
		svc := newTestAssetGroupService(repo)
		tenantID := shared.NewID()

		input := app.CreateAssetGroupInput{
			TenantID:     tenantID.String(),
			Name:         "Production Servers",
			Description:  "All production servers",
			Environment:  "production",
			Criticality:  "critical",
			BusinessUnit: "Infrastructure",
			Owner:        "Jane Smith",
			OwnerEmail:   "jane@example.com",
			Tags:         []string{"infra", "prod"},
		}

		group, err := svc.CreateAssetGroup(context.Background(), input)
		if err != nil {
			t.Fatalf("CreateAssetGroup failed: %v", err)
		}

		if group == nil {
			t.Fatal("expected non-nil group")
		}
		if group.Name() != "Production Servers" {
			t.Errorf("expected name 'Production Servers', got '%s'", group.Name())
		}
		if group.Environment() != assetgroup.EnvironmentProduction {
			t.Errorf("expected environment 'production', got '%s'", group.Environment())
		}
		if group.Criticality() != assetgroup.CriticalityCritical {
			t.Errorf("expected criticality 'critical', got '%s'", group.Criticality())
		}
		if group.BusinessUnit() != "Infrastructure" {
			t.Errorf("expected business unit 'Infrastructure', got '%s'", group.BusinessUnit())
		}
		if group.Owner() != "Jane Smith" {
			t.Errorf("expected owner 'Jane Smith', got '%s'", group.Owner())
		}
		if group.OwnerEmail() != "jane@example.com" {
			t.Errorf("expected owner email 'jane@example.com', got '%s'", group.OwnerEmail())
		}
		tags := group.Tags()
		if len(tags) != 2 {
			t.Errorf("expected 2 tags, got %d", len(tags))
		}
		if repo.createCalls != 1 {
			t.Errorf("expected 1 create call, got %d", repo.createCalls)
		}
	})

	t.Run("invalid tenant ID", func(t *testing.T) {
		repo := newMockAssetGroupServiceRepo()
		svc := newTestAssetGroupService(repo)

		input := app.CreateAssetGroupInput{
			TenantID:    "not-a-uuid",
			Name:        "Test Group",
			Environment: "production",
			Criticality: "high",
		}

		_, err := svc.CreateAssetGroup(context.Background(), input)
		if err == nil {
			t.Fatal("expected error for invalid tenant ID")
		}
		if !errors.Is(err, shared.ErrValidation) {
			t.Errorf("expected validation error, got: %v", err)
		}
	})

	t.Run("invalid environment", func(t *testing.T) {
		repo := newMockAssetGroupServiceRepo()
		svc := newTestAssetGroupService(repo)
		tenantID := shared.NewID()

		input := app.CreateAssetGroupInput{
			TenantID:    tenantID.String(),
			Name:        "Test Group",
			Environment: "invalid_env",
			Criticality: "high",
		}

		_, err := svc.CreateAssetGroup(context.Background(), input)
		if err == nil {
			t.Fatal("expected error for invalid environment")
		}
		if !errors.Is(err, shared.ErrValidation) {
			t.Errorf("expected validation error, got: %v", err)
		}
	})

	t.Run("invalid criticality", func(t *testing.T) {
		repo := newMockAssetGroupServiceRepo()
		svc := newTestAssetGroupService(repo)
		tenantID := shared.NewID()

		input := app.CreateAssetGroupInput{
			TenantID:    tenantID.String(),
			Name:        "Test Group",
			Environment: "production",
			Criticality: "extreme",
		}

		_, err := svc.CreateAssetGroup(context.Background(), input)
		if err == nil {
			t.Fatal("expected error for invalid criticality")
		}
		if !errors.Is(err, shared.ErrValidation) {
			t.Errorf("expected validation error, got: %v", err)
		}
	})

	t.Run("duplicate name", func(t *testing.T) {
		repo := newMockAssetGroupServiceRepo()
		svc := newTestAssetGroupService(repo)
		tenantID := shared.NewID()

		seedAssetGroup(repo, tenantID, "Existing Group", assetgroup.EnvironmentProduction, assetgroup.CriticalityHigh)

		input := app.CreateAssetGroupInput{
			TenantID:    tenantID.String(),
			Name:        "Existing Group",
			Environment: "production",
			Criticality: "high",
		}

		_, err := svc.CreateAssetGroup(context.Background(), input)
		if err == nil {
			t.Fatal("expected error for duplicate name")
		}
		if !errors.Is(err, shared.ErrAlreadyExists) {
			t.Errorf("expected already exists error, got: %v", err)
		}
	})

	t.Run("repo create error", func(t *testing.T) {
		repo := newMockAssetGroupServiceRepo()
		repo.createErr = errors.New("database connection lost")
		svc := newTestAssetGroupService(repo)
		tenantID := shared.NewID()

		input := app.CreateAssetGroupInput{
			TenantID:    tenantID.String(),
			Name:        "Test Group",
			Environment: "production",
			Criticality: "high",
		}

		_, err := svc.CreateAssetGroup(context.Background(), input)
		if err == nil {
			t.Fatal("expected error from repo")
		}
		if err.Error() != "database connection lost" {
			t.Errorf("expected 'database connection lost', got: %v", err)
		}
	})

	t.Run("with asset IDs", func(t *testing.T) {
		repo := newMockAssetGroupServiceRepo()
		svc := newTestAssetGroupService(repo)
		tenantID := shared.NewID()
		assetID1 := shared.NewID()
		assetID2 := shared.NewID()

		input := app.CreateAssetGroupInput{
			TenantID:    tenantID.String(),
			Name:        "Group With Assets",
			Environment: "staging",
			Criticality: "medium",
			AssetIDs:    []string{assetID1.String(), assetID2.String()},
		}

		group, err := svc.CreateAssetGroup(context.Background(), input)
		if err != nil {
			t.Fatalf("CreateAssetGroup failed: %v", err)
		}
		if group == nil {
			t.Fatal("expected non-nil group")
		}
		if repo.addAssetsCalls != 1 {
			t.Errorf("expected 1 AddAssets call, got %d", repo.addAssetsCalls)
		}
		if repo.recalculateCalls != 1 {
			t.Errorf("expected 1 RecalculateCounts call, got %d", repo.recalculateCalls)
		}
	})
}

// =============================================================================
// Tests for GetAssetGroup
// =============================================================================

func TestGetAssetGroup(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		repo := newMockAssetGroupServiceRepo()
		svc := newTestAssetGroupService(repo)
		tenantID := shared.NewID()

		existing := seedAssetGroup(repo, tenantID, "My Group", assetgroup.EnvironmentStaging, assetgroup.CriticalityMedium)

		result, err := svc.GetAssetGroup(context.Background(), tenantID.String(), existing.ID())
		if err != nil {
			t.Fatalf("GetAssetGroup failed: %v", err)
		}
		if result.Name() != "My Group" {
			t.Errorf("expected name 'My Group', got '%s'", result.Name())
		}
		if result.Environment() != assetgroup.EnvironmentStaging {
			t.Errorf("expected environment 'staging', got '%s'", result.Environment())
		}
	})

	t.Run("not found", func(t *testing.T) {
		repo := newMockAssetGroupServiceRepo()
		svc := newTestAssetGroupService(repo)

		_, err := svc.GetAssetGroup(context.Background(), shared.NewID().String(), shared.NewID())
		if err == nil {
			t.Fatal("expected error for non-existent group")
		}
		if !errors.Is(err, shared.ErrNotFound) {
			t.Errorf("expected ErrNotFound, got: %v", err)
		}
	})
}

// =============================================================================
// Tests for UpdateAssetGroup
// =============================================================================

func TestUpdateAssetGroup(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		repo := newMockAssetGroupServiceRepo()
		svc := newTestAssetGroupService(repo)
		tenantID := shared.NewID()

		existing := seedAssetGroup(repo, tenantID, "Original", assetgroup.EnvironmentProduction, assetgroup.CriticalityHigh)

		newName := "Updated Name"
		newDesc := "Updated description"
		newEnv := "staging"
		newCrit := "medium"
		input := app.UpdateAssetGroupInput{
			Name:        &newName,
			Description: &newDesc,
			Environment: &newEnv,
			Criticality: &newCrit,
		}

		result, err := svc.UpdateAssetGroup(context.Background(), tenantID.String(), existing.ID(), input)
		if err != nil {
			t.Fatalf("UpdateAssetGroup failed: %v", err)
		}
		if result.Name() != "Updated Name" {
			t.Errorf("expected name 'Updated Name', got '%s'", result.Name())
		}
		if result.Description() != "Updated description" {
			t.Errorf("expected description 'Updated description', got '%s'", result.Description())
		}
		if result.Environment() != assetgroup.EnvironmentStaging {
			t.Errorf("expected environment 'staging', got '%s'", result.Environment())
		}
		if result.Criticality() != assetgroup.CriticalityMedium {
			t.Errorf("expected criticality 'medium', got '%s'", result.Criticality())
		}
		if repo.updateCalls != 1 {
			t.Errorf("expected 1 update call, got %d", repo.updateCalls)
		}
	})

	t.Run("not found", func(t *testing.T) {
		repo := newMockAssetGroupServiceRepo()
		svc := newTestAssetGroupService(repo)
		tenantID := shared.NewID()

		newName := "Updated"
		input := app.UpdateAssetGroupInput{
			Name: &newName,
		}

		_, err := svc.UpdateAssetGroup(context.Background(), tenantID.String(), shared.NewID(), input)
		if err == nil {
			t.Fatal("expected error for non-existent group")
		}
		if !errors.Is(err, shared.ErrNotFound) {
			t.Errorf("expected ErrNotFound, got: %v", err)
		}
	})

	t.Run("update name only", func(t *testing.T) {
		repo := newMockAssetGroupServiceRepo()
		svc := newTestAssetGroupService(repo)
		tenantID := shared.NewID()

		existing := seedAssetGroup(repo, tenantID, "Old Name", assetgroup.EnvironmentProduction, assetgroup.CriticalityHigh)

		newName := "New Name"
		input := app.UpdateAssetGroupInput{
			Name: &newName,
		}

		result, err := svc.UpdateAssetGroup(context.Background(), tenantID.String(), existing.ID(), input)
		if err != nil {
			t.Fatalf("UpdateAssetGroup failed: %v", err)
		}
		if result.Name() != "New Name" {
			t.Errorf("expected name 'New Name', got '%s'", result.Name())
		}
		// Environment and criticality should remain unchanged
		if result.Environment() != assetgroup.EnvironmentProduction {
			t.Errorf("expected environment unchanged, got '%s'", result.Environment())
		}
		if result.Criticality() != assetgroup.CriticalityHigh {
			t.Errorf("expected criticality unchanged, got '%s'", result.Criticality())
		}
	})

	t.Run("update environment", func(t *testing.T) {
		repo := newMockAssetGroupServiceRepo()
		svc := newTestAssetGroupService(repo)
		tenantID := shared.NewID()

		existing := seedAssetGroup(repo, tenantID, "Env Test", assetgroup.EnvironmentProduction, assetgroup.CriticalityHigh)

		newEnv := "development"
		input := app.UpdateAssetGroupInput{
			Environment: &newEnv,
		}

		result, err := svc.UpdateAssetGroup(context.Background(), tenantID.String(), existing.ID(), input)
		if err != nil {
			t.Fatalf("UpdateAssetGroup failed: %v", err)
		}
		if result.Environment() != assetgroup.EnvironmentDevelopment {
			t.Errorf("expected environment 'development', got '%s'", result.Environment())
		}
	})

	t.Run("invalid environment", func(t *testing.T) {
		repo := newMockAssetGroupServiceRepo()
		svc := newTestAssetGroupService(repo)
		tenantID := shared.NewID()

		existing := seedAssetGroup(repo, tenantID, "Bad Env", assetgroup.EnvironmentProduction, assetgroup.CriticalityHigh)

		badEnv := "invalid_environment"
		input := app.UpdateAssetGroupInput{
			Environment: &badEnv,
		}

		_, err := svc.UpdateAssetGroup(context.Background(), tenantID.String(), existing.ID(), input)
		if err == nil {
			t.Fatal("expected error for invalid environment")
		}
		if !errors.Is(err, shared.ErrValidation) {
			t.Errorf("expected validation error, got: %v", err)
		}
	})

	t.Run("update criticality", func(t *testing.T) {
		repo := newMockAssetGroupServiceRepo()
		svc := newTestAssetGroupService(repo)
		tenantID := shared.NewID()

		existing := seedAssetGroup(repo, tenantID, "Crit Test", assetgroup.EnvironmentProduction, assetgroup.CriticalityHigh)

		newCrit := "low"
		input := app.UpdateAssetGroupInput{
			Criticality: &newCrit,
		}

		result, err := svc.UpdateAssetGroup(context.Background(), tenantID.String(), existing.ID(), input)
		if err != nil {
			t.Fatalf("UpdateAssetGroup failed: %v", err)
		}
		if result.Criticality() != assetgroup.CriticalityLow {
			t.Errorf("expected criticality 'low', got '%s'", result.Criticality())
		}
	})

	t.Run("invalid criticality", func(t *testing.T) {
		repo := newMockAssetGroupServiceRepo()
		svc := newTestAssetGroupService(repo)
		tenantID := shared.NewID()

		existing := seedAssetGroup(repo, tenantID, "Bad Crit", assetgroup.EnvironmentProduction, assetgroup.CriticalityHigh)

		badCrit := "ultra"
		input := app.UpdateAssetGroupInput{
			Criticality: &badCrit,
		}

		_, err := svc.UpdateAssetGroup(context.Background(), tenantID.String(), existing.ID(), input)
		if err == nil {
			t.Fatal("expected error for invalid criticality")
		}
		if !errors.Is(err, shared.ErrValidation) {
			t.Errorf("expected validation error, got: %v", err)
		}
	})

	t.Run("update tags", func(t *testing.T) {
		repo := newMockAssetGroupServiceRepo()
		svc := newTestAssetGroupService(repo)
		tenantID := shared.NewID()

		existing := seedAssetGroup(repo, tenantID, "Tags Test", assetgroup.EnvironmentProduction, assetgroup.CriticalityHigh)

		newTags := []string{"web", "api", "microservice"}
		input := app.UpdateAssetGroupInput{
			Tags: newTags,
		}

		result, err := svc.UpdateAssetGroup(context.Background(), tenantID.String(), existing.ID(), input)
		if err != nil {
			t.Fatalf("UpdateAssetGroup failed: %v", err)
		}
		tags := result.Tags()
		if len(tags) != 3 {
			t.Errorf("expected 3 tags, got %d", len(tags))
		}
	})
}

// =============================================================================
// Tests for DeleteAssetGroup
// =============================================================================

func TestDeleteAssetGroup(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		repo := newMockAssetGroupServiceRepo()
		svc := newTestAssetGroupService(repo)
		tenantID := shared.NewID()

		existing := seedAssetGroup(repo, tenantID, "To Delete", assetgroup.EnvironmentTesting, assetgroup.CriticalityLow)

		err := svc.DeleteAssetGroup(context.Background(), existing.ID())
		if err != nil {
			t.Fatalf("DeleteAssetGroup failed: %v", err)
		}

		// Verify it was removed
		_, err = svc.GetAssetGroup(context.Background(), tenantID.String(), existing.ID())
		if err == nil {
			t.Fatal("expected group to be deleted")
		}
		if repo.deleteCalls != 1 {
			t.Errorf("expected 1 delete call, got %d", repo.deleteCalls)
		}
	})

	t.Run("not found", func(t *testing.T) {
		repo := newMockAssetGroupServiceRepo()
		svc := newTestAssetGroupService(repo)

		err := svc.DeleteAssetGroup(context.Background(), shared.NewID())
		if err == nil {
			t.Fatal("expected error for non-existent group")
		}
		if !errors.Is(err, shared.ErrNotFound) {
			t.Errorf("expected ErrNotFound, got: %v", err)
		}
	})

	t.Run("repo error", func(t *testing.T) {
		repo := newMockAssetGroupServiceRepo()
		repo.deleteErr = errors.New("database timeout")
		svc := newTestAssetGroupService(repo)
		tenantID := shared.NewID()

		existing := seedAssetGroup(repo, tenantID, "Error Delete", assetgroup.EnvironmentProduction, assetgroup.CriticalityHigh)

		err := svc.DeleteAssetGroup(context.Background(), existing.ID())
		if err == nil {
			t.Fatal("expected error from repo")
		}
		if err.Error() != "database timeout" {
			t.Errorf("expected 'database timeout', got: %v", err)
		}
	})
}

// =============================================================================
// Tests for ListAssetGroups
// =============================================================================

func TestListAssetGroups(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		repo := newMockAssetGroupServiceRepo()
		svc := newTestAssetGroupService(repo)
		tenantID := shared.NewID()

		seedAssetGroup(repo, tenantID, "Group A", assetgroup.EnvironmentProduction, assetgroup.CriticalityCritical)
		seedAssetGroup(repo, tenantID, "Group B", assetgroup.EnvironmentStaging, assetgroup.CriticalityHigh)
		seedAssetGroup(repo, tenantID, "Group C", assetgroup.EnvironmentDevelopment, assetgroup.CriticalityMedium)

		input := app.ListAssetGroupsInput{
			TenantID: tenantID.String(),
			Page:     1,
			PerPage:  20,
		}

		result, err := svc.ListAssetGroups(context.Background(), input)
		if err != nil {
			t.Fatalf("ListAssetGroups failed: %v", err)
		}
		if result == nil {
			t.Fatal("expected non-nil result")
		}
		if len(result.Groups) != 3 {
			t.Errorf("expected 3 groups, got %d", len(result.Groups))
		}
		if result.Total != 3 {
			t.Errorf("expected total 3, got %d", result.Total)
		}
	})

	t.Run("with environments filter", func(t *testing.T) {
		repo := newMockAssetGroupServiceRepo()
		svc := newTestAssetGroupService(repo)
		tenantID := shared.NewID()

		seedAssetGroup(repo, tenantID, "Prod Group", assetgroup.EnvironmentProduction, assetgroup.CriticalityCritical)

		input := app.ListAssetGroupsInput{
			TenantID:     tenantID.String(),
			Environments: []string{"production", "staging"},
			Page:         1,
			PerPage:      20,
		}

		result, err := svc.ListAssetGroups(context.Background(), input)
		if err != nil {
			t.Fatalf("ListAssetGroups failed: %v", err)
		}
		// Mock returns all groups regardless of filter, but we verify no error
		if result == nil {
			t.Fatal("expected non-nil result")
		}
	})

	t.Run("with criticalities filter", func(t *testing.T) {
		repo := newMockAssetGroupServiceRepo()
		svc := newTestAssetGroupService(repo)
		tenantID := shared.NewID()

		seedAssetGroup(repo, tenantID, "Critical Group", assetgroup.EnvironmentProduction, assetgroup.CriticalityCritical)

		input := app.ListAssetGroupsInput{
			TenantID:      tenantID.String(),
			Criticalities: []string{"critical", "high"},
			Page:          1,
			PerPage:       20,
		}

		result, err := svc.ListAssetGroups(context.Background(), input)
		if err != nil {
			t.Fatalf("ListAssetGroups failed: %v", err)
		}
		if result == nil {
			t.Fatal("expected non-nil result")
		}
	})

	t.Run("with tags filter", func(t *testing.T) {
		repo := newMockAssetGroupServiceRepo()
		svc := newTestAssetGroupService(repo)
		tenantID := shared.NewID()

		seedAssetGroup(repo, tenantID, "Tagged Group", assetgroup.EnvironmentProduction, assetgroup.CriticalityHigh)

		input := app.ListAssetGroupsInput{
			TenantID: tenantID.String(),
			Tags:     []string{"web", "api"},
			Page:     1,
			PerPage:  20,
		}

		result, err := svc.ListAssetGroups(context.Background(), input)
		if err != nil {
			t.Fatalf("ListAssetGroups failed: %v", err)
		}
		if result == nil {
			t.Fatal("expected non-nil result")
		}
	})

	t.Run("with search filter", func(t *testing.T) {
		repo := newMockAssetGroupServiceRepo()
		svc := newTestAssetGroupService(repo)
		tenantID := shared.NewID()

		seedAssetGroup(repo, tenantID, "Searchable Group", assetgroup.EnvironmentProduction, assetgroup.CriticalityHigh)

		input := app.ListAssetGroupsInput{
			TenantID: tenantID.String(),
			Search:   "Searchable",
			Page:     1,
			PerPage:  20,
		}

		result, err := svc.ListAssetGroups(context.Background(), input)
		if err != nil {
			t.Fatalf("ListAssetGroups failed: %v", err)
		}
		if result == nil {
			t.Fatal("expected non-nil result")
		}
	})

	t.Run("with has findings filter", func(t *testing.T) {
		repo := newMockAssetGroupServiceRepo()
		svc := newTestAssetGroupService(repo)
		tenantID := shared.NewID()

		seedAssetGroup(repo, tenantID, "Findings Group", assetgroup.EnvironmentProduction, assetgroup.CriticalityHigh)

		hasFindings := true
		input := app.ListAssetGroupsInput{
			TenantID:    tenantID.String(),
			HasFindings: &hasFindings,
			Page:        1,
			PerPage:     20,
		}

		result, err := svc.ListAssetGroups(context.Background(), input)
		if err != nil {
			t.Fatalf("ListAssetGroups failed: %v", err)
		}
		if result == nil {
			t.Fatal("expected non-nil result")
		}
	})

	t.Run("with risk score range", func(t *testing.T) {
		repo := newMockAssetGroupServiceRepo()
		svc := newTestAssetGroupService(repo)
		tenantID := shared.NewID()

		seedAssetGroup(repo, tenantID, "Risk Group", assetgroup.EnvironmentProduction, assetgroup.CriticalityHigh)

		minScore := 20
		maxScore := 80
		input := app.ListAssetGroupsInput{
			TenantID:     tenantID.String(),
			MinRiskScore: &minScore,
			MaxRiskScore: &maxScore,
			Page:         1,
			PerPage:      20,
		}

		result, err := svc.ListAssetGroups(context.Background(), input)
		if err != nil {
			t.Fatalf("ListAssetGroups failed: %v", err)
		}
		if result == nil {
			t.Fatal("expected non-nil result")
		}
	})

	t.Run("repo error", func(t *testing.T) {
		repo := newMockAssetGroupServiceRepo()
		repo.listErr = errors.New("query failed")
		svc := newTestAssetGroupService(repo)

		input := app.ListAssetGroupsInput{
			TenantID: shared.NewID().String(),
			Page:     1,
			PerPage:  20,
		}

		_, err := svc.ListAssetGroups(context.Background(), input)
		if err == nil {
			t.Fatal("expected error from repo")
		}
		if err.Error() != "query failed" {
			t.Errorf("expected 'query failed', got: %v", err)
		}
	})
}

// =============================================================================
// Tests for GetAssetGroupStats
// =============================================================================

func TestGetAssetGroupStats(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		repo := newMockAssetGroupServiceRepo()
		repo.statsResult = &assetgroup.Stats{
			Total:            5,
			TotalAssets:      100,
			TotalFindings:    42,
			AverageRiskScore: 55.5,
			ByEnvironment: map[assetgroup.Environment]int64{
				assetgroup.EnvironmentProduction: 3,
				assetgroup.EnvironmentStaging:    2,
			},
			ByCriticality: map[assetgroup.Criticality]int64{
				assetgroup.CriticalityCritical: 1,
				assetgroup.CriticalityHigh:     4,
			},
		}
		svc := newTestAssetGroupService(repo)
		tenantID := shared.NewID()

		stats, err := svc.GetAssetGroupStats(context.Background(), tenantID.String())
		if err != nil {
			t.Fatalf("GetAssetGroupStats failed: %v", err)
		}
		if stats == nil {
			t.Fatal("expected non-nil stats")
		}
		if stats.Total != 5 {
			t.Errorf("expected total 5, got %d", stats.Total)
		}
		if stats.TotalAssets != 100 {
			t.Errorf("expected total assets 100, got %d", stats.TotalAssets)
		}
		if stats.TotalFindings != 42 {
			t.Errorf("expected total findings 42, got %d", stats.TotalFindings)
		}
		if repo.getStatsCalls != 1 {
			t.Errorf("expected 1 GetStats call, got %d", repo.getStatsCalls)
		}
	})

	t.Run("invalid tenant ID", func(t *testing.T) {
		repo := newMockAssetGroupServiceRepo()
		svc := newTestAssetGroupService(repo)

		_, err := svc.GetAssetGroupStats(context.Background(), "not-valid")
		if err == nil {
			t.Fatal("expected error for invalid tenant ID")
		}
		if !errors.Is(err, shared.ErrValidation) {
			t.Errorf("expected validation error, got: %v", err)
		}
	})

	t.Run("repo error", func(t *testing.T) {
		repo := newMockAssetGroupServiceRepo()
		repo.getStatsErr = errors.New("stats query failed")
		svc := newTestAssetGroupService(repo)
		tenantID := shared.NewID()

		_, err := svc.GetAssetGroupStats(context.Background(), tenantID.String())
		if err == nil {
			t.Fatal("expected error from repo")
		}
		if err.Error() != "stats query failed" {
			t.Errorf("expected 'stats query failed', got: %v", err)
		}
	})
}

// =============================================================================
// Tests for AddAssetsToGroup
// =============================================================================

func TestAddAssetsToGroup(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		repo := newMockAssetGroupServiceRepo()
		svc := newTestAssetGroupService(repo)
		groupID := shared.NewID()
		assetID1 := shared.NewID()
		assetID2 := shared.NewID()

		err := svc.AddAssetsToGroup(context.Background(), groupID, []string{assetID1.String(), assetID2.String()})
		if err != nil {
			t.Fatalf("AddAssetsToGroup failed: %v", err)
		}
		if repo.addAssetsCalls != 1 {
			t.Errorf("expected 1 AddAssets call, got %d", repo.addAssetsCalls)
		}
		if repo.recalculateCalls != 1 {
			t.Errorf("expected 1 RecalculateCounts call, got %d", repo.recalculateCalls)
		}
		assets := repo.groupAssets[groupID.String()]
		if len(assets) != 2 {
			t.Errorf("expected 2 assets added, got %d", len(assets))
		}
	})

	t.Run("empty list", func(t *testing.T) {
		repo := newMockAssetGroupServiceRepo()
		svc := newTestAssetGroupService(repo)
		groupID := shared.NewID()

		err := svc.AddAssetsToGroup(context.Background(), groupID, []string{})
		if err != nil {
			t.Fatalf("AddAssetsToGroup with empty list should succeed, got: %v", err)
		}
		if repo.addAssetsCalls != 0 {
			t.Errorf("expected 0 AddAssets calls for empty list, got %d", repo.addAssetsCalls)
		}
	})

	t.Run("invalid IDs filtered", func(t *testing.T) {
		repo := newMockAssetGroupServiceRepo()
		svc := newTestAssetGroupService(repo)
		groupID := shared.NewID()
		validID := shared.NewID()

		err := svc.AddAssetsToGroup(context.Background(), groupID, []string{
			validID.String(),
			"not-a-uuid",
			"also-invalid",
		})
		if err != nil {
			t.Fatalf("AddAssetsToGroup failed: %v", err)
		}
		// Only the valid ID should be passed through
		if repo.addAssetsCalls != 1 {
			t.Errorf("expected 1 AddAssets call, got %d", repo.addAssetsCalls)
		}
		assets := repo.groupAssets[groupID.String()]
		if len(assets) != 1 {
			t.Errorf("expected 1 valid asset added, got %d", len(assets))
		}
	})

	t.Run("all invalid IDs returns nil", func(t *testing.T) {
		repo := newMockAssetGroupServiceRepo()
		svc := newTestAssetGroupService(repo)
		groupID := shared.NewID()

		err := svc.AddAssetsToGroup(context.Background(), groupID, []string{
			"not-a-uuid",
			"also-invalid",
		})
		if err != nil {
			t.Fatalf("AddAssetsToGroup with all invalid IDs should return nil, got: %v", err)
		}
		if repo.addAssetsCalls != 0 {
			t.Errorf("expected 0 AddAssets calls when all IDs invalid, got %d", repo.addAssetsCalls)
		}
	})

	t.Run("repo error", func(t *testing.T) {
		repo := newMockAssetGroupServiceRepo()
		repo.addAssetsErr = errors.New("constraint violation")
		svc := newTestAssetGroupService(repo)
		groupID := shared.NewID()

		err := svc.AddAssetsToGroup(context.Background(), groupID, []string{shared.NewID().String()})
		if err == nil {
			t.Fatal("expected error from repo")
		}
		if err.Error() != "constraint violation" {
			t.Errorf("expected 'constraint violation', got: %v", err)
		}
	})
}

// =============================================================================
// Tests for RemoveAssetsFromGroup
// =============================================================================

func TestRemoveAssetsFromGroup(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		repo := newMockAssetGroupServiceRepo()
		svc := newTestAssetGroupService(repo)
		groupID := shared.NewID()
		assetID1 := shared.NewID()
		assetID2 := shared.NewID()

		// Pre-populate assets
		repo.groupAssets[groupID.String()] = []shared.ID{assetID1, assetID2}

		err := svc.RemoveAssetsFromGroup(context.Background(), groupID, []string{assetID1.String()})
		if err != nil {
			t.Fatalf("RemoveAssetsFromGroup failed: %v", err)
		}
		if repo.removeAssetsCalls != 1 {
			t.Errorf("expected 1 RemoveAssets call, got %d", repo.removeAssetsCalls)
		}
		if repo.recalculateCalls != 1 {
			t.Errorf("expected 1 RecalculateCounts call, got %d", repo.recalculateCalls)
		}
		remaining := repo.groupAssets[groupID.String()]
		if len(remaining) != 1 {
			t.Errorf("expected 1 remaining asset, got %d", len(remaining))
		}
	})

	t.Run("empty list", func(t *testing.T) {
		repo := newMockAssetGroupServiceRepo()
		svc := newTestAssetGroupService(repo)
		groupID := shared.NewID()

		err := svc.RemoveAssetsFromGroup(context.Background(), groupID, []string{})
		if err != nil {
			t.Fatalf("RemoveAssetsFromGroup with empty list should succeed, got: %v", err)
		}
		if repo.removeAssetsCalls != 0 {
			t.Errorf("expected 0 RemoveAssets calls for empty list, got %d", repo.removeAssetsCalls)
		}
	})
}

// =============================================================================
// Tests for GetGroupAssets
// =============================================================================

func TestGetGroupAssets(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		repo := newMockAssetGroupServiceRepo()
		repo.groupAssetsResult = pagination.Result[*assetgroup.GroupAsset]{
			Data: []*assetgroup.GroupAsset{
				{
					ID:           shared.NewID(),
					Name:         "web-server-01",
					Type:         "server",
					Status:       "active",
					RiskScore:    72,
					FindingCount: 3,
				},
				{
					ID:           shared.NewID(),
					Name:         "api-gateway",
					Type:         "service",
					Status:       "active",
					RiskScore:    45,
					FindingCount: 1,
				},
			},
			Total:      2,
			Page:       1,
			PerPage:    20,
			TotalPages: 1,
		}
		svc := newTestAssetGroupService(repo)
		groupID := shared.NewID()

		result, err := svc.GetGroupAssets(context.Background(), groupID, 1, 20)
		if err != nil {
			t.Fatalf("GetGroupAssets failed: %v", err)
		}
		if len(result.Data) != 2 {
			t.Errorf("expected 2 assets, got %d", len(result.Data))
		}
		if result.Total != 2 {
			t.Errorf("expected total 2, got %d", result.Total)
		}
		if repo.getGroupAssetsCalls != 1 {
			t.Errorf("expected 1 GetGroupAssets call, got %d", repo.getGroupAssetsCalls)
		}
	})
}

// =============================================================================
// Tests for GetGroupFindings
// =============================================================================

func TestGetGroupFindings(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		repo := newMockAssetGroupServiceRepo()
		repo.groupFindingsResult = pagination.Result[*assetgroup.GroupFinding]{
			Data: []*assetgroup.GroupFinding{
				{
					ID:        shared.NewID(),
					Title:     "SQL Injection",
					Severity:  "critical",
					Status:    "open",
					AssetID:   shared.NewID(),
					AssetName: "web-server-01",
					AssetType: "server",
				},
			},
			Total:      1,
			Page:       1,
			PerPage:    20,
			TotalPages: 1,
		}
		svc := newTestAssetGroupService(repo)
		groupID := shared.NewID()

		result, err := svc.GetGroupFindings(context.Background(), groupID, 1, 20)
		if err != nil {
			t.Fatalf("GetGroupFindings failed: %v", err)
		}
		if len(result.Data) != 1 {
			t.Errorf("expected 1 finding, got %d", len(result.Data))
		}
		if result.Data[0].Title != "SQL Injection" {
			t.Errorf("expected title 'SQL Injection', got '%s'", result.Data[0].Title)
		}
		if repo.getGroupFindingCalls != 1 {
			t.Errorf("expected 1 GetGroupFindings call, got %d", repo.getGroupFindingCalls)
		}
	})
}

// =============================================================================
// Tests for BulkUpdateAssetGroups
// =============================================================================

func TestBulkUpdateAssetGroups(t *testing.T) {
	t.Run("success with partial failures", func(t *testing.T) {
		repo := newMockAssetGroupServiceRepo()
		svc := newTestAssetGroupService(repo)
		tenantID := shared.NewID()

		g1 := seedAssetGroup(repo, tenantID, "Bulk 1", assetgroup.EnvironmentProduction, assetgroup.CriticalityHigh)
		g2 := seedAssetGroup(repo, tenantID, "Bulk 2", assetgroup.EnvironmentStaging, assetgroup.CriticalityMedium)
		nonExistentID := shared.NewID()

		newEnv := "testing"
		input := app.BulkUpdateInput{
			GroupIDs:    []string{g1.ID().String(), g2.ID().String(), nonExistentID.String()},
			Environment: &newEnv,
		}

		updated, err := svc.BulkUpdateAssetGroups(context.Background(), tenantID.String(), input)
		if err != nil {
			t.Fatalf("BulkUpdateAssetGroups failed: %v", err)
		}
		// 2 succeed, 1 fails (not found)
		if updated != 2 {
			t.Errorf("expected 2 updated, got %d", updated)
		}
	})

	t.Run("all invalid IDs", func(t *testing.T) {
		repo := newMockAssetGroupServiceRepo()
		svc := newTestAssetGroupService(repo)
		tenantID := shared.NewID()

		newCrit := "low"
		input := app.BulkUpdateInput{
			GroupIDs:    []string{"not-a-uuid", "also-invalid"},
			Criticality: &newCrit,
		}

		updated, err := svc.BulkUpdateAssetGroups(context.Background(), tenantID.String(), input)
		if err != nil {
			t.Fatalf("BulkUpdateAssetGroups failed: %v", err)
		}
		if updated != 0 {
			t.Errorf("expected 0 updated for all invalid IDs, got %d", updated)
		}
	})
}

// =============================================================================
// Tests for BulkDeleteAssetGroups
// =============================================================================

func TestBulkDeleteAssetGroups(t *testing.T) {
	t.Run("success with partial failures", func(t *testing.T) {
		repo := newMockAssetGroupServiceRepo()
		svc := newTestAssetGroupService(repo)
		tenantID := shared.NewID()

		g1 := seedAssetGroup(repo, tenantID, "Delete 1", assetgroup.EnvironmentProduction, assetgroup.CriticalityHigh)
		g2 := seedAssetGroup(repo, tenantID, "Delete 2", assetgroup.EnvironmentStaging, assetgroup.CriticalityMedium)
		nonExistentID := shared.NewID()

		groupIDs := []string{g1.ID().String(), g2.ID().String(), nonExistentID.String()}

		deleted, err := svc.BulkDeleteAssetGroups(context.Background(), groupIDs)
		if err != nil {
			t.Fatalf("BulkDeleteAssetGroups failed: %v", err)
		}
		// 2 succeed, 1 fails (not found)
		if deleted != 2 {
			t.Errorf("expected 2 deleted, got %d", deleted)
		}

		// Verify groups were removed from repo
		if len(repo.groups) != 0 {
			t.Errorf("expected 0 remaining groups, got %d", len(repo.groups))
		}
	})

	t.Run("all invalid IDs", func(t *testing.T) {
		repo := newMockAssetGroupServiceRepo()
		svc := newTestAssetGroupService(repo)

		deleted, err := svc.BulkDeleteAssetGroups(context.Background(), []string{"bad-id", "worse-id"})
		if err != nil {
			t.Fatalf("BulkDeleteAssetGroups failed: %v", err)
		}
		if deleted != 0 {
			t.Errorf("expected 0 deleted for all invalid IDs, got %d", deleted)
		}
	})
}

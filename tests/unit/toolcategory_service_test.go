package unit

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/openctemio/api/internal/app"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/domain/toolcategory"
	"github.com/openctemio/api/pkg/logger"
	"github.com/openctemio/api/pkg/pagination"
)

// =============================================================================
// Mock ToolCategory Repository
// =============================================================================

type toolCatMockRepo struct {
	mu         sync.Mutex
	categories map[shared.ID]*toolcategory.ToolCategory

	// Error overrides
	createErr      error
	getByIDErr     error
	getByNameErr   error
	listErr        error
	listAllErr     error
	updateErr      error
	deleteErr      error
	existsByNameErr error
	countErr       error

	// Call tracking
	createCalls      int
	getByIDCalls     int
	getByNameCalls   int
	listCalls        int
	listAllCalls     int
	updateCalls      int
	deleteCalls      int
	existsByNameCalls int
	countCalls       int

	// Captured arguments
	lastFilter     toolcategory.Filter
	lastPagination pagination.Pagination

	// ExistsByName overrides (keyed by name)
	existsByNameResults map[string]bool
}

func newToolCatMockRepo() *toolCatMockRepo {
	return &toolCatMockRepo{
		categories:          make(map[shared.ID]*toolcategory.ToolCategory),
		existsByNameResults: make(map[string]bool),
	}
}

func (m *toolCatMockRepo) Create(_ context.Context, category *toolcategory.ToolCategory) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.createCalls++
	if m.createErr != nil {
		return m.createErr
	}
	m.categories[category.ID] = category
	return nil
}

func (m *toolCatMockRepo) GetByID(_ context.Context, id shared.ID) (*toolcategory.ToolCategory, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.getByIDCalls++
	if m.getByIDErr != nil {
		return nil, m.getByIDErr
	}
	cat, ok := m.categories[id]
	if !ok {
		return nil, errors.New("category not found")
	}
	return cat, nil
}

func (m *toolCatMockRepo) GetByName(_ context.Context, tenantID *shared.ID, name string) (*toolcategory.ToolCategory, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.getByNameCalls++
	if m.getByNameErr != nil {
		return nil, m.getByNameErr
	}
	for _, cat := range m.categories {
		if cat.Name == name {
			if tenantID == nil && cat.TenantID == nil {
				return cat, nil
			}
			if tenantID != nil && cat.TenantID != nil && *tenantID == *cat.TenantID {
				return cat, nil
			}
		}
	}
	return nil, errors.New("category not found")
}

func (m *toolCatMockRepo) List(_ context.Context, filter toolcategory.Filter, page pagination.Pagination) (pagination.Result[*toolcategory.ToolCategory], error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.listCalls++
	m.lastFilter = filter
	m.lastPagination = page
	if m.listErr != nil {
		return pagination.Result[*toolcategory.ToolCategory]{}, m.listErr
	}
	cats := make([]*toolcategory.ToolCategory, 0, len(m.categories))
	for _, cat := range m.categories {
		cats = append(cats, cat)
	}
	return pagination.NewResult(cats, int64(len(cats)), page), nil
}

func (m *toolCatMockRepo) ListAll(_ context.Context, tenantID *shared.ID) ([]*toolcategory.ToolCategory, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.listAllCalls++
	if m.listAllErr != nil {
		return nil, m.listAllErr
	}
	cats := make([]*toolcategory.ToolCategory, 0, len(m.categories))
	for _, cat := range m.categories {
		cats = append(cats, cat)
	}
	return cats, nil
}

func (m *toolCatMockRepo) Update(_ context.Context, category *toolcategory.ToolCategory) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.updateCalls++
	if m.updateErr != nil {
		return m.updateErr
	}
	m.categories[category.ID] = category
	return nil
}

func (m *toolCatMockRepo) Delete(_ context.Context, id shared.ID) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.deleteCalls++
	if m.deleteErr != nil {
		return m.deleteErr
	}
	delete(m.categories, id)
	return nil
}

func (m *toolCatMockRepo) ExistsByName(_ context.Context, tenantID *shared.ID, name string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.existsByNameCalls++
	if m.existsByNameErr != nil {
		return false, m.existsByNameErr
	}
	// Check overrides first
	if result, ok := m.existsByNameResults[name]; ok {
		return result, nil
	}
	// Default: check actual store
	for _, cat := range m.categories {
		if cat.Name == name {
			if tenantID == nil && cat.TenantID == nil {
				return true, nil
			}
			if tenantID != nil && cat.TenantID != nil && *tenantID == *cat.TenantID {
				return true, nil
			}
		}
	}
	return false, nil
}

func (m *toolCatMockRepo) CountByTenant(_ context.Context, _ shared.ID) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.countCalls++
	if m.countErr != nil {
		return 0, m.countErr
	}
	return int64(len(m.categories)), nil
}

// Helper to add a category directly to the mock store.
func (m *toolCatMockRepo) addCategory(cat *toolcategory.ToolCategory) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.categories[cat.ID] = cat
}

// =============================================================================
// Helper: create service
// =============================================================================

func newToolCatTestService() (*app.ToolCategoryService, *toolCatMockRepo) {
	repo := newToolCatMockRepo()
	log := logger.NewNop()
	svc := app.NewToolCategoryService(repo, nil, log)
	return svc, repo
}

// Helper: create a tenant category in the mock store.
func toolCatCreateTenantCategory(repo *toolCatMockRepo, tenantID shared.ID, name, displayName string) *toolcategory.ToolCategory {
	createdBy := shared.NewID()
	cat, _ := toolcategory.NewTenantCategory(tenantID, createdBy, name, displayName, "desc", "folder", "gray")
	repo.addCategory(cat)
	return cat
}

// Helper: create a platform category in the mock store.
func toolCatCreatePlatformCategory(repo *toolCatMockRepo, name, displayName string) *toolcategory.ToolCategory {
	cat, _ := toolcategory.NewPlatformCategory(name, displayName, "desc", "shield", "blue", 1)
	repo.addCategory(cat)
	return cat
}

// =============================================================================
// Tests: ListCategories
// =============================================================================

func TestToolCatListCategories_Success(t *testing.T) {
	svc, repo := newToolCatTestService()
	ctx := context.Background()

	tenantID := shared.NewID()
	toolCatCreatePlatformCategory(repo, "sast", "SAST")
	toolCatCreateTenantCategory(repo, tenantID, "my-cat", "My Category")

	result, err := svc.ListCategories(ctx, app.ListCategoriesInput{
		TenantID: tenantID.String(),
		Page:     1,
		PerPage:  20,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Data) != 2 {
		t.Fatalf("expected 2 categories, got %d", len(result.Data))
	}
	if repo.listCalls != 1 {
		t.Fatalf("expected 1 list call, got %d", repo.listCalls)
	}
}

func TestToolCatListCategories_NoTenantID(t *testing.T) {
	svc, repo := newToolCatTestService()
	ctx := context.Background()

	toolCatCreatePlatformCategory(repo, "sast", "SAST")

	result, err := svc.ListCategories(ctx, app.ListCategoriesInput{
		Page:    1,
		PerPage: 20,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Data) != 1 {
		t.Fatalf("expected 1 category, got %d", len(result.Data))
	}
}

func TestToolCatListCategories_InvalidTenantID(t *testing.T) {
	svc, _ := newToolCatTestService()
	ctx := context.Background()

	_, err := svc.ListCategories(ctx, app.ListCategoriesInput{
		TenantID: "not-a-uuid",
		Page:     1,
		PerPage:  20,
	})
	if err == nil {
		t.Fatal("expected error for invalid tenant ID")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("expected ErrValidation, got: %v", err)
	}
}

func TestToolCatListCategories_RepoError(t *testing.T) {
	svc, repo := newToolCatTestService()
	ctx := context.Background()

	repo.listErr = errors.New("database error")

	_, err := svc.ListCategories(ctx, app.ListCategoriesInput{
		Page:    1,
		PerPage: 20,
	})
	if err == nil {
		t.Fatal("expected error from repo")
	}
}

func TestToolCatListCategories_WithSearch(t *testing.T) {
	svc, repo := newToolCatTestService()
	ctx := context.Background()

	_, err := svc.ListCategories(ctx, app.ListCategoriesInput{
		Search:  "sast",
		Page:    1,
		PerPage: 20,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if repo.lastFilter.Search != "sast" {
		t.Fatalf("expected search 'sast', got '%s'", repo.lastFilter.Search)
	}
}

func TestToolCatListCategories_WithIsBuiltinFilter(t *testing.T) {
	svc, repo := newToolCatTestService()
	ctx := context.Background()

	isBuiltin := true
	_, err := svc.ListCategories(ctx, app.ListCategoriesInput{
		IsBuiltin: &isBuiltin,
		Page:      1,
		PerPage:   20,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if repo.lastFilter.IsBuiltin == nil || *repo.lastFilter.IsBuiltin != true {
		t.Fatal("expected IsBuiltin filter to be true")
	}
}

// =============================================================================
// Tests: ListAllCategories
// =============================================================================

func TestToolCatListAllCategories_Success(t *testing.T) {
	svc, repo := newToolCatTestService()
	ctx := context.Background()

	tenantID := shared.NewID()
	toolCatCreatePlatformCategory(repo, "sast", "SAST")
	toolCatCreateTenantCategory(repo, tenantID, "custom-cat", "Custom Cat")

	cats, err := svc.ListAllCategories(ctx, tenantID.String())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cats) != 2 {
		t.Fatalf("expected 2 categories, got %d", len(cats))
	}
	if repo.listAllCalls != 1 {
		t.Fatalf("expected 1 listAll call, got %d", repo.listAllCalls)
	}
}

func TestToolCatListAllCategories_EmptyTenantID(t *testing.T) {
	svc, _ := newToolCatTestService()
	ctx := context.Background()

	cats, err := svc.ListAllCategories(ctx, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	_ = cats // No error expected
}

func TestToolCatListAllCategories_InvalidTenantID(t *testing.T) {
	svc, _ := newToolCatTestService()
	ctx := context.Background()

	_, err := svc.ListAllCategories(ctx, "bad-id")
	if err == nil {
		t.Fatal("expected error for invalid tenant ID")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("expected ErrValidation, got: %v", err)
	}
}

func TestToolCatListAllCategories_RepoError(t *testing.T) {
	svc, repo := newToolCatTestService()
	ctx := context.Background()

	repo.listAllErr = errors.New("db down")

	_, err := svc.ListAllCategories(ctx, "")
	if err == nil {
		t.Fatal("expected error from repo")
	}
}

// =============================================================================
// Tests: GetCategory
// =============================================================================

func TestToolCatGetCategory_Success(t *testing.T) {
	svc, repo := newToolCatTestService()
	ctx := context.Background()

	cat := toolCatCreatePlatformCategory(repo, "dast", "DAST")

	result, err := svc.GetCategory(ctx, cat.ID.String())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Name != "dast" {
		t.Fatalf("expected name 'dast', got '%s'", result.Name)
	}
	if repo.getByIDCalls != 1 {
		t.Fatalf("expected 1 getByID call, got %d", repo.getByIDCalls)
	}
}

func TestToolCatGetCategory_InvalidID(t *testing.T) {
	svc, _ := newToolCatTestService()
	ctx := context.Background()

	_, err := svc.GetCategory(ctx, "invalid")
	if err == nil {
		t.Fatal("expected error for invalid ID")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("expected ErrValidation, got: %v", err)
	}
}

func TestToolCatGetCategory_NotFound(t *testing.T) {
	svc, _ := newToolCatTestService()
	ctx := context.Background()

	_, err := svc.GetCategory(ctx, shared.NewID().String())
	if err == nil {
		t.Fatal("expected error for not found")
	}
}

func TestToolCatGetCategory_RepoError(t *testing.T) {
	svc, repo := newToolCatTestService()
	ctx := context.Background()

	repo.getByIDErr = errors.New("db error")

	_, err := svc.GetCategory(ctx, shared.NewID().String())
	if err == nil {
		t.Fatal("expected error from repo")
	}
}

// =============================================================================
// Tests: CreateCategory
// =============================================================================

func TestToolCatCreateCategory_Success(t *testing.T) {
	svc, repo := newToolCatTestService()
	ctx := context.Background()

	tenantID := shared.NewID()
	userID := shared.NewID()

	cat, err := svc.CreateCategory(ctx, app.CreateCategoryInput{
		TenantID:    tenantID.String(),
		CreatedBy:   userID.String(),
		Name:        "my-custom",
		DisplayName: "My Custom",
		Description: "A custom category",
		Icon:        "shield",
		Color:       "blue",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cat.Name != "my-custom" {
		t.Fatalf("expected name 'my-custom', got '%s'", cat.Name)
	}
	if cat.DisplayName != "My Custom" {
		t.Fatalf("expected display name 'My Custom', got '%s'", cat.DisplayName)
	}
	if cat.Icon != "shield" {
		t.Fatalf("expected icon 'shield', got '%s'", cat.Icon)
	}
	if cat.Color != "blue" {
		t.Fatalf("expected color 'blue', got '%s'", cat.Color)
	}
	if cat.IsBuiltin {
		t.Fatal("expected IsBuiltin to be false")
	}
	if cat.TenantID == nil || *cat.TenantID != tenantID {
		t.Fatal("expected tenant ID to match")
	}
	if repo.createCalls != 1 {
		t.Fatalf("expected 1 create call, got %d", repo.createCalls)
	}
	// ExistsByName called twice: once for platform, once for tenant
	if repo.existsByNameCalls != 2 {
		t.Fatalf("expected 2 existsByName calls, got %d", repo.existsByNameCalls)
	}
}

func TestToolCatCreateCategory_DefaultIconAndColor(t *testing.T) {
	svc, _ := newToolCatTestService()
	ctx := context.Background()

	tenantID := shared.NewID()
	userID := shared.NewID()

	cat, err := svc.CreateCategory(ctx, app.CreateCategoryInput{
		TenantID:    tenantID.String(),
		CreatedBy:   userID.String(),
		Name:        "no-icon",
		DisplayName: "No Icon",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cat.Icon != "folder" {
		t.Fatalf("expected default icon 'folder', got '%s'", cat.Icon)
	}
	if cat.Color != "gray" {
		t.Fatalf("expected default color 'gray', got '%s'", cat.Color)
	}
}

func TestToolCatCreateCategory_InvalidTenantID(t *testing.T) {
	svc, _ := newToolCatTestService()
	ctx := context.Background()

	_, err := svc.CreateCategory(ctx, app.CreateCategoryInput{
		TenantID:    "bad",
		CreatedBy:   shared.NewID().String(),
		Name:        "test",
		DisplayName: "Test",
	})
	if err == nil {
		t.Fatal("expected error for invalid tenant ID")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("expected ErrValidation, got: %v", err)
	}
}

func TestToolCatCreateCategory_InvalidCreatedBy(t *testing.T) {
	svc, _ := newToolCatTestService()
	ctx := context.Background()

	_, err := svc.CreateCategory(ctx, app.CreateCategoryInput{
		TenantID:    shared.NewID().String(),
		CreatedBy:   "bad",
		Name:        "test",
		DisplayName: "Test",
	})
	if err == nil {
		t.Fatal("expected error for invalid created_by")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("expected ErrValidation, got: %v", err)
	}
}

func TestToolCatCreateCategory_DuplicatePlatformName(t *testing.T) {
	svc, repo := newToolCatTestService()
	ctx := context.Background()

	// Pre-set platform name as existing
	repo.existsByNameResults["sast"] = true

	_, err := svc.CreateCategory(ctx, app.CreateCategoryInput{
		TenantID:    shared.NewID().String(),
		CreatedBy:   shared.NewID().String(),
		Name:        "sast",
		DisplayName: "SAST",
	})
	if err == nil {
		t.Fatal("expected error for duplicate platform name")
	}
	if !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("expected ErrConflict, got: %v", err)
	}
}

func TestToolCatCreateCategory_DuplicateTenantName(t *testing.T) {
	svc, repo := newToolCatTestService()
	ctx := context.Background()

	tenantID := shared.NewID()
	// Create an existing tenant category
	toolCatCreateTenantCategory(repo, tenantID, "my-cat", "My Category")

	_, err := svc.CreateCategory(ctx, app.CreateCategoryInput{
		TenantID:    tenantID.String(),
		CreatedBy:   shared.NewID().String(),
		Name:        "my-cat",
		DisplayName: "My Category Again",
	})
	if err == nil {
		t.Fatal("expected error for duplicate tenant name")
	}
	if !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("expected ErrConflict, got: %v", err)
	}
}

func TestToolCatCreateCategory_PlatformCheckError(t *testing.T) {
	svc, repo := newToolCatTestService()
	ctx := context.Background()

	repo.existsByNameErr = errors.New("db error")

	_, err := svc.CreateCategory(ctx, app.CreateCategoryInput{
		TenantID:    shared.NewID().String(),
		CreatedBy:   shared.NewID().String(),
		Name:        "test-cat",
		DisplayName: "Test Cat",
	})
	if err == nil {
		t.Fatal("expected error from ExistsByName")
	}
}

func TestToolCatCreateCategory_RepoCreateError(t *testing.T) {
	svc, repo := newToolCatTestService()
	ctx := context.Background()

	repo.createErr = errors.New("db error")

	_, err := svc.CreateCategory(ctx, app.CreateCategoryInput{
		TenantID:    shared.NewID().String(),
		CreatedBy:   shared.NewID().String(),
		Name:        "test-cat",
		DisplayName: "Test Cat",
	})
	if err == nil {
		t.Fatal("expected error from repo Create")
	}
}

// =============================================================================
// Tests: UpdateCategory
// =============================================================================

func TestToolCatUpdateCategory_Success(t *testing.T) {
	svc, repo := newToolCatTestService()
	ctx := context.Background()

	tenantID := shared.NewID()
	cat := toolCatCreateTenantCategory(repo, tenantID, "my-cat", "Old Name")

	updated, err := svc.UpdateCategory(ctx, app.UpdateCategoryInput{
		TenantID:    tenantID.String(),
		ID:          cat.ID.String(),
		DisplayName: "New Name",
		Description: "Updated desc",
		Icon:        "star",
		Color:       "red",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if updated.DisplayName != "New Name" {
		t.Fatalf("expected display name 'New Name', got '%s'", updated.DisplayName)
	}
	if updated.Description != "Updated desc" {
		t.Fatalf("expected description 'Updated desc', got '%s'", updated.Description)
	}
	if updated.Icon != "star" {
		t.Fatalf("expected icon 'star', got '%s'", updated.Icon)
	}
	if updated.Color != "red" {
		t.Fatalf("expected color 'red', got '%s'", updated.Color)
	}
	if repo.updateCalls != 1 {
		t.Fatalf("expected 1 update call, got %d", repo.updateCalls)
	}
}

func TestToolCatUpdateCategory_DefaultIconAndColor(t *testing.T) {
	svc, repo := newToolCatTestService()
	ctx := context.Background()

	tenantID := shared.NewID()
	cat := toolCatCreateTenantCategory(repo, tenantID, "my-cat", "Name")

	updated, err := svc.UpdateCategory(ctx, app.UpdateCategoryInput{
		TenantID:    tenantID.String(),
		ID:          cat.ID.String(),
		DisplayName: "Name",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if updated.Icon != "folder" {
		t.Fatalf("expected default icon 'folder', got '%s'", updated.Icon)
	}
	if updated.Color != "gray" {
		t.Fatalf("expected default color 'gray', got '%s'", updated.Color)
	}
}

func TestToolCatUpdateCategory_InvalidTenantID(t *testing.T) {
	svc, _ := newToolCatTestService()
	ctx := context.Background()

	_, err := svc.UpdateCategory(ctx, app.UpdateCategoryInput{
		TenantID:    "bad",
		ID:          shared.NewID().String(),
		DisplayName: "Test",
	})
	if err == nil {
		t.Fatal("expected error for invalid tenant ID")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("expected ErrValidation, got: %v", err)
	}
}

func TestToolCatUpdateCategory_InvalidCategoryID(t *testing.T) {
	svc, _ := newToolCatTestService()
	ctx := context.Background()

	_, err := svc.UpdateCategory(ctx, app.UpdateCategoryInput{
		TenantID:    shared.NewID().String(),
		ID:          "bad",
		DisplayName: "Test",
	})
	if err == nil {
		t.Fatal("expected error for invalid category ID")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("expected ErrValidation, got: %v", err)
	}
}

func TestToolCatUpdateCategory_NotFound(t *testing.T) {
	svc, _ := newToolCatTestService()
	ctx := context.Background()

	_, err := svc.UpdateCategory(ctx, app.UpdateCategoryInput{
		TenantID:    shared.NewID().String(),
		ID:          shared.NewID().String(),
		DisplayName: "Test",
	})
	if err == nil {
		t.Fatal("expected error for not found")
	}
}

func TestToolCatUpdateCategory_CannotModifyPlatformCategory(t *testing.T) {
	svc, repo := newToolCatTestService()
	ctx := context.Background()

	cat := toolCatCreatePlatformCategory(repo, "sast", "SAST")

	_, err := svc.UpdateCategory(ctx, app.UpdateCategoryInput{
		TenantID:    shared.NewID().String(),
		ID:          cat.ID.String(),
		DisplayName: "Hacked",
	})
	if err == nil {
		t.Fatal("expected error for modifying platform category")
	}
	if !errors.Is(err, shared.ErrForbidden) {
		t.Fatalf("expected ErrForbidden, got: %v", err)
	}
}

func TestToolCatUpdateCategory_CannotModifyOtherTenantCategory(t *testing.T) {
	svc, repo := newToolCatTestService()
	ctx := context.Background()

	tenantA := shared.NewID()
	tenantB := shared.NewID()
	cat := toolCatCreateTenantCategory(repo, tenantA, "tenant-a-cat", "Tenant A Cat")

	_, err := svc.UpdateCategory(ctx, app.UpdateCategoryInput{
		TenantID:    tenantB.String(),
		ID:          cat.ID.String(),
		DisplayName: "Stolen",
	})
	if err == nil {
		t.Fatal("expected error for modifying another tenant's category")
	}
	if !errors.Is(err, shared.ErrForbidden) {
		t.Fatalf("expected ErrForbidden, got: %v", err)
	}
}

func TestToolCatUpdateCategory_RepoUpdateError(t *testing.T) {
	svc, repo := newToolCatTestService()
	ctx := context.Background()

	tenantID := shared.NewID()
	cat := toolCatCreateTenantCategory(repo, tenantID, "my-cat", "Name")
	repo.updateErr = errors.New("db error")

	_, err := svc.UpdateCategory(ctx, app.UpdateCategoryInput{
		TenantID:    tenantID.String(),
		ID:          cat.ID.String(),
		DisplayName: "Updated",
	})
	if err == nil {
		t.Fatal("expected error from repo Update")
	}
}

// =============================================================================
// Tests: DeleteCategory
// =============================================================================

func TestToolCatDeleteCategory_Success(t *testing.T) {
	svc, repo := newToolCatTestService()
	ctx := context.Background()

	tenantID := shared.NewID()
	cat := toolCatCreateTenantCategory(repo, tenantID, "my-cat", "My Category")

	err := svc.DeleteCategory(ctx, tenantID.String(), cat.ID.String())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if repo.deleteCalls != 1 {
		t.Fatalf("expected 1 delete call, got %d", repo.deleteCalls)
	}
}

func TestToolCatDeleteCategory_InvalidTenantID(t *testing.T) {
	svc, _ := newToolCatTestService()
	ctx := context.Background()

	err := svc.DeleteCategory(ctx, "bad", shared.NewID().String())
	if err == nil {
		t.Fatal("expected error for invalid tenant ID")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("expected ErrValidation, got: %v", err)
	}
}

func TestToolCatDeleteCategory_InvalidCategoryID(t *testing.T) {
	svc, _ := newToolCatTestService()
	ctx := context.Background()

	err := svc.DeleteCategory(ctx, shared.NewID().String(), "bad")
	if err == nil {
		t.Fatal("expected error for invalid category ID")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("expected ErrValidation, got: %v", err)
	}
}

func TestToolCatDeleteCategory_NotFound(t *testing.T) {
	svc, _ := newToolCatTestService()
	ctx := context.Background()

	err := svc.DeleteCategory(ctx, shared.NewID().String(), shared.NewID().String())
	if err == nil {
		t.Fatal("expected error for not found")
	}
}

func TestToolCatDeleteCategory_CannotDeletePlatformCategory(t *testing.T) {
	svc, repo := newToolCatTestService()
	ctx := context.Background()

	cat := toolCatCreatePlatformCategory(repo, "sast", "SAST")

	err := svc.DeleteCategory(ctx, shared.NewID().String(), cat.ID.String())
	if err == nil {
		t.Fatal("expected error for deleting platform category")
	}
	if !errors.Is(err, shared.ErrForbidden) {
		t.Fatalf("expected ErrForbidden, got: %v", err)
	}
}

func TestToolCatDeleteCategory_CannotDeleteOtherTenantCategory(t *testing.T) {
	svc, repo := newToolCatTestService()
	ctx := context.Background()

	tenantA := shared.NewID()
	tenantB := shared.NewID()
	cat := toolCatCreateTenantCategory(repo, tenantA, "tenant-a-cat", "Tenant A Cat")

	err := svc.DeleteCategory(ctx, tenantB.String(), cat.ID.String())
	if err == nil {
		t.Fatal("expected error for deleting another tenant's category")
	}
	if !errors.Is(err, shared.ErrForbidden) {
		t.Fatalf("expected ErrForbidden, got: %v", err)
	}
}

func TestToolCatDeleteCategory_RepoDeleteError(t *testing.T) {
	svc, repo := newToolCatTestService()
	ctx := context.Background()

	tenantID := shared.NewID()
	cat := toolCatCreateTenantCategory(repo, tenantID, "my-cat", "My Category")
	repo.deleteErr = errors.New("db error")

	err := svc.DeleteCategory(ctx, tenantID.String(), cat.ID.String())
	if err == nil {
		t.Fatal("expected error from repo Delete")
	}
}

func TestToolCatDeleteCategory_RepoGetByIDError(t *testing.T) {
	svc, repo := newToolCatTestService()
	ctx := context.Background()

	tenantID := shared.NewID()
	cat := toolCatCreateTenantCategory(repo, tenantID, "my-cat", "My Category")
	repo.getByIDErr = errors.New("db error")

	err := svc.DeleteCategory(ctx, tenantID.String(), cat.ID.String())
	if err == nil {
		t.Fatal("expected error from repo GetByID")
	}
}

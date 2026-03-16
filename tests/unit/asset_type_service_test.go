package unit

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/openctemio/api/internal/app"
	"github.com/openctemio/api/pkg/domain/assettype"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/logger"
	"github.com/openctemio/api/pkg/pagination"
)

// ============================================================================
// Mock Repositories
// ============================================================================

// mockAssetTypeRepository implements assettype.Repository for testing.
type mockAssetTypeRepository struct {
	assetTypes        map[string]*assettype.AssetType
	assetTypesWithCat []assettype.AssetTypeWithCategory
	listErr           error
	listWithCatErr    error
	listActiveErr     error
	listActiveByCatFn func(ctx context.Context, categoryID shared.ID) ([]*assettype.AssetType, error)
}

func newMockAssetTypeRepository() *mockAssetTypeRepository {
	return &mockAssetTypeRepository{
		assetTypes: make(map[string]*assettype.AssetType),
	}
}

func (m *mockAssetTypeRepository) GetByID(_ context.Context, id shared.ID) (*assettype.AssetType, error) {
	at, ok := m.assetTypes[id.String()]
	if !ok {
		return nil, assettype.ErrAssetTypeNotFound
	}
	return at, nil
}

func (m *mockAssetTypeRepository) GetByCode(_ context.Context, code string) (*assettype.AssetType, error) {
	for _, at := range m.assetTypes {
		if at.Code() == code {
			return at, nil
		}
	}
	return nil, assettype.ErrAssetTypeNotFound
}

func (m *mockAssetTypeRepository) List(_ context.Context, _ assettype.Filter, _ assettype.ListOptions, page pagination.Pagination) (pagination.Result[*assettype.AssetType], error) {
	if m.listErr != nil {
		return pagination.Result[*assettype.AssetType]{}, m.listErr
	}
	result := make([]*assettype.AssetType, 0, len(m.assetTypes))
	for _, at := range m.assetTypes {
		result = append(result, at)
	}
	total := int64(len(result))
	return pagination.Result[*assettype.AssetType]{
		Data:       result,
		Total:      total,
		Page:       page.Page,
		PerPage:    page.PerPage,
		TotalPages: int((total + int64(page.PerPage) - 1) / int64(page.PerPage)),
	}, nil
}

func (m *mockAssetTypeRepository) ListWithCategory(_ context.Context, _ assettype.Filter, _ assettype.ListOptions, page pagination.Pagination) (pagination.Result[*assettype.AssetTypeWithCategory], error) {
	if m.listWithCatErr != nil {
		return pagination.Result[*assettype.AssetTypeWithCategory]{}, m.listWithCatErr
	}
	result := make([]*assettype.AssetTypeWithCategory, 0, len(m.assetTypesWithCat))
	for i := range m.assetTypesWithCat {
		result = append(result, &m.assetTypesWithCat[i])
	}
	total := int64(len(result))
	return pagination.Result[*assettype.AssetTypeWithCategory]{
		Data:       result,
		Total:      total,
		Page:       page.Page,
		PerPage:    page.PerPage,
		TotalPages: int((total + int64(page.PerPage) - 1) / int64(page.PerPage)),
	}, nil
}

func (m *mockAssetTypeRepository) ListActive(_ context.Context) ([]*assettype.AssetType, error) {
	if m.listActiveErr != nil {
		return nil, m.listActiveErr
	}
	result := make([]*assettype.AssetType, 0, len(m.assetTypes))
	for _, at := range m.assetTypes {
		if at.IsActive() {
			result = append(result, at)
		}
	}
	return result, nil
}

func (m *mockAssetTypeRepository) ListActiveByCategory(ctx context.Context, categoryID shared.ID) ([]*assettype.AssetType, error) {
	if m.listActiveByCatFn != nil {
		return m.listActiveByCatFn(ctx, categoryID)
	}
	result := make([]*assettype.AssetType, 0)
	for _, at := range m.assetTypes {
		if at.IsActive() && at.CategoryID() != nil && *at.CategoryID() == categoryID {
			result = append(result, at)
		}
	}
	return result, nil
}

func (m *mockAssetTypeRepository) ExistsByCode(_ context.Context, code string) (bool, error) {
	for _, at := range m.assetTypes {
		if at.Code() == code {
			return true, nil
		}
	}
	return false, nil
}

// mockCategoryRepository implements assettype.CategoryRepository for testing.
type mockCategoryRepository struct {
	categories    map[string]*assettype.Category
	listErr       error
	listActiveErr error
}

func newMockCategoryRepository() *mockCategoryRepository {
	return &mockCategoryRepository{
		categories: make(map[string]*assettype.Category),
	}
}

func (m *mockCategoryRepository) Create(_ context.Context, category *assettype.Category) error {
	m.categories[category.ID().String()] = category
	return nil
}

func (m *mockCategoryRepository) GetByID(_ context.Context, id shared.ID) (*assettype.Category, error) {
	c, ok := m.categories[id.String()]
	if !ok {
		return nil, assettype.ErrCategoryNotFound
	}
	return c, nil
}

func (m *mockCategoryRepository) GetByCode(_ context.Context, code string) (*assettype.Category, error) {
	for _, c := range m.categories {
		if c.Code() == code {
			return c, nil
		}
	}
	return nil, assettype.ErrCategoryNotFound
}

func (m *mockCategoryRepository) Update(_ context.Context, category *assettype.Category) error {
	m.categories[category.ID().String()] = category
	return nil
}

func (m *mockCategoryRepository) Delete(_ context.Context, id shared.ID) error {
	delete(m.categories, id.String())
	return nil
}

func (m *mockCategoryRepository) List(_ context.Context, _ assettype.CategoryFilter, page pagination.Pagination) (pagination.Result[*assettype.Category], error) {
	if m.listErr != nil {
		return pagination.Result[*assettype.Category]{}, m.listErr
	}
	result := make([]*assettype.Category, 0, len(m.categories))
	for _, c := range m.categories {
		result = append(result, c)
	}
	total := int64(len(result))
	return pagination.Result[*assettype.Category]{
		Data:       result,
		Total:      total,
		Page:       page.Page,
		PerPage:    page.PerPage,
		TotalPages: int((total + int64(page.PerPage) - 1) / int64(page.PerPage)),
	}, nil
}

func (m *mockCategoryRepository) ListActive(_ context.Context) ([]*assettype.Category, error) {
	if m.listActiveErr != nil {
		return nil, m.listActiveErr
	}
	result := make([]*assettype.Category, 0, len(m.categories))
	for _, c := range m.categories {
		if c.IsActive() {
			result = append(result, c)
		}
	}
	return result, nil
}

// ============================================================================
// Helper Functions
// ============================================================================

func newTestAssetTypeService() (*app.AssetTypeService, *mockAssetTypeRepository, *mockCategoryRepository) {
	repo := newMockAssetTypeRepository()
	catRepo := newMockCategoryRepository()
	log := logger.NewNop()
	svc := app.NewAssetTypeService(repo, catRepo, log)
	return svc, repo, catRepo
}

func makeTestCategory(code, name string) *assettype.Category {
	id := shared.NewID()
	now := time.Now().UTC()
	return assettype.ReconstituteCategory(id, code, name, "test description", "icon", 0, true, now, now)
}

func makeTestAssetType(code, name string, categoryID *shared.ID) *assettype.AssetType {
	id := shared.NewID()
	now := time.Now().UTC()
	return assettype.ReconstituteAssetType(
		id, categoryID, code, name, "test description",
		"icon", "#000000", 0,
		"", "", "",
		false, false,
		true, true,
		false, true,
		now, now,
	)
}

// ============================================================================
// GetCategory Tests
// ============================================================================

func TestAssetTypeService_GetCategory_Success(t *testing.T) {
	svc, _, catRepo := newTestAssetTypeService()
	ctx := context.Background()

	cat := makeTestCategory("network", "Network")
	catRepo.categories[cat.ID().String()] = cat

	result, err := svc.GetCategory(ctx, cat.ID().String())
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if result.ID() != cat.ID() {
		t.Errorf("expected category ID %s, got %s", cat.ID(), result.ID())
	}
	if result.Code() != "network" {
		t.Errorf("expected code 'network', got %q", result.Code())
	}
}

func TestAssetTypeService_GetCategory_InvalidID(t *testing.T) {
	svc, _, _ := newTestAssetTypeService()
	ctx := context.Background()

	_, err := svc.GetCategory(ctx, "not-a-uuid")
	if err == nil {
		t.Fatal("expected error for invalid ID")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected ErrValidation, got %v", err)
	}
}

func TestAssetTypeService_GetCategory_NotFound(t *testing.T) {
	svc, _, _ := newTestAssetTypeService()
	ctx := context.Background()

	id := shared.NewID()
	_, err := svc.GetCategory(ctx, id.String())
	if err == nil {
		t.Fatal("expected error for not found category")
	}
	if !errors.Is(err, assettype.ErrCategoryNotFound) {
		t.Errorf("expected ErrCategoryNotFound, got %v", err)
	}
}

// ============================================================================
// GetCategoryByCode Tests
// ============================================================================

func TestAssetTypeService_GetCategoryByCode_Success(t *testing.T) {
	svc, _, catRepo := newTestAssetTypeService()
	ctx := context.Background()

	cat := makeTestCategory("infrastructure", "Infrastructure")
	catRepo.categories[cat.ID().String()] = cat

	result, err := svc.GetCategoryByCode(ctx, "infrastructure")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if result.Code() != "infrastructure" {
		t.Errorf("expected code 'infrastructure', got %q", result.Code())
	}
}

func TestAssetTypeService_GetCategoryByCode_NotFound(t *testing.T) {
	svc, _, _ := newTestAssetTypeService()
	ctx := context.Background()

	_, err := svc.GetCategoryByCode(ctx, "nonexistent")
	if err == nil {
		t.Fatal("expected error for not found category")
	}
	if !errors.Is(err, assettype.ErrCategoryNotFound) {
		t.Errorf("expected ErrCategoryNotFound, got %v", err)
	}
}

// ============================================================================
// ListCategories Tests
// ============================================================================

func TestAssetTypeService_ListCategories_Success(t *testing.T) {
	svc, _, catRepo := newTestAssetTypeService()
	ctx := context.Background()

	cat1 := makeTestCategory("network", "Network")
	cat2 := makeTestCategory("application", "Application")
	catRepo.categories[cat1.ID().String()] = cat1
	catRepo.categories[cat2.ID().String()] = cat2

	filter := assettype.NewCategoryFilter()
	page := pagination.Pagination{Page: 1, PerPage: 10}

	result, err := svc.ListCategories(ctx, filter, page)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if result.Total != 2 {
		t.Errorf("expected total 2, got %d", result.Total)
	}
	if len(result.Data) != 2 {
		t.Errorf("expected 2 items, got %d", len(result.Data))
	}
}

func TestAssetTypeService_ListCategories_RepoError(t *testing.T) {
	svc, _, catRepo := newTestAssetTypeService()
	ctx := context.Background()

	catRepo.listErr = errors.New("database connection failed")

	filter := assettype.NewCategoryFilter()
	page := pagination.Pagination{Page: 1, PerPage: 10}

	_, err := svc.ListCategories(ctx, filter, page)
	if err == nil {
		t.Fatal("expected error from repository")
	}
}

// ============================================================================
// ListActiveCategories Tests
// ============================================================================

func TestAssetTypeService_ListActiveCategories_Success(t *testing.T) {
	svc, _, catRepo := newTestAssetTypeService()
	ctx := context.Background()

	cat1 := makeTestCategory("network", "Network")
	cat2 := makeTestCategory("cloud", "Cloud")
	catRepo.categories[cat1.ID().String()] = cat1
	catRepo.categories[cat2.ID().String()] = cat2

	result, err := svc.ListActiveCategories(ctx)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if len(result) != 2 {
		t.Errorf("expected 2 active categories, got %d", len(result))
	}
}

func TestAssetTypeService_ListActiveCategories_RepoError(t *testing.T) {
	svc, _, catRepo := newTestAssetTypeService()
	ctx := context.Background()

	catRepo.listActiveErr = errors.New("database timeout")

	_, err := svc.ListActiveCategories(ctx)
	if err == nil {
		t.Fatal("expected error from repository")
	}
}

// ============================================================================
// GetAssetType Tests
// ============================================================================

func TestAssetTypeService_GetAssetType_Success(t *testing.T) {
	svc, repo, _ := newTestAssetTypeService()
	ctx := context.Background()

	at := makeTestAssetType("ip_address", "IP Address", nil)
	repo.assetTypes[at.ID().String()] = at

	result, err := svc.GetAssetType(ctx, at.ID().String())
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if result.ID() != at.ID() {
		t.Errorf("expected asset type ID %s, got %s", at.ID(), result.ID())
	}
	if result.Code() != "ip_address" {
		t.Errorf("expected code 'ip_address', got %q", result.Code())
	}
}

func TestAssetTypeService_GetAssetType_InvalidID(t *testing.T) {
	svc, _, _ := newTestAssetTypeService()
	ctx := context.Background()

	_, err := svc.GetAssetType(ctx, "bad-id")
	if err == nil {
		t.Fatal("expected error for invalid ID")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected ErrValidation, got %v", err)
	}
}

func TestAssetTypeService_GetAssetType_NotFound(t *testing.T) {
	svc, _, _ := newTestAssetTypeService()
	ctx := context.Background()

	id := shared.NewID()
	_, err := svc.GetAssetType(ctx, id.String())
	if err == nil {
		t.Fatal("expected error for not found asset type")
	}
	if !errors.Is(err, assettype.ErrAssetTypeNotFound) {
		t.Errorf("expected ErrAssetTypeNotFound, got %v", err)
	}
}

// ============================================================================
// GetAssetTypeByCode Tests
// ============================================================================

func TestAssetTypeService_GetAssetTypeByCode_Success(t *testing.T) {
	svc, repo, _ := newTestAssetTypeService()
	ctx := context.Background()

	at := makeTestAssetType("domain", "Domain", nil)
	repo.assetTypes[at.ID().String()] = at

	result, err := svc.GetAssetTypeByCode(ctx, "domain")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if result.Code() != "domain" {
		t.Errorf("expected code 'domain', got %q", result.Code())
	}
	if result.Name() != "Domain" {
		t.Errorf("expected name 'Domain', got %q", result.Name())
	}
}

func TestAssetTypeService_GetAssetTypeByCode_NotFound(t *testing.T) {
	svc, _, _ := newTestAssetTypeService()
	ctx := context.Background()

	_, err := svc.GetAssetTypeByCode(ctx, "nonexistent_type")
	if err == nil {
		t.Fatal("expected error for not found asset type")
	}
	if !errors.Is(err, assettype.ErrAssetTypeNotFound) {
		t.Errorf("expected ErrAssetTypeNotFound, got %v", err)
	}
}

// ============================================================================
// ListAssetTypes Tests
// ============================================================================

func TestAssetTypeService_ListAssetTypes_Success(t *testing.T) {
	svc, repo, _ := newTestAssetTypeService()
	ctx := context.Background()

	at1 := makeTestAssetType("ip_address", "IP Address", nil)
	at2 := makeTestAssetType("domain", "Domain", nil)
	repo.assetTypes[at1.ID().String()] = at1
	repo.assetTypes[at2.ID().String()] = at2

	filter := assettype.NewFilter()
	opts := assettype.NewListOptions()
	page := pagination.Pagination{Page: 1, PerPage: 10}

	result, err := svc.ListAssetTypes(ctx, filter, opts, page)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if result.Total != 2 {
		t.Errorf("expected total 2, got %d", result.Total)
	}
	if len(result.Data) != 2 {
		t.Errorf("expected 2 items, got %d", len(result.Data))
	}
	if result.Page != 1 {
		t.Errorf("expected page 1, got %d", result.Page)
	}
	if result.PerPage != 10 {
		t.Errorf("expected per_page 10, got %d", result.PerPage)
	}
}

func TestAssetTypeService_ListAssetTypes_RepoError(t *testing.T) {
	svc, repo, _ := newTestAssetTypeService()
	ctx := context.Background()

	repo.listErr = errors.New("query failed")

	filter := assettype.NewFilter()
	opts := assettype.NewListOptions()
	page := pagination.Pagination{Page: 1, PerPage: 10}

	_, err := svc.ListAssetTypes(ctx, filter, opts, page)
	if err == nil {
		t.Fatal("expected error from repository")
	}
}

// ============================================================================
// ListAssetTypesWithCategory Tests
// ============================================================================

func TestAssetTypeService_ListAssetTypesWithCategory_Success(t *testing.T) {
	svc, repo, _ := newTestAssetTypeService()
	ctx := context.Background()

	cat := makeTestCategory("network", "Network")
	catID := cat.ID()
	at := makeTestAssetType("ip_address", "IP Address", &catID)

	repo.assetTypesWithCat = []assettype.AssetTypeWithCategory{
		{AssetType: at, Category: cat},
	}

	filter := assettype.NewFilter()
	opts := assettype.NewListOptions()
	page := pagination.Pagination{Page: 1, PerPage: 10}

	result, err := svc.ListAssetTypesWithCategory(ctx, filter, opts, page)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if result.Total != 1 {
		t.Errorf("expected total 1, got %d", result.Total)
	}
	if result.Data[0].AssetType.Code() != "ip_address" {
		t.Errorf("expected code 'ip_address', got %q", result.Data[0].AssetType.Code())
	}
	if result.Data[0].Category.Code() != "network" {
		t.Errorf("expected category code 'network', got %q", result.Data[0].Category.Code())
	}
}

func TestAssetTypeService_ListAssetTypesWithCategory_RepoError(t *testing.T) {
	svc, repo, _ := newTestAssetTypeService()
	ctx := context.Background()

	repo.listWithCatErr = errors.New("join query failed")

	filter := assettype.NewFilter()
	opts := assettype.NewListOptions()
	page := pagination.Pagination{Page: 1, PerPage: 10}

	_, err := svc.ListAssetTypesWithCategory(ctx, filter, opts, page)
	if err == nil {
		t.Fatal("expected error from repository")
	}
}

// ============================================================================
// ListActiveAssetTypes Tests
// ============================================================================

func TestAssetTypeService_ListActiveAssetTypes_Success(t *testing.T) {
	svc, repo, _ := newTestAssetTypeService()
	ctx := context.Background()

	at1 := makeTestAssetType("ip_address", "IP Address", nil)
	at2 := makeTestAssetType("domain", "Domain", nil)
	repo.assetTypes[at1.ID().String()] = at1
	repo.assetTypes[at2.ID().String()] = at2

	result, err := svc.ListActiveAssetTypes(ctx)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if len(result) != 2 {
		t.Errorf("expected 2 active asset types, got %d", len(result))
	}
}

func TestAssetTypeService_ListActiveAssetTypes_RepoError(t *testing.T) {
	svc, repo, _ := newTestAssetTypeService()
	ctx := context.Background()

	repo.listActiveErr = errors.New("database unavailable")

	_, err := svc.ListActiveAssetTypes(ctx)
	if err == nil {
		t.Fatal("expected error from repository")
	}
}

// ============================================================================
// ListActiveAssetTypesByCategory Tests
// ============================================================================

func TestAssetTypeService_ListActiveAssetTypesByCategory_Success(t *testing.T) {
	svc, repo, _ := newTestAssetTypeService()
	ctx := context.Background()

	catID := shared.NewID()
	at1 := makeTestAssetType("ip_address", "IP Address", &catID)
	at2 := makeTestAssetType("cidr", "CIDR Range", &catID)
	repo.assetTypes[at1.ID().String()] = at1
	repo.assetTypes[at2.ID().String()] = at2

	result, err := svc.ListActiveAssetTypesByCategory(ctx, catID.String())
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if len(result) != 2 {
		t.Errorf("expected 2 asset types in category, got %d", len(result))
	}
}

func TestAssetTypeService_ListActiveAssetTypesByCategory_InvalidID(t *testing.T) {
	svc, _, _ := newTestAssetTypeService()
	ctx := context.Background()

	_, err := svc.ListActiveAssetTypesByCategory(ctx, "invalid-uuid")
	if err == nil {
		t.Fatal("expected error for invalid category ID")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected ErrValidation, got %v", err)
	}
}

func TestAssetTypeService_ListActiveAssetTypesByCategory_RepoError(t *testing.T) {
	svc, repo, _ := newTestAssetTypeService()
	ctx := context.Background()

	repoErr := errors.New("database error")
	repo.listActiveByCatFn = func(_ context.Context, _ shared.ID) ([]*assettype.AssetType, error) {
		return nil, repoErr
	}

	catID := shared.NewID()
	_, err := svc.ListActiveAssetTypesByCategory(ctx, catID.String())
	if err == nil {
		t.Fatal("expected error from repository")
	}
	if !errors.Is(err, repoErr) {
		t.Errorf("expected repoErr, got %v", err)
	}
}

// ============================================================================
// Edge Case Tests
// ============================================================================

func TestAssetTypeService_GetCategory_EmptyStringID(t *testing.T) {
	svc, _, _ := newTestAssetTypeService()
	ctx := context.Background()

	_, err := svc.GetCategory(ctx, "")
	if err == nil {
		t.Fatal("expected error for empty string ID")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected ErrValidation, got %v", err)
	}
}

func TestAssetTypeService_GetAssetType_EmptyStringID(t *testing.T) {
	svc, _, _ := newTestAssetTypeService()
	ctx := context.Background()

	_, err := svc.GetAssetType(ctx, "")
	if err == nil {
		t.Fatal("expected error for empty string ID")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected ErrValidation, got %v", err)
	}
}

func TestAssetTypeService_ListActiveAssetTypesByCategory_EmptyStringID(t *testing.T) {
	svc, _, _ := newTestAssetTypeService()
	ctx := context.Background()

	_, err := svc.ListActiveAssetTypesByCategory(ctx, "")
	if err == nil {
		t.Fatal("expected error for empty string category ID")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected ErrValidation, got %v", err)
	}
}

func TestAssetTypeService_ListCategories_EmptyResult(t *testing.T) {
	svc, _, _ := newTestAssetTypeService()
	ctx := context.Background()

	filter := assettype.NewCategoryFilter()
	page := pagination.Pagination{Page: 1, PerPage: 10}

	result, err := svc.ListCategories(ctx, filter, page)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if result.Total != 0 {
		t.Errorf("expected total 0, got %d", result.Total)
	}
	if len(result.Data) != 0 {
		t.Errorf("expected 0 items, got %d", len(result.Data))
	}
}

func TestAssetTypeService_ListActiveAssetTypes_EmptyResult(t *testing.T) {
	svc, _, _ := newTestAssetTypeService()
	ctx := context.Background()

	result, err := svc.ListActiveAssetTypes(ctx)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if len(result) != 0 {
		t.Errorf("expected 0 active asset types, got %d", len(result))
	}
}

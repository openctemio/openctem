package unit

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/openctemio/api/internal/app"
	"github.com/openctemio/api/pkg/domain/findingsource"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/logger"
	"github.com/openctemio/api/pkg/pagination"
)

// ============================================================================
// Mock Repositories
// ============================================================================

// findingSrcMockRepository implements findingsource.Repository for testing.
type findingSrcMockRepository struct {
	sources               map[string]*findingsource.FindingSource
	sourcesWithCat        []*findingsource.FindingSourceWithCategory
	listErr               error
	listWithCatErr        error
	listActiveErr         error
	listActiveWithCatErr  error
	listActiveByCatErr    error
	isValidCodeFn         func(ctx context.Context, code string) (bool, error)
}

func newFindingSrcMockRepository() *findingSrcMockRepository {
	return &findingSrcMockRepository{
		sources: make(map[string]*findingsource.FindingSource),
	}
}

func (m *findingSrcMockRepository) GetByID(_ context.Context, id shared.ID) (*findingsource.FindingSource, error) {
	s, ok := m.sources[id.String()]
	if !ok {
		return nil, findingsource.ErrFindingSourceNotFound
	}
	return s, nil
}

func (m *findingSrcMockRepository) GetByCode(_ context.Context, code string) (*findingsource.FindingSource, error) {
	for _, s := range m.sources {
		if s.Code() == code {
			return s, nil
		}
	}
	return nil, findingsource.ErrFindingSourceNotFound
}

func (m *findingSrcMockRepository) List(_ context.Context, _ findingsource.Filter, _ findingsource.ListOptions, page pagination.Pagination) (pagination.Result[*findingsource.FindingSource], error) {
	if m.listErr != nil {
		return pagination.Result[*findingsource.FindingSource]{}, m.listErr
	}
	result := make([]*findingsource.FindingSource, 0, len(m.sources))
	for _, s := range m.sources {
		result = append(result, s)
	}
	total := int64(len(result))
	return pagination.Result[*findingsource.FindingSource]{
		Data:       result,
		Total:      total,
		Page:       page.Page,
		PerPage:    page.PerPage,
		TotalPages: int((total + int64(page.PerPage) - 1) / int64(page.PerPage)),
	}, nil
}

func (m *findingSrcMockRepository) ListWithCategory(_ context.Context, _ findingsource.Filter, _ findingsource.ListOptions, page pagination.Pagination) (pagination.Result[*findingsource.FindingSourceWithCategory], error) {
	if m.listWithCatErr != nil {
		return pagination.Result[*findingsource.FindingSourceWithCategory]{}, m.listWithCatErr
	}
	result := make([]*findingsource.FindingSourceWithCategory, 0, len(m.sourcesWithCat))
	result = append(result, m.sourcesWithCat...)
	total := int64(len(result))
	return pagination.Result[*findingsource.FindingSourceWithCategory]{
		Data:       result,
		Total:      total,
		Page:       page.Page,
		PerPage:    page.PerPage,
		TotalPages: int((total + int64(page.PerPage) - 1) / int64(page.PerPage)),
	}, nil
}

func (m *findingSrcMockRepository) ListActive(_ context.Context) ([]*findingsource.FindingSource, error) {
	if m.listActiveErr != nil {
		return nil, m.listActiveErr
	}
	result := make([]*findingsource.FindingSource, 0, len(m.sources))
	for _, s := range m.sources {
		if s.IsActive() {
			result = append(result, s)
		}
	}
	return result, nil
}

func (m *findingSrcMockRepository) ListActiveWithCategory(_ context.Context) ([]*findingsource.FindingSourceWithCategory, error) {
	if m.listActiveWithCatErr != nil {
		return nil, m.listActiveWithCatErr
	}
	result := make([]*findingsource.FindingSourceWithCategory, 0)
	for _, swc := range m.sourcesWithCat {
		if swc.FindingSource.IsActive() {
			result = append(result, swc)
		}
	}
	return result, nil
}

func (m *findingSrcMockRepository) ListActiveByCategory(_ context.Context, categoryID shared.ID) ([]*findingsource.FindingSource, error) {
	if m.listActiveByCatErr != nil {
		return nil, m.listActiveByCatErr
	}
	result := make([]*findingsource.FindingSource, 0)
	for _, s := range m.sources {
		if s.IsActive() && s.CategoryID() != nil && *s.CategoryID() == categoryID {
			result = append(result, s)
		}
	}
	return result, nil
}

func (m *findingSrcMockRepository) ExistsByCode(_ context.Context, code string) (bool, error) {
	for _, s := range m.sources {
		if s.Code() == code {
			return true, nil
		}
	}
	return false, nil
}

func (m *findingSrcMockRepository) IsValidCode(ctx context.Context, code string) (bool, error) {
	if m.isValidCodeFn != nil {
		return m.isValidCodeFn(ctx, code)
	}
	for _, s := range m.sources {
		if s.Code() == code && s.IsActive() {
			return true, nil
		}
	}
	return false, nil
}

// findingSrcMockCategoryRepository implements findingsource.CategoryRepository for testing.
type findingSrcMockCategoryRepository struct {
	categories    map[string]*findingsource.Category
	listErr       error
	listActiveErr error
}

func newFindingSrcMockCategoryRepository() *findingSrcMockCategoryRepository {
	return &findingSrcMockCategoryRepository{
		categories: make(map[string]*findingsource.Category),
	}
}

func (m *findingSrcMockCategoryRepository) Create(_ context.Context, category *findingsource.Category) error {
	m.categories[category.ID().String()] = category
	return nil
}

func (m *findingSrcMockCategoryRepository) GetByID(_ context.Context, id shared.ID) (*findingsource.Category, error) {
	c, ok := m.categories[id.String()]
	if !ok {
		return nil, findingsource.ErrCategoryNotFound
	}
	return c, nil
}

func (m *findingSrcMockCategoryRepository) GetByCode(_ context.Context, code string) (*findingsource.Category, error) {
	for _, c := range m.categories {
		if c.Code() == code {
			return c, nil
		}
	}
	return nil, findingsource.ErrCategoryNotFound
}

func (m *findingSrcMockCategoryRepository) Update(_ context.Context, category *findingsource.Category) error {
	m.categories[category.ID().String()] = category
	return nil
}

func (m *findingSrcMockCategoryRepository) Delete(_ context.Context, id shared.ID) error {
	delete(m.categories, id.String())
	return nil
}

func (m *findingSrcMockCategoryRepository) List(_ context.Context, _ findingsource.CategoryFilter, page pagination.Pagination) (pagination.Result[*findingsource.Category], error) {
	if m.listErr != nil {
		return pagination.Result[*findingsource.Category]{}, m.listErr
	}
	result := make([]*findingsource.Category, 0, len(m.categories))
	for _, c := range m.categories {
		result = append(result, c)
	}
	total := int64(len(result))
	return pagination.Result[*findingsource.Category]{
		Data:       result,
		Total:      total,
		Page:       page.Page,
		PerPage:    page.PerPage,
		TotalPages: int((total + int64(page.PerPage) - 1) / int64(page.PerPage)),
	}, nil
}

func (m *findingSrcMockCategoryRepository) ListActive(_ context.Context) ([]*findingsource.Category, error) {
	if m.listActiveErr != nil {
		return nil, m.listActiveErr
	}
	result := make([]*findingsource.Category, 0, len(m.categories))
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

func newTestFindingSourceService() (*app.FindingSourceService, *findingSrcMockRepository, *findingSrcMockCategoryRepository) {
	repo := newFindingSrcMockRepository()
	catRepo := newFindingSrcMockCategoryRepository()
	log := logger.NewNop()
	svc := app.NewFindingSourceService(repo, catRepo, log)
	return svc, repo, catRepo
}

func makeFindingSrcTestCategory(code, name string) *findingsource.Category {
	id := shared.NewID()
	now := time.Now().UTC()
	return findingsource.ReconstituteCategory(id, code, name, "test description", "icon", 0, true, now, now)
}

func makeFindingSrcTestSource(code, name string, categoryID *shared.ID) *findingsource.FindingSource {
	id := shared.NewID()
	now := time.Now().UTC()
	return findingsource.ReconstituteFindingSource(
		id, categoryID, code, name, "test description",
		"icon", "#000000", 0,
		false, true,
		now, now,
	)
}

func makeFindingSrcTestInactiveSource(code, name string) *findingsource.FindingSource {
	id := shared.NewID()
	now := time.Now().UTC()
	return findingsource.ReconstituteFindingSource(
		id, nil, code, name, "inactive source",
		"icon", "#000000", 0,
		false, false,
		now, now,
	)
}

// ============================================================================
// GetCategory Tests
// ============================================================================

func TestFindingSourceService_GetCategory_Success(t *testing.T) {
	svc, _, catRepo := newTestFindingSourceService()
	ctx := context.Background()

	cat := makeFindingSrcTestCategory("sast", "SAST")
	catRepo.categories[cat.ID().String()] = cat

	result, err := svc.GetCategory(ctx, cat.ID().String())
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if result.ID() != cat.ID() {
		t.Errorf("expected category ID %s, got %s", cat.ID(), result.ID())
	}
	if result.Code() != "sast" {
		t.Errorf("expected code 'sast', got %q", result.Code())
	}
}

func TestFindingSourceService_GetCategory_InvalidID(t *testing.T) {
	svc, _, _ := newTestFindingSourceService()
	ctx := context.Background()

	_, err := svc.GetCategory(ctx, "not-a-uuid")
	if err == nil {
		t.Fatal("expected error for invalid ID")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected ErrValidation, got %v", err)
	}
}

func TestFindingSourceService_GetCategory_NotFound(t *testing.T) {
	svc, _, _ := newTestFindingSourceService()
	ctx := context.Background()

	id := shared.NewID()
	_, err := svc.GetCategory(ctx, id.String())
	if err == nil {
		t.Fatal("expected error for not found category")
	}
	if !errors.Is(err, findingsource.ErrCategoryNotFound) {
		t.Errorf("expected ErrCategoryNotFound, got %v", err)
	}
}

// ============================================================================
// GetCategoryByCode Tests
// ============================================================================

func TestFindingSourceService_GetCategoryByCode_Success(t *testing.T) {
	svc, _, catRepo := newTestFindingSourceService()
	ctx := context.Background()

	cat := makeFindingSrcTestCategory("dast", "DAST")
	catRepo.categories[cat.ID().String()] = cat

	result, err := svc.GetCategoryByCode(ctx, "dast")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if result.Code() != "dast" {
		t.Errorf("expected code 'dast', got %q", result.Code())
	}
}

func TestFindingSourceService_GetCategoryByCode_NotFound(t *testing.T) {
	svc, _, _ := newTestFindingSourceService()
	ctx := context.Background()

	_, err := svc.GetCategoryByCode(ctx, "nonexistent")
	if err == nil {
		t.Fatal("expected error for not found category")
	}
	if !errors.Is(err, findingsource.ErrCategoryNotFound) {
		t.Errorf("expected ErrCategoryNotFound, got %v", err)
	}
}

// ============================================================================
// ListCategories Tests
// ============================================================================

func TestFindingSourceService_ListCategories_Success(t *testing.T) {
	svc, _, catRepo := newTestFindingSourceService()
	ctx := context.Background()

	cat1 := makeFindingSrcTestCategory("sast", "SAST")
	cat2 := makeFindingSrcTestCategory("dast", "DAST")
	catRepo.categories[cat1.ID().String()] = cat1
	catRepo.categories[cat2.ID().String()] = cat2

	filter := findingsource.NewCategoryFilter()
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

func TestFindingSourceService_ListCategories_RepoError(t *testing.T) {
	svc, _, catRepo := newTestFindingSourceService()
	ctx := context.Background()

	catRepo.listErr = errors.New("database error")

	filter := findingsource.NewCategoryFilter()
	page := pagination.Pagination{Page: 1, PerPage: 10}

	_, err := svc.ListCategories(ctx, filter, page)
	if err == nil {
		t.Fatal("expected error from repository")
	}
}

func TestFindingSourceService_ListCategories_Empty(t *testing.T) {
	svc, _, _ := newTestFindingSourceService()
	ctx := context.Background()

	filter := findingsource.NewCategoryFilter()
	page := pagination.Pagination{Page: 1, PerPage: 10}

	result, err := svc.ListCategories(ctx, filter, page)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if result.Total != 0 {
		t.Errorf("expected total 0, got %d", result.Total)
	}
}

// ============================================================================
// ListActiveCategories Tests
// ============================================================================

func TestFindingSourceService_ListActiveCategories_Success(t *testing.T) {
	svc, _, catRepo := newTestFindingSourceService()
	ctx := context.Background()

	cat1 := makeFindingSrcTestCategory("sast", "SAST")
	cat2 := makeFindingSrcTestCategory("dast", "DAST")
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

func TestFindingSourceService_ListActiveCategories_RepoError(t *testing.T) {
	svc, _, catRepo := newTestFindingSourceService()
	ctx := context.Background()

	catRepo.listActiveErr = errors.New("database error")

	_, err := svc.ListActiveCategories(ctx)
	if err == nil {
		t.Fatal("expected error from repository")
	}
}

// ============================================================================
// GetFindingSource Tests
// ============================================================================

func TestFindingSourceService_GetFindingSource_Success(t *testing.T) {
	svc, repo, _ := newTestFindingSourceService()
	ctx := context.Background()

	src := makeFindingSrcTestSource("semgrep", "Semgrep", nil)
	repo.sources[src.ID().String()] = src

	result, err := svc.GetFindingSource(ctx, src.ID().String())
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if result.ID() != src.ID() {
		t.Errorf("expected source ID %s, got %s", src.ID(), result.ID())
	}
	if result.Code() != "semgrep" {
		t.Errorf("expected code 'semgrep', got %q", result.Code())
	}
}

func TestFindingSourceService_GetFindingSource_InvalidID(t *testing.T) {
	svc, _, _ := newTestFindingSourceService()
	ctx := context.Background()

	_, err := svc.GetFindingSource(ctx, "not-a-uuid")
	if err == nil {
		t.Fatal("expected error for invalid ID")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected ErrValidation, got %v", err)
	}
}

func TestFindingSourceService_GetFindingSource_NotFound(t *testing.T) {
	svc, _, _ := newTestFindingSourceService()
	ctx := context.Background()

	id := shared.NewID()
	_, err := svc.GetFindingSource(ctx, id.String())
	if err == nil {
		t.Fatal("expected error for not found source")
	}
	if !errors.Is(err, findingsource.ErrFindingSourceNotFound) {
		t.Errorf("expected ErrFindingSourceNotFound, got %v", err)
	}
}

// ============================================================================
// GetFindingSourceByCode Tests
// ============================================================================

func TestFindingSourceService_GetFindingSourceByCode_Success(t *testing.T) {
	svc, repo, _ := newTestFindingSourceService()
	ctx := context.Background()

	src := makeFindingSrcTestSource("nuclei", "Nuclei", nil)
	repo.sources[src.ID().String()] = src

	result, err := svc.GetFindingSourceByCode(ctx, "nuclei")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if result.Code() != "nuclei" {
		t.Errorf("expected code 'nuclei', got %q", result.Code())
	}
}

func TestFindingSourceService_GetFindingSourceByCode_NotFound(t *testing.T) {
	svc, _, _ := newTestFindingSourceService()
	ctx := context.Background()

	_, err := svc.GetFindingSourceByCode(ctx, "nonexistent")
	if err == nil {
		t.Fatal("expected error for not found source")
	}
	if !errors.Is(err, findingsource.ErrFindingSourceNotFound) {
		t.Errorf("expected ErrFindingSourceNotFound, got %v", err)
	}
}

// ============================================================================
// ListFindingSources Tests
// ============================================================================

func TestFindingSourceService_ListFindingSources_Success(t *testing.T) {
	svc, repo, _ := newTestFindingSourceService()
	ctx := context.Background()

	src1 := makeFindingSrcTestSource("semgrep", "Semgrep", nil)
	src2 := makeFindingSrcTestSource("nuclei", "Nuclei", nil)
	repo.sources[src1.ID().String()] = src1
	repo.sources[src2.ID().String()] = src2

	filter := findingsource.NewFilter()
	opts := findingsource.NewListOptions()
	page := pagination.Pagination{Page: 1, PerPage: 10}

	result, err := svc.ListFindingSources(ctx, filter, opts, page)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if result.Total != 2 {
		t.Errorf("expected total 2, got %d", result.Total)
	}
}

func TestFindingSourceService_ListFindingSources_RepoError(t *testing.T) {
	svc, repo, _ := newTestFindingSourceService()
	ctx := context.Background()

	repo.listErr = errors.New("database error")

	filter := findingsource.NewFilter()
	opts := findingsource.NewListOptions()
	page := pagination.Pagination{Page: 1, PerPage: 10}

	_, err := svc.ListFindingSources(ctx, filter, opts, page)
	if err == nil {
		t.Fatal("expected error from repository")
	}
}

// ============================================================================
// ListFindingSourcesWithCategory Tests
// ============================================================================

func TestFindingSourceService_ListFindingSourcesWithCategory_Success(t *testing.T) {
	svc, repo, _ := newTestFindingSourceService()
	ctx := context.Background()

	catID := shared.NewID()
	src := makeFindingSrcTestSource("semgrep", "Semgrep", &catID)
	cat := makeFindingSrcTestCategory("sast", "SAST")
	repo.sourcesWithCat = []*findingsource.FindingSourceWithCategory{
		{FindingSource: src, Category: cat},
	}

	filter := findingsource.NewFilter()
	opts := findingsource.NewListOptions()
	page := pagination.Pagination{Page: 1, PerPage: 10}

	result, err := svc.ListFindingSourcesWithCategory(ctx, filter, opts, page)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if result.Total != 1 {
		t.Errorf("expected total 1, got %d", result.Total)
	}
	if result.Data[0].FindingSource.Code() != "semgrep" {
		t.Errorf("expected code 'semgrep', got %q", result.Data[0].FindingSource.Code())
	}
	if result.Data[0].Category.Code() != "sast" {
		t.Errorf("expected category code 'sast', got %q", result.Data[0].Category.Code())
	}
}

func TestFindingSourceService_ListFindingSourcesWithCategory_RepoError(t *testing.T) {
	svc, repo, _ := newTestFindingSourceService()
	ctx := context.Background()

	repo.listWithCatErr = errors.New("database error")

	filter := findingsource.NewFilter()
	opts := findingsource.NewListOptions()
	page := pagination.Pagination{Page: 1, PerPage: 10}

	_, err := svc.ListFindingSourcesWithCategory(ctx, filter, opts, page)
	if err == nil {
		t.Fatal("expected error from repository")
	}
}

// ============================================================================
// ListActiveFindingSources Tests
// ============================================================================

func TestFindingSourceService_ListActiveFindingSources_Success(t *testing.T) {
	svc, repo, _ := newTestFindingSourceService()
	ctx := context.Background()

	active := makeFindingSrcTestSource("semgrep", "Semgrep", nil)
	inactive := makeFindingSrcTestInactiveSource("legacy", "Legacy Scanner")
	repo.sources[active.ID().String()] = active
	repo.sources[inactive.ID().String()] = inactive

	result, err := svc.ListActiveFindingSources(ctx)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if len(result) != 1 {
		t.Errorf("expected 1 active source, got %d", len(result))
	}
	if result[0].Code() != "semgrep" {
		t.Errorf("expected code 'semgrep', got %q", result[0].Code())
	}
}

func TestFindingSourceService_ListActiveFindingSources_RepoError(t *testing.T) {
	svc, repo, _ := newTestFindingSourceService()
	ctx := context.Background()

	repo.listActiveErr = errors.New("database error")

	_, err := svc.ListActiveFindingSources(ctx)
	if err == nil {
		t.Fatal("expected error from repository")
	}
}

// ============================================================================
// ListActiveFindingSourcesWithCategory Tests
// ============================================================================

func TestFindingSourceService_ListActiveFindingSourcesWithCategory_Success(t *testing.T) {
	svc, repo, _ := newTestFindingSourceService()
	ctx := context.Background()

	catID := shared.NewID()
	activeSrc := makeFindingSrcTestSource("nuclei", "Nuclei", &catID)
	cat := makeFindingSrcTestCategory("dast", "DAST")
	repo.sourcesWithCat = []*findingsource.FindingSourceWithCategory{
		{FindingSource: activeSrc, Category: cat},
	}

	result, err := svc.ListActiveFindingSourcesWithCategory(ctx)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if len(result) != 1 {
		t.Errorf("expected 1 active source with category, got %d", len(result))
	}
}

func TestFindingSourceService_ListActiveFindingSourcesWithCategory_RepoError(t *testing.T) {
	svc, repo, _ := newTestFindingSourceService()
	ctx := context.Background()

	repo.listActiveWithCatErr = errors.New("database error")

	_, err := svc.ListActiveFindingSourcesWithCategory(ctx)
	if err == nil {
		t.Fatal("expected error from repository")
	}
}

// ============================================================================
// ListActiveFindingSourcesByCategory Tests
// ============================================================================

func TestFindingSourceService_ListActiveFindingSourcesByCategory_Success(t *testing.T) {
	svc, repo, _ := newTestFindingSourceService()
	ctx := context.Background()

	catID := shared.NewID()
	src1 := makeFindingSrcTestSource("semgrep", "Semgrep", &catID)
	src2 := makeFindingSrcTestSource("nuclei", "Nuclei", &catID)
	otherCatID := shared.NewID()
	src3 := makeFindingSrcTestSource("trivy", "Trivy", &otherCatID)
	repo.sources[src1.ID().String()] = src1
	repo.sources[src2.ID().String()] = src2
	repo.sources[src3.ID().String()] = src3

	result, err := svc.ListActiveFindingSourcesByCategory(ctx, catID.String())
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if len(result) != 2 {
		t.Errorf("expected 2 sources for category, got %d", len(result))
	}
}

func TestFindingSourceService_ListActiveFindingSourcesByCategory_InvalidID(t *testing.T) {
	svc, _, _ := newTestFindingSourceService()
	ctx := context.Background()

	_, err := svc.ListActiveFindingSourcesByCategory(ctx, "bad-uuid")
	if err == nil {
		t.Fatal("expected error for invalid category ID")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected ErrValidation, got %v", err)
	}
}

func TestFindingSourceService_ListActiveFindingSourcesByCategory_Empty(t *testing.T) {
	svc, _, _ := newTestFindingSourceService()
	ctx := context.Background()

	catID := shared.NewID()
	result, err := svc.ListActiveFindingSourcesByCategory(ctx, catID.String())
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if len(result) != 0 {
		t.Errorf("expected 0 sources, got %d", len(result))
	}
}

func TestFindingSourceService_ListActiveFindingSourcesByCategory_RepoError(t *testing.T) {
	svc, repo, _ := newTestFindingSourceService()
	ctx := context.Background()

	repo.listActiveByCatErr = errors.New("database error")
	catID := shared.NewID()

	_, err := svc.ListActiveFindingSourcesByCategory(ctx, catID.String())
	if err == nil {
		t.Fatal("expected error from repository")
	}
}

// ============================================================================
// IsValidSourceCode Tests
// ============================================================================

func TestFindingSourceService_IsValidSourceCode_Valid(t *testing.T) {
	svc, repo, _ := newTestFindingSourceService()
	ctx := context.Background()

	src := makeFindingSrcTestSource("semgrep", "Semgrep", nil)
	repo.sources[src.ID().String()] = src

	valid, err := svc.IsValidSourceCode(ctx, "semgrep")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if !valid {
		t.Error("expected 'semgrep' to be valid")
	}
}

func TestFindingSourceService_IsValidSourceCode_Invalid(t *testing.T) {
	svc, _, _ := newTestFindingSourceService()
	ctx := context.Background()

	valid, err := svc.IsValidSourceCode(ctx, "nonexistent")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if valid {
		t.Error("expected 'nonexistent' to be invalid")
	}
}

func TestFindingSourceService_IsValidSourceCode_InactiveSource(t *testing.T) {
	svc, repo, _ := newTestFindingSourceService()
	ctx := context.Background()

	inactive := makeFindingSrcTestInactiveSource("legacy", "Legacy Scanner")
	repo.sources[inactive.ID().String()] = inactive

	valid, err := svc.IsValidSourceCode(ctx, "legacy")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if valid {
		t.Error("expected inactive source to be invalid")
	}
}

func TestFindingSourceService_IsValidSourceCode_RepoError(t *testing.T) {
	svc, repo, _ := newTestFindingSourceService()
	ctx := context.Background()

	repo.isValidCodeFn = func(_ context.Context, _ string) (bool, error) {
		return false, errors.New("database error")
	}

	_, err := svc.IsValidSourceCode(ctx, "semgrep")
	if err == nil {
		t.Fatal("expected error from repository")
	}
}

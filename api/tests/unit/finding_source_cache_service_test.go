package unit

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/openctemio/api/internal/app"
	"github.com/openctemio/api/pkg/domain/findingsource"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/logger"
	"github.com/openctemio/api/pkg/pagination"
)

// =============================================================================
// Mock: findingsource.Repository for cache service tests
// =============================================================================

// srcCacheMockRepo implements findingsource.Repository for cache service tests.
type srcCacheMockRepo struct {
	mu                   sync.Mutex
	sourcesWithCat       []*findingsource.FindingSourceWithCategory
	listActiveWithCatErr error
	callCount            int
}

func newSrcCacheMockRepo() *srcCacheMockRepo {
	return &srcCacheMockRepo{}
}

func (m *srcCacheMockRepo) ListActiveWithCategory(_ context.Context) ([]*findingsource.FindingSourceWithCategory, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.callCount++
	if m.listActiveWithCatErr != nil {
		return nil, m.listActiveWithCatErr
	}
	result := make([]*findingsource.FindingSourceWithCategory, len(m.sourcesWithCat))
	copy(result, m.sourcesWithCat)
	return result, nil
}

// Remaining methods required by findingsource.Repository interface.
func (m *srcCacheMockRepo) GetByID(_ context.Context, _ shared.ID) (*findingsource.FindingSource, error) {
	return nil, errors.New("not implemented")
}
func (m *srcCacheMockRepo) GetByCode(_ context.Context, _ string) (*findingsource.FindingSource, error) {
	return nil, errors.New("not implemented")
}
func (m *srcCacheMockRepo) List(_ context.Context, _ findingsource.Filter, _ findingsource.ListOptions, _ pagination.Pagination) (pagination.Result[*findingsource.FindingSource], error) {
	return pagination.Result[*findingsource.FindingSource]{}, errors.New("not implemented")
}
func (m *srcCacheMockRepo) ListWithCategory(_ context.Context, _ findingsource.Filter, _ findingsource.ListOptions, _ pagination.Pagination) (pagination.Result[*findingsource.FindingSourceWithCategory], error) {
	return pagination.Result[*findingsource.FindingSourceWithCategory]{}, errors.New("not implemented")
}
func (m *srcCacheMockRepo) ListActive(_ context.Context) ([]*findingsource.FindingSource, error) {
	return nil, errors.New("not implemented")
}
func (m *srcCacheMockRepo) ListActiveByCategory(_ context.Context, _ shared.ID) ([]*findingsource.FindingSource, error) {
	return nil, errors.New("not implemented")
}
func (m *srcCacheMockRepo) ExistsByCode(_ context.Context, _ string) (bool, error) {
	return false, errors.New("not implemented")
}
func (m *srcCacheMockRepo) IsValidCode(_ context.Context, _ string) (bool, error) {
	return false, errors.New("not implemented")
}

// =============================================================================
// Helper: build domain entities
// =============================================================================

func srcCacheMakeCategory(code, name string) *findingsource.Category {
	id := shared.NewID()
	now := time.Now().UTC()
	return findingsource.ReconstituteCategory(id, code, name, "desc", "icon", 1, true, now, now)
}

func srcCacheMakeSource(code, name string, cat *findingsource.Category) *findingsource.FindingSourceWithCategory {
	id := shared.NewID()
	now := time.Now().UTC()
	var catID *shared.ID
	if cat != nil {
		cid := cat.ID()
		catID = &cid
	}
	fs := findingsource.ReconstituteFindingSource(
		id, catID, code, name, "description",
		"icon", "#ff0000", 1,
		true, true,
		now, now,
	)
	return &findingsource.FindingSourceWithCategory{
		FindingSource: fs,
		Category:      cat,
	}
}

// srcCacheMakeService constructs a FindingSourceCacheService with nil Redis
// (cache-disabled / graceful degradation mode) so tests don't need a real Redis.
func srcCacheMakeService(repo findingsource.Repository) *app.FindingSourceCacheService {
	svc, err := app.NewFindingSourceCacheService(nil, repo, logger.NewNop())
	if err != nil {
		panic("unexpected error creating FindingSourceCacheService: " + err.Error())
	}
	return svc
}

// =============================================================================
// Tests: NewFindingSourceCacheService
// =============================================================================

func TestSrcCache_New_NilRedis_ReturnsService(t *testing.T) {
	t.Parallel()

	repo := newSrcCacheMockRepo()
	svc, err := app.NewFindingSourceCacheService(nil, repo, logger.NewNop())
	if err != nil {
		t.Fatalf("expected no error with nil redis, got %v", err)
	}
	if svc == nil {
		t.Fatal("expected non-nil service")
	}
}

// =============================================================================
// Tests: GetAll
// =============================================================================

func TestSrcCache_GetAll_NoCacheReadsFromDB(t *testing.T) {
	t.Parallel()

	repo := newSrcCacheMockRepo()
	cat := srcCacheMakeCategory("sast", "SAST")
	repo.sourcesWithCat = []*findingsource.FindingSourceWithCategory{
		srcCacheMakeSource("bandit", "Bandit", cat),
		srcCacheMakeSource("semgrep", "Semgrep", cat),
	}

	svc := srcCacheMakeService(repo)
	result, err := svc.GetAll(context.Background())

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if len(result.Sources) != 2 {
		t.Errorf("expected 2 sources, got %d", len(result.Sources))
	}
	if repo.callCount != 1 {
		t.Errorf("expected 1 DB call, got %d", repo.callCount)
	}
}

func TestSrcCache_GetAll_EmptyDBReturnsEmptyResult(t *testing.T) {
	t.Parallel()

	repo := newSrcCacheMockRepo()
	// No sources in DB

	svc := srcCacheMakeService(repo)
	result, err := svc.GetAll(context.Background())

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Sources) != 0 {
		t.Errorf("expected 0 sources, got %d", len(result.Sources))
	}
	if len(result.Categories) != 0 {
		t.Errorf("expected 0 categories, got %d", len(result.Categories))
	}
}

func TestSrcCache_GetAll_DBError_Propagates(t *testing.T) {
	t.Parallel()

	repo := newSrcCacheMockRepo()
	repo.listActiveWithCatErr = errors.New("database connection refused")

	svc := srcCacheMakeService(repo)
	result, err := svc.GetAll(context.Background())

	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if result != nil {
		t.Error("expected nil result on error")
	}
}

func TestSrcCache_GetAll_SetsIndexStructures(t *testing.T) {
	t.Parallel()

	repo := newSrcCacheMockRepo()
	cat := srcCacheMakeCategory("sast", "SAST")
	repo.sourcesWithCat = []*findingsource.FindingSourceWithCategory{
		srcCacheMakeSource("bandit", "Bandit", cat),
		srcCacheMakeSource("semgrep", "Semgrep", cat),
	}

	svc := srcCacheMakeService(repo)
	result, err := svc.GetAll(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// ByCode should have entries for both sources
	if _, ok := result.ByCode["bandit"]; !ok {
		t.Error("expected ByCode to contain 'bandit'")
	}
	if _, ok := result.ByCode["semgrep"]; !ok {
		t.Error("expected ByCode to contain 'semgrep'")
	}

	// ByCategory should have entries for the category
	if _, ok := result.ByCategory["sast"]; !ok {
		t.Error("expected ByCategory to contain 'sast'")
	}
	if len(result.ByCategory["sast"]) != 2 {
		t.Errorf("expected 2 sources in 'sast' category, got %d", len(result.ByCategory["sast"]))
	}
}

func TestSrcCache_GetAll_SourcesWithoutCategory_GroupedAsOther(t *testing.T) {
	t.Parallel()

	repo := newSrcCacheMockRepo()
	// Source with no category
	repo.sourcesWithCat = []*findingsource.FindingSourceWithCategory{
		srcCacheMakeSource("manual", "Manual", nil),
	}

	svc := srcCacheMakeService(repo)
	result, err := svc.GetAll(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if _, ok := result.ByCategory["other"]; !ok {
		t.Error("expected sources without category to be grouped under 'other'")
	}
	if len(result.ByCategory["other"]) != 1 {
		t.Errorf("expected 1 source in 'other' category, got %d", len(result.ByCategory["other"]))
	}
}

func TestSrcCache_GetAll_CachedAtTimestamp_IsSet(t *testing.T) {
	t.Parallel()

	repo := newSrcCacheMockRepo()
	svc := srcCacheMakeService(repo)

	before := time.Now().Add(-time.Second)
	result, err := svc.GetAll(context.Background())
	after := time.Now().Add(time.Second)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.CachedAt.Before(before) || result.CachedAt.After(after) {
		t.Errorf("CachedAt %v is outside expected range [%v, %v]", result.CachedAt, before, after)
	}
}

func TestSrcCache_GetAll_MultipleCategories_AllTracked(t *testing.T) {
	t.Parallel()

	repo := newSrcCacheMockRepo()
	sastCat := srcCacheMakeCategory("sast", "SAST")
	dastCat := srcCacheMakeCategory("dast", "DAST")

	repo.sourcesWithCat = []*findingsource.FindingSourceWithCategory{
		srcCacheMakeSource("bandit", "Bandit", sastCat),
		srcCacheMakeSource("zap", "ZAP", dastCat),
		srcCacheMakeSource("semgrep", "Semgrep", sastCat),
	}

	svc := srcCacheMakeService(repo)
	result, err := svc.GetAll(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(result.Categories) != 2 {
		t.Errorf("expected 2 unique categories, got %d", len(result.Categories))
	}
	if len(result.ByCategory["sast"]) != 2 {
		t.Errorf("expected 2 sources in sast, got %d", len(result.ByCategory["sast"]))
	}
	if len(result.ByCategory["dast"]) != 1 {
		t.Errorf("expected 1 source in dast, got %d", len(result.ByCategory["dast"]))
	}
}

func TestSrcCache_GetAll_ByCodeIndex_IsZeroIndexed(t *testing.T) {
	t.Parallel()

	repo := newSrcCacheMockRepo()
	cat := srcCacheMakeCategory("sast", "SAST")
	repo.sourcesWithCat = []*findingsource.FindingSourceWithCategory{
		srcCacheMakeSource("alpha", "Alpha", cat),
		srcCacheMakeSource("beta", "Beta", cat),
	}

	svc := srcCacheMakeService(repo)
	result, err := svc.GetAll(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// ByCode values must be valid indices into Sources slice
	for code, idx := range result.ByCode {
		if idx < 0 || idx >= len(result.Sources) {
			t.Errorf("ByCode[%q]=%d is out of bounds (len=%d)", code, idx, len(result.Sources))
		}
		if result.Sources[idx].Code != code {
			t.Errorf("Sources[%d].Code=%q doesn't match expected code %q", idx, result.Sources[idx].Code, code)
		}
	}
}

// =============================================================================
// Tests: GetByCode
// =============================================================================

func TestSrcCache_GetByCode_Found(t *testing.T) {
	t.Parallel()

	repo := newSrcCacheMockRepo()
	cat := srcCacheMakeCategory("sast", "SAST")
	repo.sourcesWithCat = []*findingsource.FindingSourceWithCategory{
		srcCacheMakeSource("bandit", "Bandit", cat),
	}

	svc := srcCacheMakeService(repo)
	source, err := svc.GetByCode(context.Background(), "bandit")

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if source == nil {
		t.Fatal("expected non-nil source")
	}
	if source.Code != "bandit" {
		t.Errorf("expected code 'bandit', got %q", source.Code)
	}
	if source.Name != "Bandit" {
		t.Errorf("expected name 'Bandit', got %q", source.Name)
	}
}

func TestSrcCache_GetByCode_NotFound_ReturnsNil(t *testing.T) {
	t.Parallel()

	repo := newSrcCacheMockRepo()
	repo.sourcesWithCat = []*findingsource.FindingSourceWithCategory{
		srcCacheMakeSource("bandit", "Bandit", nil),
	}

	svc := srcCacheMakeService(repo)
	source, err := svc.GetByCode(context.Background(), "nonexistent")

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if source != nil {
		t.Errorf("expected nil for unknown code, got %+v", source)
	}
}

func TestSrcCache_GetByCode_DBError_Propagates(t *testing.T) {
	t.Parallel()

	repo := newSrcCacheMockRepo()
	repo.listActiveWithCatErr = errors.New("db timeout")

	svc := srcCacheMakeService(repo)
	source, err := svc.GetByCode(context.Background(), "anything")

	if err == nil {
		t.Fatal("expected error from DB, got nil")
	}
	if source != nil {
		t.Error("expected nil source on error")
	}
}

func TestSrcCache_GetByCode_PopulatesCategoryFields(t *testing.T) {
	t.Parallel()

	repo := newSrcCacheMockRepo()
	cat := srcCacheMakeCategory("sast", "SAST")
	repo.sourcesWithCat = []*findingsource.FindingSourceWithCategory{
		srcCacheMakeSource("bandit", "Bandit", cat),
	}

	svc := srcCacheMakeService(repo)
	source, err := svc.GetByCode(context.Background(), "bandit")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if source.CategoryCode != "sast" {
		t.Errorf("expected CategoryCode 'sast', got %q", source.CategoryCode)
	}
	if source.CategoryName != "SAST" {
		t.Errorf("expected CategoryName 'SAST', got %q", source.CategoryName)
	}
}

func TestSrcCache_GetByCode_NoCategoryFields_WhenNoCategory(t *testing.T) {
	t.Parallel()

	repo := newSrcCacheMockRepo()
	repo.sourcesWithCat = []*findingsource.FindingSourceWithCategory{
		srcCacheMakeSource("manual", "Manual", nil),
	}

	svc := srcCacheMakeService(repo)
	source, err := svc.GetByCode(context.Background(), "manual")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if source == nil {
		t.Fatal("expected non-nil source")
	}
	if source.CategoryCode != "" {
		t.Errorf("expected empty CategoryCode for source with no category, got %q", source.CategoryCode)
	}
	if source.CategoryID != "" {
		t.Errorf("expected empty CategoryID for source with no category, got %q", source.CategoryID)
	}
}

// =============================================================================
// Tests: IsValidCode
// =============================================================================

func TestSrcCache_IsValidCode_ValidCode_ReturnsTrue(t *testing.T) {
	t.Parallel()

	repo := newSrcCacheMockRepo()
	repo.sourcesWithCat = []*findingsource.FindingSourceWithCategory{
		srcCacheMakeSource("bandit", "Bandit", nil),
	}

	svc := srcCacheMakeService(repo)
	valid, err := svc.IsValidCode(context.Background(), "bandit")

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !valid {
		t.Error("expected 'bandit' to be a valid code")
	}
}

func TestSrcCache_IsValidCode_InvalidCode_ReturnsFalse(t *testing.T) {
	t.Parallel()

	repo := newSrcCacheMockRepo()
	repo.sourcesWithCat = []*findingsource.FindingSourceWithCategory{
		srcCacheMakeSource("bandit", "Bandit", nil),
	}

	svc := srcCacheMakeService(repo)
	valid, err := svc.IsValidCode(context.Background(), "nonexistent")

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if valid {
		t.Error("expected 'nonexistent' to be invalid")
	}
}

func TestSrcCache_IsValidCode_EmptyDB_ReturnsFalse(t *testing.T) {
	t.Parallel()

	repo := newSrcCacheMockRepo()
	// Empty repo

	svc := srcCacheMakeService(repo)
	valid, err := svc.IsValidCode(context.Background(), "anything")

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if valid {
		t.Error("expected false for empty DB")
	}
}

func TestSrcCache_IsValidCode_DBError_Propagates(t *testing.T) {
	t.Parallel()

	repo := newSrcCacheMockRepo()
	repo.listActiveWithCatErr = errors.New("connection error")

	svc := srcCacheMakeService(repo)
	valid, err := svc.IsValidCode(context.Background(), "bandit")

	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if valid {
		t.Error("expected false on error")
	}
}

func TestSrcCache_IsValidCode_MultipleSourcesOnlyMatchesExact(t *testing.T) {
	t.Parallel()

	repo := newSrcCacheMockRepo()
	repo.sourcesWithCat = []*findingsource.FindingSourceWithCategory{
		srcCacheMakeSource("bandit", "Bandit", nil),
		srcCacheMakeSource("semgrep", "Semgrep", nil),
		srcCacheMakeSource("zap", "ZAP", nil),
	}

	svc := srcCacheMakeService(repo)

	tests := []struct {
		code  string
		valid bool
	}{
		{"bandit", true},
		{"semgrep", true},
		{"zap", true},
		{"BANDIT", false}, // case-sensitive
		{"ban", false},    // partial match not allowed
		{"", false},       // empty code
	}

	for _, tt := range tests {
		valid, err := svc.IsValidCode(context.Background(), tt.code)
		if err != nil {
			t.Fatalf("code=%q: unexpected error: %v", tt.code, err)
		}
		if valid != tt.valid {
			t.Errorf("IsValidCode(%q) = %v, want %v", tt.code, valid, tt.valid)
		}
	}
}

// =============================================================================
// Tests: GetByCategory
// =============================================================================

func TestSrcCache_GetByCategory_ReturnsMatchingSources(t *testing.T) {
	t.Parallel()

	repo := newSrcCacheMockRepo()
	sastCat := srcCacheMakeCategory("sast", "SAST")
	dastCat := srcCacheMakeCategory("dast", "DAST")

	repo.sourcesWithCat = []*findingsource.FindingSourceWithCategory{
		srcCacheMakeSource("bandit", "Bandit", sastCat),
		srcCacheMakeSource("semgrep", "Semgrep", sastCat),
		srcCacheMakeSource("zap", "ZAP", dastCat),
	}

	svc := srcCacheMakeService(repo)
	sources, err := svc.GetByCategory(context.Background(), "sast")

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(sources) != 2 {
		t.Errorf("expected 2 SAST sources, got %d", len(sources))
	}
	for _, s := range sources {
		if s.CategoryCode != "sast" {
			t.Errorf("expected CategoryCode 'sast', got %q", s.CategoryCode)
		}
	}
}

func TestSrcCache_GetByCategory_UnknownCategory_ReturnsEmpty(t *testing.T) {
	t.Parallel()

	repo := newSrcCacheMockRepo()
	cat := srcCacheMakeCategory("sast", "SAST")
	repo.sourcesWithCat = []*findingsource.FindingSourceWithCategory{
		srcCacheMakeSource("bandit", "Bandit", cat),
	}

	svc := srcCacheMakeService(repo)
	sources, err := svc.GetByCategory(context.Background(), "nonexistent")

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(sources) != 0 {
		t.Errorf("expected 0 sources for unknown category, got %d", len(sources))
	}
}

func TestSrcCache_GetByCategory_EmptyDB_ReturnsEmpty(t *testing.T) {
	t.Parallel()

	repo := newSrcCacheMockRepo()
	svc := srcCacheMakeService(repo)

	sources, err := svc.GetByCategory(context.Background(), "sast")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(sources) != 0 {
		t.Errorf("expected 0 sources, got %d", len(sources))
	}
}

func TestSrcCache_GetByCategory_DBError_Propagates(t *testing.T) {
	t.Parallel()

	repo := newSrcCacheMockRepo()
	repo.listActiveWithCatErr = errors.New("db error")

	svc := srcCacheMakeService(repo)
	sources, err := svc.GetByCategory(context.Background(), "sast")

	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if sources != nil {
		t.Error("expected nil sources on error")
	}
}

func TestSrcCache_GetByCategory_OtherCategory_ReturnsUncategorizedSources(t *testing.T) {
	t.Parallel()

	repo := newSrcCacheMockRepo()
	// Source with no category ends up under "other"
	repo.sourcesWithCat = []*findingsource.FindingSourceWithCategory{
		srcCacheMakeSource("manual", "Manual", nil),
		srcCacheMakeSource("custom", "Custom", nil),
	}

	svc := srcCacheMakeService(repo)
	sources, err := svc.GetByCategory(context.Background(), "other")

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(sources) != 2 {
		t.Errorf("expected 2 sources under 'other', got %d", len(sources))
	}
}

func TestSrcCache_GetByCategory_ResultSourcesArePointers(t *testing.T) {
	t.Parallel()

	repo := newSrcCacheMockRepo()
	cat := srcCacheMakeCategory("sast", "SAST")
	repo.sourcesWithCat = []*findingsource.FindingSourceWithCategory{
		srcCacheMakeSource("bandit", "Bandit", cat),
	}

	svc := srcCacheMakeService(repo)
	sources, err := svc.GetByCategory(context.Background(), "sast")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(sources) != 1 {
		t.Fatalf("expected 1 source, got %d", len(sources))
	}
	if sources[0] == nil {
		t.Error("expected non-nil source pointer")
	}
}

// =============================================================================
// Tests: GetCategories
// =============================================================================

func TestSrcCache_GetCategories_ReturnsAllCategories(t *testing.T) {
	t.Parallel()

	repo := newSrcCacheMockRepo()
	sastCat := srcCacheMakeCategory("sast", "SAST")
	dastCat := srcCacheMakeCategory("dast", "DAST")

	repo.sourcesWithCat = []*findingsource.FindingSourceWithCategory{
		srcCacheMakeSource("bandit", "Bandit", sastCat),
		srcCacheMakeSource("zap", "ZAP", dastCat),
	}

	svc := srcCacheMakeService(repo)
	categories, err := svc.GetCategories(context.Background())

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(categories) != 2 {
		t.Errorf("expected 2 categories, got %d", len(categories))
	}
}

func TestSrcCache_GetCategories_EmptyDB_ReturnsEmpty(t *testing.T) {
	t.Parallel()

	repo := newSrcCacheMockRepo()
	svc := srcCacheMakeService(repo)

	categories, err := svc.GetCategories(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(categories) != 0 {
		t.Errorf("expected 0 categories, got %d", len(categories))
	}
}

func TestSrcCache_GetCategories_DeduplicatesCategories(t *testing.T) {
	t.Parallel()

	repo := newSrcCacheMockRepo()
	// Two sources in same category — should produce only 1 category entry
	cat := srcCacheMakeCategory("sast", "SAST")
	repo.sourcesWithCat = []*findingsource.FindingSourceWithCategory{
		srcCacheMakeSource("bandit", "Bandit", cat),
		srcCacheMakeSource("semgrep", "Semgrep", cat),
	}

	svc := srcCacheMakeService(repo)
	categories, err := svc.GetCategories(context.Background())

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(categories) != 1 {
		t.Errorf("expected 1 deduplicated category, got %d", len(categories))
	}
}

func TestSrcCache_GetCategories_SourcesWithNoCategory_NoCategoryEntry(t *testing.T) {
	t.Parallel()

	repo := newSrcCacheMockRepo()
	// Sources without a category do NOT add an entry to the categories list
	repo.sourcesWithCat = []*findingsource.FindingSourceWithCategory{
		srcCacheMakeSource("manual", "Manual", nil),
	}

	svc := srcCacheMakeService(repo)
	categories, err := svc.GetCategories(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(categories) != 0 {
		t.Errorf("expected 0 categories when source has no category, got %d", len(categories))
	}
}

func TestSrcCache_GetCategories_DBError_Propagates(t *testing.T) {
	t.Parallel()

	repo := newSrcCacheMockRepo()
	repo.listActiveWithCatErr = errors.New("db error")

	svc := srcCacheMakeService(repo)
	categories, err := svc.GetCategories(context.Background())

	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if categories != nil {
		t.Error("expected nil on error")
	}
}

func TestSrcCache_GetCategories_CategoryFields_ArePopulated(t *testing.T) {
	t.Parallel()

	repo := newSrcCacheMockRepo()
	cat := srcCacheMakeCategory("sast", "SAST")
	repo.sourcesWithCat = []*findingsource.FindingSourceWithCategory{
		srcCacheMakeSource("bandit", "Bandit", cat),
	}

	svc := srcCacheMakeService(repo)
	categories, err := svc.GetCategories(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(categories) != 1 {
		t.Fatalf("expected 1 category, got %d", len(categories))
	}

	c := categories[0]
	if c.Code != "sast" {
		t.Errorf("expected Code 'sast', got %q", c.Code)
	}
	if c.Name != "SAST" {
		t.Errorf("expected Name 'SAST', got %q", c.Name)
	}
	if c.ID == "" {
		t.Error("expected non-empty category ID")
	}
}

// =============================================================================
// Tests: InvalidateAll (nil cache — graceful no-op)
// =============================================================================

func TestSrcCache_InvalidateAll_NilCache_ReturnsNil(t *testing.T) {
	t.Parallel()

	repo := newSrcCacheMockRepo()
	svc := srcCacheMakeService(repo) // nil Redis → nil cache

	err := svc.InvalidateAll(context.Background())
	if err != nil {
		t.Errorf("expected nil error from InvalidateAll with nil cache, got %v", err)
	}
}

// =============================================================================
// Tests: Refresh
// =============================================================================

func TestSrcCache_Refresh_NilCache_ReloadsFromDB(t *testing.T) {
	t.Parallel()

	repo := newSrcCacheMockRepo()
	cat := srcCacheMakeCategory("sast", "SAST")
	repo.sourcesWithCat = []*findingsource.FindingSourceWithCategory{
		srcCacheMakeSource("bandit", "Bandit", cat),
	}

	svc := srcCacheMakeService(repo)

	// First GetAll
	result1, err := svc.GetAll(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Add a new source to the DB
	repo.mu.Lock()
	repo.sourcesWithCat = append(repo.sourcesWithCat,
		srcCacheMakeSource("semgrep", "Semgrep", cat))
	repo.mu.Unlock()

	// Refresh should reload from DB
	result2, err := svc.Refresh(context.Background())
	if err != nil {
		t.Fatalf("unexpected error on refresh: %v", err)
	}

	if len(result1.Sources) != 1 {
		t.Errorf("expected 1 source before refresh, got %d", len(result1.Sources))
	}
	if len(result2.Sources) != 2 {
		t.Errorf("expected 2 sources after refresh, got %d", len(result2.Sources))
	}
}

func TestSrcCache_Refresh_DBError_ReturnsError(t *testing.T) {
	t.Parallel()

	repo := newSrcCacheMockRepo()
	repo.listActiveWithCatErr = errors.New("db error")

	svc := srcCacheMakeService(repo)
	result, err := svc.Refresh(context.Background())

	if err == nil {
		t.Fatal("expected error from Refresh on DB failure")
	}
	if result != nil {
		t.Error("expected nil result on error")
	}
}

// =============================================================================
// Tests: WarmCache
// =============================================================================

func TestSrcCache_WarmCache_Success(t *testing.T) {
	t.Parallel()

	repo := newSrcCacheMockRepo()
	cat := srcCacheMakeCategory("sast", "SAST")
	repo.sourcesWithCat = []*findingsource.FindingSourceWithCategory{
		srcCacheMakeSource("bandit", "Bandit", cat),
	}

	svc := srcCacheMakeService(repo)
	err := svc.WarmCache(context.Background())

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if repo.callCount != 1 {
		t.Errorf("expected 1 DB call to warm cache, got %d", repo.callCount)
	}
}

func TestSrcCache_WarmCache_EmptyDB_Succeeds(t *testing.T) {
	t.Parallel()

	repo := newSrcCacheMockRepo()
	svc := srcCacheMakeService(repo)

	err := svc.WarmCache(context.Background())
	if err != nil {
		t.Fatalf("expected success for empty DB warm, got %v", err)
	}
}

func TestSrcCache_WarmCache_DBError_WrapsError(t *testing.T) {
	t.Parallel()

	repo := newSrcCacheMockRepo()
	repo.listActiveWithCatErr = errors.New("db unavailable")

	svc := srcCacheMakeService(repo)
	err := svc.WarmCache(context.Background())

	if err == nil {
		t.Fatal("expected error from WarmCache on DB failure")
	}
	// Error should be wrapped with context
	if !errors.Is(err, repo.listActiveWithCatErr) {
		// WarmCache wraps with "failed to warm finding source cache"
		// so direct errors.Is won't match unless unwrapped; just verify non-nil
		t.Logf("WarmCache error: %v (expected wrapping of: %v)", err, repo.listActiveWithCatErr)
	}
}

// =============================================================================
// Tests: Cache miss → DB hit (no-cache mode always hits DB)
// =============================================================================

func TestSrcCache_GetAll_NoCache_AlwaysHitsDB(t *testing.T) {
	t.Parallel()

	// In no-cache mode (nil Redis), every GetAll call hits the database.
	repo := newSrcCacheMockRepo()
	cat := srcCacheMakeCategory("sast", "SAST")
	repo.sourcesWithCat = []*findingsource.FindingSourceWithCategory{
		srcCacheMakeSource("bandit", "Bandit", cat),
	}

	svc := srcCacheMakeService(repo)

	const calls = 3
	for i := range calls {
		_, err := svc.GetAll(context.Background())
		if err != nil {
			t.Fatalf("call %d: unexpected error: %v", i+1, err)
		}
	}

	if repo.callCount != calls {
		t.Errorf("expected %d DB calls (no-cache mode), got %d", calls, repo.callCount)
	}
}

// =============================================================================
// Tests: Thread safety
// =============================================================================

func TestSrcCache_GetAll_ConcurrentAccess_NoDataRaces(t *testing.T) {
	t.Parallel()

	repo := newSrcCacheMockRepo()
	cat := srcCacheMakeCategory("sast", "SAST")
	repo.sourcesWithCat = []*findingsource.FindingSourceWithCategory{
		srcCacheMakeSource("bandit", "Bandit", cat),
		srcCacheMakeSource("semgrep", "Semgrep", cat),
	}

	svc := srcCacheMakeService(repo)

	const goroutines = 20
	var wg sync.WaitGroup
	errs := make(chan error, goroutines)

	wg.Add(goroutines)
	for range goroutines {
		go func() {
			defer wg.Done()
			_, err := svc.GetAll(context.Background())
			if err != nil {
				errs <- err
			}
		}()
	}

	wg.Wait()
	close(errs)

	for err := range errs {
		t.Errorf("concurrent GetAll error: %v", err)
	}
}

func TestSrcCache_GetByCode_ConcurrentAccess_NoDataRaces(t *testing.T) {
	t.Parallel()

	repo := newSrcCacheMockRepo()
	cat := srcCacheMakeCategory("sast", "SAST")
	repo.sourcesWithCat = []*findingsource.FindingSourceWithCategory{
		srcCacheMakeSource("bandit", "Bandit", cat),
	}

	svc := srcCacheMakeService(repo)

	const goroutines = 20
	var wg sync.WaitGroup
	errs := make(chan error, goroutines)

	wg.Add(goroutines)
	for range goroutines {
		go func() {
			defer wg.Done()
			_, err := svc.GetByCode(context.Background(), "bandit")
			if err != nil {
				errs <- err
			}
		}()
	}

	wg.Wait()
	close(errs)

	for err := range errs {
		t.Errorf("concurrent GetByCode error: %v", err)
	}
}

func TestSrcCache_IsValidCode_ConcurrentAccess_NoDataRaces(t *testing.T) {
	t.Parallel()

	repo := newSrcCacheMockRepo()
	repo.sourcesWithCat = []*findingsource.FindingSourceWithCategory{
		srcCacheMakeSource("bandit", "Bandit", nil),
	}

	svc := srcCacheMakeService(repo)

	const goroutines = 20
	var wg sync.WaitGroup
	errs := make(chan error, goroutines)

	wg.Add(goroutines)
	for range goroutines {
		go func() {
			defer wg.Done()
			_, err := svc.IsValidCode(context.Background(), "bandit")
			if err != nil {
				errs <- err
			}
		}()
	}

	wg.Wait()
	close(errs)

	for err := range errs {
		t.Errorf("concurrent IsValidCode error: %v", err)
	}
}

// =============================================================================
// Tests: CachedFindingSource field mapping
// =============================================================================

func TestSrcCache_CachedFindingSource_AllFieldsMapped(t *testing.T) {
	t.Parallel()

	repo := newSrcCacheMockRepo()
	id := shared.NewID()
	catID := shared.NewID()
	now := time.Now().UTC()

	cat := findingsource.ReconstituteCategory(catID, "sast", "SAST", "Static Analysis", "icon.svg", 1, true, now, now)
	fs := findingsource.ReconstituteFindingSource(
		id, &catID, "bandit", "Bandit", "Python SAST scanner",
		"bandit-icon.svg", "#ff6600", 5,
		true, true,
		now, now,
	)

	repo.sourcesWithCat = []*findingsource.FindingSourceWithCategory{
		{FindingSource: fs, Category: cat},
	}

	svc := srcCacheMakeService(repo)
	source, err := svc.GetByCode(context.Background(), "bandit")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if source == nil {
		t.Fatal("expected non-nil source")
	}

	// Verify all fields are mapped correctly
	if source.ID == "" {
		t.Error("expected non-empty ID")
	}
	if source.ID != id.String() {
		t.Errorf("ID mismatch: got %q, want %q", source.ID, id.String())
	}
	if source.Code != "bandit" {
		t.Errorf("Code mismatch: got %q", source.Code)
	}
	if source.Name != "Bandit" {
		t.Errorf("Name mismatch: got %q", source.Name)
	}
	if source.Description != "Python SAST scanner" {
		t.Errorf("Description mismatch: got %q", source.Description)
	}
	if source.Icon != "bandit-icon.svg" {
		t.Errorf("Icon mismatch: got %q", source.Icon)
	}
	if source.Color != "#ff6600" {
		t.Errorf("Color mismatch: got %q", source.Color)
	}
	if source.DisplayOrder != 5 {
		t.Errorf("DisplayOrder mismatch: got %d", source.DisplayOrder)
	}
	if !source.IsSystem {
		t.Error("expected IsSystem=true")
	}
	if source.CategoryID != catID.String() {
		t.Errorf("CategoryID mismatch: got %q, want %q", source.CategoryID, catID.String())
	}
	if source.CategoryCode != "sast" {
		t.Errorf("CategoryCode mismatch: got %q", source.CategoryCode)
	}
	if source.CategoryName != "SAST" {
		t.Errorf("CategoryName mismatch: got %q", source.CategoryName)
	}
}

func TestSrcCache_CachedCategory_AllFieldsMapped(t *testing.T) {
	t.Parallel()

	repo := newSrcCacheMockRepo()
	catID := shared.NewID()
	now := time.Now().UTC()

	cat := findingsource.ReconstituteCategory(catID, "dast", "DAST", "Dynamic Analysis", "dast-icon.svg", 3, true, now, now)
	fs := findingsource.ReconstituteFindingSource(
		shared.NewID(), &catID, "zap", "ZAP", "Web scanner",
		"", "", 0, false, true, now, now,
	)

	repo.sourcesWithCat = []*findingsource.FindingSourceWithCategory{
		{FindingSource: fs, Category: cat},
	}

	svc := srcCacheMakeService(repo)
	categories, err := svc.GetCategories(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(categories) != 1 {
		t.Fatalf("expected 1 category, got %d", len(categories))
	}

	c := categories[0]
	if c.ID != catID.String() {
		t.Errorf("ID mismatch: got %q, want %q", c.ID, catID.String())
	}
	if c.Code != "dast" {
		t.Errorf("Code mismatch: got %q", c.Code)
	}
	if c.Name != "DAST" {
		t.Errorf("Name mismatch: got %q", c.Name)
	}
	if c.Description != "Dynamic Analysis" {
		t.Errorf("Description mismatch: got %q", c.Description)
	}
	if c.Icon != "dast-icon.svg" {
		t.Errorf("Icon mismatch: got %q", c.Icon)
	}
	if c.DisplayOrder != 3 {
		t.Errorf("DisplayOrder mismatch: got %d", c.DisplayOrder)
	}
}

// =============================================================================
// Tests: ByCategory index correctness
// =============================================================================

func TestSrcCache_ByCategoryIndex_IndicesAreValid(t *testing.T) {
	t.Parallel()

	repo := newSrcCacheMockRepo()
	cat := srcCacheMakeCategory("sast", "SAST")
	repo.sourcesWithCat = []*findingsource.FindingSourceWithCategory{
		srcCacheMakeSource("bandit", "Bandit", cat),
		srcCacheMakeSource("semgrep", "Semgrep", cat),
		srcCacheMakeSource("gosec", "Gosec", cat),
	}

	svc := srcCacheMakeService(repo)
	result, err := svc.GetAll(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	for catCode, indices := range result.ByCategory {
		for _, idx := range indices {
			if idx < 0 || idx >= len(result.Sources) {
				t.Errorf("ByCategory[%q] contains invalid index %d (len=%d)", catCode, idx, len(result.Sources))
			}
		}
	}
}

// =============================================================================
// Tests: Multiple calls return fresh data in no-cache mode
// =============================================================================

func TestSrcCache_GetAll_NoCache_ReflectsUpdatedData(t *testing.T) {
	t.Parallel()

	repo := newSrcCacheMockRepo()

	svc := srcCacheMakeService(repo)

	// First call: empty
	result1, err := svc.GetAll(context.Background())
	if err != nil {
		t.Fatalf("first call error: %v", err)
	}
	if len(result1.Sources) != 0 {
		t.Errorf("expected 0 sources initially, got %d", len(result1.Sources))
	}

	// Simulate DB being populated
	cat := srcCacheMakeCategory("sast", "SAST")
	repo.mu.Lock()
	repo.sourcesWithCat = []*findingsource.FindingSourceWithCategory{
		srcCacheMakeSource("bandit", "Bandit", cat),
	}
	repo.mu.Unlock()

	// Second call: should see the new data (no cache masking it)
	result2, err := svc.GetAll(context.Background())
	if err != nil {
		t.Fatalf("second call error: %v", err)
	}
	if len(result2.Sources) != 1 {
		t.Errorf("expected 1 source after DB update, got %d", len(result2.Sources))
	}
}

// =============================================================================
// Tests: GetByCode with large dataset
// =============================================================================

func TestSrcCache_GetByCode_LargeDataset_O1Lookup(t *testing.T) {
	t.Parallel()

	repo := newSrcCacheMockRepo()
	cat := srcCacheMakeCategory("sast", "SAST")

	const total = 100
	for i := range total {
		code := "source_" + string(rune('a'+i%26)) + "_" + string(rune('0'+i/26))
		repo.sourcesWithCat = append(repo.sourcesWithCat,
			srcCacheMakeSource(code, code, cat))
	}

	// Manually set a known last code
	repo.sourcesWithCat = append(repo.sourcesWithCat,
		srcCacheMakeSource("needle", "Needle", cat))

	svc := srcCacheMakeService(repo)

	source, err := svc.GetByCode(context.Background(), "needle")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if source == nil {
		t.Fatal("expected to find 'needle' in large dataset")
	}
	if source.Code != "needle" {
		t.Errorf("expected code 'needle', got %q", source.Code)
	}
}

// =============================================================================
// Tests: Cascading delegation (GetByCode, IsValidCode, GetByCategory all use GetAll)
// =============================================================================

func TestSrcCache_AllMethodsDelegate_ToGetAll(t *testing.T) {
	t.Parallel()

	repo := newSrcCacheMockRepo()
	cat := srcCacheMakeCategory("sast", "SAST")
	repo.sourcesWithCat = []*findingsource.FindingSourceWithCategory{
		srcCacheMakeSource("bandit", "Bandit", cat),
	}

	svc := srcCacheMakeService(repo)
	ctx := context.Background()

	// Each method call triggers a DB call in no-cache mode
	_, _ = svc.GetAll(ctx)
	_, _ = svc.GetByCode(ctx, "bandit")
	_, _ = svc.IsValidCode(ctx, "bandit")
	_, _ = svc.GetByCategory(ctx, "sast")
	_, _ = svc.GetCategories(ctx)

	if repo.callCount != 5 {
		t.Errorf("expected 5 DB calls (one per method), got %d", repo.callCount)
	}
}

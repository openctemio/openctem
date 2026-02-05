package app

import (
	"context"
	"fmt"

	"github.com/openctemio/api/pkg/domain/findingsource"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/logger"
	"github.com/openctemio/api/pkg/pagination"
)

// FindingSourceService handles finding source-related business operations.
// Finding sources are read-only system configuration created via DB seed or by system admin.
type FindingSourceService struct {
	repo         findingsource.Repository
	categoryRepo findingsource.CategoryRepository
	logger       *logger.Logger
}

// NewFindingSourceService creates a new FindingSourceService.
func NewFindingSourceService(repo findingsource.Repository, categoryRepo findingsource.CategoryRepository, log *logger.Logger) *FindingSourceService {
	return &FindingSourceService{
		repo:         repo,
		categoryRepo: categoryRepo,
		logger:       log.With("service", "finding_source"),
	}
}

// GetCategory retrieves a category by ID.
func (s *FindingSourceService) GetCategory(ctx context.Context, categoryID string) (*findingsource.Category, error) {
	parsedID, err := shared.IDFromString(categoryID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid id format", shared.ErrValidation)
	}

	return s.categoryRepo.GetByID(ctx, parsedID)
}

// GetCategoryByCode retrieves a category by code.
func (s *FindingSourceService) GetCategoryByCode(ctx context.Context, code string) (*findingsource.Category, error) {
	return s.categoryRepo.GetByCode(ctx, code)
}

// ListCategories lists categories with pagination.
func (s *FindingSourceService) ListCategories(ctx context.Context, filter findingsource.CategoryFilter, page pagination.Pagination) (pagination.Result[*findingsource.Category], error) {
	return s.categoryRepo.List(ctx, filter, page)
}

// ListActiveCategories lists all active categories.
func (s *FindingSourceService) ListActiveCategories(ctx context.Context) ([]*findingsource.Category, error) {
	return s.categoryRepo.ListActive(ctx)
}

// GetFindingSource retrieves a finding source by ID.
func (s *FindingSourceService) GetFindingSource(ctx context.Context, findingSourceID string) (*findingsource.FindingSource, error) {
	parsedID, err := shared.IDFromString(findingSourceID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid id format", shared.ErrValidation)
	}

	return s.repo.GetByID(ctx, parsedID)
}

// GetFindingSourceByCode retrieves a finding source by code.
func (s *FindingSourceService) GetFindingSourceByCode(ctx context.Context, code string) (*findingsource.FindingSource, error) {
	return s.repo.GetByCode(ctx, code)
}

// ListFindingSources lists finding sources with filtering and pagination.
func (s *FindingSourceService) ListFindingSources(ctx context.Context, filter findingsource.Filter, opts findingsource.ListOptions, page pagination.Pagination) (pagination.Result[*findingsource.FindingSource], error) {
	return s.repo.List(ctx, filter, opts, page)
}

// ListFindingSourcesWithCategory lists finding sources with their categories.
func (s *FindingSourceService) ListFindingSourcesWithCategory(ctx context.Context, filter findingsource.Filter, opts findingsource.ListOptions, page pagination.Pagination) (pagination.Result[*findingsource.FindingSourceWithCategory], error) {
	return s.repo.ListWithCategory(ctx, filter, opts, page)
}

// ListActiveFindingSources lists all active finding sources.
func (s *FindingSourceService) ListActiveFindingSources(ctx context.Context) ([]*findingsource.FindingSource, error) {
	return s.repo.ListActive(ctx)
}

// ListActiveFindingSourcesWithCategory lists all active finding sources with their categories.
func (s *FindingSourceService) ListActiveFindingSourcesWithCategory(ctx context.Context) ([]*findingsource.FindingSourceWithCategory, error) {
	return s.repo.ListActiveWithCategory(ctx)
}

// ListActiveFindingSourcesByCategory lists active finding sources by category.
func (s *FindingSourceService) ListActiveFindingSourcesByCategory(ctx context.Context, categoryID string) ([]*findingsource.FindingSource, error) {
	categoryIDParsed, err := shared.IDFromString(categoryID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid category id format", shared.ErrValidation)
	}

	return s.repo.ListActiveByCategory(ctx, categoryIDParsed)
}

// IsValidSourceCode checks if the code is a valid active finding source.
func (s *FindingSourceService) IsValidSourceCode(ctx context.Context, code string) (bool, error) {
	return s.repo.IsValidCode(ctx, code)
}

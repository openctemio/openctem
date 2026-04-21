package asset

import (
	"context"
	"fmt"

	assettypedom "github.com/openctemio/api/pkg/domain/assettype"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/logger"
	"github.com/openctemio/api/pkg/pagination"
)

// AssetTypeService handles asset type-related business operations.
// Asset types are read-only system configuration created via DB seed or by system admin.
type AssetTypeService struct {
	repo         assettypedom.Repository
	categoryRepo assettypedom.CategoryRepository
	logger       *logger.Logger
}

// NewAssetTypeService creates a new AssetTypeService.
func NewAssetTypeService(repo assettypedom.Repository, categoryRepo assettypedom.CategoryRepository, log *logger.Logger) *AssetTypeService {
	return &AssetTypeService{
		repo:         repo,
		categoryRepo: categoryRepo,
		logger:       log.With("service", "asset_type"),
	}
}

// GetCategory retrieves a category by ID.
func (s *AssetTypeService) GetCategory(ctx context.Context, categoryID string) (*assettypedom.Category, error) {
	parsedID, err := shared.IDFromString(categoryID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid id format", shared.ErrValidation)
	}

	return s.categoryRepo.GetByID(ctx, parsedID)
}

// GetCategoryByCode retrieves a category by code.
func (s *AssetTypeService) GetCategoryByCode(ctx context.Context, code string) (*assettypedom.Category, error) {
	return s.categoryRepo.GetByCode(ctx, code)
}

// ListCategories lists categories with pagination.
func (s *AssetTypeService) ListCategories(ctx context.Context, filter assettypedom.CategoryFilter, page pagination.Pagination) (pagination.Result[*assettypedom.Category], error) {
	return s.categoryRepo.List(ctx, filter, page)
}

// ListActiveCategories lists all active categories.
func (s *AssetTypeService) ListActiveCategories(ctx context.Context) ([]*assettypedom.Category, error) {
	return s.categoryRepo.ListActive(ctx)
}

// GetAssetType retrieves an asset type by ID.
func (s *AssetTypeService) GetAssetType(ctx context.Context, assetTypeID string) (*assettypedom.AssetType, error) {
	parsedID, err := shared.IDFromString(assetTypeID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid id format", shared.ErrValidation)
	}

	return s.repo.GetByID(ctx, parsedID)
}

// GetAssetTypeByCode retrieves an asset type by code.
func (s *AssetTypeService) GetAssetTypeByCode(ctx context.Context, code string) (*assettypedom.AssetType, error) {
	return s.repo.GetByCode(ctx, code)
}

// ListAssetTypes lists asset types with filtering and pagination.
func (s *AssetTypeService) ListAssetTypes(ctx context.Context, filter assettypedom.Filter, opts assettypedom.ListOptions, page pagination.Pagination) (pagination.Result[*assettypedom.AssetType], error) {
	return s.repo.List(ctx, filter, opts, page)
}

// ListAssetTypesWithCategory lists asset types with their categories.
func (s *AssetTypeService) ListAssetTypesWithCategory(ctx context.Context, filter assettypedom.Filter, opts assettypedom.ListOptions, page pagination.Pagination) (pagination.Result[*assettypedom.AssetTypeWithCategory], error) {
	return s.repo.ListWithCategory(ctx, filter, opts, page)
}

// ListActiveAssetTypes lists all active asset types.
func (s *AssetTypeService) ListActiveAssetTypes(ctx context.Context) ([]*assettypedom.AssetType, error) {
	return s.repo.ListActive(ctx)
}

// ListActiveAssetTypesByCategory lists active asset types by category.
func (s *AssetTypeService) ListActiveAssetTypesByCategory(ctx context.Context, categoryID string) ([]*assettypedom.AssetType, error) {
	categoryIDParsed, err := shared.IDFromString(categoryID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid category id format", shared.ErrValidation)
	}

	return s.repo.ListActiveByCategory(ctx, categoryIDParsed)
}

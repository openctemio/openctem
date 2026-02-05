package app

import (
	"context"
	"fmt"

	"github.com/openctemio/api/pkg/domain/assettype"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/logger"
	"github.com/openctemio/api/pkg/pagination"
)

// AssetTypeService handles asset type-related business operations.
// Asset types are read-only system configuration created via DB seed or by system admin.
type AssetTypeService struct {
	repo         assettype.Repository
	categoryRepo assettype.CategoryRepository
	logger       *logger.Logger
}

// NewAssetTypeService creates a new AssetTypeService.
func NewAssetTypeService(repo assettype.Repository, categoryRepo assettype.CategoryRepository, log *logger.Logger) *AssetTypeService {
	return &AssetTypeService{
		repo:         repo,
		categoryRepo: categoryRepo,
		logger:       log.With("service", "asset_type"),
	}
}

// GetCategory retrieves a category by ID.
func (s *AssetTypeService) GetCategory(ctx context.Context, categoryID string) (*assettype.Category, error) {
	parsedID, err := shared.IDFromString(categoryID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid id format", shared.ErrValidation)
	}

	return s.categoryRepo.GetByID(ctx, parsedID)
}

// GetCategoryByCode retrieves a category by code.
func (s *AssetTypeService) GetCategoryByCode(ctx context.Context, code string) (*assettype.Category, error) {
	return s.categoryRepo.GetByCode(ctx, code)
}

// ListCategories lists categories with pagination.
func (s *AssetTypeService) ListCategories(ctx context.Context, filter assettype.CategoryFilter, page pagination.Pagination) (pagination.Result[*assettype.Category], error) {
	return s.categoryRepo.List(ctx, filter, page)
}

// ListActiveCategories lists all active categories.
func (s *AssetTypeService) ListActiveCategories(ctx context.Context) ([]*assettype.Category, error) {
	return s.categoryRepo.ListActive(ctx)
}

// GetAssetType retrieves an asset type by ID.
func (s *AssetTypeService) GetAssetType(ctx context.Context, assetTypeID string) (*assettype.AssetType, error) {
	parsedID, err := shared.IDFromString(assetTypeID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid id format", shared.ErrValidation)
	}

	return s.repo.GetByID(ctx, parsedID)
}

// GetAssetTypeByCode retrieves an asset type by code.
func (s *AssetTypeService) GetAssetTypeByCode(ctx context.Context, code string) (*assettype.AssetType, error) {
	return s.repo.GetByCode(ctx, code)
}

// ListAssetTypes lists asset types with filtering and pagination.
func (s *AssetTypeService) ListAssetTypes(ctx context.Context, filter assettype.Filter, opts assettype.ListOptions, page pagination.Pagination) (pagination.Result[*assettype.AssetType], error) {
	return s.repo.List(ctx, filter, opts, page)
}

// ListAssetTypesWithCategory lists asset types with their categories.
func (s *AssetTypeService) ListAssetTypesWithCategory(ctx context.Context, filter assettype.Filter, opts assettype.ListOptions, page pagination.Pagination) (pagination.Result[*assettype.AssetTypeWithCategory], error) {
	return s.repo.ListWithCategory(ctx, filter, opts, page)
}

// ListActiveAssetTypes lists all active asset types.
func (s *AssetTypeService) ListActiveAssetTypes(ctx context.Context) ([]*assettype.AssetType, error) {
	return s.repo.ListActive(ctx)
}

// ListActiveAssetTypesByCategory lists active asset types by category.
func (s *AssetTypeService) ListActiveAssetTypesByCategory(ctx context.Context, categoryID string) ([]*assettype.AssetType, error) {
	categoryIDParsed, err := shared.IDFromString(categoryID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid category id format", shared.ErrValidation)
	}

	return s.repo.ListActiveByCategory(ctx, categoryIDParsed)
}

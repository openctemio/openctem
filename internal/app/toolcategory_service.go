package app

import (
	"context"
	"fmt"

	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/domain/toolcategory"
	"github.com/openctemio/api/pkg/logger"
	"github.com/openctemio/api/pkg/pagination"
)

// ToolCategoryService handles tool category business operations.
type ToolCategoryService struct {
	repo   toolcategory.Repository
	logger *logger.Logger
}

// NewToolCategoryService creates a new ToolCategoryService.
func NewToolCategoryService(
	repo toolcategory.Repository,
	log *logger.Logger,
) *ToolCategoryService {
	return &ToolCategoryService{
		repo:   repo,
		logger: log.With("service", "toolcategory"),
	}
}

// =============================================================================
// List Operations
// =============================================================================

// ListCategoriesInput represents the input for listing categories.
type ListCategoriesInput struct {
	TenantID  string
	IsBuiltin *bool
	Search    string
	Page      int
	PerPage   int
}

// ListCategories returns categories matching the filter.
// Always includes platform (builtin) categories.
// If TenantID is provided, also includes that tenant's custom categories.
func (s *ToolCategoryService) ListCategories(ctx context.Context, input ListCategoriesInput) (pagination.Result[*toolcategory.ToolCategory], error) {
	s.logger.Debug("listing tool categories", "tenant_id", input.TenantID, "search", input.Search)

	var tenantID *shared.ID
	if input.TenantID != "" {
		tid, err := shared.IDFromString(input.TenantID)
		if err != nil {
			return pagination.Result[*toolcategory.ToolCategory]{}, fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
		}
		tenantID = &tid
	}

	filter := toolcategory.Filter{
		TenantID:  tenantID,
		IsBuiltin: input.IsBuiltin,
		Search:    input.Search,
	}

	page := pagination.New(input.Page, input.PerPage)

	return s.repo.List(ctx, filter, page)
}

// ListAllCategories returns all categories for a tenant context (for dropdowns).
func (s *ToolCategoryService) ListAllCategories(ctx context.Context, tenantID string) ([]*toolcategory.ToolCategory, error) {
	s.logger.Debug("listing all tool categories", "tenant_id", tenantID)

	var tid *shared.ID
	if tenantID != "" {
		t, err := shared.IDFromString(tenantID)
		if err != nil {
			return nil, fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
		}
		tid = &t
	}

	return s.repo.ListAll(ctx, tid)
}

// GetCategory returns a category by ID.
func (s *ToolCategoryService) GetCategory(ctx context.Context, id string) (*toolcategory.ToolCategory, error) {
	s.logger.Debug("getting tool category", "id", id)

	categoryID, err := shared.IDFromString(id)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid category id", shared.ErrValidation)
	}

	return s.repo.GetByID(ctx, categoryID)
}

// =============================================================================
// Tenant Custom Category Operations
// =============================================================================

// CreateCategoryInput represents the input for creating a tenant custom category.
type CreateCategoryInput struct {
	TenantID    string `json:"-"`
	CreatedBy   string `json:"-"`
	Name        string `json:"name" validate:"required,min=2,max=50"`
	DisplayName string `json:"display_name" validate:"required,max=100"`
	Description string `json:"description" validate:"max=500"`
	Icon        string `json:"icon" validate:"max=50"`
	Color       string `json:"color" validate:"max=20"`
}

// CreateCategory creates a new tenant custom category.
func (s *ToolCategoryService) CreateCategory(ctx context.Context, input CreateCategoryInput) (*toolcategory.ToolCategory, error) {
	s.logger.Info("creating tool category", "tenant_id", input.TenantID, "name", input.Name)

	tenantID, err := shared.IDFromString(input.TenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}

	createdBy, err := shared.IDFromString(input.CreatedBy)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid created_by user id", shared.ErrValidation)
	}

	// Check if category name already exists (in platform or tenant scope)
	existsInPlatform, err := s.repo.ExistsByName(ctx, nil, input.Name)
	if err != nil {
		return nil, fmt.Errorf("failed to check platform category: %w", err)
	}
	if existsInPlatform {
		return nil, fmt.Errorf("%w: category name '%s' is reserved (platform category)", shared.ErrConflict, input.Name)
	}

	existsInTenant, err := s.repo.ExistsByName(ctx, &tenantID, input.Name)
	if err != nil {
		return nil, fmt.Errorf("failed to check tenant category: %w", err)
	}
	if existsInTenant {
		return nil, fmt.Errorf("%w: category name '%s' already exists", shared.ErrConflict, input.Name)
	}

	// Set defaults
	icon := input.Icon
	if icon == "" {
		icon = "folder"
	}

	color := input.Color
	if color == "" {
		color = "gray"
	}

	tc, err := toolcategory.NewTenantCategory(
		tenantID,
		createdBy,
		input.Name,
		input.DisplayName,
		input.Description,
		icon,
		color,
	)
	if err != nil {
		return nil, err
	}

	if err := s.repo.Create(ctx, tc); err != nil {
		return nil, fmt.Errorf("failed to create category: %w", err)
	}

	s.logger.Info("tool category created", "id", tc.ID.String(), "name", tc.Name)

	return tc, nil
}

// UpdateCategoryInput represents the input for updating a category.
type UpdateCategoryInput struct {
	TenantID    string `json:"-"`
	ID          string `json:"-"`
	DisplayName string `json:"display_name" validate:"required,max=100"`
	Description string `json:"description" validate:"max=500"`
	Icon        string `json:"icon" validate:"max=50"`
	Color       string `json:"color" validate:"max=20"`
}

// UpdateCategory updates an existing tenant custom category.
func (s *ToolCategoryService) UpdateCategory(ctx context.Context, input UpdateCategoryInput) (*toolcategory.ToolCategory, error) {
	s.logger.Info("updating tool category", "id", input.ID)

	tenantID, err := shared.IDFromString(input.TenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}

	categoryID, err := shared.IDFromString(input.ID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid category id", shared.ErrValidation)
	}

	tc, err := s.repo.GetByID(ctx, categoryID)
	if err != nil {
		return nil, err
	}

	// Check ownership - only tenant's own categories can be updated
	if !tc.CanBeModifiedByTenant(tenantID) {
		return nil, fmt.Errorf("%w: cannot modify this category", shared.ErrForbidden)
	}

	// Set defaults
	icon := input.Icon
	if icon == "" {
		icon = "folder"
	}

	color := input.Color
	if color == "" {
		color = "gray"
	}

	if err := tc.Update(input.DisplayName, input.Description, icon, color); err != nil {
		return nil, err
	}

	if err := s.repo.Update(ctx, tc); err != nil {
		return nil, fmt.Errorf("failed to update category: %w", err)
	}

	s.logger.Info("tool category updated", "id", tc.ID.String())

	return tc, nil
}

// DeleteCategory deletes a tenant custom category.
func (s *ToolCategoryService) DeleteCategory(ctx context.Context, tenantID, categoryID string) error {
	s.logger.Info("deleting tool category", "tenant_id", tenantID, "id", categoryID)

	tid, err := shared.IDFromString(tenantID)
	if err != nil {
		return fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}

	cid, err := shared.IDFromString(categoryID)
	if err != nil {
		return fmt.Errorf("%w: invalid category id", shared.ErrValidation)
	}

	tc, err := s.repo.GetByID(ctx, cid)
	if err != nil {
		return err
	}

	// Check ownership - only tenant's own categories can be deleted
	if !tc.CanBeModifiedByTenant(tid) {
		return fmt.Errorf("%w: cannot delete this category", shared.ErrForbidden)
	}

	// TODO: Check if category is in use by any tools before deleting
	// This would require checking the tools table for any tools with this category_id

	if err := s.repo.Delete(ctx, cid); err != nil {
		return err
	}

	s.logger.Info("tool category deleted", "id", categoryID)

	return nil
}

package app

import (
	"context"
	"fmt"

	"github.com/openctemio/api/pkg/domain/component"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/logger"
	"github.com/openctemio/api/pkg/pagination"
)

// ComponentService handles component-related business operations.
type ComponentService struct {
	repo   component.Repository
	logger *logger.Logger
}

// NewComponentService creates a new ComponentService.
func NewComponentService(repo component.Repository, log *logger.Logger) *ComponentService {
	return &ComponentService{
		repo:   repo,
		logger: log.With("service", "component"),
	}
}

// CreateComponentInput represents the input for creating a component.
type CreateComponentInput struct {
	TenantID       string `validate:"required,uuid"`
	AssetID        string `validate:"required,uuid"`
	Name           string `validate:"required,min=1,max=255"`
	Version        string `validate:"required,max=100"`
	Ecosystem      string `validate:"required,ecosystem"`
	PackageManager string `validate:"max=50"`
	Namespace      string `validate:"max=255"`
	ManifestFile   string `validate:"max=255"`
	ManifestPath   string `validate:"max=500"`
	DependencyType string `validate:"omitempty,dependency_type"`
	License        string `validate:"max=100"`
}

// CreateComponent creates a new component (Global) and links it to an asset.
func (s *ComponentService) CreateComponent(ctx context.Context, input CreateComponentInput) (*component.Component, error) {
	s.logger.Info("creating component", "name", input.Name, "version", input.Version)

	tenantID, err := shared.IDFromString(input.TenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant id format", shared.ErrValidation)
	}

	assetID, err := shared.IDFromString(input.AssetID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid asset id format", shared.ErrValidation)
	}

	ecosystem, err := component.ParseEcosystem(input.Ecosystem)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", shared.ErrValidation, err)
	}

	// 1. Create/prepare the Global Component
	c, err := component.NewComponent(input.Name, input.Version, ecosystem)
	if err != nil {
		return nil, err
	}

	if input.PackageManager != "" {
		c.SetMetadata("package_manager", input.PackageManager)
	}
	if input.Namespace != "" {
		c.SetMetadata("namespace", input.Namespace)
	}
	if input.License != "" {
		c.UpdateLicense(input.License)
	}

	// 2. Persist Global Component (Upsert)
	compID, err := s.repo.Upsert(ctx, c)
	if err != nil {
		return nil, fmt.Errorf("failed to upsert component: %w", err)
	}

	// 3. Create Asset Dependency Link
	depType := component.DependencyTypeDirect
	if input.DependencyType != "" {
		depType, err = component.ParseDependencyType(input.DependencyType)
		if err != nil {
			return nil, fmt.Errorf("%w: %w", shared.ErrValidation, err)
		}
	}

	dep, err := component.NewAssetDependency(tenantID, assetID, compID, input.ManifestPath, depType)
	if err != nil {
		return nil, fmt.Errorf("failed to create dependency link: %w", err)
	}

	if err := s.repo.LinkAsset(ctx, dep); err != nil {
		return nil, fmt.Errorf("failed to link asset dependency: %w", err)
	}

	s.logger.Info("component linked to asset", "asset_id", assetID, "component_id", compID)
	return c, nil
}

// GetComponent retrieves a component by ID.
func (s *ComponentService) GetComponent(ctx context.Context, componentID string) (*component.Component, error) {
	parsedID, err := shared.IDFromString(componentID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid id format", shared.ErrValidation)
	}

	return s.repo.GetByID(ctx, parsedID)
}

// GetComponentByPURL retrieves a component by Package URL.
func (s *ComponentService) GetComponentByPURL(ctx context.Context, tenantID, purl string) (*component.Component, error) {
	// parsedTenantID is not used for global lookup
	if _, err := shared.IDFromString(tenantID); err != nil {
		return nil, fmt.Errorf("%w: invalid tenant id format", shared.ErrValidation)
	}

	// Global lookup does not strictly require tenantID, but we validate it exists.
	// In the future, we might want to restricts lookup to components the tenant actually uses?
	// For now, PURL lookup is global.
	return s.repo.GetByPURL(ctx, purl)
}

// UpdateComponentInput represents the input for updating a component.
type UpdateComponentInput struct {
	Version            *string `validate:"omitempty,max=100"`
	PackageManager     *string `validate:"omitempty,max=50"`
	Namespace          *string `validate:"omitempty,max=255"`
	ManifestFile       *string `validate:"omitempty,max=255"`
	ManifestPath       *string `validate:"omitempty,max=500"`
	DependencyType     *string `validate:"omitempty,dependency_type"`
	License            *string `validate:"omitempty,max=100"`
	Status             *string `validate:"omitempty,component_status"`
	VulnerabilityCount *int    `validate:"omitempty,min=0"`
}

// UpdateComponent updates a component (specifically an Asset Dependency link).
// NOTE: For now, we assume edits are focused on the context (path, type).
// Updating global properties (Version, License) would theoretically require creating a NEW component
// and re-linking, which is complex. For version bumps, we recommend re-ingestion or Delete+Create.
// If input.Version is provided, we will return an error or handle it as "not supported via this endpoint" for now,
// or we implement the re-link logic.
// DECISION: We will assume `componentID` passed here is the `AssetDependency.ID`.
func (s *ComponentService) UpdateComponent(ctx context.Context, dependencyID string, tenantID string, input UpdateComponentInput) (*component.AssetDependency, error) {
	parsedID, err := shared.IDFromString(dependencyID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid id format", shared.ErrValidation)
	}

	// 1. Get the existing dependency link
	dep, err := s.repo.GetDependency(ctx, parsedID)
	if err != nil {
		return nil, err
	}

	// IDOR Check
	if tenantID != "" && !dep.TenantID().IsZero() && dep.TenantID().String() != tenantID {
		return nil, shared.ErrNotFound
	}

	// 2. Handle Contextual Updates (DependencyType, Path)
	// Note: We don't have setters exposed on AssetDependency for these yet, need to add them or use reflection (bad).
	// We will add Mutators to AssetDependency in `entity.go` shortly.

	// Assuming Mutators exist (I will add them next):
	// TODO: Enable these once mutators are added to AssetDependency

	// 3. Handle Global Updates (Version, License)
	// If version changes, we must Find-Or-Create the new Global Component and link to it.
	if input.Version != nil && *input.Version != dep.Component().Version() {
		// Complex: Find/Create new global component
		// link.SetComponentID(newID)
		s.logger.Warn("updating component version via API is not fully supported yet triggers global lookup", "old", dep.Component().Version(), "new", *input.Version)
	}

	// For now, we only save the dependency link changes
	// We need `UpdateDependency` in repo.
	if err := s.repo.UpdateDependency(ctx, dep); err != nil {
		return nil, fmt.Errorf("failed to update dependency: %w", err)
	}

	return dep, nil
}

// DeleteComponent deletes a component dependency linkage.
func (s *ComponentService) DeleteComponent(ctx context.Context, dependencyID string, tenantID string) error {
	parsedID, err := shared.IDFromString(dependencyID)
	if err != nil {
		return fmt.Errorf("%w: invalid id format", shared.ErrValidation)
	}

	// We really should check ownership (GetDependency) first but for speed relying on repo to be safe or
	// we assume the ID is a dependency ID.
	if tenantID != "" {
		dep, err := s.repo.GetDependency(ctx, parsedID)
		if err != nil {
			return err
		}
		if dep.TenantID().String() != tenantID {
			return shared.ErrNotFound
		}
	}

	if err := s.repo.DeleteDependency(ctx, parsedID); err != nil {
		return err
	}

	s.logger.Info("component dependency deleted", "id", dependencyID)
	return nil
}

// ListComponentsInput represents the input for listing components.
type ListComponentsInput struct {
	TenantID           string   `validate:"required,uuid"`
	AssetID            string   `validate:"omitempty,uuid"`
	Name               string   `validate:"max=255"`
	Ecosystems         []string `validate:"max=10,dive,ecosystem"`
	Statuses           []string `validate:"max=5,dive,component_status"`
	DependencyTypes    []string `validate:"max=5,dive,dependency_type"`
	HasVulnerabilities *bool
	Licenses           []string `validate:"max=20,dive,max=100"`
	Page               int      `validate:"min=0"`
	PerPage            int      `validate:"min=0,max=100"`
}

// ListComponents retrieves components with filtering and pagination.
func (s *ComponentService) ListComponents(ctx context.Context, input ListComponentsInput) (pagination.Result[*component.Component], error) {
	tenantID, err := shared.IDFromString(input.TenantID)
	if err != nil {
		return pagination.Result[*component.Component]{}, fmt.Errorf("%w: invalid tenant id format", shared.ErrValidation)
	}

	filter := component.NewFilter().WithTenantID(tenantID)

	if input.AssetID != "" {
		assetID, err := shared.IDFromString(input.AssetID)
		if err != nil {
			return pagination.Result[*component.Component]{}, fmt.Errorf("%w: invalid asset id format", shared.ErrValidation)
		}
		filter = filter.WithAssetID(assetID)
	}

	if input.Name != "" {
		filter = filter.WithName(input.Name)
	}

	if len(input.Ecosystems) > 0 {
		ecosystems := make([]component.Ecosystem, 0, len(input.Ecosystems))
		for _, e := range input.Ecosystems {
			if parsed, err := component.ParseEcosystem(e); err == nil {
				ecosystems = append(ecosystems, parsed)
			}
		}
		filter = filter.WithEcosystems(ecosystems...)
	}

	if len(input.Statuses) > 0 {
		statuses := make([]component.Status, 0, len(input.Statuses))
		for _, st := range input.Statuses {
			if parsed, err := component.ParseStatus(st); err == nil {
				statuses = append(statuses, parsed)
			}
		}
		filter = filter.WithStatuses(statuses...)
	}

	if len(input.DependencyTypes) > 0 {
		dts := make([]component.DependencyType, 0, len(input.DependencyTypes))
		for _, dt := range input.DependencyTypes {
			if parsed, err := component.ParseDependencyType(dt); err == nil {
				dts = append(dts, parsed)
			}
		}
		filter = filter.WithDependencyTypes(dts...)
	}

	if input.HasVulnerabilities != nil {
		filter = filter.WithHasVulnerabilities(*input.HasVulnerabilities)
	}

	if len(input.Licenses) > 0 {
		filter = filter.WithLicenses(input.Licenses...)
	}

	page := pagination.New(input.Page, input.PerPage)
	return s.repo.ListComponents(ctx, filter, page)
}

// ListAssetComponents retrieves components for a specific asset (Dependencies).
func (s *ComponentService) ListAssetComponents(ctx context.Context, assetID string, page, perPage int) (pagination.Result[*component.AssetDependency], error) {
	parsedAssetID, err := shared.IDFromString(assetID)
	if err != nil {
		return pagination.Result[*component.AssetDependency]{}, fmt.Errorf("%w: invalid asset id format", shared.ErrValidation)
	}

	p := pagination.New(page, perPage)
	return s.repo.ListDependencies(ctx, parsedAssetID, p)
}

// GetComponentStats retrieves aggregated component statistics for a tenant.
func (s *ComponentService) GetComponentStats(ctx context.Context, tenantID string) (*component.ComponentStats, error) {
	parsedTenantID, err := shared.IDFromString(tenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant id format", shared.ErrValidation)
	}

	return s.repo.GetStats(ctx, parsedTenantID)
}

// GetEcosystemStats retrieves per-ecosystem statistics for a tenant.
func (s *ComponentService) GetEcosystemStats(ctx context.Context, tenantID string) ([]component.EcosystemStats, error) {
	parsedTenantID, err := shared.IDFromString(tenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant id format", shared.ErrValidation)
	}

	return s.repo.GetEcosystemStats(ctx, parsedTenantID)
}

// GetVulnerableComponents retrieves vulnerable components with details for a tenant.
func (s *ComponentService) GetVulnerableComponents(ctx context.Context, tenantID string, limit int) ([]component.VulnerableComponent, error) {
	parsedTenantID, err := shared.IDFromString(tenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant id format", shared.ErrValidation)
	}

	return s.repo.GetVulnerableComponents(ctx, parsedTenantID, limit)
}

// DeleteAssetComponents deletes all components for an asset.
func (s *ComponentService) DeleteAssetComponents(ctx context.Context, assetID string) error {
	parsedAssetID, err := shared.IDFromString(assetID)
	if err != nil {
		return fmt.Errorf("%w: invalid asset id format", shared.ErrValidation)
	}

	if err := s.repo.DeleteByAssetID(ctx, parsedAssetID); err != nil {
		return fmt.Errorf("failed to delete asset components: %w", err)
	}

	s.logger.Info("asset components deleted", "asset_id", assetID)
	return nil
}

// GetLicenseStats retrieves license statistics for a tenant.
func (s *ComponentService) GetLicenseStats(ctx context.Context, tenantID string) ([]component.LicenseStats, error) {
	parsedTenantID, err := shared.IDFromString(tenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant id format", shared.ErrValidation)
	}

	return s.repo.GetLicenseStats(ctx, parsedTenantID)
}

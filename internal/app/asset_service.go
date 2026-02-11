package app

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/openctemio/api/pkg/domain/asset"
	"github.com/openctemio/api/pkg/domain/assetgroup"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/logger"
	"github.com/openctemio/api/pkg/pagination"
)

// AssetService handles asset-related business operations.
type AssetService struct {
	repo           asset.Repository
	repoExtRepo    asset.RepositoryExtensionRepository
	assetGroupRepo assetgroup.Repository // For recalculating group stats
	logger         *logger.Logger
}

// NewAssetService creates a new AssetService.
func NewAssetService(repo asset.Repository, log *logger.Logger) *AssetService {
	return &AssetService{
		repo:   repo,
		logger: log.With("service", "asset"),
	}
}

// SetRepositoryExtensionRepository sets the repository extension repository.
func (s *AssetService) SetRepositoryExtensionRepository(repo asset.RepositoryExtensionRepository) {
	s.repoExtRepo = repo
}

// SetAssetGroupRepository sets the asset group repository for recalculating stats.
func (s *AssetService) SetAssetGroupRepository(repo assetgroup.Repository) {
	s.assetGroupRepo = repo
}

// HasRepositoryExtensionRepository returns true if the repository extension repository is configured.
func (s *AssetService) HasRepositoryExtensionRepository() bool {
	return s.repoExtRepo != nil
}

// CreateAssetInput represents the input for creating an asset.
type CreateAssetInput struct {
	TenantID    string   `validate:"omitempty,uuid"`
	Name        string   `validate:"required,min=1,max=255"`
	Type        string   `validate:"required,asset_type"`
	Criticality string   `validate:"required,criticality"`
	Scope       string   `validate:"omitempty,scope"`
	Exposure    string   `validate:"omitempty,exposure"`
	Description string   `validate:"max=1000"`
	Tags        []string `validate:"max=20,dive,max=50"`
}

// CreateAsset creates a new asset.
func (s *AssetService) CreateAsset(ctx context.Context, input CreateAssetInput) (*asset.Asset, error) {
	s.logger.Info("creating asset", "name", input.Name)

	assetType, err := asset.ParseAssetType(input.Type)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", shared.ErrValidation, err)
	}

	criticality, err := asset.ParseCriticality(input.Criticality)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", shared.ErrValidation, err)
	}

	// Parse tenant ID for existence check
	var tenantID shared.ID
	if input.TenantID != "" {
		tenantID, err = shared.IDFromString(input.TenantID)
		if err != nil {
			return nil, fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
		}
	}

	exists, err := s.repo.ExistsByName(ctx, tenantID, input.Name)
	if err != nil {
		return nil, fmt.Errorf("failed to check asset existence: %w", err)
	}
	if exists {
		return nil, asset.AlreadyExistsError(input.Name)
	}

	a, err := asset.NewAsset(input.Name, assetType, criticality)
	if err != nil {
		return nil, err
	}

	// Set tenant ID if provided (already parsed above)
	if !tenantID.IsZero() {
		a.SetTenantID(tenantID)
	}

	// Set scope if provided
	if input.Scope != "" {
		scope, err := asset.ParseScope(input.Scope)
		if err != nil {
			return nil, fmt.Errorf("%w: %w", shared.ErrValidation, err)
		}
		_ = a.UpdateScope(scope)
	}

	// Set exposure if provided
	if input.Exposure != "" {
		exposure, err := asset.ParseExposure(input.Exposure)
		if err != nil {
			return nil, fmt.Errorf("%w: %w", shared.ErrValidation, err)
		}
		_ = a.UpdateExposure(exposure)
	}

	if input.Description != "" {
		a.UpdateDescription(input.Description)
	}
	for _, tag := range input.Tags {
		a.AddTag(tag)
	}

	// Calculate initial risk score
	a.CalculateRiskScore()

	if err := s.repo.Create(ctx, a); err != nil {
		return nil, fmt.Errorf("failed to create asset: %w", err)
	}

	s.logger.Info("asset created", "id", a.ID().String(), "name", a.Name())
	return a, nil
}

// GetAsset retrieves an asset by ID within a tenant.
// Security: Requires tenantID to prevent cross-tenant data access.
func (s *AssetService) GetAsset(ctx context.Context, tenantID, assetID string) (*asset.Asset, error) {
	parsedTenantID, err := shared.IDFromString(tenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant id format", shared.ErrValidation)
	}

	parsedID, err := shared.IDFromString(assetID)
	if err != nil {
		// Return NotFound instead of Validation error - from user's perspective, resource doesn't exist
		return nil, shared.ErrNotFound
	}

	return s.repo.GetByID(ctx, parsedTenantID, parsedID)
}

// UpdateAssetInput represents the input for updating an asset.
type UpdateAssetInput struct {
	Name        *string  `validate:"omitempty,min=1,max=255"`
	Criticality *string  `validate:"omitempty,criticality"`
	Scope       *string  `validate:"omitempty,scope"`
	Exposure    *string  `validate:"omitempty,exposure"`
	Description *string  `validate:"omitempty,max=1000"`
	Tags        []string `validate:"omitempty,max=20,dive,max=50"`
}

// UpdateAsset updates an existing asset.
// Security: Requires tenantID to prevent cross-tenant data modification.
func (s *AssetService) UpdateAsset(ctx context.Context, assetID string, tenantID string, input UpdateAssetInput) (*asset.Asset, error) {
	parsedTenantID, err := shared.IDFromString(tenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant id format", shared.ErrValidation)
	}

	parsedID, err := shared.IDFromString(assetID)
	if err != nil {
		return nil, shared.ErrNotFound
	}

	// GetByID with tenantID automatically enforces tenant isolation
	a, err := s.repo.GetByID(ctx, parsedTenantID, parsedID)
	if err != nil {
		return nil, err
	}

	if input.Name != nil {
		if err := a.UpdateName(*input.Name); err != nil {
			return nil, err
		}
	}

	if input.Criticality != nil {
		criticality, err := asset.ParseCriticality(*input.Criticality)
		if err != nil {
			return nil, fmt.Errorf("%w: %w", shared.ErrValidation, err)
		}
		if err := a.UpdateCriticality(criticality); err != nil {
			return nil, err
		}
	}

	if input.Scope != nil {
		scope, err := asset.ParseScope(*input.Scope)
		if err != nil {
			return nil, fmt.Errorf("%w: %w", shared.ErrValidation, err)
		}
		if err := a.UpdateScope(scope); err != nil {
			return nil, err
		}
	}

	if input.Exposure != nil {
		exposure, err := asset.ParseExposure(*input.Exposure)
		if err != nil {
			return nil, fmt.Errorf("%w: %w", shared.ErrValidation, err)
		}
		if err := a.UpdateExposure(exposure); err != nil {
			return nil, err
		}
	}

	if input.Description != nil {
		a.UpdateDescription(*input.Description)
	}

	if input.Tags != nil {
		for _, tag := range a.Tags() {
			a.RemoveTag(tag)
		}
		for _, tag := range input.Tags {
			a.AddTag(tag)
		}
	}

	// Recalculate risk score after updates
	a.CalculateRiskScore()

	if err := s.repo.Update(ctx, a); err != nil {
		return nil, fmt.Errorf("failed to update asset: %w", err)
	}

	// Recalculate affected group stats (risk_score, finding_count, etc.)
	s.recalculateAffectedGroups(ctx, parsedID)

	s.logger.Info("asset updated", "id", a.ID().String())
	return a, nil
}

// DeleteAsset deletes an asset by ID.
// Security: Requires tenantID to prevent cross-tenant deletion.
func (s *AssetService) DeleteAsset(ctx context.Context, assetID string, tenantID string) error {
	parsedTenantID, err := shared.IDFromString(tenantID)
	if err != nil {
		return fmt.Errorf("%w: invalid tenant id format", shared.ErrValidation)
	}

	parsedID, err := shared.IDFromString(assetID)
	if err != nil {
		return shared.ErrNotFound
	}

	// Get groups containing this asset BEFORE deletion
	var groupIDs []shared.ID
	if s.assetGroupRepo != nil {
		groupIDs, _ = s.assetGroupRepo.GetGroupIDsByAssetID(ctx, parsedID)
	}

	// Delete with tenantID automatically enforces tenant isolation
	if err := s.repo.Delete(ctx, parsedTenantID, parsedID); err != nil {
		return err
	}

	// Recalculate affected group stats after deletion
	for _, groupID := range groupIDs {
		if err := s.assetGroupRepo.RecalculateCounts(ctx, groupID); err != nil {
			s.logger.Warn("failed to recalculate group stats after asset deletion",
				"assetID", assetID, "groupID", groupID, "error", err)
		}
	}

	s.logger.Info("asset deleted", "id", assetID)
	return nil
}

// recalculateAffectedGroups recalculates stats for groups containing the asset.
func (s *AssetService) recalculateAffectedGroups(ctx context.Context, assetID shared.ID) {
	if s.assetGroupRepo == nil {
		return
	}

	groupIDs, err := s.assetGroupRepo.GetGroupIDsByAssetID(ctx, assetID)
	if err != nil {
		s.logger.Warn("failed to get groups for asset", "assetID", assetID, "error", err)
		return
	}

	for _, groupID := range groupIDs {
		if err := s.assetGroupRepo.RecalculateCounts(ctx, groupID); err != nil {
			s.logger.Warn("failed to recalculate group stats",
				"assetID", assetID, "groupID", groupID, "error", err)
		}
	}
}

// ListAssetsInput represents the input for listing assets.
type ListAssetsInput struct {
	TenantID      string   `validate:"omitempty,uuid"`
	Name          string   `validate:"max=255"`
	Types         []string `validate:"max=20,dive,asset_type"`
	Criticalities []string `validate:"max=5,dive,criticality"`
	Statuses      []string `validate:"max=3,dive,status"`
	Scopes        []string `validate:"max=6,dive,scope"`
	Exposures     []string `validate:"max=5,dive,exposure"`
	Tags          []string `validate:"max=20,dive,max=50"`
	Search        string   `validate:"max=255"` // Full-text search across name and description
	MinRiskScore  *int     `validate:"omitempty,min=0,max=100"`
	MaxRiskScore  *int     `validate:"omitempty,min=0,max=100"`
	HasFindings   *bool    // Filter by whether asset has findings
	Sort          string   `validate:"max=100"` // Sort field (e.g., "-created_at", "name")
	Page          int      `validate:"min=0"`
	PerPage       int      `validate:"min=0,max=100"`
}

// ListAssets retrieves assets with filtering, sorting, and pagination.
func (s *AssetService) ListAssets(ctx context.Context, input ListAssetsInput) (pagination.Result[*asset.Asset], error) {
	filter := asset.NewFilter()

	// Tenant filter
	if input.TenantID != "" {
		filter = filter.WithTenantID(input.TenantID)
	}

	// Name filter
	if input.Name != "" {
		filter = filter.WithName(input.Name)
	}

	// Asset types filter
	if len(input.Types) > 0 {
		types := make([]asset.AssetType, 0, len(input.Types))
		for _, t := range input.Types {
			if parsed, err := asset.ParseAssetType(t); err == nil {
				types = append(types, parsed)
			}
		}
		filter = filter.WithTypes(types...)
	}

	// Criticalities filter
	if len(input.Criticalities) > 0 {
		criticalities := make([]asset.Criticality, 0, len(input.Criticalities))
		for _, c := range input.Criticalities {
			if parsed, err := asset.ParseCriticality(c); err == nil {
				criticalities = append(criticalities, parsed)
			}
		}
		filter = filter.WithCriticalities(criticalities...)
	}

	// Statuses filter
	if len(input.Statuses) > 0 {
		statuses := make([]asset.Status, 0, len(input.Statuses))
		for _, st := range input.Statuses {
			if parsed, err := asset.ParseStatus(st); err == nil {
				statuses = append(statuses, parsed)
			}
		}
		filter = filter.WithStatuses(statuses...)
	}

	// Scopes filter
	if len(input.Scopes) > 0 {
		scopes := make([]asset.Scope, 0, len(input.Scopes))
		for _, sc := range input.Scopes {
			if parsed, err := asset.ParseScope(sc); err == nil {
				scopes = append(scopes, parsed)
			}
		}
		filter = filter.WithScopes(scopes...)
	}

	// Exposures filter
	if len(input.Exposures) > 0 {
		exposures := make([]asset.Exposure, 0, len(input.Exposures))
		for _, ex := range input.Exposures {
			if parsed, err := asset.ParseExposure(ex); err == nil {
				exposures = append(exposures, parsed)
			}
		}
		filter = filter.WithExposures(exposures...)
	}

	// Tags filter
	if len(input.Tags) > 0 {
		filter = filter.WithTags(input.Tags...)
	}

	// Search filter
	if input.Search != "" {
		filter = filter.WithSearch(input.Search)
	}

	// Risk score filters
	if input.MinRiskScore != nil {
		filter = filter.WithMinRiskScore(*input.MinRiskScore)
	}
	if input.MaxRiskScore != nil {
		filter = filter.WithMaxRiskScore(*input.MaxRiskScore)
	}

	// Has findings filter
	if input.HasFindings != nil {
		filter = filter.WithHasFindings(*input.HasFindings)
	}

	// Build list options with sorting
	opts := asset.NewListOptions()
	if input.Sort != "" {
		sortOpt := pagination.NewSortOption(asset.AllowedSortFields()).Parse(input.Sort)
		opts = opts.WithSort(sortOpt)
	}

	page := pagination.New(input.Page, input.PerPage)
	return s.repo.List(ctx, filter, opts, page)
}

// ActivateAsset activates an asset.
// Security: Requires tenantID to prevent cross-tenant activation.
func (s *AssetService) ActivateAsset(ctx context.Context, tenantID, assetID string) (*asset.Asset, error) {
	parsedTenantID, err := shared.IDFromString(tenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant id format", shared.ErrValidation)
	}

	parsedID, err := shared.IDFromString(assetID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid id format", shared.ErrValidation)
	}

	a, err := s.repo.GetByID(ctx, parsedTenantID, parsedID)
	if err != nil {
		return nil, err
	}

	a.Activate()

	if err := s.repo.Update(ctx, a); err != nil {
		return nil, fmt.Errorf("failed to activate asset: %w", err)
	}

	s.logger.Info("asset activated", "id", assetID)
	return a, nil
}

// DeactivateAsset deactivates an asset.
// Security: Requires tenantID to prevent cross-tenant deactivation.
func (s *AssetService) DeactivateAsset(ctx context.Context, tenantID, assetID string) (*asset.Asset, error) {
	parsedTenantID, err := shared.IDFromString(tenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant id format", shared.ErrValidation)
	}

	parsedID, err := shared.IDFromString(assetID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid id format", shared.ErrValidation)
	}

	a, err := s.repo.GetByID(ctx, parsedTenantID, parsedID)
	if err != nil {
		return nil, err
	}

	a.Deactivate()

	if err := s.repo.Update(ctx, a); err != nil {
		return nil, fmt.Errorf("failed to deactivate asset: %w", err)
	}

	s.logger.Info("asset deactivated", "id", assetID)
	return a, nil
}

// ArchiveAsset archives an asset.
// Security: Requires tenantID to prevent cross-tenant archival.
func (s *AssetService) ArchiveAsset(ctx context.Context, tenantID, assetID string) (*asset.Asset, error) {
	parsedTenantID, err := shared.IDFromString(tenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant id format", shared.ErrValidation)
	}

	parsedID, err := shared.IDFromString(assetID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid id format", shared.ErrValidation)
	}

	a, err := s.repo.GetByID(ctx, parsedTenantID, parsedID)
	if err != nil {
		return nil, err
	}

	a.Archive()

	if err := s.repo.Update(ctx, a); err != nil {
		return nil, fmt.Errorf("failed to archive asset: %w", err)
	}

	s.logger.Info("asset archived", "id", assetID)
	return a, nil
}

// BulkUpdateAssetStatusInput represents input for bulk asset status update.
type BulkUpdateAssetStatusInput struct {
	AssetIDs []string
	Status   string // "active", "inactive", "archived"
}

// BulkAssetStatusResult represents the result of a bulk asset status operation.
type BulkAssetStatusResult struct {
	Updated int      `json:"updated"`
	Failed  int      `json:"failed"`
	Errors  []string `json:"errors,omitempty"`
}

// BulkUpdateAssetStatus updates the status of multiple assets.
// Security: Requires tenantID to prevent cross-tenant status changes.
// OPTIMIZED: Reduces N API calls to a single batch operation.
func (s *AssetService) BulkUpdateAssetStatus(ctx context.Context, tenantID string, input BulkUpdateAssetStatusInput) (*BulkAssetStatusResult, error) {
	parsedTenantID, err := shared.IDFromString(tenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant id format", shared.ErrValidation)
	}

	if len(input.AssetIDs) == 0 {
		return &BulkAssetStatusResult{}, nil
	}

	// Validate status
	status := input.Status
	if status != "active" && status != "inactive" && status != "archived" {
		return nil, fmt.Errorf("%w: invalid status '%s', must be one of: active, inactive, archived", shared.ErrValidation, status)
	}

	result := &BulkAssetStatusResult{}

	for _, idStr := range input.AssetIDs {
		parsedID, err := shared.IDFromString(idStr)
		if err != nil {
			result.Failed++
			result.Errors = append(result.Errors, fmt.Sprintf("%s: invalid id format", idStr))
			continue
		}

		// GetByID with tenantID automatically enforces tenant isolation
		a, err := s.repo.GetByID(ctx, parsedTenantID, parsedID)
		if err != nil {
			result.Failed++
			result.Errors = append(result.Errors, fmt.Sprintf("%s: %v", idStr, err))
			continue
		}

		// Apply status change
		switch status {
		case "active":
			a.Activate()
		case "inactive":
			a.Deactivate()
		case "archived":
			a.Archive()
		}

		if err := s.repo.Update(ctx, a); err != nil {
			result.Failed++
			result.Errors = append(result.Errors, fmt.Sprintf("%s: %v", idStr, err))
			continue
		}

		result.Updated++
	}

	s.logger.Info("bulk asset status update completed",
		"status", status,
		"updated", result.Updated,
		"failed", result.Failed)

	return result, nil
}

// CreateRepositoryAssetInput represents the input for creating a repository asset.
type CreateRepositoryAssetInput struct {
	// Basic info
	TenantID       string   `validate:"omitempty,uuid"`
	Name           string   `validate:"required,min=1,max=255"`
	Description    string   `validate:"max=1000"`
	Criticality    string   `validate:"required,criticality"`
	Scope          string   `validate:"omitempty,scope"`
	Exposure       string   `validate:"omitempty,exposure"`
	Tags           []string `validate:"max=20,dive,max=50"`
	Provider       string   `validate:"omitempty"`
	ExternalID     string   `validate:"omitempty,max=255"`
	Classification string   `validate:"omitempty"`
	// Repository extension fields
	RepoID          string           `validate:"omitempty,max=255"`
	FullName        string           `validate:"required,max=500"`
	SCMOrganization string           `validate:"omitempty,max=255"`
	CloneURL        string           `validate:"omitempty,url"`
	WebURL          string           `validate:"omitempty,url"`
	SSHURL          string           `validate:"omitempty,max=500"`
	DefaultBranch   string           `validate:"omitempty,max=100"`
	Visibility      string           `validate:"omitempty"`
	Language        string           `validate:"omitempty,max=50"`
	Languages       map[string]int64 `validate:"omitempty"`
	Topics          []string         `validate:"max=50,dive,max=100"`
	// Stats
	Stars      int `validate:"min=0"`
	Forks      int `validate:"min=0"`
	Watchers   int `validate:"min=0"`
	OpenIssues int `validate:"min=0"`
	SizeKB     int `validate:"min=0"`
	// Scan settings
	ScanEnabled  bool   `validate:"omitempty"`
	ScanSchedule string `validate:"omitempty,max=100"`
	// Timestamps from SCM (ISO 8601 format)
	RepoCreatedAt string `validate:"omitempty"`
	RepoUpdatedAt string `validate:"omitempty"`
	RepoPushedAt  string `validate:"omitempty"`
}

// CreateRepositoryAsset creates a new repository asset with its extension.
// If an existing asset matches (by name or fullName), it will be updated with SCM data.
func (s *AssetService) CreateRepositoryAsset(ctx context.Context, input CreateRepositoryAssetInput) (*asset.Asset, *asset.RepositoryExtension, error) {
	if s.repoExtRepo == nil {
		return nil, nil, fmt.Errorf("%w: repository extension repository not configured", shared.ErrInternal)
	}

	s.logger.Info("creating repository asset", "name", input.Name, "fullName", input.FullName)

	criticality, err := asset.ParseCriticality(input.Criticality)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %w", shared.ErrValidation, err)
	}

	// Parse tenant ID early for searching
	var tenantID shared.ID
	if input.TenantID != "" {
		tenantID, err = shared.IDFromString(input.TenantID)
		if err != nil {
			return nil, nil, fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
		}
	}

	// Try to find existing asset that matches this repository
	// This handles the case where an agent created the asset first
	existingAsset := s.findMatchingRepositoryAsset(ctx, tenantID, input)
	if existingAsset != nil {
		s.logger.Info("found existing asset, updating with SCM data",
			"asset_id", existingAsset.ID().String(),
			"existing_name", existingAsset.Name(),
			"new_fullName", input.FullName,
		)
		return s.updateExistingRepositoryAsset(ctx, existingAsset, input, criticality)
	}

	// Check if asset with same name exists (strict check for new assets)
	exists, err := s.repo.ExistsByName(ctx, tenantID, input.Name)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to check asset existence: %w", err)
	}
	if exists {
		return nil, nil, asset.AlreadyExistsError(input.Name)
	}

	// Create the base asset with Repository type
	a, err := asset.NewAsset(input.Name, asset.AssetTypeRepository, criticality)
	if err != nil {
		return nil, nil, err
	}

	// Set tenant ID if provided (already parsed above)
	if !tenantID.IsZero() {
		a.SetTenantID(tenantID)
	}

	// Set scope if provided
	if input.Scope != "" {
		scope, err := asset.ParseScope(input.Scope)
		if err != nil {
			return nil, nil, fmt.Errorf("%w: %w", shared.ErrValidation, err)
		}
		_ = a.UpdateScope(scope)
	}

	// Set exposure if provided
	if input.Exposure != "" {
		exposure, err := asset.ParseExposure(input.Exposure)
		if err != nil {
			return nil, nil, fmt.Errorf("%w: %w", shared.ErrValidation, err)
		}
		_ = a.UpdateExposure(exposure)
	}

	if input.Description != "" {
		a.UpdateDescription(input.Description)
	}
	for _, tag := range input.Tags {
		a.AddTag(tag)
	}

	// Set provider info if provided
	if input.Provider != "" {
		provider := asset.ParseProvider(input.Provider)
		a.SetProvider(provider)
		if input.ExternalID != "" {
			a.SetExternalID(input.ExternalID)
		}
	}

	// Set classification if provided
	if input.Classification != "" {
		classification := asset.ParseClassification(input.Classification)
		a.SetClassification(classification)
	}

	// Calculate initial risk score
	a.CalculateRiskScore()

	// Create the asset first
	if err := s.repo.Create(ctx, a); err != nil {
		return nil, nil, fmt.Errorf("failed to create asset: %w", err)
	}

	// Parse visibility
	visibility := asset.RepoVisibilityPrivate
	if input.Visibility != "" {
		visibility = asset.ParseRepoVisibility(input.Visibility)
	}

	// Create the repository extension
	repoExt, err := asset.NewRepositoryExtension(a.ID(), input.FullName, visibility)
	if err != nil {
		// Rollback: delete the asset if extension creation fails
		if deleteErr := s.repo.Delete(ctx, tenantID, a.ID()); deleteErr != nil {
			s.logger.Error("rollback delete failed after extension creation error", "assetID", a.ID(), "error", deleteErr)
		}
		return nil, nil, fmt.Errorf("failed to create repository extension: %w", err)
	}

	// Apply optional repository extension fields
	applyRepoExtensionFields(repoExt, input)

	if err := s.repoExtRepo.Create(ctx, repoExt); err != nil {
		// Rollback: delete the asset if extension creation fails
		if deleteErr := s.repo.Delete(ctx, tenantID, a.ID()); deleteErr != nil {
			s.logger.Error("rollback delete failed after repo extension save error", "assetID", a.ID(), "error", deleteErr)
		}
		return nil, nil, fmt.Errorf("failed to create repository extension: %w", err)
	}

	s.logger.Info("repository asset created", "id", a.ID().String(), "name", a.Name(), "fullName", input.FullName)
	return a, repoExt, nil
}

// applyRepoExtensionFields applies optional fields to a repository extension.
func applyRepoExtensionFields(repoExt *asset.RepositoryExtension, input CreateRepositoryAssetInput) {
	if input.RepoID != "" {
		repoExt.SetRepoID(input.RepoID)
	}
	if input.SCMOrganization != "" {
		repoExt.SetSCMOrganization(input.SCMOrganization)
	}
	if input.CloneURL != "" {
		repoExt.SetCloneURL(input.CloneURL)
	}
	if input.WebURL != "" {
		repoExt.SetWebURL(input.WebURL)
	}
	if input.SSHURL != "" {
		repoExt.SetSSHURL(input.SSHURL)
	}
	if input.DefaultBranch != "" {
		repoExt.SetDefaultBranch(input.DefaultBranch)
	}
	if input.Language != "" {
		repoExt.SetLanguage(input.Language)
	}
	if input.Languages != nil {
		repoExt.SetLanguages(input.Languages)
	}
	if len(input.Topics) > 0 {
		repoExt.SetTopics(input.Topics)
	}

	// Stats
	repoExt.UpdateStats(input.Stars, input.Forks, input.Watchers, input.OpenIssues, 0, input.SizeKB)

	// Scan settings
	if input.ScanEnabled {
		repoExt.EnableScan(input.ScanSchedule)
	} else {
		repoExt.DisableScan()
	}

	// Timestamps from SCM
	var repoCreatedAt, repoUpdatedAt, repoPushedAt *time.Time
	if input.RepoCreatedAt != "" {
		if t, err := time.Parse(time.RFC3339, input.RepoCreatedAt); err == nil {
			repoCreatedAt = &t
		}
	}
	if input.RepoUpdatedAt != "" {
		if t, err := time.Parse(time.RFC3339, input.RepoUpdatedAt); err == nil {
			repoUpdatedAt = &t
		}
	}
	if input.RepoPushedAt != "" {
		if t, err := time.Parse(time.RFC3339, input.RepoPushedAt); err == nil {
			repoPushedAt = &t
		}
	}
	if repoCreatedAt != nil || repoUpdatedAt != nil || repoPushedAt != nil {
		repoExt.UpdateRepoTimestamps(repoCreatedAt, repoUpdatedAt, repoPushedAt)
	}
}

// GetRepositoryExtension retrieves the repository extension for an asset.
// Security: Requires tenantID to prevent cross-tenant data access.
func (s *AssetService) GetRepositoryExtension(ctx context.Context, tenantID, assetID string) (*asset.RepositoryExtension, error) {
	if s.repoExtRepo == nil {
		return nil, fmt.Errorf("%w: repository extension repository not configured", shared.ErrInternal)
	}

	parsedTenantID, err := shared.IDFromString(tenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant id format", shared.ErrValidation)
	}

	parsedID, err := shared.IDFromString(assetID)
	if err != nil {
		return nil, shared.ErrNotFound
	}

	// Verify asset exists and is a repository type
	a, err := s.repo.GetByID(ctx, parsedTenantID, parsedID)
	if err != nil {
		return nil, err
	}
	if a.Type() != asset.AssetTypeRepository {
		return nil, shared.ErrNotFound
	}

	return s.repoExtRepo.GetByAssetID(ctx, parsedID)
}

// GetAssetWithRepository retrieves an asset with its repository extension.
// Security: Requires tenantID to prevent cross-tenant data access.
func (s *AssetService) GetAssetWithRepository(ctx context.Context, tenantID, assetID string) (*asset.Asset, *asset.RepositoryExtension, error) {
	parsedTenantID, err := shared.IDFromString(tenantID)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: invalid tenant id format", shared.ErrValidation)
	}

	parsedID, err := shared.IDFromString(assetID)
	if err != nil {
		// Return NotFound instead of Validation error - from user's perspective, resource doesn't exist
		return nil, nil, shared.ErrNotFound
	}

	a, err := s.repo.GetByID(ctx, parsedTenantID, parsedID)
	if err != nil {
		return nil, nil, err
	}

	// Only fetch extension if it's a repository asset
	if a.Type() != asset.AssetTypeRepository || s.repoExtRepo == nil {
		return a, nil, nil
	}

	repoExt, err := s.repoExtRepo.GetByAssetID(ctx, parsedID)
	if err != nil {
		// Only swallow "not found" errors - extension might not exist yet
		// Propagate other database errors
		if errors.Is(err, shared.ErrNotFound) {
			return a, nil, nil
		}
		s.logger.Error("database error getting repository extension", "assetID", assetID, "error", err)
		return nil, nil, fmt.Errorf("failed to get repository extension: %w", err)
	}

	return a, repoExt, nil
}

// UpdateRepositoryExtensionInput represents the input for updating a repository extension.
type UpdateRepositoryExtensionInput struct {
	RepoID               *string          `validate:"omitempty,max=255"`
	FullName             *string          `validate:"omitempty,max=500"`
	SCMOrganization      *string          `validate:"omitempty,max=255"`
	CloneURL             *string          `validate:"omitempty,url"`
	WebURL               *string          `validate:"omitempty,url"`
	SSHURL               *string          `validate:"omitempty,max=500"`
	DefaultBranch        *string          `validate:"omitempty,max=100"`
	Visibility           *string          `validate:"omitempty"`
	Language             *string          `validate:"omitempty,max=50"`
	Languages            map[string]int64 `validate:"omitempty"`
	Topics               []string         `validate:"omitempty,max=50,dive,max=100"`
	Stars                *int             `validate:"omitempty,min=0"`
	Forks                *int             `validate:"omitempty,min=0"`
	Watchers             *int             `validate:"omitempty,min=0"`
	OpenIssues           *int             `validate:"omitempty,min=0"`
	ContributorsCount    *int             `validate:"omitempty,min=0"`
	SizeKB               *int             `validate:"omitempty,min=0"`
	BranchCount          *int             `validate:"omitempty,min=0"`
	ProtectedBranchCount *int             `validate:"omitempty,min=0"`
	ComponentCount       *int             `validate:"omitempty,min=0"`
}

// UpdateRepositoryExtension updates the repository extension for an asset.
// Security: Requires tenantID to prevent cross-tenant data modification.
func (s *AssetService) UpdateRepositoryExtension(ctx context.Context, tenantID, assetID string, input UpdateRepositoryExtensionInput) (*asset.RepositoryExtension, error) {
	if s.repoExtRepo == nil {
		return nil, fmt.Errorf("%w: repository extension repository not configured", shared.ErrInternal)
	}

	parsedTenantID, err := shared.IDFromString(tenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant id format", shared.ErrValidation)
	}

	parsedID, err := shared.IDFromString(assetID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid id format", shared.ErrValidation)
	}

	// Verify asset exists and is a repository type
	a, err := s.repo.GetByID(ctx, parsedTenantID, parsedID)
	if err != nil {
		return nil, err
	}
	if a.Type() != asset.AssetTypeRepository {
		return nil, shared.ErrNotFound
	}

	repoExt, err := s.repoExtRepo.GetByAssetID(ctx, parsedID)
	if err != nil {
		return nil, err
	}

	// Apply updates
	if input.RepoID != nil {
		repoExt.SetRepoID(*input.RepoID)
	}
	if input.FullName != nil {
		repoExt.SetFullName(*input.FullName)
	}
	if input.SCMOrganization != nil {
		repoExt.SetSCMOrganization(*input.SCMOrganization)
	}
	if input.CloneURL != nil {
		repoExt.SetCloneURL(*input.CloneURL)
	}
	if input.WebURL != nil {
		repoExt.SetWebURL(*input.WebURL)
	}
	if input.SSHURL != nil {
		repoExt.SetSSHURL(*input.SSHURL)
	}
	if input.DefaultBranch != nil {
		repoExt.SetDefaultBranch(*input.DefaultBranch)
	}
	if input.Visibility != nil {
		repoExt.SetVisibility(asset.ParseRepoVisibility(*input.Visibility))
	}
	if input.Language != nil {
		repoExt.SetLanguage(*input.Language)
	}
	if input.Languages != nil {
		repoExt.SetLanguages(input.Languages)
	}
	if input.Topics != nil {
		repoExt.SetTopics(input.Topics)
	}
	if input.Stars != nil {
		repoExt.SetStars(*input.Stars)
	}
	if input.Forks != nil {
		repoExt.SetForks(*input.Forks)
	}
	if input.Watchers != nil {
		repoExt.SetWatchers(*input.Watchers)
	}
	if input.OpenIssues != nil {
		repoExt.SetOpenIssues(*input.OpenIssues)
	}
	if input.ContributorsCount != nil {
		repoExt.SetContributorsCount(*input.ContributorsCount)
	}
	if input.SizeKB != nil {
		repoExt.SetSizeKB(*input.SizeKB)
	}
	if input.BranchCount != nil {
		repoExt.SetBranchCount(*input.BranchCount)
	}
	if input.ProtectedBranchCount != nil {
		repoExt.SetProtectedBranchCount(*input.ProtectedBranchCount)
	}
	if input.ComponentCount != nil {
		repoExt.SetComponentCount(*input.ComponentCount)
	}

	if err := s.repoExtRepo.Update(ctx, repoExt); err != nil {
		return nil, fmt.Errorf("failed to update repository extension: %w", err)
	}

	s.logger.Info("repository extension updated", "assetID", assetID)
	return repoExt, nil
}

// GetAssetByExternalID retrieves an asset by provider and external ID.
func (s *AssetService) GetAssetByExternalID(ctx context.Context, tenantID, provider, externalID string) (*asset.Asset, error) {
	parsedTenantID, err := shared.IDFromString(tenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant id format", shared.ErrValidation)
	}

	parsedProvider := asset.ParseProvider(provider)
	return s.repo.GetByExternalID(ctx, parsedTenantID, parsedProvider, externalID)
}

// MarkAssetSyncing marks an asset as currently syncing.
// Security: Requires tenantID to prevent cross-tenant status modification.
func (s *AssetService) MarkAssetSyncing(ctx context.Context, tenantID, assetID string) (*asset.Asset, error) {
	parsedTenantID, err := shared.IDFromString(tenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant id format", shared.ErrValidation)
	}

	parsedID, err := shared.IDFromString(assetID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid id format", shared.ErrValidation)
	}

	a, err := s.repo.GetByID(ctx, parsedTenantID, parsedID)
	if err != nil {
		return nil, err
	}

	a.MarkSyncing()

	if err := s.repo.Update(ctx, a); err != nil {
		return nil, fmt.Errorf("failed to update asset sync status: %w", err)
	}

	s.logger.Info("asset marked as syncing", "id", assetID)
	return a, nil
}

// MarkAssetSynced marks an asset as successfully synced.
// Security: Requires tenantID to prevent cross-tenant status modification.
func (s *AssetService) MarkAssetSynced(ctx context.Context, tenantID, assetID string) (*asset.Asset, error) {
	parsedTenantID, err := shared.IDFromString(tenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant id format", shared.ErrValidation)
	}

	parsedID, err := shared.IDFromString(assetID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid id format", shared.ErrValidation)
	}

	a, err := s.repo.GetByID(ctx, parsedTenantID, parsedID)
	if err != nil {
		return nil, err
	}

	a.MarkSynced()

	if err := s.repo.Update(ctx, a); err != nil {
		return nil, fmt.Errorf("failed to update asset sync status: %w", err)
	}

	s.logger.Info("asset marked as synced", "id", assetID)
	return a, nil
}

// MarkAssetSyncFailed marks an asset sync as failed with an error message.
// Security: Requires tenantID to prevent cross-tenant status modification.
func (s *AssetService) MarkAssetSyncFailed(ctx context.Context, tenantID, assetID string, syncError string) (*asset.Asset, error) {
	parsedTenantID, err := shared.IDFromString(tenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant id format", shared.ErrValidation)
	}

	parsedID, err := shared.IDFromString(assetID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid id format", shared.ErrValidation)
	}

	a, err := s.repo.GetByID(ctx, parsedTenantID, parsedID)
	if err != nil {
		return nil, err
	}

	a.MarkSyncError(syncError)

	if err := s.repo.Update(ctx, a); err != nil {
		return nil, fmt.Errorf("failed to update asset sync status: %w", err)
	}

	s.logger.Info("asset sync marked as failed", "id", assetID, "error", syncError)
	return a, nil
}

// UpdateFindingCount updates the finding count for an asset.
// Security: Requires tenantID to prevent cross-tenant data modification.
func (s *AssetService) UpdateFindingCount(ctx context.Context, tenantID, assetID string, count int) error {
	parsedTenantID, err := shared.IDFromString(tenantID)
	if err != nil {
		return fmt.Errorf("%w: invalid tenant id format", shared.ErrValidation)
	}

	parsedID, err := shared.IDFromString(assetID)
	if err != nil {
		return fmt.Errorf("%w: invalid id format", shared.ErrValidation)
	}

	a, err := s.repo.GetByID(ctx, parsedTenantID, parsedID)
	if err != nil {
		return err
	}

	a.UpdateFindingCount(count)
	a.CalculateRiskScore()

	if err := s.repo.Update(ctx, a); err != nil {
		return fmt.Errorf("failed to update asset finding count: %w", err)
	}

	s.logger.Info("asset finding count updated", "id", assetID, "count", count)
	return nil
}

// UpdateRepositoryFindingCount updates the finding count for a repository extension.
func (s *AssetService) UpdateRepositoryFindingCount(ctx context.Context, assetID string, count int) error {
	if s.repoExtRepo == nil {
		return fmt.Errorf("%w: repository extension repository not configured", shared.ErrInternal)
	}

	parsedID, err := shared.IDFromString(assetID)
	if err != nil {
		return fmt.Errorf("%w: invalid id format", shared.ErrValidation)
	}

	repoExt, err := s.repoExtRepo.GetByAssetID(ctx, parsedID)
	if err != nil {
		return err
	}

	repoExt.SetFindingCount(count)
	repoExt.CalculateRiskScore()

	if err := s.repoExtRepo.Update(ctx, repoExt); err != nil {
		return fmt.Errorf("failed to update repository finding count: %w", err)
	}

	s.logger.Info("repository finding count updated", "assetID", assetID, "count", count)
	return nil
}

// EnableRepositoryScan enables scanning for a repository asset.
func (s *AssetService) EnableRepositoryScan(ctx context.Context, assetID string, schedule string) error {
	if s.repoExtRepo == nil {
		return fmt.Errorf("%w: repository extension repository not configured", shared.ErrInternal)
	}

	parsedID, err := shared.IDFromString(assetID)
	if err != nil {
		return fmt.Errorf("%w: invalid id format", shared.ErrValidation)
	}

	repoExt, err := s.repoExtRepo.GetByAssetID(ctx, parsedID)
	if err != nil {
		return err
	}

	repoExt.EnableScan(schedule)

	if err := s.repoExtRepo.Update(ctx, repoExt); err != nil {
		return fmt.Errorf("failed to enable repository scan: %w", err)
	}

	s.logger.Info("repository scan enabled", "assetID", assetID, "schedule", schedule)
	return nil
}

// DisableRepositoryScan disables scanning for a repository asset.
func (s *AssetService) DisableRepositoryScan(ctx context.Context, assetID string) error {
	if s.repoExtRepo == nil {
		return fmt.Errorf("%w: repository extension repository not configured", shared.ErrInternal)
	}

	parsedID, err := shared.IDFromString(assetID)
	if err != nil {
		return fmt.Errorf("%w: invalid id format", shared.ErrValidation)
	}

	repoExt, err := s.repoExtRepo.GetByAssetID(ctx, parsedID)
	if err != nil {
		return err
	}

	repoExt.DisableScan()

	if err := s.repoExtRepo.Update(ctx, repoExt); err != nil {
		return fmt.Errorf("failed to disable repository scan: %w", err)
	}

	s.logger.Info("repository scan disabled", "assetID", assetID)
	return nil
}

// RecordRepositoryScan records a scan completion for a repository.
func (s *AssetService) RecordRepositoryScan(ctx context.Context, assetID string) error {
	if s.repoExtRepo == nil {
		return fmt.Errorf("%w: repository extension repository not configured", shared.ErrInternal)
	}

	parsedID, err := shared.IDFromString(assetID)
	if err != nil {
		return fmt.Errorf("%w: invalid id format", shared.ErrValidation)
	}

	repoExt, err := s.repoExtRepo.GetByAssetID(ctx, parsedID)
	if err != nil {
		return err
	}

	repoExt.RecordScan()

	if err := s.repoExtRepo.Update(ctx, repoExt); err != nil {
		return fmt.Errorf("failed to record repository scan: %w", err)
	}

	s.logger.Info("repository scan recorded", "assetID", assetID)
	return nil
}

// findMatchingRepositoryAsset tries to find an existing asset that matches the repository.
// This handles cases where an agent created an asset before SCM sync.
func (s *AssetService) findMatchingRepositoryAsset(ctx context.Context, tenantID shared.ID, input CreateRepositoryAssetInput) *asset.Asset {
	// Extract repo name from FullName (e.g., "sdk" from "openctemio/sdk")
	repoName := input.Name
	if input.FullName != "" {
		parts := strings.Split(input.FullName, "/")
		repoName = parts[len(parts)-1]
	}

	// Parse provider
	provider := asset.ProviderManual
	if input.Provider != "" {
		provider = asset.ParseProvider(input.Provider)
	}

	// 1. Try to find by external_id matching FullName (e.g., "openctemio/sdk")
	if input.FullName != "" && !tenantID.IsZero() {
		existing, err := s.repo.GetByExternalID(ctx, tenantID, provider, input.FullName)
		if err == nil && existing != nil {
			return existing
		}
	}

	// 2. Try to find by name matching the repo name
	// This handles agent-created assets with names like "github.com/openctemio/sdk-go"
	if !tenantID.IsZero() {
		existing, err := s.repo.GetByName(ctx, tenantID, repoName)
		if err == nil && existing != nil && existing.Type() == asset.AssetTypeRepository {
			return existing
		}
	}

	// 3. Try to find by exact name match
	if !tenantID.IsZero() {
		existing, err := s.repo.GetByName(ctx, tenantID, input.Name)
		if err == nil && existing != nil && existing.Type() == asset.AssetTypeRepository {
			return existing
		}
	}

	// 4. Try to find by external_id containing the repo name
	// This handles agent-created assets with external_id like "openctemio/openctemio/sdk"
	if input.FullName != "" && !tenantID.IsZero() {
		existing, err := s.repo.GetByExternalID(ctx, tenantID, provider, repoName)
		if err == nil && existing != nil {
			return existing
		}
	}

	// 5. Try to find repository asset by full name (org/repo pattern) - MORE PRECISE
	// This handles agent-created assets like "github.com-xxx/openctemio/sdk"
	// matching FullName "openctemio/sdk"
	if input.FullName != "" && !tenantID.IsZero() {
		existing, err := s.repo.FindRepositoryByFullName(ctx, tenantID, input.FullName)
		if err == nil && existing != nil {
			s.logger.Debug("found existing asset by full name pattern",
				"asset_id", existing.ID().String(),
				"existing_name", existing.Name(),
				"full_name", input.FullName,
			)
			return existing
		}
	}

	// 6. Try to find repository asset whose name ends with the repo name - LESS PRECISE
	// This is a fallback and may match incorrectly if there are multiple repos with same name
	// Only use this if no other match was found
	// NOTE: This could match github.com/a/repo with github.com/b/repo incorrectly!
	// if repoName != "" && !tenantID.IsZero() {
	// 	existing, err := s.repo.FindRepositoryByRepoName(ctx, tenantID, repoName)
	// 	if err == nil && existing != nil {
	// 		s.logger.Debug("found existing asset by repo name suffix",
	// 			"asset_id", existing.ID().String(),
	// 			"existing_name", existing.Name(),
	// 			"repo_name", repoName,
	// 		)
	// 		return existing
	// 	}
	// }

	return nil
}

// updateExistingRepositoryAsset updates an existing asset with new SCM data.
func (s *AssetService) updateExistingRepositoryAsset(
	ctx context.Context,
	existingAsset *asset.Asset,
	input CreateRepositoryAssetInput,
	criticality asset.Criticality,
) (*asset.Asset, *asset.RepositoryExtension, error) {
	// Update asset fields with SCM data
	// Only update name if the existing name looks like an agent-generated name
	existingName := existingAsset.Name()
	if strings.Contains(existingName, "github.com-") ||
		strings.Contains(existingName, "gitlab.com-") ||
		strings.Contains(existingName, "bitbucket.org-") {
		// Update to the clean name from SCM
		if err := existingAsset.UpdateName(input.Name); err != nil {
			s.logger.Warn("failed to update asset name", "error", err)
		}
	}

	// Update criticality
	_ = existingAsset.UpdateCriticality(criticality)

	// Update description if provided
	if input.Description != "" {
		existingAsset.UpdateDescription(input.Description)
	}

	// Set scope if provided
	if input.Scope != "" {
		scope, _ := asset.ParseScope(input.Scope)
		_ = existingAsset.UpdateScope(scope)
	}

	// Set exposure if provided
	if input.Exposure != "" {
		exposure, _ := asset.ParseExposure(input.Exposure)
		_ = existingAsset.UpdateExposure(exposure)
	}

	// Update provider info from SCM
	if input.Provider != "" {
		provider := asset.ParseProvider(input.Provider)
		existingAsset.SetProvider(provider)
	}
	if input.ExternalID != "" {
		existingAsset.SetExternalID(input.ExternalID)
	} else if input.FullName != "" {
		// Use FullName as external_id for matching
		existingAsset.SetExternalID(input.FullName)
	}

	// Update classification if provided
	if input.Classification != "" {
		classification := asset.ParseClassification(input.Classification)
		existingAsset.SetClassification(classification)
	}

	// Add new tags
	for _, tag := range input.Tags {
		existingAsset.AddTag(tag)
	}

	// Recalculate risk score
	existingAsset.CalculateRiskScore()

	// Mark as synced
	existingAsset.MarkSynced()

	// Update the asset
	if err := s.repo.Update(ctx, existingAsset); err != nil {
		return nil, nil, fmt.Errorf("failed to update existing asset: %w", err)
	}

	// Try to get existing repository extension, or create new one
	var repoExt *asset.RepositoryExtension
	repoExt, err := s.repoExtRepo.GetByAssetID(ctx, existingAsset.ID())
	if err != nil || repoExt == nil {
		// Create new repository extension
		visibility := asset.RepoVisibilityPrivate
		if input.Visibility != "" {
			visibility = asset.ParseRepoVisibility(input.Visibility)
		}

		repoExt, err = asset.NewRepositoryExtension(existingAsset.ID(), input.FullName, visibility)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to create repository extension: %w", err)
		}

		applyRepoExtensionFields(repoExt, input)

		if err := s.repoExtRepo.Create(ctx, repoExt); err != nil {
			return nil, nil, fmt.Errorf("failed to create repository extension: %w", err)
		}
	} else {
		// Update existing repository extension
		if input.FullName != "" {
			repoExt.SetFullName(input.FullName)
		}
		if input.Visibility != "" {
			repoExt.SetVisibility(asset.ParseRepoVisibility(input.Visibility))
		}

		applyRepoExtensionFields(repoExt, input)

		if err := s.repoExtRepo.Update(ctx, repoExt); err != nil {
			return nil, nil, fmt.Errorf("failed to update repository extension: %w", err)
		}
	}

	s.logger.Info("updated existing repository asset with SCM data",
		"asset_id", existingAsset.ID().String(),
		"name", existingAsset.Name(),
		"fullName", input.FullName,
	)

	return existingAsset, repoExt, nil
}

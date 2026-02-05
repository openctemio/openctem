package app

import (
	"context"
	"fmt"

	"github.com/openctemio/api/pkg/domain/assetgroup"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/logger"
	"github.com/openctemio/api/pkg/pagination"
)

// AssetGroupService handles asset group business logic.
type AssetGroupService struct {
	repo   assetgroup.Repository
	logger *logger.Logger
}

// NewAssetGroupService creates a new asset group service.
func NewAssetGroupService(repo assetgroup.Repository, log *logger.Logger) *AssetGroupService {
	return &AssetGroupService{
		repo:   repo,
		logger: log,
	}
}

// CreateAssetGroupInput represents input for creating an asset group.
type CreateAssetGroupInput struct {
	TenantID     string
	Name         string   `validate:"required,min=1,max=255"`
	Description  string   `validate:"max=1000"`
	Environment  string   `validate:"required,asset_group_environment"`
	Criticality  string   `validate:"required,asset_group_criticality"`
	BusinessUnit string   `validate:"max=255"`
	Owner        string   `validate:"max=255"`
	OwnerEmail   string   `validate:"omitempty,email,max=255"`
	Tags         []string `validate:"max=20,dive,max=50"`
	AssetIDs     []string `validate:"dive,uuid"`
}

// UpdateAssetGroupInput represents input for updating an asset group.
type UpdateAssetGroupInput struct {
	Name         *string  `validate:"omitempty,min=1,max=255"`
	Description  *string  `validate:"omitempty,max=1000"`
	Environment  *string  `validate:"omitempty,asset_group_environment"`
	Criticality  *string  `validate:"omitempty,asset_group_criticality"`
	BusinessUnit *string  `validate:"omitempty,max=255"`
	Owner        *string  `validate:"omitempty,max=255"`
	OwnerEmail   *string  `validate:"omitempty,email,max=255"`
	Tags         []string `validate:"omitempty,max=20,dive,max=50"`
}

// ListAssetGroupsInput represents input for listing asset groups.
type ListAssetGroupsInput struct {
	TenantID      string
	Search        string
	Environments  []string
	Criticalities []string
	BusinessUnit  string
	Owner         string
	Tags          []string
	HasFindings   *bool
	MinRiskScore  *int
	MaxRiskScore  *int
	Sort          string
	Page          int `validate:"min=1"`
	PerPage       int `validate:"min=1,max=100"`
}

// ListAssetGroupsOutput represents output from listing asset groups.
type ListAssetGroupsOutput struct {
	Groups []*assetgroup.AssetGroup
	Total  int64
	Page   int
	Pages  int
}

// CreateAssetGroup creates a new asset group.
func (s *AssetGroupService) CreateAssetGroup(ctx context.Context, input CreateAssetGroupInput) (*assetgroup.AssetGroup, error) {
	tenantID, err := shared.IDFromString(input.TenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant ID", shared.ErrValidation)
	}

	env, ok := assetgroup.ParseEnvironment(input.Environment)
	if !ok {
		return nil, fmt.Errorf("%w: invalid environment", shared.ErrValidation)
	}

	crit, ok := assetgroup.ParseCriticality(input.Criticality)
	if !ok {
		return nil, fmt.Errorf("%w: invalid criticality", shared.ErrValidation)
	}

	// Check for duplicate name
	exists, err := s.repo.ExistsByName(ctx, tenantID, input.Name)
	if err != nil {
		return nil, err
	}
	if exists {
		return nil, fmt.Errorf("%w: asset group with this name already exists", shared.ErrAlreadyExists)
	}

	group, err := assetgroup.NewAssetGroupWithTenant(tenantID, input.Name, env, crit)
	if err != nil {
		return nil, err
	}

	group.UpdateDescription(input.Description)
	group.UpdateBusinessUnit(input.BusinessUnit)
	group.UpdateOwner(input.Owner, input.OwnerEmail)
	if len(input.Tags) > 0 {
		group.SetTags(input.Tags)
	}

	if err := s.repo.Create(ctx, group); err != nil {
		return nil, err
	}

	// Add assets to group if provided
	if len(input.AssetIDs) > 0 {
		assetIDs := make([]shared.ID, 0, len(input.AssetIDs))
		for _, idStr := range input.AssetIDs {
			id, err := shared.IDFromString(idStr)
			if err != nil {
				s.logger.Warn("invalid asset ID", "id", idStr, "error", err)
				continue
			}
			assetIDs = append(assetIDs, id)
		}
		if len(assetIDs) > 0 {
			if err := s.repo.AddAssets(ctx, group.ID(), assetIDs); err != nil {
				s.logger.Error("failed to add assets to group", "group_id", group.ID(), "error", err)
			}
			// Recalculate counts
			if err := s.repo.RecalculateCounts(ctx, group.ID()); err != nil {
				s.logger.Error("failed to recalculate counts", "group_id", group.ID(), "error", err)
			}
			// Refresh group from database
			group, _ = s.repo.GetByID(ctx, group.ID())
		}
	}

	s.logger.Info("asset group created", "id", group.ID(), "name", input.Name)
	return group, nil
}

// GetAssetGroup retrieves an asset group by ID.
func (s *AssetGroupService) GetAssetGroup(ctx context.Context, id shared.ID) (*assetgroup.AssetGroup, error) {
	return s.repo.GetByID(ctx, id)
}

// UpdateAssetGroup updates an existing asset group.
func (s *AssetGroupService) UpdateAssetGroup(ctx context.Context, id shared.ID, input UpdateAssetGroupInput) (*assetgroup.AssetGroup, error) {
	group, err := s.repo.GetByID(ctx, id)
	if err != nil {
		return nil, err
	}

	if input.Name != nil {
		if err := group.UpdateName(*input.Name); err != nil {
			return nil, err
		}
	}

	if input.Description != nil {
		group.UpdateDescription(*input.Description)
	}

	if input.Environment != nil {
		env, ok := assetgroup.ParseEnvironment(*input.Environment)
		if !ok {
			return nil, fmt.Errorf("%w: invalid environment", shared.ErrValidation)
		}
		if err := group.UpdateEnvironment(env); err != nil {
			return nil, err
		}
	}

	if input.Criticality != nil {
		crit, ok := assetgroup.ParseCriticality(*input.Criticality)
		if !ok {
			return nil, fmt.Errorf("%w: invalid criticality", shared.ErrValidation)
		}
		if err := group.UpdateCriticality(crit); err != nil {
			return nil, err
		}
	}

	if input.BusinessUnit != nil {
		group.UpdateBusinessUnit(*input.BusinessUnit)
	}

	if input.Owner != nil || input.OwnerEmail != nil {
		owner := group.Owner()
		email := group.OwnerEmail()
		if input.Owner != nil {
			owner = *input.Owner
		}
		if input.OwnerEmail != nil {
			email = *input.OwnerEmail
		}
		group.UpdateOwner(owner, email)
	}

	if input.Tags != nil {
		group.SetTags(input.Tags)
	}

	if err := s.repo.Update(ctx, group); err != nil {
		return nil, err
	}

	s.logger.Info("asset group updated", "id", id)
	return group, nil
}

// DeleteAssetGroup deletes an asset group.
func (s *AssetGroupService) DeleteAssetGroup(ctx context.Context, id shared.ID) error {
	if err := s.repo.Delete(ctx, id); err != nil {
		return err
	}
	s.logger.Info("asset group deleted", "id", id)
	return nil
}

// ListAssetGroups lists asset groups with filtering and pagination.
func (s *AssetGroupService) ListAssetGroups(ctx context.Context, input ListAssetGroupsInput) (*ListAssetGroupsOutput, error) {
	filter := assetgroup.NewFilter().WithTenantID(input.TenantID)

	if input.Search != "" {
		filter = filter.WithSearch(input.Search)
	}

	if len(input.Environments) > 0 {
		envs := make([]assetgroup.Environment, 0, len(input.Environments))
		for _, e := range input.Environments {
			if env, ok := assetgroup.ParseEnvironment(e); ok {
				envs = append(envs, env)
			}
		}
		if len(envs) > 0 {
			filter = filter.WithEnvironments(envs...)
		}
	}

	if len(input.Criticalities) > 0 {
		crits := make([]assetgroup.Criticality, 0, len(input.Criticalities))
		for _, c := range input.Criticalities {
			if crit, ok := assetgroup.ParseCriticality(c); ok {
				crits = append(crits, crit)
			}
		}
		if len(crits) > 0 {
			filter = filter.WithCriticalities(crits...)
		}
	}

	if input.BusinessUnit != "" {
		filter = filter.WithBusinessUnit(input.BusinessUnit)
	}

	if len(input.Tags) > 0 {
		filter = filter.WithTags(input.Tags...)
	}

	if input.HasFindings != nil {
		filter = filter.WithHasFindings(*input.HasFindings)
	}

	if input.MinRiskScore != nil {
		filter.MinRiskScore = input.MinRiskScore
	}
	if input.MaxRiskScore != nil {
		filter.MaxRiskScore = input.MaxRiskScore
	}

	opts := assetgroup.NewListOptions()
	if input.Sort != "" {
		sortOpt := pagination.NewSortOption(assetgroup.AllowedSortFields()).Parse(input.Sort)
		opts = opts.WithSort(sortOpt)
	}

	page := pagination.New(input.Page, input.PerPage)

	result, err := s.repo.List(ctx, filter, opts, page)
	if err != nil {
		return nil, err
	}

	return &ListAssetGroupsOutput{
		Groups: result.Data,
		Total:  result.Total,
		Page:   result.Page,
		Pages:  result.TotalPages,
	}, nil
}

// GetAssetGroupStats retrieves aggregated statistics.
func (s *AssetGroupService) GetAssetGroupStats(ctx context.Context, tenantID string) (*assetgroup.Stats, error) {
	tid, err := shared.IDFromString(tenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant ID", shared.ErrValidation)
	}
	return s.repo.GetStats(ctx, tid)
}

// AddAssetsToGroup adds assets to a group.
func (s *AssetGroupService) AddAssetsToGroup(ctx context.Context, groupID shared.ID, assetIDs []string) error {
	ids := make([]shared.ID, 0, len(assetIDs))
	for _, idStr := range assetIDs {
		id, err := shared.IDFromString(idStr)
		if err != nil {
			continue
		}
		ids = append(ids, id)
	}

	if len(ids) == 0 {
		return nil
	}

	if err := s.repo.AddAssets(ctx, groupID, ids); err != nil {
		return err
	}

	// Recalculate counts
	return s.repo.RecalculateCounts(ctx, groupID)
}

// RemoveAssetsFromGroup removes assets from a group.
func (s *AssetGroupService) RemoveAssetsFromGroup(ctx context.Context, groupID shared.ID, assetIDs []string) error {
	ids := make([]shared.ID, 0, len(assetIDs))
	for _, idStr := range assetIDs {
		id, err := shared.IDFromString(idStr)
		if err != nil {
			continue
		}
		ids = append(ids, id)
	}

	if len(ids) == 0 {
		return nil
	}

	if err := s.repo.RemoveAssets(ctx, groupID, ids); err != nil {
		return err
	}

	// Recalculate counts
	return s.repo.RecalculateCounts(ctx, groupID)
}

// GetGroupAssets retrieves assets in a group.
func (s *AssetGroupService) GetGroupAssets(ctx context.Context, groupID shared.ID, pageNum, perPage int) (pagination.Result[*assetgroup.GroupAsset], error) {
	page := pagination.New(pageNum, perPage)
	return s.repo.GetGroupAssets(ctx, groupID, page)
}

// GetGroupFindings retrieves findings for assets in a group.
func (s *AssetGroupService) GetGroupFindings(ctx context.Context, groupID shared.ID, pageNum, perPage int) (pagination.Result[*assetgroup.GroupFinding], error) {
	page := pagination.New(pageNum, perPage)
	return s.repo.GetGroupFindings(ctx, groupID, page)
}

// BulkUpdateInput represents input for bulk updating asset groups.
type BulkUpdateInput struct {
	GroupIDs    []string
	Environment *string `validate:"omitempty,asset_group_environment"`
	Criticality *string `validate:"omitempty,asset_group_criticality"`
}

// BulkUpdateAssetGroups updates multiple asset groups.
func (s *AssetGroupService) BulkUpdateAssetGroups(ctx context.Context, input BulkUpdateInput) (int, error) {
	updated := 0
	for _, idStr := range input.GroupIDs {
		id, err := shared.IDFromString(idStr)
		if err != nil {
			continue
		}

		_, err = s.UpdateAssetGroup(ctx, id, UpdateAssetGroupInput{
			Environment: input.Environment,
			Criticality: input.Criticality,
		})
		if err != nil {
			s.logger.Warn("bulk update failed for group", "id", idStr, "error", err)
			continue
		}
		updated++
	}
	return updated, nil
}

// BulkDeleteAssetGroups deletes multiple asset groups.
func (s *AssetGroupService) BulkDeleteAssetGroups(ctx context.Context, groupIDs []string) (int, error) {
	deleted := 0
	for _, idStr := range groupIDs {
		id, err := shared.IDFromString(idStr)
		if err != nil {
			continue
		}

		if err := s.DeleteAssetGroup(ctx, id); err != nil {
			s.logger.Warn("bulk delete failed for group", "id", idStr, "error", err)
			continue
		}
		deleted++
	}
	return deleted, nil
}

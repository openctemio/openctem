package asset

import (
	"context"
	"fmt"

	businessunitdom "github.com/openctemio/api/pkg/domain/businessunit"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/logger"
	"github.com/openctemio/api/pkg/pagination"
)

// BusinessUnitService manages business units.
type BusinessUnitService struct {
	repo   businessunitdom.Repository
	logger *logger.Logger
}

// NewBusinessUnitService creates a new service.
func NewBusinessUnitService(repo businessunitdom.Repository, log *logger.Logger) *BusinessUnitService {
	return &BusinessUnitService{repo: repo, logger: log}
}

// CreateBusinessUnitInput holds input for creating a BU.
type CreateBusinessUnitInput struct {
	TenantID    string
	Name        string
	Description string
	OwnerName   string
	OwnerEmail  string
	Tags        []string
}

// Create creates a new business unit.
func (s *BusinessUnitService) Create(ctx context.Context, input CreateBusinessUnitInput) (*businessunitdom.BusinessUnit, error) {
	tid, err := shared.IDFromString(input.TenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}
	bu, err := businessunitdom.NewBusinessUnit(tid, input.Name)
	if err != nil {
		return nil, err
	}
	bu.Update(input.Name, input.Description, input.OwnerName, input.OwnerEmail)
	bu.SetTags(input.Tags)
	if err := s.repo.Create(ctx, bu); err != nil {
		return nil, fmt.Errorf("failed to create business unit: %w", err)
	}
	return bu, nil
}

// Get retrieves a BU.
func (s *BusinessUnitService) Get(ctx context.Context, tenantID, buID string) (*businessunitdom.BusinessUnit, error) {
	tid, _ := shared.IDFromString(tenantID)
	bid, _ := shared.IDFromString(buID)
	return s.repo.GetByID(ctx, tid, bid)
}

// List lists BUs.
func (s *BusinessUnitService) List(ctx context.Context, tenantID string, filter businessunitdom.Filter, page pagination.Pagination) (pagination.Result[*businessunitdom.BusinessUnit], error) {
	tid, _ := shared.IDFromString(tenantID)
	filter.TenantID = &tid
	return s.repo.List(ctx, filter, page)
}

// UpdateBusinessUnitInput holds input for updating a BU.
type UpdateBusinessUnitInput struct {
	TenantID    string
	ID          string
	Name        string
	Description string
	OwnerName   string
	OwnerEmail  string
	Tags        []string
}

// Update updates an existing business unit.
func (s *BusinessUnitService) Update(ctx context.Context, input UpdateBusinessUnitInput) (*businessunitdom.BusinessUnit, error) {
	tid, err := shared.IDFromString(input.TenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}
	bid, err := shared.IDFromString(input.ID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid business unit id", shared.ErrValidation)
	}
	bu, err := s.repo.GetByID(ctx, tid, bid)
	if err != nil {
		return nil, fmt.Errorf("failed to get business unit: %w", err)
	}
	bu.Update(input.Name, input.Description, input.OwnerName, input.OwnerEmail)
	bu.SetTags(input.Tags)
	if err := s.repo.Update(ctx, bu); err != nil {
		return nil, fmt.Errorf("failed to update business unit: %w", err)
	}
	return bu, nil
}

// Delete deletes a BU.
func (s *BusinessUnitService) Delete(ctx context.Context, tenantID, buID string) error {
	tid, _ := shared.IDFromString(tenantID)
	bid, _ := shared.IDFromString(buID)
	return s.repo.Delete(ctx, tid, bid)
}

// AddAsset links an asset to a BU.
func (s *BusinessUnitService) AddAsset(ctx context.Context, tenantID, buID, assetID string) error {
	tid, _ := shared.IDFromString(tenantID)
	bid, _ := shared.IDFromString(buID)
	aid, _ := shared.IDFromString(assetID)
	return s.repo.AddAsset(ctx, tid, bid, aid)
}

// RemoveAsset unlinks an asset from a BU.
func (s *BusinessUnitService) RemoveAsset(ctx context.Context, tenantID, buID, assetID string) error {
	tid, _ := shared.IDFromString(tenantID)
	bid, _ := shared.IDFromString(buID)
	aid, _ := shared.IDFromString(assetID)
	return s.repo.RemoveAsset(ctx, tid, bid, aid)
}

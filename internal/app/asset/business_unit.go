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
	repo         businessunitdom.Repository
	assetChecker assetTenantChecker
	logger       *logger.Logger
}

// NewBusinessUnitService creates a new service. assetChecker verifies that an
// asset being linked belongs to the caller's tenant (may be nil in tests).
func NewBusinessUnitService(repo businessunitdom.Repository, assetChecker assetTenantChecker, log *logger.Logger) *BusinessUnitService {
	return &BusinessUnitService{repo: repo, assetChecker: assetChecker, logger: log}
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
	tid, bid, aid, err := s.parseBUAssetIDs(tenantID, buID, assetID)
	if err != nil {
		return err
	}
	// Verify the BU and the asset both belong to this tenant before linking
	// (the link table is otherwise tenant-blind, allowing a foreign asset to
	// be associated and pollute risk rollups).
	if _, err := s.repo.GetByID(ctx, tid, bid); err != nil {
		return err
	}
	if s.assetChecker != nil {
		if _, err := s.assetChecker.GetByID(ctx, tid, aid); err != nil {
			return err
		}
	}
	if err := s.repo.AddAsset(ctx, tid, bid, aid); err != nil {
		return err
	}
	if err := s.repo.RecalculateCounts(ctx, tid, bid); err != nil {
		s.logger.Warn("recalculate business unit counts", "bu_id", bid.String(), "error", err)
	}
	return nil
}

// RemoveAsset unlinks an asset from a BU.
func (s *BusinessUnitService) RemoveAsset(ctx context.Context, tenantID, buID, assetID string) error {
	tid, bid, aid, err := s.parseBUAssetIDs(tenantID, buID, assetID)
	if err != nil {
		return err
	}
	if _, err := s.repo.GetByID(ctx, tid, bid); err != nil {
		return err
	}
	if err := s.repo.RemoveAsset(ctx, tid, bid, aid); err != nil {
		return err
	}
	if err := s.repo.RecalculateCounts(ctx, tid, bid); err != nil {
		s.logger.Warn("recalculate business unit counts", "bu_id", bid.String(), "error", err)
	}
	return nil
}

// parseBUAssetIDs validates and parses the tenant, business-unit and asset IDs.
func (s *BusinessUnitService) parseBUAssetIDs(tenantID, buID, assetID string) (tid, bid, aid shared.ID, err error) {
	if tid, err = shared.IDFromString(tenantID); err != nil {
		return tid, bid, aid, fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}
	if bid, err = shared.IDFromString(buID); err != nil {
		return tid, bid, aid, fmt.Errorf("%w: invalid business unit id", shared.ErrValidation)
	}
	if aid, err = shared.IDFromString(assetID); err != nil {
		return tid, bid, aid, fmt.Errorf("%w: invalid asset id", shared.ErrValidation)
	}
	return tid, bid, aid, nil
}

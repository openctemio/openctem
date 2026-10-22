package asset

import (
	"context"
	"errors"
	"fmt"

	"github.com/openctemio/openctem/api/internal/app/datascope"

	businessunitdom "github.com/openctemio/openctem/api/pkg/domain/businessunit"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/pagination"
)

// BusinessUnitService manages business units.
type BusinessUnitService struct {
	repo         businessunitdom.Repository
	assetChecker assetTenantChecker
	dataScope    *datascope.Enforcer
	logger       *logger.Logger
}

// SetDataScope makes linking or unlinking an asset answer 404 when the
// caller may not see it: a BU link changes the asset's effective
// criticality, so it is a write on the asset.
func (s *BusinessUnitService) SetDataScope(e *datascope.Enforcer) { s.dataScope = e }

func (s *BusinessUnitService) assertAssetInScope(ctx context.Context, tid, aid shared.ID) error {
	if s.dataScope == nil {
		return nil
	}
	return s.dataScope.AssertAsset(ctx, tid, aid)
}

// NewBusinessUnitService creates a new service. assetChecker verifies that an
// asset being linked belongs to the caller's tenant (may be nil in tests).
func NewBusinessUnitService(repo businessunitdom.Repository, assetChecker assetTenantChecker, log *logger.Logger) *BusinessUnitService {
	return &BusinessUnitService{repo: repo, assetChecker: assetChecker, logger: log}
}

// CreateBusinessUnitInput holds input for creating a BU. Criticality,
// RiskTolerance and ParentID are optional (nil = use default / none); an
// empty ParentID string clears the parent.
type CreateBusinessUnitInput struct {
	TenantID      string
	Name          string
	Description   string
	OwnerName     string
	OwnerEmail    string
	Criticality   *string
	RiskTolerance *string
	ParentID      *string
	Tags          []string
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
	if err := applyCriticality(bu, input.Criticality); err != nil {
		return nil, err
	}
	if err := applyRiskTolerance(bu, input.RiskTolerance); err != nil {
		return nil, err
	}
	scope, err := s.resolveScope(ctx, tid)
	if err != nil {
		return nil, err
	}
	if err := s.applyParent(ctx, tid, bu, input.ParentID, scope); err != nil {
		return nil, err
	}
	if err := s.repo.Create(ctx, bu); err != nil {
		return nil, fmt.Errorf("failed to create business unit: %w", err)
	}
	if scope.Restricted() {
		bu.HideOwnerEmail()
	}
	return bu, nil
}

// applyCriticality sets criticality from an optional string (nil = leave as-is).
func applyCriticality(bu *businessunitdom.BusinessUnit, val *string) error {
	if val == nil || *val == "" {
		return nil
	}
	c, ok := businessunitdom.ParseCriticality(*val)
	if !ok {
		return fmt.Errorf("%w: invalid criticality %q", shared.ErrValidation, *val)
	}
	return bu.SetCriticality(c)
}

// applyRiskTolerance sets risk tolerance from an optional string (nil = leave as-is).
func applyRiskTolerance(bu *businessunitdom.BusinessUnit, val *string) error {
	if val == nil || *val == "" {
		return nil
	}
	t, ok := businessunitdom.ParseRiskTolerance(*val)
	if !ok {
		return fmt.Errorf("%w: invalid risk_tolerance %q", shared.ErrValidation, *val)
	}
	return bu.SetRiskTolerance(t)
}

// applyParent resolves and validates an optional parent_id. nil = leave
// unchanged; empty string = clear the parent; otherwise the referenced BU must
// exist within the same tenant, must not be the unit itself, and must not
// introduce a cycle in the hierarchy.
func (s *BusinessUnitService) applyParent(ctx context.Context, tid shared.ID, bu *businessunitdom.BusinessUnit, val *string, scope *shared.DataScope) error {
	if val == nil {
		return nil
	}
	if *val == "" {
		return bu.SetParent(nil)
	}
	pid, err := shared.IDFromString(*val)
	if err != nil {
		return fmt.Errorf("%w: invalid parent_id", shared.ErrValidation)
	}
	if pid == bu.ID() {
		return fmt.Errorf("%w: a business unit cannot be its own parent", shared.ErrValidation)
	}
	// Same-tenant enforcement: GetByID is tenant-scoped, so a cross-tenant or
	// bogus parent simply is not found → reject as a validation error.
	parent, err := s.repo.GetByID(ctx, tid, pid)
	if err != nil {
		if errors.Is(err, shared.ErrNotFound) {
			return fmt.Errorf("%w: parent business unit not found in this tenant", shared.ErrValidation)
		}
		return fmt.Errorf("failed to resolve parent business unit: %w", err)
	}
	// A restricted caller cannot place a unit under one they cannot see: the
	// parent answers as if it did not exist.
	if ok, err := s.visible(ctx, tid, pid, scope); err != nil {
		return err
	} else if !ok {
		return fmt.Errorf("%w: parent business unit not found in this tenant", shared.ErrValidation)
	}
	// Cycle guard: walk the prospective parent's ancestor chain; if this unit
	// appears, linking would create a cycle.
	//
	// KNOWN TOCTOU (accepted): the ancestor read + this write are not one
	// transaction, so two concurrent Updates each setting the other as parent
	// can both pass the check and produce a small cycle. It is bounded — every
	// ancestor walk is capped at maxHierarchyDepth (64) hops, so a cycle only
	// yields an inconsistent hierarchy, never an infinite loop or DoS. A clean
	// fix needs a transaction spanning the read+check+write (or a recursive-CTE
	// assertion in Repository.Update); the Repository interface has no tx
	// support today, so plumbing it is disproportionate for this LOW-severity,
	// contained race. Left as-is intentionally.
	cursor := parent
	for hops := 0; cursor != nil && cursor.ParentID() != nil && hops < maxHierarchyDepth; hops++ {
		if *cursor.ParentID() == bu.ID() {
			return fmt.Errorf("%w: parent assignment would create a hierarchy cycle", shared.ErrValidation)
		}
		next, err := s.repo.GetByID(ctx, tid, *cursor.ParentID())
		if err != nil {
			break // broken/inaccessible ancestor — nothing more to check
		}
		cursor = next
	}
	return bu.SetParent(&pid)
}

// maxHierarchyDepth bounds the ancestor walk when detecting cycles.
const maxHierarchyDepth = 64

// Get retrieves a BU as the caller may see it: a unit not visible to a
// restricted caller answers businessunit.ErrNotFound (404).
func (s *BusinessUnitService) Get(ctx context.Context, tenantID, buID string) (*businessunitdom.BusinessUnit, error) {
	tid, _ := shared.IDFromString(tenantID)
	bid, _ := shared.IDFromString(buID)
	bu, err := s.repo.GetByID(ctx, tid, bid)
	if err != nil {
		return nil, err
	}
	scope, err := s.resolveScope(ctx, tid)
	if err != nil {
		return nil, err
	}
	if ok, err := s.visible(ctx, tid, bid, scope); err != nil {
		return nil, err
	} else if !ok {
		return nil, businessunitdom.ErrNotFound
	}
	if err := s.present(ctx, tid, scope, bu); err != nil {
		return nil, err
	}
	return bu, nil
}

// resolveScope returns the caller's data scope in tid (nil = unrestricted,
// also when no enforcer is wired).
func (s *BusinessUnitService) resolveScope(ctx context.Context, tid shared.ID) (*shared.DataScope, error) {
	if s.dataScope == nil {
		return nil, nil
	}
	scope, err := s.dataScope.Resolve(ctx, tid)
	if err != nil {
		return nil, fmt.Errorf("resolve data scope: %w", err)
	}
	return scope, nil
}

// visible reports whether the unit is visible to the caller (research/233
// D4): always for an unrestricted caller; for a restricted one only when the
// unit or a unit below it holds an asset in their scope.
func (s *BusinessUnitService) visible(ctx context.Context, tid, bid shared.ID, scope *shared.DataScope) (bool, error) {
	if !scope.Restricted() {
		return true, nil
	}
	res, err := s.repo.List(ctx, businessunitdom.Filter{
		TenantID: &tid, IDs: []shared.ID{bid}, DataScope: scope,
	}, pagination.New(1, 1))
	if err != nil {
		return false, err
	}
	return len(res.Data) > 0, nil
}

// writableUnit loads the unit for a change by the caller. A restricted
// caller may change a unit visible to them, or an empty one: no asset and no
// unit below it (a unit they just created). A unit whose assets all sit in
// the units below it is not empty: its name, criticality and placement
// reach those assets (criticality is inherited down the hierarchy). Any
// other unit answers businessunit.ErrNotFound, as a read does.
func (s *BusinessUnitService) writableUnit(ctx context.Context, tid, bid shared.ID) (*businessunitdom.BusinessUnit, *shared.DataScope, error) {
	bu, err := s.repo.GetByID(ctx, tid, bid)
	if err != nil {
		return nil, nil, err
	}
	scope, err := s.resolveScope(ctx, tid)
	if err != nil {
		return nil, nil, err
	}
	ok, err := s.visible(ctx, tid, bid, scope)
	if err != nil {
		return nil, nil, err
	}
	if ok {
		return bu, scope, nil
	}
	ids, err := s.repo.ListAssetIDs(ctx, tid, bid)
	if err != nil {
		return nil, nil, err
	}
	if len(ids) > 0 {
		return nil, nil, businessunitdom.ErrNotFound
	}
	children, err := s.repo.List(ctx, businessunitdom.Filter{TenantID: &tid, ParentID: &bid}, pagination.New(1, 1))
	if err != nil {
		return nil, nil, err
	}
	if children.Total > 0 {
		return nil, nil, businessunitdom.ErrNotFound
	}
	return bu, scope, nil
}

// present prepares units for the caller's response, in memory only. The
// stored rollup counters cover every asset of the unit, so a scoped caller
// gets counts over the assets they may see (a restricted reader would
// otherwise learn how many assets and findings sit outside their scope),
// and a restricted caller never gets the owner email (personal data).
func (s *BusinessUnitService) present(ctx context.Context, tid shared.ID, scope *shared.DataScope, units ...*businessunitdom.BusinessUnit) error {
	if scope == nil || len(units) == 0 {
		return nil
	}
	ids := make([]shared.ID, len(units))
	for i, u := range units {
		ids[i] = u.ID()
	}
	stats, err := s.repo.ScopedStats(ctx, tid, ids, scope)
	if err != nil {
		return err
	}
	for _, u := range units {
		u.ShowStats(stats[u.ID()])
		if scope.Restricted() {
			u.HideOwnerEmail()
		}
	}
	return nil
}

// List lists the BUs visible to the caller; the total counts only those.
func (s *BusinessUnitService) List(ctx context.Context, tenantID string, filter businessunitdom.Filter, page pagination.Pagination) (pagination.Result[*businessunitdom.BusinessUnit], error) {
	tid, _ := shared.IDFromString(tenantID)
	filter.TenantID = &tid
	scope, err := s.resolveScope(ctx, tid)
	if err != nil {
		return pagination.Result[*businessunitdom.BusinessUnit]{}, err
	}
	filter.DataScope = scope
	res, err := s.repo.List(ctx, filter, page)
	if err != nil {
		return res, err
	}
	if err := s.present(ctx, tid, scope, res.Data...); err != nil {
		return pagination.Result[*businessunitdom.BusinessUnit]{}, err
	}
	return res, nil
}

// UpdateBusinessUnitInput holds input for updating a BU. Criticality,
// RiskTolerance and ParentID are optional (nil = leave unchanged); an empty
// ParentID string clears the parent.
type UpdateBusinessUnitInput struct {
	TenantID      string
	ID            string
	Name          string
	Description   string
	OwnerName     string
	OwnerEmail    string
	Criticality   *string
	RiskTolerance *string
	ParentID      *string
	Tags          []string
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
	bu, scope, err := s.writableUnit(ctx, tid, bid)
	if err != nil {
		return nil, fmt.Errorf("failed to get business unit: %w", err)
	}
	if scope.Restricted() {
		// The owner email is hidden from a restricted caller, so their
		// edit form never holds it: keep the stored value.
		input.OwnerEmail = bu.OwnerEmail()
	}
	bu.Update(input.Name, input.Description, input.OwnerName, input.OwnerEmail)
	bu.SetTags(input.Tags)
	if err := applyCriticality(bu, input.Criticality); err != nil {
		return nil, err
	}
	if err := applyRiskTolerance(bu, input.RiskTolerance); err != nil {
		return nil, err
	}
	if err := s.applyParent(ctx, tid, bu, input.ParentID, scope); err != nil {
		return nil, err
	}
	if err := s.repo.Update(ctx, bu); err != nil {
		return nil, fmt.Errorf("failed to update business unit: %w", err)
	}
	// Saved first: the response carries the reader's scoped counters.
	if err := s.present(ctx, tid, scope, bu); err != nil {
		return nil, err
	}
	return bu, nil
}

// Delete deletes a BU.
func (s *BusinessUnitService) Delete(ctx context.Context, tenantID, buID string) error {
	tid, _ := shared.IDFromString(tenantID)
	bid, _ := shared.IDFromString(buID)
	if _, _, err := s.writableUnit(ctx, tid, bid); err != nil {
		return err
	}
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
	if _, _, err := s.writableUnit(ctx, tid, bid); err != nil {
		return err
	}
	if s.assetChecker != nil {
		if _, err := s.assetChecker.GetByID(ctx, tid, aid); err != nil {
			return err
		}
	}
	if err := s.assertAssetInScope(ctx, tid, aid); err != nil {
		return err
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
	if _, _, err := s.writableUnit(ctx, tid, bid); err != nil {
		return err
	}
	if err := s.assertAssetInScope(ctx, tid, aid); err != nil {
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

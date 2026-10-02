package finding

import (
	"context"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/accesscontrol"
	"github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// ownerlessAssetRepo returns an asset whose assets.owner_id is nil (the common
// case — owner_id is only set by email auto-match). This forces AutoAssignToOwners
// down the Phase-0 fallback path.
type ownerlessAssetRepo struct {
	asset.Repository
	name string
}

func (r *ownerlessAssetRepo) GetByID(_ context.Context, tenantID, _ shared.ID) (*asset.Asset, error) {
	a, err := asset.NewAssetWithTenant(tenantID, r.name, asset.AssetTypeHost, asset.CriticalityMedium)
	if err != nil {
		return nil, err
	}
	// owner_id intentionally left nil
	return a, nil
}

// stubAccessCtrl returns a fixed primary-owner brief for every asset.
type stubAccessCtrl struct {
	accesscontrol.Repository
	brief *accesscontrol.OwnerBrief
}

func (r *stubAccessCtrl) GetPrimaryOwnerBrief(_ context.Context, _, _ shared.ID) (*accesscontrol.OwnerBrief, error) {
	return r.brief, nil
}

// TestAutoAssignToOwners_FallsBackToRACIPrimaryUser: when assets.owner_id is nil
// but a primary RACI *user* owner exists, the finding is assigned to that user
// (Phase 0 unification of the two ownership models).
func TestAutoAssignToOwners_FallsBackToRACIPrimaryUser(t *testing.T) {
	tenantID := shared.NewID()
	assetID := shared.NewID()
	primaryUser := shared.NewID()

	findingRepo := &autoAssignFindingRepo{
		pages: [][]*vulnerability.Finding{{unassignedFinding(t, tenantID, assetID)}},
	}
	assetRepo := &ownerlessAssetRepo{name: "host-1"}
	accessCtrl := &stubAccessCtrl{brief: &accesscontrol.OwnerBrief{ID: primaryUser.String(), Type: "user", Name: "Dev A"}}

	svc := NewFindingActionsService(findingRepo, accessCtrl, nil, assetRepo, nil, nil, logger.NewNop())

	res, err := svc.AutoAssignToOwners(context.Background(), tenantID.String(), shared.NewID().String(), vulnerability.NewFindingFilter())
	if err != nil {
		t.Fatalf("AutoAssignToOwners: %v", err)
	}
	if res.Assigned != 1 {
		t.Errorf("Assigned = %d, want 1 (RACI primary user fallback)", res.Assigned)
	}
	if res.Unassigned != 0 {
		t.Errorf("Unassigned = %d, want 0", res.Unassigned)
	}
}

// TestAutoAssignToOwners_GroupPrimaryOwnerNotAssignable: a primary owner that is
// a GROUP (not a user) cannot be a finding assignee, so the finding stays
// unassigned rather than being wrongly assigned to a group id.
func TestAutoAssignToOwners_GroupPrimaryOwnerNotAssignable(t *testing.T) {
	tenantID := shared.NewID()
	assetID := shared.NewID()
	groupID := shared.NewID()

	findingRepo := &autoAssignFindingRepo{
		pages: [][]*vulnerability.Finding{{unassignedFinding(t, tenantID, assetID)}},
	}
	assetRepo := &ownerlessAssetRepo{name: "host-1"}
	accessCtrl := &stubAccessCtrl{brief: &accesscontrol.OwnerBrief{ID: groupID.String(), Type: "group", Name: "Platform Team"}}

	svc := NewFindingActionsService(findingRepo, accessCtrl, nil, assetRepo, nil, nil, logger.NewNop())

	res, err := svc.AutoAssignToOwners(context.Background(), tenantID.String(), shared.NewID().String(), vulnerability.NewFindingFilter())
	if err != nil {
		t.Fatalf("AutoAssignToOwners: %v", err)
	}
	if res.Assigned != 0 {
		t.Errorf("Assigned = %d, want 0 (group primary is not an assignee)", res.Assigned)
	}
	if res.Unassigned != 1 {
		t.Errorf("Unassigned = %d, want 1", res.Unassigned)
	}
}

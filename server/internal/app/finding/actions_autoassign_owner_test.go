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

// plainAssetRepo returns an asset for any id. Owners are not part of the asset
// any more: asset_owners is the only owner store.
type plainAssetRepo struct {
	asset.Repository
	name string
}

func (r *plainAssetRepo) GetByID(_ context.Context, tenantID, _ shared.ID) (*asset.Asset, error) {
	return asset.NewAssetWithTenant(tenantID, r.name, asset.AssetTypeHost, asset.CriticalityMedium)
}

// stubAccessCtrl serves the asset_owners lookups the finding actions use:
// primary user owners per asset and the assets a user owns.
type stubAccessCtrl struct {
	accesscontrol.Repository
	primary      map[shared.ID]shared.ID          // asset → primary user owner
	owned        map[shared.ID]map[shared.ID]bool // user → assets they own (primary or secondary)
	primaryCalls int
}

func (r *stubAccessCtrl) GetPrimaryUserOwnersByAssetIDs(_ context.Context, _ shared.ID, assetIDs []shared.ID) (map[shared.ID]shared.ID, error) {
	r.primaryCalls++
	out := make(map[shared.ID]shared.ID)
	for _, id := range assetIDs {
		if u, ok := r.primary[id]; ok {
			out[id] = u
		}
	}
	return out, nil
}

func (r *stubAccessCtrl) FilterAssetsOwnedByUser(_ context.Context, _, userID shared.ID, assetIDs []shared.ID) (map[shared.ID]bool, error) {
	out := make(map[shared.ID]bool)
	for _, id := range assetIDs {
		if r.owned[userID][id] {
			out[id] = true
		}
	}
	return out, nil
}

// The finding is assigned to the asset's primary user owner from asset_owners.
func TestAutoAssignToOwners_AssignsPrimaryUserOwner(t *testing.T) {
	tenantID := shared.NewID()
	assetID := shared.NewID()
	primaryUser := shared.NewID()

	f := unassignedFinding(t, tenantID, assetID)
	findingRepo := &autoAssignFindingRepo{pages: [][]*vulnerability.Finding{{f}}}
	accessCtrl := &stubAccessCtrl{primary: map[shared.ID]shared.ID{assetID: primaryUser}}

	svc := NewFindingActionsService(findingRepo, accessCtrl, nil, &plainAssetRepo{name: "host-1"}, nil, nil, logger.NewNop())

	res, err := svc.AutoAssignToOwners(context.Background(), tenantID.String(), shared.NewID().String(), vulnerability.NewFindingFilter())
	if err != nil {
		t.Fatalf("AutoAssignToOwners: %v", err)
	}
	if res.Assigned != 1 || res.Unassigned != 0 {
		t.Fatalf("Assigned=%d Unassigned=%d, want 1 and 0", res.Assigned, res.Unassigned)
	}
	if f.AssignedTo() == nil || *f.AssignedTo() != primaryUser {
		t.Errorf("assigned to %v, want the primary user owner %s", f.AssignedTo(), primaryUser)
	}
}

// An asset whose only primary owner is a group (or that has no owner) has no
// primary USER owner, so the finding stays unassigned.
func TestAutoAssignToOwners_NoPrimaryUserOwnerStaysUnassigned(t *testing.T) {
	tenantID := shared.NewID()
	assetID := shared.NewID()

	findingRepo := &autoAssignFindingRepo{
		pages: [][]*vulnerability.Finding{{unassignedFinding(t, tenantID, assetID)}},
	}
	accessCtrl := &stubAccessCtrl{primary: map[shared.ID]shared.ID{}}

	svc := NewFindingActionsService(findingRepo, accessCtrl, nil, &plainAssetRepo{name: "host-1"}, nil, nil, logger.NewNop())

	res, err := svc.AutoAssignToOwners(context.Background(), tenantID.String(), shared.NewID().String(), vulnerability.NewFindingFilter())
	if err != nil {
		t.Fatalf("AutoAssignToOwners: %v", err)
	}
	if res.Assigned != 0 || res.Unassigned != 1 {
		t.Errorf("Assigned=%d Unassigned=%d, want 0 and 1", res.Assigned, res.Unassigned)
	}
}

// canMarkFixApplied's owner path reads the preloaded asset_owners set: an
// owner of the finding's asset may mark it, anyone else may not.
func TestCanMarkFixApplied_AssetOwnerFromAssetOwners(t *testing.T) {
	tenantID := shared.NewID()
	ownedAsset := shared.NewID()
	otherAsset := shared.NewID()
	user := shared.NewID()

	accessCtrl := &stubAccessCtrl{owned: map[shared.ID]map[shared.ID]bool{user: {ownedAsset: true}}}
	svc := NewFindingActionsService(&autoAssignFindingRepo{}, accessCtrl, nil, &plainAssetRepo{}, nil, nil, logger.NewNop())

	onOwned := unassignedFinding(t, tenantID, ownedAsset)
	onOther := unassignedFinding(t, tenantID, otherAsset)
	owned := svc.assetsOwnedBy(context.Background(), tenantID, user, []*vulnerability.Finding{onOwned, onOther})

	if !svc.canMarkFixApplied(user, nil, nil, owned, onOwned) {
		t.Error("owner of the asset must be able to mark its finding fix_applied")
	}
	if svc.canMarkFixApplied(user, nil, nil, owned, onOther) {
		t.Error("a user who does not own the asset must not pass the owner check")
	}
}

package postgres

import (
	"context"
	"testing"
	"time"
)

// A run on a feature or pull-request branch must not reopen a finding that
// was resolved on the default branch; a finding that exists only on branches
// (branch-only) is not default-branch state and still reopens on its branch.
// The ingest path withholds the fingerprints this lookup returns, for runs
// that are not on the default branch; a default-branch run does not use it.
func TestDefaultBranchResolvedFingerprints(t *testing.T) {
	db := openReopenDB(t)
	ctx := context.Background()
	repo := NewFindingRepository(&DB{DB: db})

	tenantID := seedTestTenant(ctx, t, db)
	otherTenant := seedTestTenant(ctx, t, db)
	assetID := seedTestAsset(ctx, t, db, tenantID)
	otherAsset := seedTestAsset(ctx, t, db, otherTenant)

	_, defaultFP := seedClosedFinding(ctx, t, db, tenantID, assetID, "resolved", "security_reviewed")
	branchID, branchFP := seedClosedFinding(ctx, t, db, tenantID, assetID, "resolved", "auto_fixed")
	_, openFP := seedClosedFinding(ctx, t, db, tenantID, assetID, "confirmed", "")
	_, otherTenantFP := seedClosedFinding(ctx, t, db, otherTenant, otherAsset, "resolved", "security_reviewed")
	if _, err := db.ExecContext(ctx, `UPDATE findings SET branch_only = TRUE WHERE id = $1`, branchID.String()); err != nil {
		t.Fatal(err)
	}

	got, err := repo.DefaultBranchResolvedFingerprints(ctx, tenantID, []string{defaultFP, branchFP, openFP, otherTenantFP})
	if err != nil {
		t.Fatal(err)
	}
	if !got[defaultFP] {
		t.Error("a finding resolved on the default branch must be withheld from branch runs")
	}
	if got[branchFP] {
		t.Error("a branch-only finding must still reopen on its branch")
	}
	if got[openFP] {
		t.Error("an open finding has nothing to withhold")
	}
	if got[otherTenantFP] {
		t.Error("another tenant's finding leaked into the lookup")
	}

	// A default-branch run reopens the same finding (no guard applies).
	reopened, err := repo.AutoReopenByFingerprintsBatch(ctx, tenantID, []string{defaultFP}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := reopened[defaultFP]; !ok {
		t.Error("a default-branch run must reopen a resolved default-branch finding")
	}
}

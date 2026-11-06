package integration

import (
	"context"
	"testing"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// The merge report lists exactly the assets the merge deleted, with the names
// stored in the review's tenant. A review row that names another tenant's
// asset is refused and nothing is deleted or reported.
func TestApproveAndMergeReport_ListsTheDeletedAssets(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()
	ctx := context.Background()

	tenant := createTestTenant(t, db, "dedupreport")
	other := createTestTenant(t, db, "dedupreport-other")
	keep := createTestAsset(t, db, tenant, "report-keep")
	m1 := createTestAsset(t, db, tenant, "report-merge-1")
	m2 := createTestAsset(t, db, tenant, "report-merge-2")
	foreign := createTestAsset(t, db, other, "report-foreign")

	insert := func(ids, names []string) shared.ID {
		id := shared.NewID()
		if _, err := db.Exec(`INSERT INTO asset_dedup_review
			(id, tenant_id, normalized_name, asset_type, keep_asset_id, keep_asset_name,
			 merge_asset_ids, merge_asset_names, status)
			VALUES ($1,$2,'report-keep','repository',$3,'report-keep',$4,$5,'pending')`,
			id.String(), tenant.String(), keep.String(), pq.Array(ids), pq.Array(names)); err != nil {
			t.Fatal(err)
		}
		return id
	}
	repo := postgres.NewAssetDedupRepository(&postgres.DB{DB: db})

	bad := insert([]string{m1.String(), foreign.String()}, []string{"report-merge-1", "report-foreign"})
	if rep, err := repo.ApproveAndMergeReport(ctx, tenant.String(), bad.String(), shared.NewID().String(), nil); err == nil || rep != nil {
		t.Fatalf("a review naming another tenant's asset must be refused, got %+v %v", rep, err)
	}
	var n int
	if err := db.QueryRow(`SELECT count(*) FROM assets WHERE id = ANY($1)`, pq.Array([]string{m1.String(), foreign.String()})).Scan(&n); err != nil || n != 2 {
		t.Fatalf("a refused merge deleted assets: n=%d err=%v", n, err)
	}
	if _, err := db.Exec(`DELETE FROM asset_dedup_review WHERE id = $1`, bad.String()); err != nil {
		t.Fatal(err)
	}

	reviewID := insert([]string{m1.String(), m2.String()}, []string{"report-merge-1", "report-merge-2"})
	rep, err := repo.ApproveAndMergeReport(ctx, tenant.String(), reviewID.String(), shared.NewID().String(), nil)
	if err != nil {
		t.Fatalf("merge: %v", err)
	}
	if rep.KeptAssetID != keep.String() || rep.KeptName != "report-keep" || rep.ReviewID != reviewID.String() {
		t.Errorf("report header = %+v", rep)
	}
	got := map[string]string{}
	for _, m := range rep.MergedAssets {
		got[m.ID] = m.Name
	}
	if len(got) != 2 || got[m1.String()] != "report-merge-1" || got[m2.String()] != "report-merge-2" {
		t.Errorf("merged assets = %v, want exactly the two", got)
	}
	if err := db.QueryRow(`SELECT count(*) FROM assets WHERE id = $1 AND tenant_id = $2`, foreign.String(), other.String()).Scan(&n); err != nil || n != 1 {
		t.Errorf("the other tenant's asset must survive: n=%d err=%v", n, err)
	}
}

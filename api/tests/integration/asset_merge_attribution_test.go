package integration

import (
	"context"
	"database/sql"
	"testing"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// mergeOne approves a review merging merge into keep.
func mergeOne(t *testing.T, db *sql.DB, tenant, keep, merge shared.ID) {
	t.Helper()
	reviewID := shared.NewID().String()
	if _, err := db.Exec(`INSERT INTO asset_dedup_review (id, tenant_id, normalized_name, asset_type, keep_asset_id, keep_asset_name, merge_asset_ids, merge_asset_names, status)
		VALUES ($1,$2,'n','host',$3,'k',$4,$5,'pending')`, reviewID, tenant.String(), keep.String(),
		pq.Array([]string{merge.String()}), pq.Array([]string{"m"})); err != nil {
		t.Fatal(err)
	}
	user := shared.NewID().String()
	if _, err := db.Exec(`INSERT INTO users (id, email, name) VALUES ($1, $2, 'merge')`, user, user+"@merge.test"); err != nil {
		t.Fatal(err)
	}
	if err := postgres.NewAssetDedupRepository(&postgres.DB{DB: db}).ApproveAndMerge(context.Background(), tenant.String(), reviewID, user, nil); err != nil {
		t.Fatalf("ApproveAndMerge: %v", err)
	}
}

func attributionOf(t *testing.T, db *sql.DB, asset shared.ID) (state string, human bool, found bool) {
	t.Helper()
	err := db.QueryRow(`SELECT state, decided_at IS NOT NULL FROM asset_attributions WHERE asset_id = $1`, asset.String()).Scan(&state, &human)
	if err == sql.ErrNoRows {
		return "", false, false
	}
	if err != nil {
		t.Fatal(err)
	}
	return state, human, true
}

// RFC-036 attribution survives an asset merge: a person's decision is never
// cascaded away, automation never demotes a legacy asset, and evidence moves
// without duplicates.
func TestApproveAndMerge_KeepsAttributionDecisions(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()
	tenant := createTestTenant(t, db, "mergeattr")
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := db.Exec(q, args...); err != nil {
			t.Fatalf("%v\n%s", err, q)
		}
	}
	attr := func(asset shared.ID, state string, decidedAgo string) {
		t.Helper()
		if decidedAgo == "" {
			exec(`INSERT INTO asset_attributions (asset_id, tenant_id, state, confidence) VALUES ($1,$2,$3,85)`, asset.String(), tenant.String(), state)
			return
		}
		exec(`INSERT INTO asset_attributions (asset_id, tenant_id, state, confidence, decided_at) VALUES ($1,$2,$3,85, now() - $4::interval)`,
			asset.String(), tenant.String(), state, decidedAgo)
	}

	// 1. The merged asset carries a person's rejection, the kept one only an
	//    automatic needs_review: the rejection moves to the kept asset.
	keep := createTestAsset(t, db, tenant, "k1-mergeattr")
	merge := createTestAsset(t, db, tenant, "m1-mergeattr")
	attr(keep, "needs_review", "")
	attr(merge, "rejected", "1 hour")
	mergeOne(t, db, tenant, keep, merge)
	if s, human, ok := attributionOf(t, db, keep); !ok || s != "rejected" || !human {
		t.Errorf("case 1: kept attribution = %q human=%v found=%v, want the person's rejection", s, human, ok)
	}

	// 2. Both decided by people: the most recent decision wins.
	keep = createTestAsset(t, db, tenant, "k2-mergeattr")
	merge = createTestAsset(t, db, tenant, "m2-mergeattr")
	attr(keep, "confirmed", "2 days")
	attr(merge, "dependency", "1 hour")
	mergeOne(t, db, tenant, keep, merge)
	if s, _, _ := attributionOf(t, db, keep); s != "dependency" {
		t.Errorf("case 2: kept attribution = %q, want the newer decision (dependency)", s)
	}
	keep = createTestAsset(t, db, tenant, "k3-mergeattr")
	merge = createTestAsset(t, db, tenant, "m3-mergeattr")
	attr(keep, "confirmed", "1 hour")
	attr(merge, "rejected", "2 days")
	mergeOne(t, db, tenant, keep, merge)
	if s, _, _ := attributionOf(t, db, keep); s != "confirmed" {
		t.Errorf("case 3: kept attribution = %q, want its own newer decision (confirmed)", s)
	}

	// 4. A legacy kept asset (no record) is not demoted by a merged asset's
	//    automatic needs_review; the evidence still moves, deduplicated, with
	//    the earliest first sighting.
	keep = createTestAsset(t, db, tenant, "k4-mergeattr")
	merge = createTestAsset(t, db, tenant, "m4-mergeattr")
	attr(merge, "needs_review", "")
	exec(`INSERT INTO easm_evidence (id, tenant_id, asset_id, rule, technique, source, weight, first_observed_at)
		VALUES ($1,$2,$3,'fqdn_under_asserted_root','cert_transparency','crt.sh',0.85, now() - interval '1 day'),
		       ($4,$2,$5,'fqdn_under_asserted_root','cert_transparency','crt.sh',0.85, now() - interval '9 days'),
		       ($6,$2,$5,'tenant_scanned','scan','sensor',0.95, now())`,
		shared.NewID().String(), tenant.String(), keep.String(), shared.NewID().String(), merge.String(), shared.NewID().String())
	mergeOne(t, db, tenant, keep, merge)
	if s, _, ok := attributionOf(t, db, keep); ok {
		t.Errorf("case 4: legacy kept asset got a record %q", s)
	}
	var n, oldDays int
	if err := db.QueryRow(`SELECT count(*), max(EXTRACT(day FROM now() - first_observed_at))::int FROM easm_evidence WHERE asset_id = $1`, keep.String()).Scan(&n, &oldDays); err != nil {
		t.Fatal(err)
	}
	if n != 2 || oldDays < 8 {
		t.Errorf("case 4: kept evidence rows=%d oldest=%dd, want 2 rows and the 9-day-old first sighting", n, oldDays)
	}
}

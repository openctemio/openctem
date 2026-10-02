package integration

import (
	"context"
	"testing"

	"github.com/lib/pq"
	"github.com/openctemio/api/internal/app/ingest"
	"github.com/openctemio/api/internal/infra/postgres"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/logger"
	"github.com/openctemio/ctis"
)

// TestApproveAndMerge_ConflictSafe verifies that merging duplicate assets:
//   - does NOT crash on UNIQUE/CHECK conflicts (asset_services, asset_relationships),
//   - preserves asset_components (previously cascade-deleted = data loss),
//   - drops would-be self-loop relationships,
//   - deletes the merged assets and marks the review merged.
func TestApproveAndMerge_ConflictSafe(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()
	ctx := context.Background()

	tenant := createTestTenant(t, db, "dedupmerge")
	keep := createTestAsset(t, db, tenant, "keep-asset")
	merge1 := createTestAsset(t, db, tenant, "merge-asset-1")
	other := createTestAsset(t, db, tenant, "other-asset")

	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := db.Exec(q, args...); err != nil {
			t.Fatalf("setup exec failed: %v\nquery: %s", err, q)
		}
	}
	svc := func(assetID shared.ID, port int, proto string) {
		exec(`INSERT INTO asset_services (id, tenant_id, asset_id, port, protocol)
			VALUES ($1,$2,$3,$4,$5)`, shared.NewID().String(), tenant.String(), assetID.String(), port, proto)
	}
	rel := func(src, tgt shared.ID, typ string) {
		exec(`INSERT INTO asset_relationships (id, tenant_id, source_asset_id, target_asset_id, relationship_type)
			VALUES ($1,$2,$3,$4,$5)`, shared.NewID().String(), tenant.String(), src.String(), tgt.String(), typ)
	}
	comp := func(assetID, compID shared.ID, path string) {
		exec(`INSERT INTO asset_components (id, tenant_id, asset_id, component_id, path, name, ecosystem)
			VALUES ($1,$2,$3,$4,$5,$6,'npm')`, shared.NewID().String(), tenant.String(), assetID.String(), compID.String(), path, "lib")
	}

	compA, compB := shared.NewID(), shared.NewID()

	// asset_services: keep tcp/443; merge1 tcp/443 (conflict→drop) + tcp/8080 (move)
	svc(keep, 443, "tcp")
	svc(merge1, 443, "tcp")
	svc(merge1, 8080, "tcp")

	// asset_relationships: merge1→other (move), merge1→keep (self-loop→drop),
	// keep→other depends_on + merge1→other depends_on (dup→drop one)
	rel(merge1, other, "contains")
	rel(merge1, keep, "depends_on")
	rel(keep, other, "depends_on")
	rel(merge1, other, "depends_on")

	// asset_components: keep compA@/a; merge1 compA@/a (conflict→drop) + compB@/b (move)
	comp(keep, compA, "/a")
	comp(merge1, compA, "/a")
	comp(merge1, compB, "/b")

	// review row (keep + merge1)
	reviewID := shared.NewID()
	exec(`INSERT INTO asset_dedup_review
		(id, tenant_id, normalized_name, asset_type, keep_asset_id, keep_asset_name,
		 merge_asset_ids, merge_asset_names, status)
		VALUES ($1,$2,'keep-asset','repository',$3,'keep-asset',$4,$5,'pending')`,
		reviewID.String(), tenant.String(), keep.String(),
		pq.Array([]string{merge1.String()}), pq.Array([]string{"merge-asset-1"}))

	// --- ACT ---
	repo := postgres.NewAssetDedupRepository(&postgres.DB{DB: db})
	if err := repo.ApproveAndMerge(ctx, tenant.String(), reviewID.String(), shared.NewID().String()); err != nil {
		t.Fatalf("ApproveAndMerge failed (should be conflict-safe): %v", err)
	}

	// --- ASSERT ---
	count := func(q string, args ...any) int {
		t.Helper()
		var n int
		if err := db.QueryRow(q, args...).Scan(&n); err != nil {
			t.Fatalf("count query failed: %v\n%s", err, q)
		}
		return n
	}

	// keep has both services (443 once, 8080 once) = 2, no duplicates
	if n := count(`SELECT COUNT(*) FROM asset_services WHERE asset_id=$1`, keep.String()); n != 2 {
		t.Errorf("keep services: expected 2 (443+8080), got %d", n)
	}
	// no orphaned services on merge1 (cascade-deleted with the asset)
	if n := count(`SELECT COUNT(*) FROM asset_services WHERE asset_id=$1`, merge1.String()); n != 0 {
		t.Errorf("merge1 services should be gone, got %d", n)
	}
	// relationships: keep→other contains (moved) + keep→other depends_on (1, deduped); no self-loop
	if n := count(`SELECT COUNT(*) FROM asset_relationships WHERE source_asset_id=$1 AND target_asset_id=$2`, keep.String(), other.String()); n != 2 {
		t.Errorf("keep→other relationships: expected 2 (contains+depends_on), got %d", n)
	}
	if n := count(`SELECT COUNT(*) FROM asset_relationships WHERE source_asset_id=target_asset_id`); n != 0 {
		t.Errorf("self-loop relationships must not exist, got %d", n)
	}
	// components: keep has compA@/a + compB@/b = 2
	if n := count(`SELECT COUNT(*) FROM asset_components WHERE asset_id=$1`, keep.String()); n != 2 {
		t.Errorf("keep components: expected 2 (compA+compB preserved), got %d", n)
	}
	// merge1 deleted
	if n := count(`SELECT COUNT(*) FROM assets WHERE id=$1`, merge1.String()); n != 0 {
		t.Errorf("merge1 asset should be deleted, got %d", n)
	}
	// review merged
	var status string
	if err := db.QueryRow(`SELECT status FROM asset_dedup_review WHERE id=$1`, reviewID.String()).Scan(&status); err != nil || status != "merged" {
		t.Errorf("review status: expected merged, got %q (err=%v)", status, err)
	}

	// cleanup
	_, _ = db.Exec(`DELETE FROM assets WHERE id = ANY($1)`, pq.Array([]string{keep.String(), other.String()}))
	_, _ = db.Exec(`DELETE FROM asset_dedup_review WHERE id=$1`, reviewID.String())
	_, _ = db.Exec(`DELETE FROM tenants WHERE id=$1`, tenant.String())
}

// TestUpsertReview_Idempotent verifies the enqueue path: repeated UpsertReview
// calls for the same (tenant, keep) update the single pending row instead of
// piling up duplicates, and the row is listable + approvable end-to-end.
func TestUpsertReview_Idempotent(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()
	ctx := context.Background()

	tenant := createTestTenant(t, db, "dedupenqueue")
	keep := createTestAsset(t, db, tenant, "keep")
	merge1 := createTestAsset(t, db, tenant, "merge1")
	merge2 := createTestAsset(t, db, tenant, "merge2")

	repo := postgres.NewAssetDedupRepository(&postgres.DB{DB: db})

	// First enqueue: keep + merge1
	if err := repo.UpsertReview(ctx, tenant.String(), "keep", "host", keep.String(), "keep", 0,
		[]string{merge1.String()}, []string{"merge1"}, 0); err != nil {
		t.Fatalf("first UpsertReview: %v", err)
	}
	// Second enqueue (same keep): merge1 + merge2 → must UPDATE the existing pending row
	if err := repo.UpsertReview(ctx, tenant.String(), "keep", "host", keep.String(), "keep", 0,
		[]string{merge1.String(), merge2.String()}, []string{"merge1", "merge2"}, 0); err != nil {
		t.Fatalf("second UpsertReview: %v", err)
	}

	pending, err := repo.ListPendingReviews(ctx, tenant.String())
	if err != nil {
		t.Fatalf("ListPendingReviews: %v", err)
	}
	if len(pending) != 1 {
		t.Fatalf("expected exactly 1 pending review (idempotent), got %d", len(pending))
	}
	if len(pending[0].MergeAssetIDs) != 2 {
		t.Errorf("expected refreshed review to have 2 merge targets, got %d", len(pending[0].MergeAssetIDs))
	}

	// Approve it → merge succeeds (exercises the full enqueue→approve loop)
	if err := repo.ApproveAndMerge(ctx, tenant.String(), pending[0].ID, shared.NewID().String()); err != nil {
		t.Fatalf("ApproveAndMerge after enqueue: %v", err)
	}
	var remaining int
	_ = db.QueryRow(`SELECT COUNT(*) FROM assets WHERE id = ANY($1)`,
		pq.Array([]string{merge1.String(), merge2.String()})).Scan(&remaining)
	if remaining != 0 {
		t.Errorf("merge assets should be deleted after approve, got %d", remaining)
	}

	// cleanup
	_, _ = db.Exec(`DELETE FROM assets WHERE id=$1`, keep.String())
	_, _ = db.Exec(`DELETE FROM asset_dedup_review WHERE tenant_id=$1`, tenant.String())
	_, _ = db.Exec(`DELETE FROM tenants WHERE id=$1`, tenant.String())
}

// TestIngestEnqueuesDedupReview exercises the REAL end-to-end path that was
// never verified: two existing host assets share an IP, an incoming scan asset
// with that IP arrives, the correlator detects the multi-match, and the
// processor enqueues a pending dedup review (previously MergeTargets was dropped).
func TestIngestEnqueuesDedupReview(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()
	ctx := context.Background()

	tenant := createTestTenant(t, db, "ingestdedup")

	// Two existing host assets sharing IP 10.0.0.5, non-stale (last_seen NOW).
	hostA, hostB := shared.NewID(), shared.NewID()
	for _, h := range []struct {
		id   shared.ID
		name string
	}{{hostA, "host-a-ingestdedup"}, {hostB, "host-b-ingestdedup"}} {
		if _, err := db.Exec(`INSERT INTO assets
			(id, tenant_id, name, asset_type, criticality, status, properties, last_seen, created_at, updated_at)
			VALUES ($1,$2,$3,'host','medium','active','{"ip":"10.0.0.5"}', NOW(), NOW(), NOW())`,
			h.id.String(), tenant.String(), h.name); err != nil {
			t.Fatalf("seed host %s: %v", h.name, err)
		}
	}

	log := logger.NewNop()
	repo := postgres.NewAssetRepository(&postgres.DB{DB: db})
	dedupRepo := postgres.NewAssetDedupRepository(&postgres.DB{DB: db})
	proc := ingest.NewAssetProcessor(repo, log)
	proc.SetCorrelator(ingest.NewAssetCorrelator(repo, log, ingest.CorrelationConfig{StaleAssetDays: 30, MaxIPsPerAsset: 20}))
	proc.SetDedupEnqueuer(dedupRepo)

	// Incoming asset: a host with the shared IP and a NON-matching name.
	report := &ctis.Report{
		Assets: []ctis.Asset{{
			ID:         "incoming-1",
			Type:       ctis.AssetType("host"),
			Value:      "scanner-discovered-host",
			Name:       "scanner-discovered-host",
			Properties: ctis.Properties{"ip": "10.0.0.5"},
		}},
	}
	out := &ingest.Output{}
	if _, err := proc.ProcessBatch(ctx, tenant, report, out, nil); err != nil {
		t.Fatalf("ProcessBatch: %v", err)
	}

	pending, err := dedupRepo.ListPendingReviews(ctx, tenant.String())
	if err != nil {
		t.Fatalf("ListPendingReviews: %v", err)
	}
	if len(pending) != 1 {
		t.Fatalf("expected 1 pending dedup review from ingest correlation, got %d (MergeTargets likely still dropped)", len(pending))
	}
	if len(pending[0].MergeAssetIDs) != 1 {
		t.Errorf("expected 1 merge target, got %d", len(pending[0].MergeAssetIDs))
	}

	// cleanup
	_, _ = db.Exec(`DELETE FROM asset_dedup_review WHERE tenant_id=$1`, tenant.String())
	_, _ = db.Exec(`DELETE FROM assets WHERE tenant_id=$1`, tenant.String())
	_, _ = db.Exec(`DELETE FROM tenants WHERE id=$1`, tenant.String())
}

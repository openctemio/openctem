package postgres

import (
	"context"
	"database/sql"
	"strings"
	"testing"

	_ "github.com/lib/pq"

	"github.com/openctemio/openctem/api/internal/testdb"
)

// ListAllNodes counts each asset's OPEN findings from one aggregate over the
// tenant's findings: closed and dispositioned findings and branch-only ones
// are left out, an asset without findings has 0, and another tenant's
// findings never count.
func TestListAllNodes_FindingCounts_DB(t *testing.T) {
	dbURL := testdb.URL()
	if dbURL == "" {
		t.Skip("DATABASE_URL not set; skipping DB execution check")
	}
	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer func() { _ = db.Close() }()
	ctx := context.Background()
	if err := db.PingContext(ctx); err != nil {
		t.Skipf("cannot reach DATABASE_URL: %v", err)
	}

	tenant := seedTestTenant(ctx, t, db)
	other := seedTestTenant(ctx, t, db)
	busy := seedPublicAsset(ctx, t, db, tenant)
	idle := seedPublicAsset(ctx, t, db, tenant)
	foreign := seedPublicAsset(ctx, t, db, other)
	t.Cleanup(func() {
		_, _ = db.ExecContext(context.Background(), `DELETE FROM findings WHERE tenant_id = ANY($1::uuid[])`,
			"{"+tenant.String()+","+other.String()+"}")
	})

	seedFinding(ctx, t, db, tenant, busy, "dast", "high", "new")
	seedFinding(ctx, t, db, tenant, busy, "dast", "low", "resolved")
	seedFinding(ctx, t, db, tenant, busy, "dast", "low", "false_positive")
	seedFinding(ctx, t, db, tenant, busy, "dast", "high", "confirmed")
	branchOnly := seedFinding(ctx, t, db, tenant, busy, "dast", "medium", "new")
	if _, err := db.ExecContext(ctx, `UPDATE findings SET branch_only = true WHERE id = $1`, branchOnly.String()); err != nil {
		t.Fatalf("mark branch-only: %v", err)
	}
	seedFinding(ctx, t, db, other, foreign, "dast", "critical", "new")

	nodes, err := NewAssetRepository(&DB{DB: db}).ListAllNodes(ctx, tenant)
	if err != nil {
		t.Fatalf("ListAllNodes: %v", err)
	}
	got := map[string]int{}
	for _, n := range nodes {
		got[n.ID] = n.FindingCount
	}
	if len(got) != 2 {
		t.Fatalf("nodes = %d, want the tenant's 2 assets only: %v", len(got), got)
	}
	if got[busy.String()] != 2 {
		t.Errorf("busy asset count = %d, want 2 (two open; resolved, false_positive and branch-only excluded)", got[busy.String()])
	}
	if c, ok := got[idle.String()]; !ok || c != 0 {
		t.Errorf("idle asset count = %d (present %v), want 0", c, ok)
	}
	if _, ok := got[foreign.String()]; ok {
		t.Error("another tenant's asset is listed")
	}
}

// The tenant rollups (dashboard stats, finding groups, graph node counts)
// read only columns of idx_findings_tenant_rollup_cover, so they can run as
// index-only scans. Dropping a column from it silently turns them back into
// scans of the wide findings rows.
func TestFindingsRollupCoverIndex_Columns_DB(t *testing.T) {
	dbURL := testdb.URL()
	if dbURL == "" {
		t.Skip("DATABASE_URL not set; skipping DB execution check")
	}
	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer func() { _ = db.Close() }()
	var def string
	err = db.QueryRowContext(context.Background(),
		`SELECT pg_get_indexdef('idx_findings_tenant_rollup_cover'::regclass)`).Scan(&def)
	if err != nil {
		t.Fatalf("index missing: %v", err)
	}
	for _, col := range []string{"tenant_id", "asset_id", "branch_only", "status", "severity", "priority_class", "created_at", "resolved_at", "cve_id", "cvss_score", "vulnerability_id", "source"} {
		if !strings.Contains(def, col) {
			t.Errorf("idx_findings_tenant_rollup_cover lacks %s: %s", col, def)
		}
	}
}

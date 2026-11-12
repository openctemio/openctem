package postgres

import (
	"context"
	"database/sql"
	"testing"

	_ "github.com/lib/pq"

	"github.com/openctemio/openctem/api/internal/testdb"
)

// ListOpenFindingAssetIDs returns each asset with an open finding once, never
// an asset whose findings are all closed, and never another tenant's asset.
func TestListOpenFindingAssetIDs_DB(t *testing.T) {
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

	tenant, other := seedTestTenant(ctx, t, db), seedTestTenant(ctx, t, db)
	open, closed, foreign := seedPublicAsset(ctx, t, db, tenant), seedPublicAsset(ctx, t, db, tenant), seedPublicAsset(ctx, t, db, other)
	t.Cleanup(func() {
		_, _ = db.ExecContext(context.Background(), `DELETE FROM findings WHERE tenant_id = ANY($1::uuid[])`,
			"{"+tenant.String()+","+other.String()+"}")
	})
	seedFinding(ctx, t, db, tenant, open, "dast", "high", "new")
	seedFinding(ctx, t, db, tenant, open, "dast", "low", "confirmed")
	seedFinding(ctx, t, db, tenant, closed, "dast", "high", "resolved")
	seedFinding(ctx, t, db, tenant, closed, "dast", "high", "false_positive")
	seedFinding(ctx, t, db, other, foreign, "dast", "critical", "new")

	ids, err := NewFindingRepository(&DB{DB: db}).ListOpenFindingAssetIDs(ctx, tenant)
	if err != nil {
		t.Fatalf("ListOpenFindingAssetIDs: %v", err)
	}
	if len(ids) != 1 || ids[0] != open {
		t.Fatalf("ids = %v, want only %s", ids, open)
	}
}

package postgres

import (
	"context"
	"database/sql"
	"testing"
	"time"

	_ "github.com/lib/pq"

	"github.com/openctemio/openctem/api/internal/testdb"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// A finding whose is_internet_accessible differs from its asset's is not an
// asset exposure change. The check_finding_exposure_consistency trigger used to
// record one anyway (change_type internet_exposure_changed, old = the asset's
// value, new = the finding's), so a new finding on an internal asset that a
// scanner tagged internet-facing showed up in "What changed", in "Newly
// exposed assets" and moved the dashboard's time-to-detect, while the asset
// itself never changed.
func TestFindingInsert_DoesNotRecordAssetExposureChange(t *testing.T) {
	dbURL := testdb.URL()
	if dbURL == "" {
		t.Skip("DATABASE_URL not set; skipping DB execution check")
	}
	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		t.Skipf("open db: %v", err)
	}
	defer func() { _ = db.Close() }()
	ctx := context.Background()
	if err := db.PingContext(ctx); err != nil {
		t.Skipf("cannot reach DATABASE_URL: %v", err)
	}

	tenant := seedTestTenant(ctx, t, db)
	assetID := shared.NewID()
	if _, err := db.ExecContext(ctx,
		`INSERT INTO assets (id, tenant_id, name, asset_type, scope, exposure, is_internet_accessible)
		 VALUES ($1,$2,'internal.corp','domain','internal','private',false)`,
		assetID.String(), tenant.String()); err != nil {
		t.Fatalf("seed asset: %v", err)
	}

	for i, internet := range []bool{true, false, true} {
		id := shared.NewID()
		if _, err := db.ExecContext(ctx, `
			INSERT INTO findings (id, tenant_id, asset_id, source, tool_name, message, severity, fingerprint, status, is_internet_accessible)
			VALUES ($1, $2, $3, 'dast', 'nuclei', 'msg', 'high', $4, 'new', $5)`,
			id.String(), tenant.String(), assetID.String(), id.String(), internet); err != nil {
			t.Fatalf("seed finding %d: %v", i, err)
		}
	}

	var rows int
	if err := db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM asset_state_history WHERE tenant_id = $1 AND asset_id = $2`,
		tenant.String(), assetID.String()).Scan(&rows); err != nil {
		t.Fatalf("count history: %v", err)
	}
	if rows != 0 {
		t.Fatalf("inserting findings wrote %d asset_state_history rows for an asset that did not change; want 0", rows)
	}

	repo := NewAssetStateHistoryRepository(&DB{DB: db})
	exposed, err := repo.GetNewlyExposedAssets(ctx, tenant, time.Now().Add(-time.Hour), 50)
	if err != nil {
		t.Fatalf("GetNewlyExposedAssets: %v", err)
	}
	if len(exposed) != 0 {
		t.Fatalf("internal asset listed as newly exposed (%d rows) only because a finding on it is tagged internet-facing", len(exposed))
	}
}

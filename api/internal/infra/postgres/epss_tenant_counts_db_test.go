package postgres

import (
	"context"
	"database/sql"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

func seedEPSS(ctx context.Context, t *testing.T, db *sql.DB, cve string, score float64) {
	t.Helper()
	if _, err := db.ExecContext(ctx,
		`INSERT INTO epss_scores (cve_id, epss_score, percentile, model_version, score_date)
		 VALUES ($1, $2, 0.5, 'test', CURRENT_DATE)
		 ON CONFLICT (cve_id) DO UPDATE SET epss_score = EXCLUDED.epss_score`, cve, score); err != nil {
		t.Fatalf("seed epss: %v", err)
	}
	t.Cleanup(func() {
		_, _ = db.ExecContext(context.Background(), `DELETE FROM epss_scores WHERE cve_id = $1`, cve)
	})
}

func seedCVEFinding(ctx context.Context, t *testing.T, db *sql.DB, tenantID, assetID shared.ID, cve, status string) {
	t.Helper()
	id := shared.NewID()
	if _, err := db.ExecContext(ctx, `
		INSERT INTO findings (id, tenant_id, asset_id, source, tool_name, message, severity, fingerprint, status, cve_id)
		VALUES ($1, $2, $3, 'sca', 'test', 'msg', 'high', $4, $5, $6)`,
		id.String(), tenantID.String(), assetID.String(), id.String(), status, cve); err != nil {
		t.Fatalf("seed finding: %v", err)
	}
}

// Both EPSS buckets now come from one query; the counts must be exactly the
// per-threshold tenant-scoped open counts the two separate queries returned.
func TestEPSSRepository_CountTenantOpenAboveScores(t *testing.T) {
	ctx := context.Background()
	db := openGroupsDB(t)
	repo := NewThreatIntelRepository(&DB{DB: db}).EPSS()

	tenantA := seedTestTenant(ctx, t, db)
	tenantB := seedTestTenant(ctx, t, db)
	assetA := seedOwnedAsset(ctx, t, db, tenantA, nil)
	assetB := seedOwnedAsset(ctx, t, db, tenantB, nil)

	seedEPSS(ctx, t, db, "CVE-2099-90001", 0.05)
	seedEPSS(ctx, t, db, "CVE-2099-90002", 0.20)
	seedEPSS(ctx, t, db, "CVE-2099-90003", 0.70)
	seedEPSS(ctx, t, db, "CVE-2099-90004", 0.95)

	seedCVEFinding(ctx, t, db, tenantA, assetA, "CVE-2099-90001", "new")       // below both
	seedCVEFinding(ctx, t, db, tenantA, assetA, "CVE-2099-90002", "new")       // high only
	seedCVEFinding(ctx, t, db, tenantA, assetA, "CVE-2099-90003", "confirmed") // high + critical
	seedCVEFinding(ctx, t, db, tenantA, assetA, "CVE-2099-90003", "new")       // same CVE, 2nd finding
	seedCVEFinding(ctx, t, db, tenantA, assetA, "CVE-2099-90004", "resolved")  // closed: excluded
	seedCVEFinding(ctx, t, db, tenantB, assetB, "CVE-2099-90004", "new")       // other tenant

	got, err := repo.CountTenantOpenAboveScores(ctx, tenantA, []float64{0.1, 0.5})
	if err != nil {
		t.Fatalf("CountTenantOpenAboveScores: %v", err)
	}
	if len(got) != 2 || got[0] != 3 || got[1] != 2 {
		t.Fatalf("want [3 2] (high, critical), got %v", got)
	}

	gotB, err := repo.CountTenantOpenAboveScores(ctx, tenantB, []float64{0.1, 0.5})
	if err != nil {
		t.Fatalf("tenant B: %v", err)
	}
	if gotB[0] != 1 || gotB[1] != 1 {
		t.Fatalf("tenant B: want [1 1], got %v", gotB)
	}

	empty, err := repo.CountTenantOpenAboveScores(ctx, tenantA, nil)
	if err != nil || len(empty) != 0 {
		t.Fatalf("no thresholds: got %v, %v", empty, err)
	}
}

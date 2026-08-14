package postgres

import (
	"context"
	"database/sql"
	"os"
	"testing"

	_ "github.com/lib/pq"

	"github.com/openctemio/api/pkg/domain/shared"
)

// A finding a PERSON fixed and closed (status resolved/verified with any
// resolution other than the auto ones) that a later scan re-detects used to stay
// resolved and invisible: AutoReopenByFingerprintsBatch only reopened
// resolution='auto_fixed'. It now reopens any finding closed as fixed EXCEPT
// deliberate dispositions (false_positive, accepted_risk, duplicate, suppressed).
// These tests exercise the real repository query against a migrated database.

func openReopenDB(t *testing.T) *sql.DB {
	t.Helper()
	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		t.Skip("DATABASE_URL not set; skipping reopen tests")
	}
	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		t.Skipf("open db: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := db.PingContext(context.Background()); err != nil {
		t.Skipf("cannot reach DATABASE_URL: %v", err)
	}
	return db
}

// seedClosedFinding inserts a finding in the given status with the given
// resolution, and returns its id and fingerprint.
func seedClosedFinding(ctx context.Context, t *testing.T, db *sql.DB, tenantID, assetID shared.ID, status, resolution string) (shared.ID, string) {
	t.Helper()
	id := shared.NewID()
	fp := "fp-reopen-" + id.String()
	label := "reopen probe " + id.String()
	var res any
	if resolution == "" {
		res = nil
	} else {
		res = resolution
	}
	_, err := db.ExecContext(ctx,
		`INSERT INTO findings (id, tenant_id, asset_id, title, source, tool_name, message,
		                       fingerprint, severity, status, resolution, resolved_at)
		 VALUES ($1,$2,$3,$4,'sast','probe-tool',$5,$6,'high',$7,$8,NOW())`,
		id.String(), tenantID.String(), assetID.String(), label, label, fp, status, res)
	if err != nil {
		t.Fatalf("seed finding (status=%s resolution=%s): %v", status, resolution, err)
	}
	return id, fp
}

func statusOf(ctx context.Context, t *testing.T, db *sql.DB, id shared.ID) string {
	t.Helper()
	var status string
	if err := db.QueryRowContext(ctx, `SELECT status FROM findings WHERE id=$1`, id.String()).Scan(&status); err != nil {
		t.Fatalf("read status: %v", err)
	}
	return status
}

func TestAutoReopenBatch_HumanResolvedReopens_DeliberateDispositionsDoNot(t *testing.T) {
	db := openReopenDB(t)
	ctx := context.Background()
	repo := NewFindingRepository(&DB{DB: db})

	tenantID := seedTestTenant(ctx, t, db)
	assetID := seedTestAsset(ctx, t, db, tenantID)

	// Should reopen: human-resolved (a non-auto resolution note), auto_fixed,
	// verified, and a resolved finding with NULL resolution.
	humanID, humanFP := seedClosedFinding(ctx, t, db, tenantID, assetID, "resolved", "security_reviewed")
	autoID, autoFP := seedClosedFinding(ctx, t, db, tenantID, assetID, "resolved", "auto_fixed")
	verifiedID, verifiedFP := seedClosedFinding(ctx, t, db, tenantID, assetID, "verified", "manual_retest_passed")
	nullResID, nullResFP := seedClosedFinding(ctx, t, db, tenantID, assetID, "resolved", "")

	// Should NOT reopen: deliberate dispositions carried in the resolution column.
	fpDispoID, fpDispoFP := seedClosedFinding(ctx, t, db, tenantID, assetID, "resolved", "false_positive")
	acceptID, acceptFP := seedClosedFinding(ctx, t, db, tenantID, assetID, "resolved", "accepted_risk")

	fps := []string{humanFP, autoFP, verifiedFP, nullResFP, fpDispoFP, acceptFP}
	reopened, err := repo.AutoReopenByFingerprintsBatch(ctx, tenantID, fps)
	if err != nil {
		t.Fatalf("AutoReopenByFingerprintsBatch: %v", err)
	}

	// Reopened set must be exactly the four fixed findings.
	for _, fp := range []string{humanFP, autoFP, verifiedFP, nullResFP} {
		if _, ok := reopened[fp]; !ok {
			t.Errorf("fingerprint %s was not reopened but should have been", fp)
		}
	}
	for _, fp := range []string{fpDispoFP, acceptFP} {
		if _, ok := reopened[fp]; ok {
			t.Errorf("fingerprint %s was reopened but is a deliberate disposition", fp)
		}
	}

	// Confirm persisted status: reopened → confirmed; dispositions → resolved.
	if got := statusOf(ctx, t, db, humanID); got != "confirmed" {
		t.Errorf("human-resolved finding status = %s, want confirmed", got)
	}
	if got := statusOf(ctx, t, db, autoID); got != "confirmed" {
		t.Errorf("auto_fixed finding status = %s, want confirmed", got)
	}
	if got := statusOf(ctx, t, db, verifiedID); got != "confirmed" {
		t.Errorf("verified finding status = %s, want confirmed", got)
	}
	if got := statusOf(ctx, t, db, nullResID); got != "confirmed" {
		t.Errorf("null-resolution finding status = %s, want confirmed", got)
	}
	if got := statusOf(ctx, t, db, fpDispoID); got != "resolved" {
		t.Errorf("false_positive-resolution finding status = %s, want resolved (unchanged)", got)
	}
	if got := statusOf(ctx, t, db, acceptID); got != "resolved" {
		t.Errorf("accepted_risk-resolution finding status = %s, want resolved (unchanged)", got)
	}

	// The regression trigger (migration 000199) must have classified the reopen:
	// resolved/verified → confirmed counts as a failed fix.
	var isRegression bool
	var reopenCount int
	if err := db.QueryRowContext(ctx,
		`SELECT COALESCE(is_regression,false), COALESCE(reopen_count,0) FROM findings WHERE id=$1`,
		humanID.String()).Scan(&isRegression, &reopenCount); err != nil {
		t.Fatalf("read regression state: %v", err)
	}
	if !isRegression || reopenCount != 1 {
		t.Errorf("human reopen not counted as regression: is_regression=%v reopen_count=%d", isRegression, reopenCount)
	}
}

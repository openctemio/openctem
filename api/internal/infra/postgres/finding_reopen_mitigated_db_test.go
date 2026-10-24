package postgres

import (
	"context"
	"database/sql"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// A finding closed as mitigated (a compensating control) is not reopened by
// detection; one closed as fixed is, whatever its free-text resolution note
// says. These run the real query against a migrated database.

func closeWithReason(ctx context.Context, t *testing.T, db *sql.DB, id shared.ID, reason string) {
	t.Helper()
	if _, err := db.ExecContext(ctx, `UPDATE findings SET closure_reason=$2 WHERE id=$1`, id.String(), reason); err != nil {
		t.Fatalf("set closure_reason %s: %v", reason, err)
	}
}

func mitRegressionState(ctx context.Context, t *testing.T, db *sql.DB, id shared.ID) (isRegression bool, count int) {
	t.Helper()
	if err := db.QueryRowContext(ctx,
		`SELECT COALESCE(is_regression,false), COALESCE(reopen_count,0) FROM findings WHERE id=$1`,
		id.String()).Scan(&isRegression, &count); err != nil {
		t.Fatalf("read regression state: %v", err)
	}
	return
}

func TestAutoReopenBatch_MitigatedStaysResolved(t *testing.T) {
	db := openReopenDB(t)
	ctx := context.Background()
	repo := NewFindingRepository(&DB{DB: db})
	tenantID := seedTestTenant(ctx, t, db)
	assetID := seedTestAsset(ctx, t, db, tenantID)

	mitID, mitFP := seedClosedFinding(ctx, t, db, tenantID, assetID, "resolved", "compensating_control")
	closeWithReason(ctx, t, db, mitID, "mitigated")
	fixedID, fixedFP := seedClosedFinding(ctx, t, db, tenantID, assetID, "resolved", "")
	closeWithReason(ctx, t, db, fixedID, "fixed")
	// Free-text note reads "duplicate" but the closure is fixed: a real regression.
	dupID, dupFP := seedClosedFinding(ctx, t, db, tenantID, assetID, "resolved", "duplicate")
	closeWithReason(ctx, t, db, dupID, "fixed")

	reopened, err := repo.AutoReopenByFingerprintsBatch(ctx, tenantID, []string{mitFP, fixedFP, dupFP})
	if err != nil {
		t.Fatalf("AutoReopenByFingerprintsBatch: %v", err)
	}
	if _, ok := reopened[mitFP]; ok {
		t.Errorf("mitigated finding was reopened by detection")
	}
	for _, fp := range []string{fixedFP, dupFP} {
		if _, ok := reopened[fp]; !ok {
			t.Errorf("fixed finding %s was not reopened", fp)
		}
	}
	if got := statusOf(ctx, t, db, mitID); got != "resolved" {
		t.Errorf("mitigated status = %s, want resolved", got)
	}
	var reason string
	var resolvedAt sql.NullTime
	if err := db.QueryRowContext(ctx, `SELECT COALESCE(closure_reason,''), resolved_at FROM findings WHERE id=$1`, mitID.String()).Scan(&reason, &resolvedAt); err != nil {
		t.Fatal(err)
	}
	if reason != "mitigated" || !resolvedAt.Valid {
		t.Errorf("mitigated closure was touched: reason=%q resolved_at valid=%v", reason, resolvedAt.Valid)
	}
	if reg, n := mitRegressionState(ctx, t, db, mitID); reg || n != 0 {
		t.Errorf("mitigated finding flagged as regression: %v %d", reg, n)
	}
	var reopenedAt sql.NullTime
	if err := db.QueryRowContext(ctx, `SELECT last_reopened_at FROM findings WHERE id=$1`, mitID.String()).Scan(&reopenedAt); err != nil {
		t.Fatal(err)
	}
	if reopenedAt.Valid {
		t.Errorf("mitigated finding's SLA clock restarted (last_reopened_at set)")
	}
	for _, id := range []shared.ID{fixedID, dupID} {
		if got := statusOf(ctx, t, db, id); got != "new" {
			t.Errorf("fixed finding status = %s, want new (never triaged)", got)
		}
		if reg, n := mitRegressionState(ctx, t, db, id); !reg || n != 1 {
			t.Errorf("fixed reopen not a regression: %v %d", reg, n)
		}
	}
}

func TestAutoReopenBatch_TenantIsolationSameFingerprint(t *testing.T) {
	db := openReopenDB(t)
	ctx := context.Background()
	repo := NewFindingRepository(&DB{DB: db})
	tenantA := seedTestTenant(ctx, t, db)
	tenantB := seedTestTenant(ctx, t, db)
	assetA := seedTestAsset(ctx, t, db, tenantA)
	assetB := seedTestAsset(ctx, t, db, tenantB)

	idA, fp := seedClosedFinding(ctx, t, db, tenantA, assetA, "resolved", "")
	closeWithReason(ctx, t, db, idA, "fixed")
	idB, fpB := seedClosedFinding(ctx, t, db, tenantB, assetB, "resolved", "")
	closeWithReason(ctx, t, db, idB, "fixed")
	// Give tenant B's row the same fingerprint as tenant A's.
	if _, err := db.ExecContext(ctx, `UPDATE findings SET fingerprint=$2 WHERE id=$1`, idB.String(), fp); err != nil {
		t.Fatalf("share fingerprint (was %s): %v", fpB, err)
	}

	if _, err := repo.AutoReopenByFingerprintsBatch(ctx, tenantA, []string{fp}); err != nil {
		t.Fatalf("AutoReopenByFingerprintsBatch: %v", err)
	}
	if got := statusOf(ctx, t, db, idA); got != "new" {
		t.Errorf("tenant A status = %s, want new (never triaged)", got)
	}
	if got := statusOf(ctx, t, db, idB); got != "resolved" {
		t.Errorf("tenant B status = %s, want resolved (untouched)", got)
	}
}

func TestHumanResolvedFingerprints_SkipsMitigated(t *testing.T) {
	db := openReopenDB(t)
	ctx := context.Background()
	repo := NewFindingRepository(&DB{DB: db})
	tenantID := seedTestTenant(ctx, t, db)
	assetID := seedTestAsset(ctx, t, db, tenantID)

	mitID, mitFP := seedClosedFinding(ctx, t, db, tenantID, assetID, "resolved", "")
	closeWithReason(ctx, t, db, mitID, "mitigated")
	fixedID, fixedFP := seedClosedFinding(ctx, t, db, tenantID, assetID, "resolved", "duplicate")
	closeWithReason(ctx, t, db, fixedID, "fixed")

	got, err := repo.HumanResolvedFingerprints(ctx, tenantID, []string{mitFP, fixedFP})
	if err != nil {
		t.Fatal(err)
	}
	if got[mitFP] {
		t.Errorf("mitigated finding listed as guarded")
	}
	if !got[fixedFP] {
		t.Errorf("fixed finding with a 'duplicate' note not listed as guarded")
	}
}

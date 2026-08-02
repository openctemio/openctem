package postgres

import (
	"context"
	"database/sql"
	"os"
	"testing"

	_ "github.com/lib/pq"

	"github.com/openctemio/api/pkg/domain/shared"
)

// The executive summary reports "N regressions recorded" and a regression rate
// in the UI, the CSV export and the emailed digest. Migration 000152 added the
// three columns it reads and nothing ever wrote them, so all three surfaces
// have been reporting 0 regressions / 0.0% as fact since April.
//
// Migration 000199 marks the flag in a BEFORE UPDATE trigger. These tests hold
// it to the definition the executive summary actually needs, which is narrower
// than "any reopen":
//
//   - resolved/verified -> open counts (a fix that failed)
//   - false_positive/accepted_risk -> open does NOT (a triage correction)
//
// The second rule matters because the rate's denominator is
// COUNT(status IN ('resolved','verified')). Counting reclassifications in the
// numerator would produce a rate over two different populations, which is
// worse than the zero it replaces: it looks computed.

func openRegressionDB(t *testing.T) *sql.DB {
	t.Helper()

	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		t.Skip("DATABASE_URL not set; skipping regression-tracking tests")
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

// seedRegressionFinding inserts a finding in the given status.
func seedRegressionFinding(ctx context.Context, t *testing.T, db *sql.DB, tenantID, assetID shared.ID, status string) shared.ID {
	t.Helper()

	id := shared.NewID()
	label := "regression probe " + id.String()
	_, err := db.ExecContext(ctx,
		`INSERT INTO findings (id, tenant_id, asset_id, title, source, tool_name, message,
		                       fingerprint, severity, status, resolution, resolved_at)
		 VALUES ($1, $2, $3, $4, 'sast', 'probe-tool', $5, $6, 'high', $7, 'auto_fixed', NOW())`,
		id.String(), tenantID.String(), assetID.String(),
		label, label, "fp-"+id.String(), status)
	if err != nil {
		t.Fatalf("seed finding (status=%s): %v", status, err)
	}
	return id
}

type regressionState struct {
	isRegression bool
	reopenCount  int
	lastReopened sql.NullTime
}

func readRegression(ctx context.Context, t *testing.T, db *sql.DB, id shared.ID) regressionState {
	t.Helper()
	var s regressionState
	err := db.QueryRowContext(ctx,
		`SELECT COALESCE(is_regression, false), COALESCE(reopen_count, 0), last_reopened_at
		   FROM findings WHERE id = $1`, id.String()).
		Scan(&s.isRegression, &s.reopenCount, &s.lastReopened)
	if err != nil {
		t.Fatalf("read regression state: %v", err)
	}
	return s
}

// The batch scan-ingest path: a set-based UPDATE that never loads the entity.
// This is how the overwhelming majority of reopens happen.
func TestRegression_BatchReopenIsCounted(t *testing.T) {
	db := openRegressionDB(t)
	ctx := context.Background()

	tenantID := seedTestTenant(ctx, t, db)
	assetID := seedTestAsset(ctx, t, db, tenantID)
	id := seedRegressionFinding(ctx, t, db, tenantID, assetID, "resolved")

	// Exactly what AutoReopenByFingerprintsBatch does.
	if _, err := db.ExecContext(ctx,
		`UPDATE findings SET status='confirmed', resolution=NULL, resolved_at=NULL WHERE id=$1`,
		id.String()); err != nil {
		t.Fatalf("reopen: %v", err)
	}

	got := readRegression(ctx, t, db, id)
	if !got.isRegression {
		t.Error("is_regression is false after a resolved -> confirmed reopen; the executive summary will keep reporting 0")
	}
	if got.reopenCount != 1 {
		t.Errorf("reopen_count = %d, want 1", got.reopenCount)
	}
	if !got.lastReopened.Valid {
		t.Error("last_reopened_at is NULL — the summary windows on it, so the row is invisible even when flagged")
	}
}

// Reopening twice must count twice; the flag is sticky, the counter is not.
func TestRegression_SecondReopenIncrements(t *testing.T) {
	db := openRegressionDB(t)
	ctx := context.Background()

	tenantID := seedTestTenant(ctx, t, db)
	assetID := seedTestAsset(ctx, t, db, tenantID)
	id := seedRegressionFinding(ctx, t, db, tenantID, assetID, "resolved")

	for i := 0; i < 2; i++ {
		if _, err := db.ExecContext(ctx, `UPDATE findings SET status='confirmed' WHERE id=$1`, id.String()); err != nil {
			t.Fatalf("reopen %d: %v", i, err)
		}
		if _, err := db.ExecContext(ctx, `UPDATE findings SET status='resolved' WHERE id=$1`, id.String()); err != nil {
			t.Fatalf("re-resolve %d: %v", i, err)
		}
	}

	got := readRegression(ctx, t, db, id)
	if got.reopenCount != 2 {
		t.Errorf("reopen_count = %d after two reopen cycles, want 2", got.reopenCount)
	}
	if !got.isRegression {
		t.Error("is_regression cleared by re-resolving — it must stay true; the summary asks about history")
	}
}

// A false positive being reopened is a triage correction, not a failed fix.
// Counting it would put reclassifications in a numerator whose denominator is
// COUNT(resolved|verified).
func TestRegression_FalsePositiveReopenIsNotCounted(t *testing.T) {
	db := openRegressionDB(t)
	ctx := context.Background()

	tenantID := seedTestTenant(ctx, t, db)
	assetID := seedTestAsset(ctx, t, db, tenantID)
	id := seedRegressionFinding(ctx, t, db, tenantID, assetID, "false_positive")

	if _, err := db.ExecContext(ctx, `UPDATE findings SET status='confirmed' WHERE id=$1`, id.String()); err != nil {
		t.Fatalf("reopen: %v", err)
	}

	got := readRegression(ctx, t, db, id)
	if got.isRegression {
		t.Error("false_positive -> confirmed counted as a regression; that is a reclassification, not a fix that failed")
	}
	if got.reopenCount != 0 {
		t.Errorf("reopen_count = %d, want 0", got.reopenCount)
	}
}

// Closing a finding must never mark it, and neither must the constant
// non-status updates from rescans and enrichment.
func TestRegression_ClosingAndUnrelatedUpdatesDoNotMark(t *testing.T) {
	db := openRegressionDB(t)
	ctx := context.Background()

	tenantID := seedTestTenant(ctx, t, db)
	assetID := seedTestAsset(ctx, t, db, tenantID)
	id := seedRegressionFinding(ctx, t, db, tenantID, assetID, "confirmed")

	if _, err := db.ExecContext(ctx, `UPDATE findings SET status='resolved' WHERE id=$1`, id.String()); err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if _, err := db.ExecContext(ctx, `UPDATE findings SET severity='critical' WHERE id=$1`, id.String()); err != nil {
		t.Fatalf("severity update: %v", err)
	}

	got := readRegression(ctx, t, db, id)
	if got.isRegression || got.reopenCount != 0 {
		t.Errorf("marked by closing or by an unrelated update: is_regression=%v reopen_count=%d",
			got.isRegression, got.reopenCount)
	}
}

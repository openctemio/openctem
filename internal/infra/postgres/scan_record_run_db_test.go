package postgres

import (
	"context"
	"database/sql"
	"os"
	"testing"

	_ "github.com/lib/pq"

	"github.com/openctemio/api/pkg/domain/shared"
)

// The scan-completion fix (pipeline recordScanRun) relies on
// ScanRepository.RecordRun actually persisting last_run_at/last_run_status and
// moving the counters. The generic Update() does NOT carry these columns — that
// is why the trigger-time record silently vanished and the scan read "never
// run" after a completed run. This pins the dedicated method's behavior so the
// completion path it now backs cannot regress.

func TestRecordRun_PersistsStatusAndMovesCounters(t *testing.T) {
	ctx := context.Background()
	db := openScanRecDB(t)
	repo := NewScanRepository(&DB{DB: db})
	tenantID := seedScanRecTenant(ctx, t, db)

	scanID := shared.NewID()
	if _, err := db.ExecContext(ctx,
		`INSERT INTO scans (id, tenant_id, name, scan_type, scanner_name, total_runs, successful_runs, failed_runs)
		 VALUES ($1, $2, 'completion probe', 'single', 'gitleaks', 0, 0, 0)`,
		scanID.String(), tenantID.String()); err != nil {
		t.Fatalf("seed scan: %v", err)
	}
	t.Cleanup(func() {
		_, _ = db.ExecContext(context.Background(), `DELETE FROM scans WHERE id = $1`, scanID.String())
	})

	runID := seedPipelineRun(ctx, t, db, tenantID)
	if err := repo.RecordRun(ctx, scanID, runID, "completed"); err != nil {
		t.Fatalf("RecordRun: %v", err)
	}

	var (
		status    sql.NullString
		at        sql.NullTime
		lastRun   sql.NullString
		total     int
		succeeded int
		failed    int
	)
	if err := db.QueryRowContext(ctx,
		`SELECT last_run_status, last_run_at, last_run_id, total_runs, successful_runs, failed_runs
		   FROM scans WHERE id = $1`, scanID.String(),
	).Scan(&status, &at, &lastRun, &total, &succeeded, &failed); err != nil {
		t.Fatalf("read back: %v", err)
	}

	if !status.Valid || status.String != "completed" {
		t.Errorf("last_run_status = %v, want \"completed\": a scan that just finished "+
			"must not read as never-run", status)
	}
	if !at.Valid {
		t.Error("last_run_at is NULL after a completed run")
	}
	if !lastRun.Valid || lastRun.String != runID.String() {
		t.Errorf("last_run_id = %v, want %s", lastRun, runID)
	}
	if total != 1 || succeeded != 1 || failed != 0 {
		t.Errorf("counters = total %d / ok %d / failed %d, want 1/1/0", total, succeeded, failed)
	}
}

func TestRecordRun_FailedStatusIncrementsFailedCounter(t *testing.T) {
	ctx := context.Background()
	db := openScanRecDB(t)
	repo := NewScanRepository(&DB{DB: db})
	tenantID := seedScanRecTenant(ctx, t, db)

	scanID := shared.NewID()
	if _, err := db.ExecContext(ctx,
		`INSERT INTO scans (id, tenant_id, name, scan_type, scanner_name)
		 VALUES ($1, $2, 'failed probe', 'single', 'gitleaks')`,
		scanID.String(), tenantID.String()); err != nil {
		t.Fatalf("seed scan: %v", err)
	}
	t.Cleanup(func() {
		_, _ = db.ExecContext(context.Background(), `DELETE FROM scans WHERE id = $1`, scanID.String())
	})

	if err := repo.RecordRun(ctx, scanID, seedPipelineRun(ctx, t, db, tenantID), "failed"); err != nil {
		t.Fatalf("RecordRun: %v", err)
	}

	var status string
	var total, succeeded, failed int
	if err := db.QueryRowContext(ctx,
		`SELECT last_run_status, total_runs, successful_runs, failed_runs FROM scans WHERE id = $1`,
		scanID.String()).Scan(&status, &total, &succeeded, &failed); err != nil {
		t.Fatalf("read back: %v", err)
	}
	if status != "failed" || total != 1 || succeeded != 0 || failed != 1 {
		t.Errorf("got status=%q total=%d ok=%d failed=%d, want failed/1/0/1",
			status, total, succeeded, failed)
	}
}

func openScanRecDB(t *testing.T) *sql.DB {
	t.Helper()
	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		t.Skip("DATABASE_URL not set; skipping scan RecordRun DB test")
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

func seedScanRecTenant(ctx context.Context, t *testing.T, db *sql.DB) shared.ID {
	t.Helper()
	id := shared.NewID()
	if _, err := db.ExecContext(ctx,
		`INSERT INTO tenants (id, name, slug) VALUES ($1, $2, $3)`,
		id.String(), "scan recordrun test", "scanrec-"+id.String()); err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	t.Cleanup(func() {
		_, _ = db.ExecContext(context.Background(), `DELETE FROM tenants WHERE id = $1`, id.String())
	})
	return id
}

// seedPipelineRun inserts a minimal pipeline_run so last_run_id's FK
// (fk_scans_last_run -> pipeline_runs.id) is satisfied. In production the
// completion path always passes a real run id; the test must mirror that.
func seedPipelineRun(ctx context.Context, t *testing.T, db *sql.DB, tenantID shared.ID) shared.ID {
	t.Helper()
	id := shared.NewID()
	if _, err := db.ExecContext(ctx,
		`INSERT INTO pipeline_runs (id, pipeline_id, tenant_id, trigger_type)
		 VALUES ($1, '00000000-0000-0000-0000-000000000001', $2, 'schedule')`,
		id.String(), tenantID.String()); err != nil {
		t.Fatalf("seed pipeline_run: %v", err)
	}
	t.Cleanup(func() {
		_, _ = db.ExecContext(context.Background(), `DELETE FROM pipeline_runs WHERE id = $1`, id.String())
	})
	return id
}

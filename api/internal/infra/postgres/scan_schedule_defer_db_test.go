package postgres

import (
	"context"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// A scheduled run stopped by a freeze window moves next_run_at to the end of
// the window: compare-and-set from the value the claim wrote (NULL when the
// schedule had no further occurrence), only in the scan's tenant.
func TestDeferScheduledRun(t *testing.T) {
	ctx := context.Background()
	db := openScanDB(t)
	repo := NewScanRepository(&DB{DB: db})
	tenantID := seedScanTriggerTenant(ctx, t, db)
	otherTenant := seedScanTriggerTenant(ctx, t, db)

	scanID := shared.NewID()
	if _, err := db.ExecContext(ctx,
		`INSERT INTO scans (id, tenant_id, name, scan_type, scanner_name, schedule_type, next_run_at, status)
		 VALUES ($1, $2, 'defer probe', 'single', 'nuclei', 'daily', NULL, 'active')`,
		scanID.String(), tenantID.String()); err != nil {
		t.Fatalf("seed scan: %v", err)
	}
	until := time.Now().Add(2 * time.Hour).UTC().Truncate(time.Microsecond)
	if ok, err := repo.DeferScheduledRun(ctx, otherTenant, scanID, nil, until); err != nil || ok {
		t.Fatalf("another tenant deferred the scan: ok=%v err=%v", ok, err)
	}
	if ok, err := repo.DeferScheduledRun(ctx, tenantID, scanID, nil, until); err != nil || !ok {
		t.Fatalf("defer from NULL: ok=%v err=%v", ok, err)
	}
	// A stale expected value (the scan changed meanwhile) does not move it.
	if ok, _ := repo.DeferScheduledRun(ctx, tenantID, scanID, nil, until.Add(time.Hour)); ok {
		t.Fatal("deferred although next_run_at no longer held the expected value")
	}
	var got time.Time
	if err := db.QueryRowContext(ctx, `SELECT next_run_at FROM scans WHERE id = $1`, scanID.String()).Scan(&got); err != nil {
		t.Fatal(err)
	}
	if !got.Equal(until) {
		t.Fatalf("next_run_at = %v, want %v", got, until)
	}
}

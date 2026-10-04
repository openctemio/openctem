package postgres

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// The scheduler used a session-level pg_try_advisory_lock through the pool:
// the unlock ran on another pooled session, released nothing, and the lock
// stayed held until that connection closed, after which the scan was skipped
// as "locked by another instance" on every replica. ClaimScheduledRun is a
// compare-and-set on next_run_at instead: one winner per due occurrence.
func TestClaimScheduledRun_OneWinnerPerOccurrence(t *testing.T) {
	ctx := context.Background()
	db := openScanDB(t)
	repo := NewScanRepository(&DB{DB: db})
	tenantID := seedScanTriggerTenant(ctx, t, db)

	due := time.Now().Add(-time.Minute).UTC().Truncate(time.Microsecond)
	scanID := shared.NewID()
	if _, err := db.ExecContext(ctx,
		`INSERT INTO scans (id, tenant_id, name, scan_type, scanner_name, schedule_type, next_run_at, status)
		 VALUES ($1, $2, 'claim probe', 'single', 'nuclei', 'daily', $3, 'active')`,
		scanID.String(), tenantID.String(), due); err != nil {
		t.Fatalf("seed scan: %v", err)
	}

	next := due.Add(24 * time.Hour)
	var wins int32
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ { // eight "replicas" racing for the same occurrence
		wg.Add(1)
		go func() {
			defer wg.Done()
			ok, err := repo.ClaimScheduledRun(ctx, tenantID, scanID, due, &next)
			if err != nil {
				t.Errorf("claim: %v", err)
			}
			if ok {
				atomic.AddInt32(&wins, 1)
			}
		}()
	}
	wg.Wait()
	if wins != 1 {
		t.Fatalf("%d claims won, want exactly 1", wins)
	}

	// The next occurrence is claimable again: nothing stays "locked".
	next2 := next.Add(24 * time.Hour)
	if ok, err := repo.ClaimScheduledRun(ctx, tenantID, scanID, next, &next2); err != nil || !ok {
		t.Fatalf("next occurrence: ok=%v err=%v, want claimable", ok, err)
	}

	// A paused scan is not claimed.
	if _, err := db.ExecContext(ctx, `UPDATE scans SET status = 'paused' WHERE id = $1`, scanID.String()); err != nil {
		t.Fatal(err)
	}
	if ok, _ := repo.ClaimScheduledRun(ctx, tenantID, scanID, next2, &next2); ok {
		t.Fatal("claimed a paused scan")
	}
}

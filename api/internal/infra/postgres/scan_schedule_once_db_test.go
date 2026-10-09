package postgres

// One-off scheduled scans (schedule_type once, migration 001542): the run time
// is stored and read back, the scan is due at it, and once claimed it has no
// next run and is not reported as an inert schedule.

import (
	"context"
	"slices"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/scan"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

func TestScanScheduleOnce_StoredDueAndClaimed_DB(t *testing.T) {
	ctx := context.Background()
	db := openScanDB(t)
	repo := NewScanRepository(&DB{DB: db})
	tenantID := seedScanTriggerTenant(ctx, t, db)

	sc, err := scan.NewScan(tenantID, "once-"+shared.NewID().String()[:8], shared.ID{}, scan.ScanTypeSingle)
	if err != nil {
		t.Fatal(err)
	}
	sc.SetTargets([]string{"example.com"})
	if err := sc.SetSingleScanner("nuclei", nil, 1); err != nil {
		t.Fatal(err)
	}
	runAt := time.Now().Add(2 * time.Hour).UTC().Truncate(time.Second)
	if err := sc.SetOnceSchedule(&runAt, "Asia/Ho_Chi_Minh", time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := repo.Create(ctx, sc); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = db.ExecContext(context.Background(), `DELETE FROM scans WHERE id = $1`, sc.ID.String()) })

	got, err := repo.GetByTenantAndID(ctx, tenantID, sc.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.ScheduleType != scan.ScheduleOnce || got.ScheduleRunAt == nil || !got.ScheduleRunAt.Equal(runAt) ||
		got.NextRunAt == nil || !got.NextRunAt.Equal(runAt) || got.ScheduleTimezone != "Asia/Ho_Chi_Minh" {
		t.Fatalf("read back type %s run_at %v next %v tz %s", got.ScheduleType, got.ScheduleRunAt, got.NextRunAt, got.ScheduleTimezone)
	}

	due := func(at time.Time) bool {
		t.Helper()
		list, err := repo.ListDueForExecution(ctx, at)
		if err != nil {
			t.Fatal(err)
		}
		return slices.ContainsFunc(list, func(s *scan.Scan) bool { return s.ID == sc.ID })
	}
	if due(time.Now()) {
		t.Fatal("due before its time")
	}
	if !due(runAt.Add(time.Second)) {
		t.Fatal("not due at its time")
	}

	// The scheduler claims it at its time: the occurrence after it is none.
	won, err := repo.ClaimScheduledRun(ctx, tenantID, sc.ID, runAt, got.OccurrenceAfter(runAt))
	if err != nil || !won {
		t.Fatalf("claim: won %v err %v", won, err)
	}
	if due(runAt.Add(24 * time.Hour)) {
		t.Fatal("due again after its run")
	}
	_, names, err := repo.CountScheduledWithoutNextRun(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if slices.Contains(names, sc.Name) {
		t.Fatal("a one-off scan that has run is reported as an inert schedule")
	}

	// The database refuses a once schedule without its run.
	if _, err := db.ExecContext(ctx, `UPDATE scans SET schedule_run_at = NULL WHERE id = $1`, sc.ID.String()); err == nil {
		t.Fatal("once schedule without schedule_run_at accepted")
	}
}

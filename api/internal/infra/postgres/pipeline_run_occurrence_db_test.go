package postgres

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/pipeline"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// One run per schedule occurrence (RFC-046 P1.5, migration 000351), against
// the real SQL. Before, nothing recorded which occurrence a run served, so
// only the next_run_at compare-and-set stood between two scheduler instances
// and a double-fired scan.

func newOccurrenceRun(t *testing.T, tenantID, scanID shared.ID, occurrence *time.Time) *pipeline.Run {
	t.Helper()
	tpl, _ := shared.IDFromString(quickScanTemplate)
	run, err := pipeline.NewRun(tpl, tenantID, nil, pipeline.TriggerTypeSchedule, "", map[string]any{})
	if err != nil {
		t.Fatalf("new run: %v", err)
	}
	run.ScanID = &scanID
	run.ScheduledFor = occurrence
	run.SetTotalSteps(1)
	return run
}

func TestOccurrence_SecondRunForTheSameSlotIsRefused(t *testing.T) {
	ctx := context.Background()
	db := openScanDB(t)
	runs := NewPipelineRunRepository(&DB{DB: db})
	tenantID, scanID := seedCounterScan(ctx, t, db)
	slot := time.Date(2026, 10, 3, 2, 0, 0, 0, time.UTC)

	first := newOccurrenceRun(t, tenantID, scanID, &slot)
	if err := runs.CreateRunIfUnderLimit(ctx, first, 10, 100); err != nil {
		t.Fatalf("first run: %v", err)
	}
	// The trigger path (under the scan row lock) and the plain insert both
	// refuse a second run for the slot.
	if err := runs.CreateRunIfUnderLimit(ctx, newOccurrenceRun(t, tenantID, scanID, &slot), 10, 100); !errors.Is(err, pipeline.ErrOccurrenceAlreadyRun) {
		t.Fatalf("second run via trigger path: err=%v, want ErrOccurrenceAlreadyRun", err)
	}
	if err := runs.Create(ctx, newOccurrenceRun(t, tenantID, scanID, &slot)); !errors.Is(err, pipeline.ErrOccurrenceAlreadyRun) {
		t.Fatalf("second run via plain insert: err=%v, want ErrOccurrenceAlreadyRun", err)
	}

	// The run reads back with its occurrence.
	got, err := runs.GetByTenantAndID(ctx, tenantID, first.ID)
	if err != nil {
		t.Fatalf("read run: %v", err)
	}
	if got.ScheduledFor == nil || !got.ScheduledFor.Equal(slot) {
		t.Fatalf("scheduled_for = %v, want %v", got.ScheduledFor, slot)
	}
}

func TestOccurrence_OtherSlotsScansAndUnscheduledRunsAreFree(t *testing.T) {
	ctx := context.Background()
	db := openScanDB(t)
	runs := NewPipelineRunRepository(&DB{DB: db})
	tenantID, scanID := seedCounterScan(ctx, t, db)
	_, otherScan := seedCounterScan(ctx, t, db)
	slot := time.Date(2026, 10, 3, 2, 0, 0, 0, time.UTC)
	next := slot.Add(24 * time.Hour)

	for name, run := range map[string]*pipeline.Run{
		"first slot":         newOccurrenceRun(t, tenantID, scanID, &slot),
		"next slot":          newOccurrenceRun(t, tenantID, scanID, &next),
		"manual run":         newOccurrenceRun(t, tenantID, scanID, nil),
		"another manual run": newOccurrenceRun(t, tenantID, scanID, nil),
		"same slot, other scan": func() *pipeline.Run {
			r := newOccurrenceRun(t, tenantID, otherScan, &slot)
			return r
		}(),
	} {
		if err := runs.Create(ctx, run); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
	}
}

// Two scheduler instances fire the same occurrence at once: exactly one run.
func TestOccurrence_ConcurrentTriggersCreateOneRun(t *testing.T) {
	ctx := context.Background()
	db := openScanDB(t)
	runs := NewPipelineRunRepository(&DB{DB: db})
	tenantID, scanID := seedCounterScan(ctx, t, db)
	slot := time.Date(2026, 10, 3, 3, 0, 0, 0, time.UTC)

	const replicas = 6
	var wg sync.WaitGroup
	errs := make([]error, replicas)
	start := make(chan struct{})
	for i := range replicas {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			errs[i] = runs.CreateRunIfUnderLimit(ctx, newOccurrenceRun(t, tenantID, scanID, &slot), 50, 500)
		}(i)
	}
	close(start)
	wg.Wait()

	created := 0
	for i, err := range errs {
		switch {
		case err == nil:
			created++
		case errors.Is(err, pipeline.ErrOccurrenceAlreadyRun):
		default:
			t.Fatalf("replica %d: unexpected error %v", i, err)
		}
	}
	var stored int
	if err := db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM pipeline_runs WHERE scan_id = $1 AND scheduled_for = $2`, scanID.String(), slot).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if created != 1 || stored != 1 {
		t.Fatalf("created=%d stored=%d, want exactly one run for the occurrence", created, stored)
	}
}

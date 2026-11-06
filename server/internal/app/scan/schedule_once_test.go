package scan

import (
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/scan"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Create with schedule_type once stores the run; an edit that sends the
// stored run back unchanged (the scan page re-sends its schedule with other
// changes) is kept even after the run time has passed, while a new run time
// must still be in the future.
func TestScheduleOnce_CreateAndEdit(t *testing.T) {
	sc, err := scan.NewScan(shared.NewID(), "once", shared.NewID(), scan.ScanTypeSingle)
	if err != nil {
		t.Fatal(err)
	}
	runAt := time.Now().Add(time.Hour).Truncate(time.Second)
	if err := configureScanSchedule(sc, CreateScanInput{ScheduleType: "once", RunAt: &runAt, Timezone: "Asia/Tokyo"}); err != nil {
		t.Fatal(err)
	}
	if sc.ScheduleType != scan.ScheduleOnce || sc.ScheduleRunAt == nil || !sc.ScheduleRunAt.Equal(runAt) {
		t.Fatalf("type %s run_at %v", sc.ScheduleType, sc.ScheduleRunAt)
	}
	if err := configureScanSchedule(sc, CreateScanInput{ScheduleType: "once", Timezone: "UTC"}); err == nil {
		t.Fatal("once without run_at accepted")
	}

	// The run has happened: its time is now in the past.
	past := time.Now().Add(-2 * time.Hour).Truncate(time.Second)
	sc.ScheduleRunAt = &past
	if !sameOnceRun(sc, &past, "Asia/Tokyo") {
		t.Fatal("the stored run sent back unchanged is not recognized")
	}
	other := past.Add(time.Minute)
	if sameOnceRun(sc, &other, "Asia/Tokyo") || sameOnceRun(sc, &past, "UTC") || sameOnceRun(sc, nil, "Asia/Tokyo") {
		t.Fatal("a different run time or zone counted as unchanged")
	}
}

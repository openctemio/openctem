package scan

import (
	"errors"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

func newScheduledScan(t *testing.T) *Scan {
	t.Helper()
	sc, err := NewScan(shared.NewID(), "min interval", shared.NewID(), ScanTypeSingle)
	if err != nil {
		t.Fatal(err)
	}
	sc.Status = StatusActive
	return sc
}

// RFC-046 B8: a schedule may not fire more often than every 15 minutes.
func TestSetSchedule_MinimumInterval(t *testing.T) {
	for _, tc := range []struct {
		cron string
		ok   bool
	}{
		{"*/15 * * * *", true},
		{"0 * * * *", true},
		{"0,20,40 * * * *", true},
		{"* * * * *", false},
		{"*/5 * * * *", false},
		{"0,10 * * * *", false}, // :00 and :10 are 10 minutes apart
	} {
		sc := newScheduledScan(t)
		err := sc.SetSchedule(ScheduleCrontab, tc.cron, nil, nil, "UTC")
		if tc.ok && err != nil {
			t.Errorf("%q refused: %v", tc.cron, err)
		}
		if !tc.ok && !errors.Is(err, shared.ErrValidation) {
			t.Errorf("%q accepted (err %v), want a validation error", tc.cron, err)
		}
	}
}

// A crontab stored before the minimum existed (every minute) is spaced to
// 15 minutes when the scheduler claims an occurrence.
func TestCalculateNextRun_LegacyEveryMinuteIsSpaced(t *testing.T) {
	sc := newScheduledScan(t)
	sc.ScheduleType = ScheduleCrontab
	sc.ScheduleCron = "* * * * *"
	sc.ScheduleTimezone = "UTC"
	due := time.Now().UTC().Truncate(time.Minute).Add(-30 * time.Second)
	sc.NextRunAt = &due
	next := sc.CalculateNextRunAt()
	if next == nil || next.Sub(due) < MinScheduleInterval-time.Second {
		t.Fatalf("next = %v, want at least 15 minutes after %v", next, due)
	}
	// Not due (a save): the next minute, as the expression says.
	future := time.Now().Add(time.Hour)
	sc.NextRunAt = &future
	if n := sc.CalculateNextRunAt(); n == nil || time.Until(*n) > 2*time.Minute {
		t.Fatalf("next on save = %v, want within the next minute or two", n)
	}
}

func TestOccurrenceAfter(t *testing.T) {
	sc := newScheduledScan(t)
	if err := sc.SetSchedule(ScheduleCrontab, "0 */6 * * *", nil, nil, "UTC"); err != nil {
		t.Fatal(err)
	}
	base := time.Date(2026, 10, 4, 7, 0, 0, 0, time.UTC)
	got := sc.OccurrenceAfter(base)
	if got == nil || !got.Equal(time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC)) {
		t.Fatalf("OccurrenceAfter = %v, want 12:00", got)
	}
	sc.ScheduleType = ScheduleManual
	if sc.OccurrenceAfter(base) != nil {
		t.Fatal("a manual scan has no occurrence")
	}
}

package scan

import (
	"errors"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// A weekly schedule with no day (legacy rows) ran every 8 days: the next run
// was tomorrow's slot + 7 days, so each run pushed the weekday forward.
func TestNextAtWeekday_NoDayKeepsASevenDayPeriod(t *testing.T) {
	at := time.Date(0, 1, 1, 2, 0, 0, 0, time.UTC)
	// Triggered just after its Monday 02:00 slot.
	now := time.Date(2026, 10, 5, 2, 0, 30, 0, time.UTC)
	next := nextAtWeekday(now, nil, &at)
	if want := time.Date(2026, 10, 12, 2, 0, 0, 0, time.UTC); !next.Equal(want) {
		t.Fatalf("next = %s, want %s (7 days, same weekday)", next, want)
	}
	// Before today's slot it is today's slot.
	early := time.Date(2026, 10, 5, 1, 0, 0, 0, time.UTC)
	if got := nextAtWeekday(early, nil, &at); !got.Equal(time.Date(2026, 10, 5, 2, 0, 0, 0, time.UTC)) {
		t.Fatalf("next = %s, want today's slot", got)
	}
}

func TestSetSchedule_RefusesWhatTheSchedulerCannotHonor(t *testing.T) {
	at := time.Date(0, 1, 1, 3, 0, 0, 0, time.UTC)
	cases := []struct {
		name string
		typ  ScheduleType
		cron string
		tz   string
	}{
		{"unparseable cron", ScheduleCrontab, "61 * * * *", "UTC"},
		{"six-field cron the scheduler does not read", ScheduleCrontab, "0 0 3 * * *", "UTC"},
		{"unknown timezone", ScheduleDaily, "", "Mars/Olympus_Mons"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := &Scan{Status: StatusActive}
			err := s.SetSchedule(c.typ, c.cron, nil, &at, c.tz)
			if !errors.Is(err, shared.ErrValidation) {
				t.Fatalf("err = %v, want a validation error", err)
			}
		})
	}
}

func TestSetSchedule_CronOnlyKeptForCrontab(t *testing.T) {
	at := time.Date(0, 1, 1, 3, 0, 0, 0, time.UTC)
	s := &Scan{Status: StatusActive}
	if err := s.SetSchedule(ScheduleDaily, "*/5 * * * *", nil, &at, "UTC"); err != nil {
		t.Fatal(err)
	}
	if s.ScheduleCron != "" {
		t.Fatalf("daily scan kept cron %q, which nothing honors", s.ScheduleCron)
	}
}

func TestCalculateNextRun_UnparseableStoredCronHasNoNextRun(t *testing.T) {
	s := &Scan{Status: StatusActive, ScheduleType: ScheduleCrontab, ScheduleCron: "61 * * * *", ScheduleTimezone: "UTC"}
	if next := s.CalculateNextRunAt(); next != nil {
		t.Fatalf("next = %s, want nil (inert, reported) instead of a silent 24h fallback", next)
	}
}

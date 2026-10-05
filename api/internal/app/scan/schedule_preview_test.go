package scan

import (
	"errors"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

func TestPreviewSchedule_RRuleInItsTimezone(t *testing.T) {
	now := time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)
	p, err := PreviewSchedule(SchedulePreviewInput{
		ScheduleType:  "rrule",
		ScheduleRRule: "FREQ=WEEKLY;BYDAY=MO;BYHOUR=9",
		Timezone:      "America/New_York",
		Count:         2,
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	if p.Timezone != "America/New_York" || len(p.Occurrences) != 2 {
		t.Fatalf("preview = %+v", p)
	}
	if got := p.Occurrences[0].Format(time.RFC3339); got != "2026-10-12T09:00:00-04:00" {
		t.Errorf("first occurrence %s, want Monday 09:00 EDT", got)
	}
	// Daylight saving ends 1 Nov: 09:00 local stays 09:00 local.
	if got := p.Occurrences[1].Format(time.RFC3339); got != "2026-10-19T09:00:00-04:00" {
		t.Errorf("second occurrence %s", got)
	}
}

func TestPreviewSchedule_DefaultsAndManual(t *testing.T) {
	now := time.Date(2026, 10, 4, 0, 0, 0, 0, time.UTC)
	at := time.Date(0, 1, 1, 2, 0, 0, 0, time.UTC)
	p, err := PreviewSchedule(SchedulePreviewInput{ScheduleType: "daily", ScheduleTime: &at}, now)
	if err != nil {
		t.Fatal(err)
	}
	if p.Timezone != "UTC" || len(p.Occurrences) != DefaultSchedulePreviewCount {
		t.Fatalf("preview = %+v", p)
	}
	m, err := PreviewSchedule(SchedulePreviewInput{ScheduleType: "manual"}, now)
	if err != nil || len(m.Occurrences) != 0 {
		t.Fatalf("manual preview = %+v, %v", m, err)
	}
}

// Every rule saving would refuse, the preview refuses with the same
// validation error (so the wizard can show it inline before Create).
func TestPreviewSchedule_RefusesWhatSavingRefuses(t *testing.T) {
	now := time.Date(2026, 10, 4, 0, 0, 0, 0, time.UTC)
	at := time.Date(0, 1, 1, 2, 0, 0, 0, time.UTC)
	for name, in := range map[string]SchedulePreviewInput{
		"too frequent rrule":   {ScheduleType: "rrule", ScheduleRRule: "FREQ=MINUTELY;INTERVAL=5"},
		"COUNT":                {ScheduleType: "rrule", ScheduleRRule: "FREQ=DAILY;COUNT=3"},
		"unparseable rrule":    {ScheduleType: "rrule", ScheduleRRule: "FREQ=NEVER"},
		"too frequent cron":    {ScheduleType: "crontab", ScheduleCron: "* * * * *"},
		"bad cron":             {ScheduleType: "crontab", ScheduleCron: "not a cron"},
		"unknown timezone":     {ScheduleType: "daily", ScheduleTime: &at, Timezone: "Mars/Olympus"},
		"weekly without a day": {ScheduleType: "weekly", ScheduleTime: &at},
		"unknown type":         {ScheduleType: "hourly"},
		"count too large":      {ScheduleType: "daily", ScheduleTime: &at, Count: 11},
		"count negative":       {ScheduleType: "daily", ScheduleTime: &at, Count: -1},
	} {
		if _, err := PreviewSchedule(in, now); !errors.Is(err, shared.ErrValidation) {
			t.Errorf("%s: err %v, want a validation error", name, err)
		}
	}
}

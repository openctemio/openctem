package scan

// Schedule preview: the next occurrences of a schedule, computed by the same
// code the scheduler uses, so the wizard and the scan page never show a date
// the scheduler would not fire (scans UI redesign, research/20 §3 "Schedules").

import (
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/scan"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// DefaultSchedulePreviewCount is how many occurrences a preview lists when
// the caller does not say.
const DefaultSchedulePreviewCount = 5

// SchedulePreviewInput is a schedule as the create/update requests carry it.
type SchedulePreviewInput struct {
	ScheduleType  string
	ScheduleCron  string
	ScheduleRRule string
	ScheduleDay   *int
	ScheduleTime  *time.Time
	Timezone      string
	// Count is how many occurrences to list (1..scan.MaxUpcomingOccurrences;
	// 0 means DefaultSchedulePreviewCount).
	Count int
}

// SchedulePreview is the next occurrences of a schedule, in its timezone.
type SchedulePreview struct {
	Timezone    string
	Occurrences []time.Time // in Timezone
}

// PreviewSchedule validates a schedule exactly as saving it would (the same
// rules: parseable cron or RRULE, known timezone, the 15-minute minimum) and
// returns its next occurrences after now. It reads and stores nothing, so it
// needs no tenant: the schedule is the caller's own input.
func PreviewSchedule(input SchedulePreviewInput, now time.Time) (*SchedulePreview, error) {
	count := input.Count
	if count == 0 {
		count = DefaultSchedulePreviewCount
	}
	if count < 1 || count > scan.MaxUpcomingOccurrences {
		return nil, shared.NewDomainError("VALIDATION", "count must be between 1 and 10", shared.ErrValidation)
	}

	// A throwaway scan carries the schedule through the domain validation.
	sc, err := scan.NewScan(shared.NewID(), "schedule preview", shared.ID{}, scan.ScanTypeSingle)
	if err != nil {
		return nil, err
	}
	if err := configureScanSchedule(sc, CreateScanInput{
		ScheduleType:  input.ScheduleType,
		ScheduleCron:  input.ScheduleCron,
		ScheduleRRule: input.ScheduleRRule,
		ScheduleDay:   input.ScheduleDay,
		ScheduleTime:  input.ScheduleTime,
		Timezone:      input.Timezone,
	}); err != nil {
		return nil, err
	}

	loc, err := time.LoadLocation(sc.ScheduleTimezone)
	if err != nil {
		loc = time.UTC
	}
	occ := sc.UpcomingOccurrences(now, count)
	out := make([]time.Time, len(occ))
	for i, t := range occ {
		out[i] = t.In(loc)
	}
	return &SchedulePreview{Timezone: sc.ScheduleTimezone, Occurrences: out}, nil
}

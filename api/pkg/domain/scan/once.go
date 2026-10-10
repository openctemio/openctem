package scan

import (
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// One-off scheduled runs: a scan saved now that runs once, later.

// MinOnceLead is how far ahead a one-off run must be when it is saved: a
// time in the past (or a few seconds away) is a mistake, not a schedule; to
// run now, trigger the scan.
const MinOnceLead = time.Minute

// MaxOnceAhead bounds how far ahead a one-off run may be.
const MaxOnceAhead = 366 * 24 * time.Hour

// OnceMisfireGrace is how late a one-off run may still start. A one-off run
// missed by more (the platform was down) is skipped and recorded, never run
// at a time nobody chose.
const OnceMisfireGrace = time.Hour

// SetOnceSchedule makes the scan run once, at runAt. timezone (IANA, default
// UTC) is the zone the time was chosen in, kept for display. runAt must be
// between MinOnceLead and MaxOnceAhead after now.
func (s *Scan) SetOnceSchedule(runAt *time.Time, timezone string, now time.Time) error {
	if runAt == nil || runAt.IsZero() {
		return shared.NewDomainError("VALIDATION", "run_at is required for a once schedule", shared.ErrValidation)
	}
	if timezone == "" {
		timezone = "UTC"
	}
	if _, err := time.LoadLocation(timezone); err != nil {
		return shared.NewDomainError("VALIDATION", "unknown timezone: "+timezone, shared.ErrValidation)
	}
	at := runAt.UTC().Truncate(time.Second)
	if at.Before(now.Add(MinOnceLead)) {
		return shared.NewDomainError("VALIDATION",
			"run_at must be at least a minute in the future (to run now, start the scan)", shared.ErrValidation)
	}
	if at.After(now.Add(MaxOnceAhead)) {
		return shared.NewDomainError("VALIDATION", "run_at must be within a year", shared.ErrValidation)
	}
	s.ScheduleType = ScheduleOnce
	s.ScheduleRunAt = &at
	s.ScheduleCron = ""
	s.ScheduleRRule = ""
	s.ScheduleDay = nil
	s.ScheduleTime = nil
	s.ScheduleTimezone = timezone
	s.UpdatedAt = time.Now()
	s.computeNextRunAt()
	return nil
}

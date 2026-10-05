// Package scanfreeze is the domain of scan freeze windows: times in which no
// active (T1/T2) scan work of a tenant, or of one of its scan zones, is
// dispatched. Architecture: docs/architecture/scan-zones.md ("Freeze
// windows").
//
// Whether a window is active at an instant is decided in SQL (the claim
// predicate and the repository share one expression), so the claim path and
// the trigger path can never disagree. This package validates what is stored.
package scanfreeze

import (
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Recurrence is how a window repeats.
type Recurrence string

const (
	// RecurrenceOnce is one window between two instants.
	RecurrenceOnce Recurrence = "once"
	// RecurrenceWeekly repeats on the listed ISO weekdays between two local
	// wall-clock times of the window's time zone. An end time that is not
	// after the start time ends on the next day (22:00-06:00); equal times
	// freeze the whole day from that time.
	RecurrenceWeekly Recurrence = "weekly"
)

// Caps.
const (
	MaxWindowsPerTenant = 50
	MaxOnceDuration     = 31 * 24 * time.Hour
	maxNameLen          = 100
	maxDescriptionLen   = 1000
	maxTimezoneLen      = 64
	minutesPerDay       = 24 * 60
)

var (
	// ErrNotFound is returned for a window that is not the tenant's.
	ErrNotFound = shared.NewDomainError("FREEZE_WINDOW_NOT_FOUND", "freeze window not found", shared.ErrNotFound)
	// ErrZoneNotFound is returned for a scan zone that is not the tenant's.
	ErrZoneNotFound = shared.NewDomainError("SCAN_ZONE_NOT_FOUND", "scan zone not found", shared.ErrNotFound)
	// ErrTooMany is returned when the tenant has MaxWindowsPerTenant windows.
	ErrTooMany = shared.NewDomainError("TOO_MANY_FREEZE_WINDOWS",
		fmt.Sprintf("an organization can have at most %d freeze windows", MaxWindowsPerTenant), shared.ErrValidation)
)

// Window is one freeze window.
type Window struct {
	ID       shared.ID
	TenantID shared.ID
	// ScanZoneID is the zone the window freezes; nil freezes the tenant.
	ScanZoneID  *shared.ID
	Name        string
	Description string
	// Timezone is the IANA zone of a weekly window's wall-clock times (and
	// how a one-off window is shown).
	Timezone   string
	Recurrence Recurrence
	// StartsAt and EndsAt bound a one-off window (end exclusive).
	StartsAt *time.Time
	EndsAt   *time.Time
	// Days are the ISO weekdays (1 Monday ... 7 Sunday) a weekly window
	// starts on; StartMinute and EndMinute are minutes after local midnight.
	Days        []int
	StartMinute int
	EndMinute   int
	Enabled     bool
	CreatedBy   *shared.ID
	CreatedAt   time.Time
	UpdatedAt   time.Time

	// ActiveUntil is set by the repository on reads: when the window is
	// active at read time, the end of the current occurrence.
	ActiveUntil *time.Time
}

// Spec is what a client sets on a window.
type Spec struct {
	Name        string
	Description string
	Timezone    string
	Recurrence  Recurrence
	StartsAt    *time.Time
	EndsAt      *time.Time
	Days        []int
	// StartTime and EndTime are "HH:MM" (weekly).
	StartTime string
	EndTime   string
	Enabled   bool
}

// NewWindow validates spec and returns a new window of the tenant. A one-off
// window must end after now.
func NewWindow(tenantID shared.ID, zoneID *shared.ID, spec Spec, createdBy *shared.ID, now time.Time) (*Window, error) {
	w := &Window{ID: shared.NewID(), TenantID: tenantID, ScanZoneID: zoneID, CreatedBy: createdBy, CreatedAt: now, UpdatedAt: now}
	if err := w.apply(spec); err != nil {
		return nil, err
	}
	if w.Recurrence == RecurrenceOnce && !w.EndsAt.After(now) {
		return nil, invalid("ends_at is in the past")
	}
	return w, nil
}

// Update replaces the window's settings with spec. The zone does not change.
func (w *Window) Update(spec Spec, now time.Time) error {
	next := *w
	if err := next.apply(spec); err != nil {
		return err
	}
	next.UpdatedAt = now
	*w = next
	return nil
}

// Spec returns the window's settings, for a partial update.
func (w *Window) Spec() Spec {
	s := Spec{
		Name: w.Name, Description: w.Description, Timezone: w.Timezone, Recurrence: w.Recurrence,
		StartsAt: w.StartsAt, EndsAt: w.EndsAt, Enabled: w.Enabled,
	}
	if w.Recurrence == RecurrenceWeekly {
		s.Days = slices.Clone(w.Days)
		s.StartTime = FormatMinute(w.StartMinute)
		s.EndTime = FormatMinute(w.EndMinute)
	}
	return s
}

func (w *Window) apply(spec Spec) error {
	name := strings.TrimSpace(spec.Name)
	if name == "" || len([]rune(name)) > maxNameLen {
		return invalid(fmt.Sprintf("name must be 1 to %d characters", maxNameLen))
	}
	if len([]rune(spec.Description)) > maxDescriptionLen {
		return invalid(fmt.Sprintf("description must be at most %d characters", maxDescriptionLen))
	}
	tz, err := ValidateTimezone(spec.Timezone)
	if err != nil {
		return err
	}
	w.Name, w.Description, w.Timezone, w.Enabled = name, spec.Description, tz, spec.Enabled

	switch spec.Recurrence {
	case RecurrenceOnce:
		if spec.StartsAt == nil || spec.EndsAt == nil {
			return invalid("a one-off window needs starts_at and ends_at")
		}
		start, end := spec.StartsAt.UTC(), spec.EndsAt.UTC()
		if !end.After(start) {
			return invalid("ends_at must be after starts_at")
		}
		if end.Sub(start) > MaxOnceDuration {
			return invalid("a one-off window can last at most 31 days")
		}
		w.Recurrence, w.StartsAt, w.EndsAt = RecurrenceOnce, &start, &end
		w.Days, w.StartMinute, w.EndMinute = nil, 0, 0
	case RecurrenceWeekly:
		days, err := normalizeDays(spec.Days)
		if err != nil {
			return err
		}
		startMin, err := ParseMinute(spec.StartTime)
		if err != nil {
			return invalid("start_time: " + err.Error())
		}
		endMin, err := ParseMinute(spec.EndTime)
		if err != nil {
			return invalid("end_time: " + err.Error())
		}
		w.Recurrence, w.StartsAt, w.EndsAt = RecurrenceWeekly, nil, nil
		w.Days, w.StartMinute, w.EndMinute = days, startMin, endMin
	default:
		return invalid(`recurrence must be "once" or "weekly"`)
	}
	return nil
}

// ValidateTimezone returns the IANA zone name or a validation error. The
// repository checks again that the database knows it, since the claim
// predicate evaluates it.
func ValidateTimezone(tz string) (string, error) {
	tz = strings.TrimSpace(tz)
	if tz == "" || len(tz) > maxTimezoneLen || strings.EqualFold(tz, "local") {
		return "", invalid("timezone must be an IANA time zone name such as Europe/Berlin")
	}
	if _, err := time.LoadLocation(tz); err != nil {
		return "", invalid(fmt.Sprintf("unknown timezone %q", tz))
	}
	return tz, nil
}

func normalizeDays(days []int) ([]int, error) {
	if len(days) == 0 {
		return nil, invalid("a weekly window needs at least one day (1 Monday ... 7 Sunday)")
	}
	out := make([]int, 0, len(days))
	for _, d := range days {
		if d < 1 || d > 7 {
			return nil, invalid("days must be ISO weekdays, 1 (Monday) to 7 (Sunday)")
		}
		if !slices.Contains(out, d) {
			out = append(out, d)
		}
	}
	slices.Sort(out)
	return out, nil
}

// ParseMinute parses "HH:MM" (00:00 to 23:59) into minutes after midnight.
func ParseMinute(s string) (int, error) {
	t, err := time.Parse("15:04", strings.TrimSpace(s))
	if err != nil {
		return 0, fmt.Errorf("must be HH:MM (00:00 to 23:59)")
	}
	return t.Hour()*60 + t.Minute(), nil
}

// FormatMinute formats minutes after midnight as "HH:MM".
func FormatMinute(m int) string {
	m = ((m % minutesPerDay) + minutesPerDay) % minutesPerDay
	return fmt.Sprintf("%02d:%02d", m/60, m%60)
}

func invalid(msg string) error {
	return shared.NewDomainError("INVALID_FREEZE_WINDOW", msg, shared.ErrValidation)
}

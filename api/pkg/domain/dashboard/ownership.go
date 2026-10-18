package dashboard

import (
	"fmt"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Kind says who owns a dashboard and whose numbers it shows.
type Kind string

const (
	// KindPersonal: owned by one user, the owner's own data scope.
	KindPersonal Kind = "personal"
	// KindOrganization: owned by the organization, organization-wide numbers.
	KindOrganization Kind = "organization"
)

// Origin records how a dashboard came to be.
type Origin string

const (
	OriginUser       Origin = "user"
	OriginBuiltin    Origin = "builtin"
	OriginDuplicated Origin = "duplicated" // a personal copy of an organization dashboard
	OriginShared     Origin = "shared"     // a personal copy of a layout another member shared
)

const (
	// MaxPersonalPerUser bounds how many personal dashboards one person keeps.
	MaxPersonalPerUser = 30
	// MaxOrgPerTenant bounds how many organization dashboards one
	// organization keeps.
	MaxOrgPerTenant = 50
	// MaxAudience bounds the roles and teams of one audience.
	MaxAudience = 20
	// MaxShareRecipients bounds the recipients of one share.
	MaxShareRecipients = 10
)

// Errors of the ownership model.
var (
	ErrPersonalLimit = fmt.Errorf("%w: at most %d personal dashboards per person", shared.ErrValidation, MaxPersonalPerUser)
	ErrOrgLimit      = fmt.Errorf("%w: at most %d organization dashboards", shared.ErrValidation, MaxOrgPerTenant)
)

// Interval is a refresh cadence. The empty value means "the organization
// default" on a dashboard; the organization default itself is never empty.
type Interval string

const (
	IntervalDefault Interval = ""
	IntervalManual  Interval = "manual"
	Interval5m      Interval = "5m"
	Interval15m     Interval = "15m"
	Interval1h      Interval = "1h"
	Interval6h      Interval = "6h"
	IntervalDaily   Interval = "daily"
)

// BaseRefreshFloor is the shortest cadence any installation allows. An
// organization's floor may be longer (the limit
// dashboard_refresh_floor_minutes, set by the operator or the hosting plan).
const BaseRefreshFloor = 5 * time.Minute

// DefaultInterval is the organization default when none is set.
const DefaultInterval = Interval1h

// Period returns the time between two refreshes; 0 for manual and default.
func (i Interval) Period() time.Duration {
	switch i {
	case Interval5m:
		return 5 * time.Minute
	case Interval15m:
		return 15 * time.Minute
	case Interval1h:
		return time.Hour
	case Interval6h:
		return 6 * time.Hour
	case IntervalDaily:
		return 24 * time.Hour
	case IntervalDefault, IntervalManual:
		return 0
	}
	return 0
}

// Valid reports whether i is a known value (the empty default included).
func (i Interval) Valid() bool {
	switch i {
	case IntervalDefault, IntervalManual, Interval5m, Interval15m, Interval1h, Interval6h, IntervalDaily:
		return true
	}
	return false
}

// Schedule is a dashboard's refresh schedule.
type Schedule struct {
	Interval Interval
	// DailyMinute is the minute of the day (UTC, 0-1439) of a daily refresh;
	// nil for any other interval.
	DailyMinute *int
	// NextRefreshAt and PausedAt are the refresher's bookkeeping.
	NextRefreshAt *time.Time
	PausedAt      *time.Time
}

// NewSchedule validates a schedule against the organization's floor. Manual
// and the organization default are always allowed; a periodic interval must
// not be shorter than the floor.
func NewSchedule(interval Interval, dailyMinute *int, floor time.Duration) (Schedule, error) {
	if !interval.Valid() {
		return Schedule{}, fmt.Errorf("%w: refresh_schedule must be one of manual, 5m, 15m, 1h, 6h, daily or empty for the organization default", shared.ErrValidation)
	}
	if interval == IntervalDaily {
		if dailyMinute == nil || *dailyMinute < 0 || *dailyMinute > 1439 {
			return Schedule{}, fmt.Errorf("%w: a daily refresh needs refresh_daily_minute within 0..1439", shared.ErrValidation)
		}
		m := *dailyMinute
		dailyMinute = &m
	} else if dailyMinute != nil {
		return Schedule{}, fmt.Errorf("%w: refresh_daily_minute is only for a daily refresh", shared.ErrValidation)
	}
	if p := interval.Period(); p > 0 && p < floor {
		return Schedule{}, fmt.Errorf("%w: refreshing every %s is below this organization's minimum of %s", shared.ErrValidation, interval, floor)
	}
	return Schedule{Interval: interval, DailyMinute: dailyMinute}, nil
}

// Next returns the next refresh time after now; nil for manual and the
// organization default (the refresher resolves the default).
func (s Schedule) Next(now time.Time) *time.Time {
	now = now.UTC()
	switch s.Interval {
	case IntervalDefault, IntervalManual:
		return nil
	case IntervalDaily:
		if s.DailyMinute == nil {
			return nil
		}
		day := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)
		t := day.Add(time.Duration(*s.DailyMinute) * time.Minute)
		if !t.After(now) {
			t = t.Add(24 * time.Hour)
		}
		return &t
	case Interval5m, Interval15m, Interval1h, Interval6h:
		t := now.Add(s.Interval.Period())
		return &t
	}
	return nil
}

// PrincipalType is what an audience entry names.
type PrincipalType string

const (
	PrincipalRole  PrincipalType = "role"
	PrincipalGroup PrincipalType = "group"
)

// AudienceEntry is one role or team an organization dashboard is narrowed to.
type AudienceEntry struct {
	Type PrincipalType
	ID   shared.ID
	// Name is filled on read (the role or team name; empty when it no longer
	// exists).
	Name string
}

// ValidateAudience checks the shape of an audience: known types, no
// duplicates, at most MaxAudience entries. Membership of the tenant is
// checked by the repository.
func ValidateAudience(entries []AudienceEntry) error {
	if len(entries) > MaxAudience {
		return fmt.Errorf("%w: at most %d roles and teams in an audience", shared.ErrValidation, MaxAudience)
	}
	seen := make(map[AudienceEntry]bool, len(entries))
	for i, e := range entries {
		if e.Type != PrincipalRole && e.Type != PrincipalGroup {
			return fmt.Errorf("%w: audience[%d] type must be role or group", shared.ErrValidation, i)
		}
		if e.ID.IsZero() {
			return fmt.Errorf("%w: audience[%d] id is required", shared.ErrValidation, i)
		}
		k := AudienceEntry{Type: e.Type, ID: e.ID}
		if seen[k] {
			return fmt.Errorf("%w: audience[%d] is listed twice", shared.ErrValidation, i)
		}
		seen[k] = true
	}
	return nil
}

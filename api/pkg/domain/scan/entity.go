package scan

import (
	"fmt"
	"strings"
	"time"

	"github.com/robfig/cron/v3"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Scan represents a scan definition that binds
// an asset group with a scanner/workflow and schedule.
type Scan struct {
	ID          shared.ID
	TenantID    shared.ID
	Name        string
	Description string

	// Target - can use AssetGroupID/AssetGroupIDs, Targets, or both
	AssetGroupID  shared.ID   // Optional: primary asset group (legacy, for single asset group)
	AssetGroupIDs []shared.ID // Optional: multiple asset groups (NEW)
	Targets       []string    // Optional: direct target list (domains, IPs, URLs)

	// Scan Type
	ScanType       ScanType
	ScanWorkflowID *shared.ID     // For workflow type
	ScannerName    string         // For single type
	ScannerConfig  map[string]any // Scanner-specific configuration
	TargetsPerJob  int            // Number of targets per job batch

	// Schedule
	ScheduleType     ScheduleType
	ScheduleCron     string     // Cron expression (for crontab type)
	ScheduleRRule    string     // RFC 5545 RRULE (for rrule type), e.g. FREQ=WEEKLY;BYDAY=MO;BYHOUR=2
	ScheduleDay      *int       // Day of week (0-6) or month (1-31)
	ScheduleTime     *time.Time // Time of day to run
	ScheduleTimezone string
	NextRunAt        *time.Time // Pre-computed next run time

	// Routing
	Tags              []string         // Route to sensors with matching tags
	RunOnTenantRunner bool             // Restrict to tenant's own runners
	SensorPreference  SensorPreference // Sensor selection mode: auto, tenant, platform
	// ScanZoneID pins every target to one scan zone; nil = Automatic (each
	// target goes to the narrowest zone holding it). Targets outside the
	// selected zone are not scanned.
	ScanZoneID *shared.ID

	// Profile - links to ScanProfile for tool configs, intensity, quality gates
	ProfileID *shared.ID

	// Timeout - max execution time in seconds (default 3600 = 1h, max 86400 = 24h)
	TimeoutSeconds int

	// Retry config - automatic retry of failed runs with exponential backoff
	MaxRetries          int // 0 = no retry, max 10
	RetryBackoffSeconds int // Initial backoff (default 60s), actual delay is backoff * 2^attempt

	// AdHoc marks a quick scan that was run without being saved: it exists so
	// its runs have a scan to belong to, but it is not a configuration (the
	// list hides it) until someone saves it (SaveAsConfiguration).
	AdHoc bool

	// Status
	Status Status

	// Execution Statistics
	LastRunID      *shared.ID
	LastRunAt      *time.Time
	LastRunStatus  string
	TotalRuns      int
	SuccessfulRuns int
	FailedRuns     int
	// PartialRuns counts runs that kept results but lost some work
	// (RFC-046 D5); neither a success nor a failure.
	PartialRuns int
	// BlockedRuns counts triggers that were refused before anything was
	// dispatched (scanrun.RunStatusBlocked).
	BlockedRuns int

	// Audit
	CreatedBy *shared.ID
	CreatedAt time.Time
	UpdatedAt time.Time
}

// NewScan creates a new scan definition.
// assetGroupID is optional if targets are provided later via SetTargets.
func NewScan(tenantID shared.ID, name string, assetGroupID shared.ID, scanType ScanType) (*Scan, error) {
	if name == "" {
		return nil, shared.NewDomainError("VALIDATION", "name is required", shared.ErrValidation)
	}

	// Note: assetGroupID validation is now deferred to Validate()
	// This allows creating scans with either asset_group_id OR targets

	if scanType != ScanTypeWorkflow && scanType != ScanTypeSingle {
		return nil, shared.NewDomainError("VALIDATION", "invalid scan_type", shared.ErrValidation)
	}

	now := time.Now()
	return &Scan{
		ID:                  shared.NewID(),
		TenantID:            tenantID,
		Name:                name,
		AssetGroupID:        assetGroupID,
		AssetGroupIDs:       []shared.ID{},
		Targets:             []string{},
		ScanType:            scanType,
		ScannerConfig:       make(map[string]any),
		TargetsPerJob:       1,
		ScheduleType:        ScheduleManual,
		ScheduleTimezone:    "UTC",
		Tags:                []string{},
		SensorPreference:    SensorPreferenceAuto,
		TimeoutSeconds:      DefaultScanTimeoutSeconds,
		MaxRetries:          0,
		RetryBackoffSeconds: DefaultRetryBackoffSeconds,
		Status:              StatusActive,
		TotalRuns:           0,
		SuccessfulRuns:      0,
		FailedRuns:          0,
		CreatedAt:           now,
		UpdatedAt:           now,
	}, nil
}

// NewScanWithTargets creates a new scan definition with direct targets.
// This is used when creating scans without a pre-existing asset group.
func NewScanWithTargets(tenantID shared.ID, name string, targets []string, scanType ScanType) (*Scan, error) {
	if name == "" {
		return nil, shared.NewDomainError("VALIDATION", "name is required", shared.ErrValidation)
	}

	if len(targets) == 0 {
		return nil, shared.NewDomainError("VALIDATION", "targets are required when no asset_group_id provided", shared.ErrValidation)
	}

	if scanType != ScanTypeWorkflow && scanType != ScanTypeSingle {
		return nil, shared.NewDomainError("VALIDATION", "invalid scan_type", shared.ErrValidation)
	}

	now := time.Now()
	return &Scan{
		ID:                  shared.NewID(),
		TenantID:            tenantID,
		Name:                name,
		AssetGroupID:        shared.ID{}, // Zero value - no asset group
		AssetGroupIDs:       []shared.ID{},
		Targets:             targets,
		ScanType:            scanType,
		ScannerConfig:       make(map[string]any),
		TargetsPerJob:       1,
		ScheduleType:        ScheduleManual,
		ScheduleTimezone:    "UTC",
		Tags:                []string{},
		SensorPreference:    SensorPreferenceAuto,
		TimeoutSeconds:      DefaultScanTimeoutSeconds,
		MaxRetries:          0,
		RetryBackoffSeconds: DefaultRetryBackoffSeconds,
		Status:              StatusActive,
		TotalRuns:           0,
		SuccessfulRuns:      0,
		FailedRuns:          0,
		CreatedAt:           now,
		UpdatedAt:           now,
	}, nil
}

// SetTargets sets the direct target list for the scan.
func (s *Scan) SetTargets(targets []string) {
	if targets == nil {
		targets = []string{}
	}
	s.Targets = targets
	s.UpdatedAt = time.Now()
}

// SetAssetGroupIDs sets multiple asset group IDs for the scan.
func (s *Scan) SetAssetGroupIDs(ids []shared.ID) {
	if ids == nil {
		ids = []shared.ID{}
	}
	s.AssetGroupIDs = ids
	// Also set the primary AssetGroupID to the first one if not already set
	if s.AssetGroupID.IsZero() && len(ids) > 0 {
		s.AssetGroupID = ids[0]
	}
	s.UpdatedAt = time.Now()
}

// SetWorkflow configures the scan to use a workflow scan workflow.
func (s *Scan) SetWorkflow(scanWorkflowID shared.ID) error {
	if s.ScanType != ScanTypeWorkflow {
		return shared.NewDomainError("VALIDATION", "cannot set workflow on single scan type", shared.ErrValidation)
	}
	if scanWorkflowID.IsZero() {
		return shared.NewDomainError("VALIDATION", "scan_workflow_id is required for workflow type", shared.ErrValidation)
	}
	s.ScanWorkflowID = &scanWorkflowID
	s.ScannerName = ""
	s.ScannerConfig = nil
	s.UpdatedAt = time.Now()
	return nil
}

// SetSingleScanner configures the scan to use a single scanner.
func (s *Scan) SetSingleScanner(scannerName string, config map[string]any, targetsPerJob int) error {
	if s.ScanType != ScanTypeSingle {
		return shared.NewDomainError("VALIDATION", "cannot set scanner on workflow type", shared.ErrValidation)
	}
	if scannerName == "" {
		return shared.NewDomainError("VALIDATION", "scanner_name is required for single scan type", shared.ErrValidation)
	}
	if targetsPerJob < 1 {
		targetsPerJob = 1
	}
	s.ScannerName = scannerName
	s.ScannerConfig = config
	s.TargetsPerJob = targetsPerJob
	s.ScanWorkflowID = nil
	s.UpdatedAt = time.Now()
	return nil
}

// SetSchedule configures the schedule for the scan.
func (s *Scan) SetSchedule(scheduleType ScheduleType, cron string, day *int, t *time.Time, timezone string) error {
	switch scheduleType {
	case ScheduleManual:
		s.ScheduleCron = ""
		s.ScheduleDay = nil
		s.ScheduleTime = nil
		s.NextRunAt = nil
	case ScheduleDaily:
		if t == nil {
			return shared.NewDomainError("VALIDATION", "time is required for daily schedule", shared.ErrValidation)
		}
		s.ScheduleDay = nil
	case ScheduleWeekly:
		if day == nil || *day < 0 || *day > 6 {
			return shared.NewDomainError("VALIDATION", "day (0-6) is required for weekly schedule", shared.ErrValidation)
		}
		if t == nil {
			return shared.NewDomainError("VALIDATION", "time is required for weekly schedule", shared.ErrValidation)
		}
	case ScheduleMonthly:
		if day == nil || *day < 1 || *day > 31 {
			return shared.NewDomainError("VALIDATION", "day (1-31) is required for monthly schedule", shared.ErrValidation)
		}
		if t == nil {
			return shared.NewDomainError("VALIDATION", "time is required for monthly schedule", shared.ErrValidation)
		}
	case ScheduleCrontab:
		if cron == "" {
			return shared.NewDomainError("VALIDATION", "cron expression is required for crontab schedule", shared.ErrValidation)
		}
		// Parse with the parser the scheduler uses. An expression it cannot
		// parse used to be stored and then quietly run every 24 hours.
		sched, err := cronParser.Parse(cron)
		if err != nil {
			return shared.NewDomainError("VALIDATION", "cannot parse cron expression: "+err.Error(), shared.ErrValidation)
		}
		// Minimum interval (RFC-046 B8): a schedule that fires more often
		// than every MinScheduleInterval is a scan storm, refused on save.
		if gap := minCronGap(sched, time.Now().UTC()); gap < MinScheduleInterval {
			return shared.NewDomainError("VALIDATION",
				fmt.Sprintf("schedule fires every %s; the minimum interval is %s", gap, MinScheduleInterval),
				shared.ErrValidation)
		}
	default:
		return shared.NewDomainError("VALIDATION", "invalid schedule_type", shared.ErrValidation)
	}
	// A cron expression only drives a crontab schedule; keeping one on a
	// daily/weekly/monthly scan stored (and showed) a schedule nothing honored.
	if scheduleType != ScheduleCrontab {
		cron = ""
	}

	if timezone == "" {
		timezone = "UTC"
	}
	// An unknown zone used to be stored and then silently evaluated as UTC.
	if _, err := time.LoadLocation(timezone); err != nil {
		return shared.NewDomainError("VALIDATION", "unknown timezone: "+timezone, shared.ErrValidation)
	}

	s.ScheduleType = scheduleType
	s.ScheduleCron = cron
	s.ScheduleRRule = ""
	s.ScheduleDay = day
	s.ScheduleTime = t
	s.ScheduleTimezone = timezone
	s.UpdatedAt = time.Now()

	// Compute next run time
	s.computeNextRunAt()

	return nil
}

// computeNextRunAt calculates the next scheduled run time.
func (s *Scan) computeNextRunAt() {
	if s.ScheduleType == ScheduleManual || s.Status != StatusActive {
		s.NextRunAt = nil
		return
	}

	next := s.calculateNextRun()
	s.NextRunAt = next
}

// MinScheduleInterval is the shortest gap between two scheduled runs of a
// scan (RFC-046 B8).
const MinScheduleInterval = 15 * time.Minute

// minCronGap is the shortest gap between consecutive firings of sched over the
// next week from now (a cron expression repeats within a week, except for
// day-of-month rules, whose gaps are larger than any sub-hour one).
func minCronGap(sched cron.Schedule, now time.Time) time.Duration {
	horizon := now.Add(7 * 24 * time.Hour)
	prev := sched.Next(now)
	if prev.IsZero() {
		return 0
	}
	gap := time.Duration(1<<63 - 1)
	for i := 0; i < 2000 && prev.Before(horizon); i++ {
		next := sched.Next(prev)
		if next.IsZero() {
			break
		}
		gap = min(gap, next.Sub(prev))
		prev = next
	}
	return gap
}

// calculateNextRun computes the next run time based on schedule.
// Honors ScheduleTimezone — schedule_time is interpreted in the configured timezone,
// and cron expressions are evaluated in the same timezone.
//
// While the scan's current occurrence is due (the scheduler claiming it), the
// next one is at least MinScheduleInterval after it: a crontab stored before
// the minimum existed (every minute) runs every 15 minutes, not every minute.
func (s *Scan) calculateNextRun() *time.Time {
	now := time.Now()
	base := now
	if s.NextRunAt != nil && !s.NextRunAt.After(now) {
		if floor := s.NextRunAt.Add(MinScheduleInterval - time.Second); floor.After(base) {
			base = floor
		}
	}
	return s.occurrenceAfter(base)
}

// OccurrenceAfter returns the schedule's first occurrence strictly after t,
// in UTC, or nil for a manual scan or an unusable schedule.
func (s *Scan) OccurrenceAfter(t time.Time) *time.Time {
	return s.occurrenceAfter(t)
}

// MaxUpcomingOccurrences bounds UpcomingOccurrences (a preview, not a plan).
const MaxUpcomingOccurrences = 10

// UpcomingOccurrences returns the schedule's next n occurrences strictly after
// t, in UTC, in order: the occurrences the scheduler fires (OccurrenceAfter
// applied n times). n is capped at MaxUpcomingOccurrences; a manual scan or an
// unusable schedule has none, and a rule that ends (UNTIL) returns fewer.
func (s *Scan) UpcomingOccurrences(t time.Time, n int) []time.Time {
	n = min(n, MaxUpcomingOccurrences)
	out := make([]time.Time, 0, max(n, 0))
	for len(out) < n {
		next := s.occurrenceAfter(t)
		if next == nil || !next.After(t) {
			break
		}
		out = append(out, *next)
		t = *next
	}
	return out
}

func (s *Scan) occurrenceAfter(t time.Time) *time.Time {
	if s.ScheduleType == ScheduleManual {
		return nil
	}

	// Resolve timezone (default to UTC on parse failure to avoid silent skew)
	loc, err := time.LoadLocation(s.ScheduleTimezone)
	if err != nil || loc == nil {
		loc = time.UTC
	}

	now := t.In(loc)
	var next time.Time

	switch s.ScheduleType {
	case ScheduleDaily:
		next = nextAtTimeOfDay(now, s.ScheduleTime, 1)
	case ScheduleWeekly:
		next = nextAtWeekday(now, s.ScheduleDay, s.ScheduleTime)
	case ScheduleMonthly:
		next = nextAtDayOfMonth(now, s.ScheduleDay, s.ScheduleTime)
	case ScheduleRRule:
		r, err := parseScheduleRRule(s.ScheduleRRule, loc)
		if err != nil {
			return nil
		}
		next = r.After(now, false)
		if next.IsZero() {
			return nil
		}
	case ScheduleCrontab:
		// Parse cron expression with timezone-aware schedule. SetSchedule
		// refuses an unparseable expression; one stored before that check gets
		// no next run (the scheduler reports it at startup as inert) instead
		// of the old silent "every 24 hours from now".
		schedule, parseErr := cronParser.Parse(s.ScheduleCron)
		if parseErr != nil {
			return nil
		}
		next = schedule.Next(now)
	default:
		return nil
	}

	// Convert back to UTC for storage consistency
	utc := next.UTC()
	return &utc
}

// nextAtTimeOfDay returns the next occurrence of the given time-of-day, advancing
// at least dayOffset days from `now` (1 = tomorrow if today's slot already passed).
func nextAtTimeOfDay(now time.Time, t *time.Time, _ int) time.Time {
	hour, minute := 0, 0
	if t != nil {
		hour = t.Hour()
		minute = t.Minute()
	}
	candidate := time.Date(now.Year(), now.Month(), now.Day(), hour, minute, 0, 0, now.Location())
	if !candidate.After(now) {
		candidate = candidate.AddDate(0, 0, 1)
	}
	return candidate
}

// cronParser is the one cron dialect: 5 fields, as validated on save and
// evaluated by the scheduler.
var cronParser = cron.NewParser(cron.Minute | cron.Hour | cron.Dom | cron.Month | cron.Dow)

// nextAtWeekday returns the next occurrence of the given weekday at the given time-of-day.
//
// A weekly schedule without a day (stored before SetSchedule required one)
// keeps a 7-day period anchored on today's time slot. It used to take the
// next slot (tomorrow once today's had passed) plus 7 days: triggered at its
// slot, the next run was 8 days later, so the scan ran every 8 days and its
// weekday drifted forward each week.
func nextAtWeekday(now time.Time, dayOfWeek *int, t *time.Time) time.Time {
	if dayOfWeek == nil {
		hour, minute := 0, 0
		if t != nil {
			hour, minute = t.Hour(), t.Minute()
		}
		today := time.Date(now.Year(), now.Month(), now.Day(), hour, minute, 0, 0, now.Location())
		if today.After(now) {
			return today
		}
		return today.AddDate(0, 0, 7)
	}
	candidate := nextAtTimeOfDay(now, t, 0)
	target := time.Weekday(*dayOfWeek)
	for candidate.Weekday() != target {
		candidate = candidate.AddDate(0, 0, 1)
	}
	if !candidate.After(now) {
		candidate = candidate.AddDate(0, 0, 7)
	}
	return candidate
}

// nextAtDayOfMonth returns the next occurrence of the given day-of-month at the given time-of-day.
func nextAtDayOfMonth(now time.Time, dayOfMonth *int, t *time.Time) time.Time {
	hour, minute := 0, 0
	if t != nil {
		hour = t.Hour()
		minute = t.Minute()
	}
	day := 1
	if dayOfMonth != nil {
		day = *dayOfMonth
	}
	// Clamp the requested day to the target month's length. time.Date does NOT
	// clamp — time.Date(2026, Feb, 31, …) normalizes forward to early March, so
	// a "31st" schedule would skip February entirely and drift. Build on the
	// clamped day; if that's already past, roll to next month and re-clamp
	// (next month may also be short).
	candidate := dateOnClampedDay(now.Year(), now.Month(), day, hour, minute, now.Location())
	if !candidate.After(now) {
		// Advance one month from a day-1 anchor — adding a month to the clamped
		// candidate itself (e.g. Jan 31) would re-trigger time.Date overflow.
		next := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, now.Location()).AddDate(0, 1, 0)
		candidate = dateOnClampedDay(next.Year(), next.Month(), day, hour, minute, now.Location())
	}
	return candidate
}

// dateOnClampedDay returns time.Date for the given day-of-month, capped to the
// last valid day of that month (e.g. day 31 in February → 28/29).
func dateOnClampedDay(year int, month time.Month, day, hour, minute int, loc *time.Location) time.Time {
	// Day 0 of the next month == last day of this month.
	lastDay := time.Date(year, month+1, 0, 0, 0, 0, 0, loc).Day()
	if day > lastDay {
		day = lastDay
	}
	if day < 1 {
		day = 1
	}
	return time.Date(year, month, day, hour, minute, 0, 0, loc)
}

// CalculateNextRunAt returns the next scheduled run time.
// This is used by the scheduler to update next_run_at after triggering.
func (s *Scan) CalculateNextRunAt() *time.Time {
	return s.calculateNextRun()
}

// SetTags sets the routing tags.
func (s *Scan) SetTags(tags []string) {
	if tags == nil {
		tags = []string{}
	}
	s.Tags = tags
	s.UpdatedAt = time.Now()
}

// SetRunOnTenantRunner sets whether to restrict to tenant runners only.
func (s *Scan) SetRunOnTenantRunner(value bool) {
	s.RunOnTenantRunner = value
	s.UpdatedAt = time.Now()
}

// SetSensorPreference sets the sensor selection preference.
func (s *Scan) SetSensorPreference(pref SensorPreference) {
	if pref == "" {
		pref = SensorPreferenceAuto
	}
	s.SensorPreference = pref
	s.UpdatedAt = time.Now()
}

// SetScanZone pins the scan's targets to one scan zone; nil (or a zero id)
// means Automatic routing.
func (s *Scan) SetScanZone(zoneID *shared.ID) {
	if zoneID != nil && zoneID.IsZero() {
		zoneID = nil
	}
	s.ScanZoneID = zoneID
	s.UpdatedAt = time.Now()
}

// SetProfileID links the scan to a scan profile (for tool configs and quality gates).
// Pass nil to unlink.
func (s *Scan) SetProfileID(profileID *shared.ID) {
	s.ProfileID = profileID
	s.UpdatedAt = time.Now()
}

// SetTimeoutSeconds sets the maximum execution time in seconds.
// Enforces [MinScanTimeoutSeconds, MaxScanTimeoutSeconds] bounds at the domain layer
// (defense-in-depth — even if HTTP validation is bypassed, the domain enforces the floor).
// If <= 0, defaults to DefaultScanTimeoutSeconds.
func (s *Scan) SetTimeoutSeconds(seconds int) {
	if seconds <= 0 {
		seconds = DefaultScanTimeoutSeconds
	}
	if seconds < MinScanTimeoutSeconds {
		seconds = MinScanTimeoutSeconds
	}
	if seconds > MaxScanTimeoutSeconds {
		seconds = MaxScanTimeoutSeconds
	}
	s.TimeoutSeconds = seconds
	s.UpdatedAt = time.Now()
}

// SetRetryConfig configures the retry behavior for failed runs.
// maxRetries is capped at MaxRetryCount; backoff is bounded to [Min,Max]RetryBackoffSeconds.
func (s *Scan) SetRetryConfig(maxRetries, backoffSeconds int) {
	if maxRetries < 0 {
		maxRetries = 0
	}
	if maxRetries > MaxRetryCount {
		maxRetries = MaxRetryCount
	}
	if backoffSeconds <= 0 {
		backoffSeconds = DefaultRetryBackoffSeconds
	}
	if backoffSeconds < MinRetryBackoffSeconds {
		backoffSeconds = MinRetryBackoffSeconds
	}
	if backoffSeconds > MaxRetryBackoffSeconds {
		backoffSeconds = MaxRetryBackoffSeconds
	}
	s.MaxRetries = maxRetries
	s.RetryBackoffSeconds = backoffSeconds
	s.UpdatedAt = time.Now()
}

// CalculateRetryDelay returns the exponential backoff delay for the given attempt number.
// attempt 0 = first retry, attempt 1 = second retry, etc.
// Capped at MaxRetryBackoffSeconds.
func (s *Scan) CalculateRetryDelay(attempt int) time.Duration {
	backoff := s.RetryBackoffSeconds
	if backoff <= 0 {
		backoff = DefaultRetryBackoffSeconds
	}
	// delay = backoff * 2^attempt, capped
	delay := backoff
	for i := 0; i < attempt && delay < MaxRetryBackoffSeconds; i++ {
		delay *= 2
	}
	if delay > MaxRetryBackoffSeconds {
		delay = MaxRetryBackoffSeconds
	}
	return time.Duration(delay) * time.Second
}

// ShouldRetry returns true if a failed run with the given retry attempt should be retried.
func (s *Scan) ShouldRetry(currentAttempt int) bool {
	return s.MaxRetries > 0 && currentAttempt < s.MaxRetries
}

// Activate activates the scan.
func (s *Scan) Activate() error {
	if s.Status == StatusActive {
		return nil
	}
	s.Status = StatusActive
	s.UpdatedAt = time.Now()
	s.computeNextRunAt()
	return nil
}

// Pause pauses the scan (scheduled scans won't run).
func (s *Scan) Pause() error {
	if s.Status == StatusPaused {
		return nil
	}
	s.Status = StatusPaused
	s.NextRunAt = nil
	s.UpdatedAt = time.Now()
	return nil
}

// Disable disables the scan.
func (s *Scan) Disable() error {
	if s.Status == StatusDisabled {
		return nil
	}
	s.Status = StatusDisabled
	s.NextRunAt = nil
	s.UpdatedAt = time.Now()
	return nil
}

// RecordRun records the result of a scan run.
func (s *Scan) RecordRun(runID shared.ID, status string) {
	s.LastRunID = &runID
	now := time.Now()
	s.LastRunAt = &now
	s.LastRunStatus = status
	s.TotalRuns++

	if status == RunStatusCompleted || status == RunStatusSuccess {
		s.SuccessfulRuns++
	} else if status == RunStatusPartial {
		s.PartialRuns++
	} else if status == RunStatusFailed || status == RunStatusError {
		s.FailedRuns++
	}

	s.UpdatedAt = now

	// Compute next run time after recording
	s.computeNextRunAt()
}

// SetCreatedBy sets the user who created the scan.
func (s *Scan) SetCreatedBy(userID shared.ID) {
	s.CreatedBy = &userID
}

// Update updates the scan fields.
func (s *Scan) Update(name, description string) error {
	if name == "" {
		return shared.NewDomainError("VALIDATION", "name is required", shared.ErrValidation)
	}
	s.Name = name
	s.Description = description
	s.UpdatedAt = time.Now()
	return nil
}

// Validate validates the scan.
func (s *Scan) Validate() error {
	if s.Name == "" {
		return shared.NewDomainError("VALIDATION", "name is required", shared.ErrValidation)
	}

	// Require EITHER asset_group_id/asset_group_ids OR targets (can have any combination)
	hasAssetGroup := !s.AssetGroupID.IsZero() || len(s.AssetGroupIDs) > 0
	hasTargets := len(s.Targets) > 0
	if !hasAssetGroup && !hasTargets {
		return shared.NewDomainError("VALIDATION", "either asset_group_id/asset_group_ids or targets must be provided", shared.ErrValidation)
	}

	switch s.ScanType {
	case ScanTypeWorkflow:
		if s.ScanWorkflowID == nil || s.ScanWorkflowID.IsZero() {
			return shared.NewDomainError("VALIDATION", "scan_workflow_id is required for workflow type", shared.ErrValidation)
		}
	case ScanTypeSingle:
		if s.ScannerName == "" {
			return shared.NewDomainError("VALIDATION", "scanner_name is required for single scan type", shared.ErrValidation)
		}
	default:
		return shared.NewDomainError("VALIDATION", "invalid scan_type", shared.ErrValidation)
	}

	return nil
}

// HasTargets returns true if the scan has direct targets.
func (s *Scan) HasTargets() bool {
	return len(s.Targets) > 0
}

// HasAssetGroup returns true if the scan is linked to an asset group.
func (s *Scan) HasAssetGroup() bool {
	return !s.AssetGroupID.IsZero() || len(s.AssetGroupIDs) > 0
}

// GetAllAssetGroupIDs returns all asset group IDs (both singular and multiple).
func (s *Scan) GetAllAssetGroupIDs() []shared.ID {
	ids := make([]shared.ID, 0, len(s.AssetGroupIDs)+1)
	// Add primary asset group ID if set
	if !s.AssetGroupID.IsZero() {
		ids = append(ids, s.AssetGroupID)
	}
	// Add additional asset group IDs (avoiding duplicates)
	for _, id := range s.AssetGroupIDs {
		if !id.IsZero() && (len(ids) == 0 || ids[0] != id) {
			ids = append(ids, id)
		}
	}
	return ids
}

// CanTrigger returns true if the scan can be triggered.
func (s *Scan) CanTrigger() bool {
	return s.Status == StatusActive
}

// IsDueForExecution returns true if the scan is due for scheduled execution.
func (s *Scan) IsDueForExecution(now time.Time) bool {
	if s.Status != StatusActive {
		return false
	}
	if s.ScheduleType == ScheduleManual {
		return false
	}
	if s.NextRunAt == nil {
		return false
	}
	return now.After(*s.NextRunAt) || now.Equal(*s.NextRunAt)
}

// SaveAsConfiguration turns an ad-hoc quick scan into a saved configuration
// under name: it then shows in the Configurations list and can be scheduled
// like any other. Its runs stay attached.
func (s *Scan) SaveAsConfiguration(name string) error {
	if !s.AdHoc {
		return shared.NewDomainError("VALIDATION", "scan is already a saved configuration", shared.ErrValidation)
	}
	name = strings.TrimSpace(name)
	if name == "" {
		return shared.NewDomainError("VALIDATION", "name is required", shared.ErrValidation)
	}
	s.Name = name
	s.AdHoc = false
	s.UpdatedAt = time.Now()
	return nil
}

// Clone creates a copy of the scan with a new ID.
func (s *Scan) Clone(newName string) *Scan {
	now := time.Now()
	clone := &Scan{
		ID:                  shared.NewID(),
		TenantID:            s.TenantID,
		Name:                newName,
		Description:         s.Description,
		AssetGroupID:        s.AssetGroupID,
		AssetGroupIDs:       make([]shared.ID, len(s.AssetGroupIDs)),
		Targets:             make([]string, len(s.Targets)),
		ScanType:            s.ScanType,
		ScanWorkflowID:      s.ScanWorkflowID,
		ScannerName:         s.ScannerName,
		TargetsPerJob:       s.TargetsPerJob,
		ScheduleType:        s.ScheduleType,
		ScheduleCron:        s.ScheduleCron,
		ScheduleDay:         s.ScheduleDay,
		ScheduleTime:        s.ScheduleTime,
		ScheduleTimezone:    s.ScheduleTimezone,
		Tags:                make([]string, len(s.Tags)),
		RunOnTenantRunner:   s.RunOnTenantRunner,
		SensorPreference:    s.SensorPreference,
		ScanZoneID:          s.ScanZoneID,
		ProfileID:           s.ProfileID,
		TimeoutSeconds:      s.TimeoutSeconds,
		MaxRetries:          s.MaxRetries,
		RetryBackoffSeconds: s.RetryBackoffSeconds,
		Status:              StatusActive,
		TotalRuns:           0,
		SuccessfulRuns:      0,
		FailedRuns:          0,
		CreatedAt:           now,
		UpdatedAt:           now,
	}

	// Deep copy maps and slices
	if s.ScannerConfig != nil {
		clone.ScannerConfig = make(map[string]any)
		for k, v := range s.ScannerConfig {
			clone.ScannerConfig[k] = v
		}
	}
	copy(clone.Tags, s.Tags)
	copy(clone.Targets, s.Targets)
	copy(clone.AssetGroupIDs, s.AssetGroupIDs)

	clone.computeNextRunAt()
	return clone
}

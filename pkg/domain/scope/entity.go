package scope

import (
	"time"

	"github.com/openctemio/api/pkg/domain/shared"
)

// =============================================================================
// Scope Target Entity
// =============================================================================

// Target represents an in-scope target for security scanning.
type Target struct {
	id          shared.ID
	tenantID    shared.ID
	targetType  TargetType
	pattern     string
	description string
	priority    int
	status      Status
	tags        []string
	createdBy   string
	createdAt   time.Time
	updatedAt   time.Time
}

// NewTarget creates a new scope target.
func NewTarget(
	tenantID shared.ID,
	targetType TargetType,
	pattern string,
	description string,
	createdBy string,
) (*Target, error) {
	if tenantID.IsZero() {
		return nil, ErrInvalidTenantID
	}

	if !targetType.IsValid() {
		return nil, ErrInvalidTargetType
	}

	if err := ValidatePattern(targetType, pattern); err != nil {
		return nil, err
	}

	now := time.Now()
	return &Target{
		id:          shared.NewID(),
		tenantID:    tenantID,
		targetType:  targetType,
		pattern:     pattern,
		description: description,
		priority:    0,
		status:      StatusActive,
		tags:        []string{},
		createdBy:   createdBy,
		createdAt:   now,
		updatedAt:   now,
	}, nil
}

// ReconstituteTarget creates a Target from persistence data.
func ReconstituteTarget(
	id shared.ID,
	tenantID shared.ID,
	targetType TargetType,
	pattern string,
	description string,
	priority int,
	status Status,
	tags []string,
	createdBy string,
	createdAt time.Time,
	updatedAt time.Time,
) *Target {
	return &Target{
		id:          id,
		tenantID:    tenantID,
		targetType:  targetType,
		pattern:     pattern,
		description: description,
		priority:    priority,
		status:      status,
		tags:        tags,
		createdBy:   createdBy,
		createdAt:   createdAt,
		updatedAt:   updatedAt,
	}
}

// Getters
func (t *Target) ID() shared.ID          { return t.id }
func (t *Target) TenantID() shared.ID    { return t.tenantID }
func (t *Target) TargetType() TargetType { return t.targetType }
func (t *Target) Pattern() string        { return t.pattern }
func (t *Target) Description() string    { return t.description }
func (t *Target) Priority() int          { return t.priority }
func (t *Target) Status() Status         { return t.status }
func (t *Target) Tags() []string         { return t.tags }
func (t *Target) CreatedBy() string      { return t.createdBy }
func (t *Target) CreatedAt() time.Time   { return t.createdAt }
func (t *Target) UpdatedAt() time.Time   { return t.updatedAt }

// IsActive returns true if the target is active.
func (t *Target) IsActive() bool {
	return t.status == StatusActive
}

// Matches checks if a value matches this target's pattern.
func (t *Target) Matches(value string) bool {
	return MatchesPattern(t.targetType, t.pattern, value)
}

// Update methods
func (t *Target) UpdateDescription(description string) {
	t.description = description
	t.updatedAt = time.Now()
}

func (t *Target) UpdatePriority(priority int) {
	t.priority = priority
	t.updatedAt = time.Now()
}

func (t *Target) UpdateTags(tags []string) {
	t.tags = tags
	t.updatedAt = time.Now()
}

func (t *Target) Activate() {
	t.status = StatusActive
	t.updatedAt = time.Now()
}

func (t *Target) Deactivate() {
	t.status = StatusInactive
	t.updatedAt = time.Now()
}

// =============================================================================
// Scope Exclusion Entity
// =============================================================================

// Exclusion represents an exclusion from scope for security scanning.
type Exclusion struct {
	id            shared.ID
	tenantID      shared.ID
	exclusionType ExclusionType
	pattern       string
	reason        string
	status        Status
	expiresAt     *time.Time
	approvedBy    string
	approvedAt    *time.Time
	createdBy     string
	createdAt     time.Time
	updatedAt     time.Time
}

// NewExclusion creates a new scope exclusion.
func NewExclusion(
	tenantID shared.ID,
	exclusionType ExclusionType,
	pattern string,
	reason string,
	expiresAt *time.Time,
	createdBy string,
) (*Exclusion, error) {
	if tenantID.IsZero() {
		return nil, ErrInvalidTenantID
	}

	if !exclusionType.IsValid() {
		return nil, ErrInvalidExclusionType
	}

	if reason == "" {
		return nil, ErrReasonRequired
	}

	now := time.Now()
	return &Exclusion{
		id:            shared.NewID(),
		tenantID:      tenantID,
		exclusionType: exclusionType,
		pattern:       pattern,
		reason:        reason,
		status:        StatusActive,
		expiresAt:     expiresAt,
		createdBy:     createdBy,
		createdAt:     now,
		updatedAt:     now,
	}, nil
}

// ReconstituteExclusion creates an Exclusion from persistence data.
func ReconstituteExclusion(
	id shared.ID,
	tenantID shared.ID,
	exclusionType ExclusionType,
	pattern string,
	reason string,
	status Status,
	expiresAt *time.Time,
	approvedBy string,
	approvedAt *time.Time,
	createdBy string,
	createdAt time.Time,
	updatedAt time.Time,
) *Exclusion {
	return &Exclusion{
		id:            id,
		tenantID:      tenantID,
		exclusionType: exclusionType,
		pattern:       pattern,
		reason:        reason,
		status:        status,
		expiresAt:     expiresAt,
		approvedBy:    approvedBy,
		approvedAt:    approvedAt,
		createdBy:     createdBy,
		createdAt:     createdAt,
		updatedAt:     updatedAt,
	}
}

// Getters
func (e *Exclusion) ID() shared.ID                { return e.id }
func (e *Exclusion) TenantID() shared.ID          { return e.tenantID }
func (e *Exclusion) ExclusionType() ExclusionType { return e.exclusionType }
func (e *Exclusion) Pattern() string              { return e.pattern }
func (e *Exclusion) Reason() string               { return e.reason }
func (e *Exclusion) Status() Status               { return e.status }
func (e *Exclusion) ExpiresAt() *time.Time        { return e.expiresAt }
func (e *Exclusion) ApprovedBy() string           { return e.approvedBy }
func (e *Exclusion) ApprovedAt() *time.Time       { return e.approvedAt }
func (e *Exclusion) CreatedBy() string            { return e.createdBy }
func (e *Exclusion) CreatedAt() time.Time         { return e.createdAt }
func (e *Exclusion) UpdatedAt() time.Time         { return e.updatedAt }

// IsActive returns true if the exclusion is active and not expired.
func (e *Exclusion) IsActive() bool {
	if e.status != StatusActive {
		return false
	}
	if e.expiresAt != nil && time.Now().After(*e.expiresAt) {
		return false
	}
	return true
}

// IsApproved returns true if the exclusion has been approved.
func (e *Exclusion) IsApproved() bool {
	return e.approvedBy != "" && e.approvedAt != nil
}

// Matches checks if a value matches this exclusion's pattern.
func (e *Exclusion) Matches(value string) bool {
	// Convert exclusion type to target type for matching
	targetType := TargetType(e.exclusionType)
	return MatchesPattern(targetType, e.pattern, value)
}

// Update methods
func (e *Exclusion) UpdateReason(reason string) {
	e.reason = reason
	e.updatedAt = time.Now()
}

func (e *Exclusion) UpdateExpiresAt(expiresAt *time.Time) {
	e.expiresAt = expiresAt
	e.updatedAt = time.Now()
}

func (e *Exclusion) Approve(approvedBy string) {
	now := time.Now()
	e.approvedBy = approvedBy
	e.approvedAt = &now
	e.updatedAt = now
}

func (e *Exclusion) Activate() {
	e.status = StatusActive
	e.updatedAt = time.Now()
}

func (e *Exclusion) Deactivate() {
	e.status = StatusInactive
	e.updatedAt = time.Now()
}

func (e *Exclusion) MarkExpired() {
	e.status = StatusExpired
	e.updatedAt = time.Now()
}

// =============================================================================
// Scan Schedule Entity
// =============================================================================

// Schedule represents an automated scan schedule.
type Schedule struct {
	id                   shared.ID
	tenantID             shared.ID
	name                 string
	description          string
	scanType             ScanType
	targetScope          TargetScope
	targetIDs            []shared.ID
	targetTags           []string
	scannerConfigs       map[string]interface{}
	scheduleType         ScheduleType
	cronExpression       string
	intervalHours        int
	enabled              bool
	lastRunAt            *time.Time
	lastRunStatus        string
	nextRunAt            *time.Time
	notifyOnCompletion   bool
	notifyOnFindings     bool
	notificationChannels []string
	createdBy            string
	createdAt            time.Time
	updatedAt            time.Time
}

// NewSchedule creates a new scan schedule.
func NewSchedule(
	tenantID shared.ID,
	name string,
	scanType ScanType,
	scheduleType ScheduleType,
	createdBy string,
) (*Schedule, error) {
	if tenantID.IsZero() {
		return nil, ErrInvalidTenantID
	}

	if name == "" {
		return nil, ErrNameRequired
	}

	if !scanType.IsValid() {
		return nil, ErrInvalidScanType
	}

	if !scheduleType.IsValid() {
		return nil, ErrInvalidScheduleType
	}

	now := time.Now()
	return &Schedule{
		id:                   shared.NewID(),
		tenantID:             tenantID,
		name:                 name,
		scanType:             scanType,
		targetScope:          TargetScopeAll,
		targetIDs:            []shared.ID{},
		targetTags:           []string{},
		scannerConfigs:       make(map[string]interface{}),
		scheduleType:         scheduleType,
		enabled:              true,
		notifyOnCompletion:   true,
		notifyOnFindings:     true,
		notificationChannels: []string{"email"},
		createdBy:            createdBy,
		createdAt:            now,
		updatedAt:            now,
	}, nil
}

// ReconstituteSchedule creates a Schedule from persistence data.
func ReconstituteSchedule(
	id shared.ID,
	tenantID shared.ID,
	name string,
	description string,
	scanType ScanType,
	targetScope TargetScope,
	targetIDs []shared.ID,
	targetTags []string,
	scannerConfigs map[string]interface{},
	scheduleType ScheduleType,
	cronExpression string,
	intervalHours int,
	enabled bool,
	lastRunAt *time.Time,
	lastRunStatus string,
	nextRunAt *time.Time,
	notifyOnCompletion bool,
	notifyOnFindings bool,
	notificationChannels []string,
	createdBy string,
	createdAt time.Time,
	updatedAt time.Time,
) *Schedule {
	return &Schedule{
		id:                   id,
		tenantID:             tenantID,
		name:                 name,
		description:          description,
		scanType:             scanType,
		targetScope:          targetScope,
		targetIDs:            targetIDs,
		targetTags:           targetTags,
		scannerConfigs:       scannerConfigs,
		scheduleType:         scheduleType,
		cronExpression:       cronExpression,
		intervalHours:        intervalHours,
		enabled:              enabled,
		lastRunAt:            lastRunAt,
		lastRunStatus:        lastRunStatus,
		nextRunAt:            nextRunAt,
		notifyOnCompletion:   notifyOnCompletion,
		notifyOnFindings:     notifyOnFindings,
		notificationChannels: notificationChannels,
		createdBy:            createdBy,
		createdAt:            createdAt,
		updatedAt:            updatedAt,
	}
}

// Getters
func (s *Schedule) ID() shared.ID                          { return s.id }
func (s *Schedule) TenantID() shared.ID                    { return s.tenantID }
func (s *Schedule) Name() string                           { return s.name }
func (s *Schedule) Description() string                    { return s.description }
func (s *Schedule) ScanType() ScanType                     { return s.scanType }
func (s *Schedule) TargetScope() TargetScope               { return s.targetScope }
func (s *Schedule) TargetIDs() []shared.ID                 { return s.targetIDs }
func (s *Schedule) TargetTags() []string                   { return s.targetTags }
func (s *Schedule) ScannerConfigs() map[string]interface{} { return s.scannerConfigs }
func (s *Schedule) ScheduleType() ScheduleType             { return s.scheduleType }
func (s *Schedule) CronExpression() string                 { return s.cronExpression }
func (s *Schedule) IntervalHours() int                     { return s.intervalHours }
func (s *Schedule) Enabled() bool                          { return s.enabled }
func (s *Schedule) LastRunAt() *time.Time                  { return s.lastRunAt }
func (s *Schedule) LastRunStatus() string                  { return s.lastRunStatus }
func (s *Schedule) NextRunAt() *time.Time                  { return s.nextRunAt }
func (s *Schedule) NotifyOnCompletion() bool               { return s.notifyOnCompletion }
func (s *Schedule) NotifyOnFindings() bool                 { return s.notifyOnFindings }
func (s *Schedule) NotificationChannels() []string         { return s.notificationChannels }
func (s *Schedule) CreatedBy() string                      { return s.createdBy }
func (s *Schedule) CreatedAt() time.Time                   { return s.createdAt }
func (s *Schedule) UpdatedAt() time.Time                   { return s.updatedAt }

// Update methods
func (s *Schedule) UpdateName(name string) {
	s.name = name
	s.updatedAt = time.Now()
}

func (s *Schedule) UpdateDescription(description string) {
	s.description = description
	s.updatedAt = time.Now()
}

func (s *Schedule) SetCronSchedule(cronExpression string) {
	s.scheduleType = ScheduleTypeCron
	s.cronExpression = cronExpression
	s.intervalHours = 0
	s.updatedAt = time.Now()
}

func (s *Schedule) SetIntervalSchedule(hours int) {
	s.scheduleType = ScheduleTypeInterval
	s.intervalHours = hours
	s.cronExpression = ""
	s.updatedAt = time.Now()
}

func (s *Schedule) SetTargetScope(scope TargetScope, ids []shared.ID, tags []string) {
	s.targetScope = scope
	s.targetIDs = ids
	s.targetTags = tags
	s.updatedAt = time.Now()
}

func (s *Schedule) UpdateScannerConfigs(configs map[string]interface{}) {
	s.scannerConfigs = configs
	s.updatedAt = time.Now()
}

func (s *Schedule) Enable() {
	s.enabled = true
	s.updatedAt = time.Now()
}

func (s *Schedule) Disable() {
	s.enabled = false
	s.updatedAt = time.Now()
}

func (s *Schedule) RecordRun(status string, nextRunAt *time.Time) {
	now := time.Now()
	s.lastRunAt = &now
	s.lastRunStatus = status
	s.nextRunAt = nextRunAt
	s.updatedAt = now
}

func (s *Schedule) UpdateNotifications(onCompletion, onFindings bool, channels []string) {
	s.notifyOnCompletion = onCompletion
	s.notifyOnFindings = onFindings
	s.notificationChannels = channels
	s.updatedAt = time.Now()
}

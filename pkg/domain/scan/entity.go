package scan

import (
	"time"

	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/robfig/cron/v3"
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
	ScanType      ScanType
	PipelineID    *shared.ID     // For workflow type
	ScannerName   string         // For single type
	ScannerConfig map[string]any // Scanner-specific configuration
	TargetsPerJob int            // Number of targets per job batch

	// Schedule
	ScheduleType     ScheduleType
	ScheduleCron     string     // Cron expression (for crontab type)
	ScheduleDay      *int       // Day of week (0-6) or month (1-31)
	ScheduleTime     *time.Time // Time of day to run
	ScheduleTimezone string
	NextRunAt        *time.Time // Pre-computed next run time

	// Routing
	Tags              []string        // Route to agents with matching tags
	RunOnTenantRunner bool            // Restrict to tenant's own runners
	AgentPreference   AgentPreference // Agent selection mode: auto, tenant, platform

	// Status
	Status Status

	// Execution Statistics
	LastRunID      *shared.ID
	LastRunAt      *time.Time
	LastRunStatus  string
	TotalRuns      int
	SuccessfulRuns int
	FailedRuns     int

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
		ID:               shared.NewID(),
		TenantID:         tenantID,
		Name:             name,
		AssetGroupID:     assetGroupID,
		AssetGroupIDs:    []shared.ID{},
		Targets:          []string{},
		ScanType:         scanType,
		ScannerConfig:    make(map[string]any),
		TargetsPerJob:    1,
		ScheduleType:     ScheduleManual,
		ScheduleTimezone: "UTC",
		Tags:             []string{},
		AgentPreference:  AgentPreferenceAuto,
		Status:           StatusActive,
		TotalRuns:        0,
		SuccessfulRuns:   0,
		FailedRuns:       0,
		CreatedAt:        now,
		UpdatedAt:        now,
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
		ID:               shared.NewID(),
		TenantID:         tenantID,
		Name:             name,
		AssetGroupID:     shared.ID{}, // Zero value - no asset group
		AssetGroupIDs:    []shared.ID{},
		Targets:          targets,
		ScanType:         scanType,
		ScannerConfig:    make(map[string]any),
		TargetsPerJob:    1,
		ScheduleType:     ScheduleManual,
		ScheduleTimezone: "UTC",
		Tags:             []string{},
		AgentPreference:  AgentPreferenceAuto,
		Status:           StatusActive,
		TotalRuns:        0,
		SuccessfulRuns:   0,
		FailedRuns:       0,
		CreatedAt:        now,
		UpdatedAt:        now,
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

// SetWorkflow configures the scan to use a workflow pipeline.
func (s *Scan) SetWorkflow(pipelineID shared.ID) error {
	if s.ScanType != ScanTypeWorkflow {
		return shared.NewDomainError("VALIDATION", "cannot set workflow on single scan type", shared.ErrValidation)
	}
	if pipelineID.IsZero() {
		return shared.NewDomainError("VALIDATION", "pipeline_id is required for workflow type", shared.ErrValidation)
	}
	s.PipelineID = &pipelineID
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
	s.PipelineID = nil
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
	default:
		return shared.NewDomainError("VALIDATION", "invalid schedule_type", shared.ErrValidation)
	}

	if timezone == "" {
		timezone = "UTC"
	}

	s.ScheduleType = scheduleType
	s.ScheduleCron = cron
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

// calculateNextRun computes the next run time based on schedule.
func (s *Scan) calculateNextRun() *time.Time {
	if s.ScheduleType == ScheduleManual {
		return nil
	}

	now := time.Now()
	var next time.Time

	switch s.ScheduleType {
	case ScheduleDaily:
		next = now.Add(24 * time.Hour)
	case ScheduleWeekly:
		next = now.Add(7 * 24 * time.Hour)
	case ScheduleMonthly:
		next = now.AddDate(0, 1, 0)
	case ScheduleCrontab:
		// Parse cron expression using robfig/cron
		parser := cron.NewParser(cron.Minute | cron.Hour | cron.Dom | cron.Month | cron.Dow)
		schedule, err := parser.Parse(s.ScheduleCron)
		if err != nil {
			// Fallback to 24 hours if parsing fails
			next = now.Add(24 * time.Hour)
		} else {
			next = schedule.Next(now)
		}
	default:
		return nil
	}

	return &next
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

// SetAgentPreference sets the agent selection preference.
func (s *Scan) SetAgentPreference(pref AgentPreference) {
	if pref == "" {
		pref = AgentPreferenceAuto
	}
	s.AgentPreference = pref
	s.UpdatedAt = time.Now()
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

	if status == "completed" || status == "success" {
		s.SuccessfulRuns++
	} else if status == "failed" || status == "error" {
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
		if s.PipelineID == nil || s.PipelineID.IsZero() {
			return shared.NewDomainError("VALIDATION", "pipeline_id is required for workflow type", shared.ErrValidation)
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

// Clone creates a copy of the scan with a new ID.
func (s *Scan) Clone(newName string) *Scan {
	now := time.Now()
	clone := &Scan{
		ID:                shared.NewID(),
		TenantID:          s.TenantID,
		Name:              newName,
		Description:       s.Description,
		AssetGroupID:      s.AssetGroupID,
		AssetGroupIDs:     make([]shared.ID, len(s.AssetGroupIDs)),
		Targets:           make([]string, len(s.Targets)),
		ScanType:          s.ScanType,
		PipelineID:        s.PipelineID,
		ScannerName:       s.ScannerName,
		TargetsPerJob:     s.TargetsPerJob,
		ScheduleType:      s.ScheduleType,
		ScheduleCron:      s.ScheduleCron,
		ScheduleDay:       s.ScheduleDay,
		ScheduleTime:      s.ScheduleTime,
		ScheduleTimezone:  s.ScheduleTimezone,
		Tags:              make([]string, len(s.Tags)),
		RunOnTenantRunner: s.RunOnTenantRunner,
		AgentPreference:   s.AgentPreference,
		Status:            StatusActive,
		TotalRuns:         0,
		SuccessfulRuns:    0,
		FailedRuns:        0,
		CreatedAt:         now,
		UpdatedAt:         now,
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

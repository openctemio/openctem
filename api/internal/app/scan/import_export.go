package scan

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/audit"
	"github.com/openctemio/openctem/api/pkg/domain/scan"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// =============================================================================
// Config Export/Import Operations
// =============================================================================

// ScanConfigExport represents the exportable configuration of a scan.
// It excludes runtime data like status, execution stats, and timestamps.
type ScanConfigExport struct {
	// Metadata
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`

	// Targets
	AssetGroupIDs []string `json:"asset_group_ids,omitempty"`
	Targets       []string `json:"targets,omitempty"`
	// TargetOptions tunes how each run resolves the dynamic selectors among
	// Targets (RFC-068); omitted when every option is the default.
	TargetOptions *scan.TargetOptions `json:"target_options,omitempty"`
	// Intensity is the probe ceiling (RFC-071).
	Intensity string `json:"intensity,omitempty"`

	// Scan Type
	ScanType       string         `json:"scan_type"`
	ScanWorkflowID *string        `json:"scan_workflow_id,omitempty"`
	ScannerName    string         `json:"scanner_name,omitempty"`
	ScannerConfig  map[string]any `json:"scanner_config,omitempty"`
	TargetsPerJob  int            `json:"targets_per_job"`

	// Schedule
	ScheduleType     string  `json:"schedule_type"`
	ScheduleCron     string  `json:"schedule_cron,omitempty"`
	ScheduleRRule    string  `json:"schedule_rrule,omitempty"`
	ScheduleDay      *int    `json:"schedule_day,omitempty"`
	ScheduleTime     *string `json:"schedule_time,omitempty"`
	ScheduleTimezone string  `json:"schedule_timezone"`
	// ScheduleRunAt is the one run of a once schedule (RFC 3339).
	ScheduleRunAt *time.Time `json:"schedule_run_at,omitempty"`

	// Routing
	Tags              []string `json:"tags,omitempty"`
	RunOnTenantRunner bool     `json:"run_on_tenant_runner"`
	SensorPreference  string   `json:"sensor_preference,omitempty"`

	// Profile and timeout
	ProfileID      string `json:"profile_id,omitempty"`
	TimeoutSeconds int    `json:"timeout_seconds,omitempty"`

	// Retry config
	MaxRetries          int `json:"max_retries,omitempty"`
	RetryBackoffSeconds int `json:"retry_backoff_seconds,omitempty"`

	// Export metadata
	ExportedAt string `json:"exported_at"`
	Version    string `json:"version"`
}

// configExportVersion is the current version of the export format.
const configExportVersion = "1.0"

// ExportOptions shape an export.
type ExportOptions struct {
	// RedactSecrets masks secret-looking scanner_config values (see
	// scan.RedactConfigSecrets). Set for callers that may read a scan but
	// not edit it.
	RedactSecrets bool
}

// ExportConfig exports a scan configuration as JSON bytes.
// It strips runtime data (status, results, timestamps) and returns
// only the configuration fields needed to recreate the scan.
func (s *Service) ExportConfig(ctx context.Context, tenantID, scanID shared.ID) ([]byte, error) {
	return s.ExportConfigWithOptions(ctx, tenantID, scanID, ExportOptions{})
}

// ExportConfigWithOptions is ExportConfig with options.
func (s *Service) ExportConfigWithOptions(ctx context.Context, tenantID, scanID shared.ID, opts ExportOptions) ([]byte, error) {
	s.logger.Info("exporting scan config", "scan_id", scanID.String())

	sc, err := s.scanRepo.GetByTenantAndID(ctx, tenantID, scanID)
	if err != nil {
		return nil, err
	}

	export := ScanConfigExport{
		Name:                sc.Name,
		Description:         sc.Description,
		ScanType:            string(sc.ScanType),
		ScannerName:         sc.ScannerName,
		ScannerConfig:       sc.ScannerConfig,
		TargetsPerJob:       sc.TargetsPerJob,
		ScheduleType:        string(sc.ScheduleType),
		ScheduleCron:        sc.ScheduleCron,
		ScheduleRRule:       sc.ScheduleRRule,
		ScheduleDay:         sc.ScheduleDay,
		ScheduleTimezone:    sc.ScheduleTimezone,
		ScheduleRunAt:       sc.ScheduleRunAt,
		RunOnTenantRunner:   sc.RunOnTenantRunner,
		SensorPreference:    string(sc.SensorPreference),
		TimeoutSeconds:      sc.TimeoutSeconds,
		MaxRetries:          sc.MaxRetries,
		RetryBackoffSeconds: sc.RetryBackoffSeconds,
		ExportedAt:          time.Now().UTC().Format(time.RFC3339),
		Version:             configExportVersion,
	}
	if opts.RedactSecrets {
		export.ScannerConfig = scan.RedactConfigSecrets(sc.ScannerConfig)
	}
	export.Intensity = string(sc.EffectiveIntensity())
	if !sc.TargetOptions.IsZero() {
		o := sc.TargetOptions
		export.TargetOptions = &o
	}

	if sc.ProfileID != nil && !sc.ProfileID.IsZero() {
		export.ProfileID = sc.ProfileID.String()
	}

	// Convert targets
	if len(sc.Targets) > 0 {
		export.Targets = make([]string, len(sc.Targets))
		copy(export.Targets, sc.Targets)
	}

	// Convert asset group IDs
	allGroupIDs := sc.GetAllAssetGroupIDs()
	if len(allGroupIDs) > 0 {
		export.AssetGroupIDs = make([]string, 0, len(allGroupIDs))
		for _, id := range allGroupIDs {
			if !id.IsZero() {
				export.AssetGroupIDs = append(export.AssetGroupIDs, id.String())
			}
		}
	}

	// Convert scan workflow ID
	if sc.ScanWorkflowID != nil && !sc.ScanWorkflowID.IsZero() {
		pid := sc.ScanWorkflowID.String()
		export.ScanWorkflowID = &pid
	}

	// Convert schedule time
	if sc.ScheduleTime != nil {
		st := sc.ScheduleTime.Format("15:04")
		export.ScheduleTime = &st
	}

	// Convert tags
	if len(sc.Tags) > 0 {
		export.Tags = make([]string, len(sc.Tags))
		copy(export.Tags, sc.Tags)
	}

	data, err := json.MarshalIndent(export, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("failed to marshal scan config: %w", err)
	}

	// Audit log
	s.logAudit(ctx, AuditContext{TenantID: tenantID.String()},
		NewSuccessEvent(audit.ActionScanConfigExported, audit.ResourceTypeScanConfig, scanID.String()).
			WithResourceName(sc.Name).
			WithMessage(fmt.Sprintf("Scan config '%s' exported", sc.Name)))

	s.logger.Info("scan config exported", "id", scanID.String(), "name", sc.Name)
	return data, nil
}

// decodeScanConfigExport parses an exported scan configuration.
func decodeScanConfigExport(data []byte) (ScanConfigExport, error) {
	var export ScanConfigExport
	err := json.Unmarshal(data, &export)
	return export, err
}

// ImportConfig creates a new scan from imported JSON configuration.
// The imported config is validated and a new scan entity is created.
// ImportConfig creates a scan from an exported configuration. The importer
// becomes its owner (created_by), and the create path checks their act scope
// on the direct targets; a scan without an owner would run its schedule as
// the system (research 21b H3, RFC-050 W2).
func (s *Service) ImportConfig(ctx context.Context, tenantID shared.ID, data []byte, actorID string) (*scan.Scan, error) {
	s.logger.Info("importing scan config", "tenant_id", tenantID.String())
	if actor, err := shared.IDFromString(actorID); err != nil || actor.IsZero() {
		return nil, ErrScanActorRequired
	}

	export, err := decodeScanConfigExport(data)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid scan config JSON: %s", shared.ErrValidation, err.Error())
	}

	// Validate required fields
	if export.Name == "" {
		return nil, fmt.Errorf("%w: name is required in imported config", shared.ErrValidation)
	}
	if export.ScanType == "" {
		return nil, fmt.Errorf("%w: scan_type is required in imported config", shared.ErrValidation)
	}

	// Parse schedule time if provided
	var scheduleTime *time.Time
	if export.ScheduleTime != nil && *export.ScheduleTime != "" {
		t, err := time.Parse("15:04", *export.ScheduleTime)
		if err != nil {
			return nil, fmt.Errorf("%w: invalid schedule_time format in imported config, expected HH:MM", shared.ErrValidation)
		}
		scheduleTime = &t
	}

	// Build create input from export
	// A one-off run is a moment, not a portable setting: one that is no
	// longer ahead imports as a manual scan rather than failing the import.
	if export.ScheduleType == string(scan.ScheduleOnce) &&
		(export.ScheduleRunAt == nil || export.ScheduleRunAt.Before(time.Now().Add(scan.MinOnceLead))) {
		export.ScheduleType = string(scan.ScheduleManual)
		export.ScheduleRunAt = nil
	}
	input := CreateScanInput{
		TenantID:            tenantID.String(),
		Name:                export.Name,
		Description:         export.Description,
		AssetGroupIDs:       export.AssetGroupIDs,
		Targets:             export.Targets,
		ScanType:            export.ScanType,
		ScannerName:         export.ScannerName,
		ScannerConfig:       export.ScannerConfig,
		TargetsPerJob:       export.TargetsPerJob,
		TargetOptions:       export.TargetOptions,
		Intensity:           export.Intensity,
		ScheduleType:        export.ScheduleType,
		ScheduleCron:        export.ScheduleCron,
		ScheduleRRule:       export.ScheduleRRule,
		ScheduleDay:         export.ScheduleDay,
		ScheduleTime:        scheduleTime,
		RunAt:               export.ScheduleRunAt,
		Timezone:            export.ScheduleTimezone,
		Tags:                export.Tags,
		TenantRunner:        export.RunOnTenantRunner,
		SensorPreference:    export.SensorPreference,
		ProfileID:           export.ProfileID,
		TimeoutSeconds:      export.TimeoutSeconds,
		MaxRetries:          export.MaxRetries,
		RetryBackoffSeconds: export.RetryBackoffSeconds,
		CreatedBy:           actorID,
	}

	// Set primary asset group ID for backward compatibility
	if len(export.AssetGroupIDs) > 0 {
		input.AssetGroupID = export.AssetGroupIDs[0]
	}

	// Set scan workflow ID if workflow type
	if export.ScanWorkflowID != nil {
		input.ScanWorkflowID = *export.ScanWorkflowID
	}

	// Use the existing CreateScan method which handles all validation
	sc, err := s.CreateScan(ctx, input)
	if err != nil {
		return nil, fmt.Errorf("failed to create scan from imported config: %w", err)
	}

	// Audit log
	s.logAudit(ctx, AuditContext{TenantID: tenantID.String()},
		NewSuccessEvent(audit.ActionScanConfigImported, audit.ResourceTypeScanConfig, sc.ID.String()).
			WithResourceName(sc.Name).
			WithMessage(fmt.Sprintf("Scan config '%s' imported", sc.Name)))

	s.logger.Info("scan config imported", "id", sc.ID.String(), "name", sc.Name)
	return sc, nil
}

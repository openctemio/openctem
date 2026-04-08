package scan

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/openctemio/api/pkg/domain/audit"
	"github.com/openctemio/api/pkg/domain/scan"
	"github.com/openctemio/api/pkg/domain/shared"
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

	// Scan Type
	ScanType      string         `json:"scan_type"`
	PipelineID    *string        `json:"pipeline_id,omitempty"`
	ScannerName   string         `json:"scanner_name,omitempty"`
	ScannerConfig map[string]any `json:"scanner_config,omitempty"`
	TargetsPerJob int            `json:"targets_per_job"`

	// Schedule
	ScheduleType     string  `json:"schedule_type"`
	ScheduleCron     string  `json:"schedule_cron,omitempty"`
	ScheduleDay      *int    `json:"schedule_day,omitempty"`
	ScheduleTime     *string `json:"schedule_time,omitempty"`
	ScheduleTimezone string  `json:"schedule_timezone"`

	// Routing
	Tags              []string `json:"tags,omitempty"`
	RunOnTenantRunner bool     `json:"run_on_tenant_runner"`
	AgentPreference   string   `json:"agent_preference,omitempty"`

	// Profile and timeout
	ProfileID      string `json:"profile_id,omitempty"`
	TimeoutSeconds int    `json:"timeout_seconds,omitempty"`

	// Export metadata
	ExportedAt string `json:"exported_at"`
	Version    string `json:"version"`
}

// configExportVersion is the current version of the export format.
const configExportVersion = "1.0"

// ExportConfig exports a scan configuration as JSON bytes.
// It strips runtime data (status, results, timestamps) and returns
// only the configuration fields needed to recreate the scan.
func (s *Service) ExportConfig(ctx context.Context, tenantID, scanID shared.ID) ([]byte, error) {
	s.logger.Info("exporting scan config", "scan_id", scanID.String())

	sc, err := s.scanRepo.GetByTenantAndID(ctx, tenantID, scanID)
	if err != nil {
		return nil, err
	}

	export := ScanConfigExport{
		Name:              sc.Name,
		Description:       sc.Description,
		ScanType:          string(sc.ScanType),
		ScannerName:       sc.ScannerName,
		ScannerConfig:     sc.ScannerConfig,
		TargetsPerJob:     sc.TargetsPerJob,
		ScheduleType:      string(sc.ScheduleType),
		ScheduleCron:      sc.ScheduleCron,
		ScheduleDay:       sc.ScheduleDay,
		ScheduleTimezone:  sc.ScheduleTimezone,
		RunOnTenantRunner: sc.RunOnTenantRunner,
		AgentPreference:   string(sc.AgentPreference),
		TimeoutSeconds:    sc.TimeoutSeconds,
		ExportedAt:        time.Now().UTC().Format(time.RFC3339),
		Version:           configExportVersion,
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

	// Convert pipeline ID
	if sc.PipelineID != nil && !sc.PipelineID.IsZero() {
		pid := sc.PipelineID.String()
		export.PipelineID = &pid
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

// ImportConfig creates a new scan from imported JSON configuration.
// The imported config is validated and a new scan entity is created.
func (s *Service) ImportConfig(ctx context.Context, tenantID shared.ID, data []byte) (*scan.Scan, error) {
	s.logger.Info("importing scan config", "tenant_id", tenantID.String())

	var export ScanConfigExport
	if err := json.Unmarshal(data, &export); err != nil {
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
	input := CreateScanInput{
		TenantID:        tenantID.String(),
		Name:            export.Name,
		Description:     export.Description,
		AssetGroupIDs:   export.AssetGroupIDs,
		Targets:         export.Targets,
		ScanType:        export.ScanType,
		ScannerName:     export.ScannerName,
		ScannerConfig:   export.ScannerConfig,
		TargetsPerJob:   export.TargetsPerJob,
		ScheduleType:    export.ScheduleType,
		ScheduleCron:    export.ScheduleCron,
		ScheduleDay:     export.ScheduleDay,
		ScheduleTime:    scheduleTime,
		Timezone:        export.ScheduleTimezone,
		Tags:            export.Tags,
		TenantRunner:    export.RunOnTenantRunner,
		AgentPreference: export.AgentPreference,
		ProfileID:       export.ProfileID,
		TimeoutSeconds:  export.TimeoutSeconds,
	}

	// Set primary asset group ID for backward compatibility
	if len(export.AssetGroupIDs) > 0 {
		input.AssetGroupID = export.AssetGroupIDs[0]
	}

	// Set pipeline ID if workflow type
	if export.PipelineID != nil {
		input.PipelineID = *export.PipelineID
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

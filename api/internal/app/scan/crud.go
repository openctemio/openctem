package scan

import (
	"context"
	"fmt"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/audit"
	"github.com/openctemio/openctem/api/pkg/domain/scan"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/pagination"
	"github.com/openctemio/openctem/api/pkg/validator"
)

// =============================================================================
// Create Operations
// =============================================================================

// CreateScanInput represents the input for creating a scan.
// Either AssetGroupID/AssetGroupIDs OR Targets must be provided (can have all).
type CreateScanInput struct {
	TenantID      string   `json:"tenant_id" validate:"required,uuid"`
	Name          string   `json:"name" validate:"required,min=1,max=200"`
	Description   string   `json:"description" validate:"max=1000"`
	AssetGroupID  string   `json:"asset_group_id" validate:"omitempty,uuid"`       // Primary asset group (legacy)
	AssetGroupIDs []string `json:"asset_group_ids" validate:"omitempty,dive,uuid"` // Multiple asset groups (NEW)
	Targets       []string `json:"targets" validate:"omitempty,max=1000"`          // Direct targets
	// AssetIDs are inventory assets to scan; each is scanned by its name,
	// resolved on the server (tenant and creator scope checked).
	AssetIDs []string `json:"asset_ids" validate:"omitempty,max=1000,dive,uuid"`
	// TargetOptions tunes how each run resolves the dynamic selectors among
	// Targets (RFC-068); nil = defaults.
	TargetOptions  *scan.TargetOptions `json:"target_options"`
	ScanType       string              `json:"scan_type" validate:"required,oneof=workflow single"`
	ScanWorkflowID string              `json:"scan_workflow_id" validate:"omitempty,uuid"`
	ScannerName    string              `json:"scanner_name" validate:"max=100"`
	ScannerConfig  map[string]any      `json:"scanner_config"`
	TargetsPerJob  int                 `json:"targets_per_job"`
	ScheduleType   string              `json:"schedule_type" validate:"omitempty,oneof=manual daily weekly monthly crontab rrule once"`
	ScheduleCron   string              `json:"schedule_cron" validate:"max=100"`
	// ScheduleRRule is the RFC 5545 rule of an rrule schedule.
	ScheduleRRule string     `json:"schedule_rrule" validate:"max=500"`
	ScheduleDay   *int       `json:"schedule_day"`
	ScheduleTime  *time.Time `json:"schedule_time"`
	// RunAt is the one run of a once schedule.
	RunAt            *time.Time `json:"run_at"`
	Timezone         string     `json:"timezone" validate:"max=50"`
	Tags             []string   `json:"tags" validate:"max=20,dive,max=50"`
	TenantRunner     bool       `json:"run_on_tenant_runner"`
	SensorPreference string     `json:"sensor_preference" validate:"omitempty,oneof=auto tenant platform"` // Sensor selection mode: auto (default), tenant, platform
	ProfileID        string     `json:"profile_id" validate:"omitempty,uuid"`                              // Optional scan profile (tool configs, quality gates)
	ScanZoneID       string     `json:"scan_zone_id" validate:"omitempty,uuid"`                            // Optional: pin targets to one scan zone ("" = Automatic)
	TimeoutSeconds   int        `json:"timeout_seconds" validate:"omitempty,min=30,max=86400"`             // Max execution time (default 3600, min 30, max 86400)
	// Retry config: max_retries=0 disables retry; backoff is initial delay (exponential per attempt)
	MaxRetries          int    `json:"max_retries" validate:"omitempty,min=0,max=10"`
	RetryBackoffSeconds int    `json:"retry_backoff_seconds" validate:"omitempty,min=10,max=86400"`
	CreatedBy           string `json:"created_by" validate:"omitempty,uuid"`
	// StartWhenScopeApproved saves a scan whose direct targets are refused
	// only because pending scope entries cover them; it starts once those
	// entries are approved (scope_wait.go). Ignored when nothing waits.
	StartWhenScopeApproved bool `json:"start_when_scope_approved"`
}

// CreateScanResult represents the result of creating a scan.
// It includes the scan entity and optional compatibility warnings.
type CreateScanResult struct {
	Scan                 *scan.Scan                 `json:"scan"`
	CompatibilityWarning *AssetCompatibilityPreview `json:"compatibility_warning,omitempty"`
}

// CreateScan creates a new scan.
func (s *Service) CreateScan(ctx context.Context, input CreateScanInput) (*scan.Scan, error) {
	s.logger.Info("creating scan", "name", input.Name, "tenant_id", input.TenantID)

	tenantID, err := shared.IDFromString(input.TenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}

	// Assets by id become direct targets named by the server; from here
	// they are checked exactly like typed targets.
	assetTargets, err := s.resolveAssetTargets(ctx, tenantID, userIDPtr(input.CreatedBy), input.AssetIDs)
	if err != nil {
		return nil, err
	}
	if input.Targets, err = mergeDirectTargets(input.Targets, assetTargets); err != nil {
		return nil, err
	}

	// Security validations
	if err := s.validateScanSecurityInputs(ctx, tenantID, input); err != nil {
		return nil, err
	}

	// Validate: must have either asset_group_id/asset_group_ids or targets
	hasAssetGroup := input.AssetGroupID != "" || len(input.AssetGroupIDs) > 0
	hasTargets := len(input.Targets) > 0
	if !hasAssetGroup && !hasTargets {
		return nil, fmt.Errorf("%w: either asset_group_id/asset_group_ids, targets or asset_ids must be provided", shared.ErrValidation)
	}

	// Validate and sanitize targets if provided (SECURITY: SSRF protection)
	validatedTargets, err := s.validateScanTargets(ctx, input)
	if err != nil {
		return nil, err
	}

	// Saved to start when its scope is approved: the targets refused only
	// because a pending entry covers them (nil = not eligible).
	var awaiting map[string]bool
	if input.StartWhenScopeApproved {
		awaiting = s.awaitingScopeTargets(ctx, tenantID, validatedTargets)
	}
	waitForScope := awaiting != nil
	// The creator may scan only targets in their act scope (D9).
	if err := s.refuseOutOfActScopeAwaiting(ctx, tenantID, userIDPtr(input.CreatedBy), validatedTargets, awaiting); err != nil {
		return nil, err
	}
	// Nothing the tenant has not authorized for active scanning (RFC-036),
	// unless the caller saves it to start when the pending entries that
	// cover the refused targets are approved.
	if !waitForScope {
		if err := s.refuseUnownedTargets(ctx, tenantID, "scan_create", validatedTargets, IsTakeoverOnlyProbe(input.ScannerName, input.ScannerConfig)); err != nil {
			return nil, err
		}
	}
	if err := s.refuseUnprovenIntrusive(ctx, tenantID, input.ScannerName, validatedTargets); err != nil {
		return nil, err
	}
	if err := s.refuseTierExceeded(ctx, tenantID, input.ScannerName, validatedTargets); err != nil {
		return nil, err
	}

	// Parse and validate asset groups
	assetGroupID, assetGroupIDs, err := s.validateScanAssetGroups(ctx, tenantID, input)
	if err != nil {
		return nil, err
	}

	// Parse scan type
	scanType := scan.ScanType(input.ScanType)
	if scanType != scan.ScanTypeWorkflow && scanType != scan.ScanTypeSingle {
		return nil, fmt.Errorf("%w: invalid scan_type", shared.ErrValidation)
	}

	// Create scan entity
	sc, err := s.createScanEntity(tenantID, input.Name, scanType, assetGroupID, assetGroupIDs, validatedTargets, hasAssetGroup)
	if err != nil {
		return nil, err
	}
	sc.Description = input.Description
	if input.TargetOptions != nil {
		if err := sc.SetTargetOptions(*input.TargetOptions); err != nil {
			return nil, err
		}
	}

	// Configure scan type (workflow or single scanner)
	if err := s.configureScanType(ctx, sc, tenantID, scanType, input); err != nil {
		return nil, err
	}
	// A wildcard selector must be *.<domain> the platform lets anyone cover.
	if err := s.refuseWildcardTargets(ctx, sc); err != nil {
		return nil, err
	}

	// Configure schedule
	if err := configureScanSchedule(sc, input); err != nil {
		return nil, err
	}

	// Set tags and routing
	if len(input.Tags) > 0 {
		sc.SetTags(input.Tags)
	}
	sc.SetRunOnTenantRunner(input.TenantRunner)

	// Check sensor availability (non-blocking warning)
	s.checkScanSensorAvailability(ctx, tenantID, scanType, input)

	// Set sensor preference
	if input.SensorPreference != "" {
		sc.SetSensorPreference(scan.SensorPreference(input.SensorPreference))
	}

	// Scan zone picker: "" = Automatic routing.
	zoneID, err := s.resolveSelectedZone(ctx, tenantID, input.ScanZoneID)
	if err != nil {
		return nil, err
	}
	sc.SetScanZone(zoneID)

	// Set timeout (defaults to DefaultScanTimeoutSeconds if 0)
	sc.SetTimeoutSeconds(input.TimeoutSeconds)

	// Set retry config (defaults: max_retries=0 disables retry)
	if input.MaxRetries > 0 || input.RetryBackoffSeconds > 0 {
		sc.SetRetryConfig(input.MaxRetries, input.RetryBackoffSeconds)
	}

	// Link scan profile if provided (SQL-level tenant enforcement via GetAccessibleByID)
	if input.ProfileID != "" {
		profileID, err := shared.IDFromString(input.ProfileID)
		if err != nil {
			return nil, fmt.Errorf("%w: invalid profile_id", shared.ErrValidation)
		}
		if s.profileRepo != nil {
			// GetAccessibleByID returns ErrNotFound for cross-tenant attempts (no info leak)
			if _, err := s.profileRepo.GetAccessibleByID(ctx, tenantID, profileID); err != nil {
				return nil, fmt.Errorf("scan profile not found: %w", err)
			}
		}
		sc.SetProfileID(&profileID)
	}

	// Set created by
	if input.CreatedBy != "" {
		createdByID, err := shared.IDFromString(input.CreatedBy)
		if err == nil {
			sc.SetCreatedBy(createdByID)
		}
	}

	// Save to repository
	if err := s.scanRepo.Create(ctx, sc); err != nil {
		return nil, err
	}
	if waitForScope {
		now := time.Now().UTC()
		if err := s.scopeWaits.Create(ctx, ScopeWait{
			ScanID: sc.ID, TenantID: tenantID, RequestedBy: sc.CreatedBy, CreatedAt: now, ExpiresAt: now.Add(ScopeWaitTTL),
		}); err != nil {
			// Never keep a scan whose out-of-scope targets nothing waits on.
			if derr := s.scanRepo.Delete(ctx, tenantID, sc.ID); derr != nil {
				s.logger.Error("scope wait: rollback failed", "scan_id", sc.ID.String(), "error", logger.SanitizeError(derr))
			}
			return nil, fmt.Errorf("save scope wait: %w", err)
		}
	}

	// Audit log: scan config created
	s.logAudit(ctx, AuditContext{TenantID: input.TenantID, ActorID: input.CreatedBy},
		NewSuccessEvent(audit.ActionScanConfigCreated, audit.ResourceTypeScanConfig, sc.ID.String()).
			WithResourceName(sc.Name).
			WithMessage(fmt.Sprintf("Scan config '%s' created", sc.Name)).
			WithMetadata("scan_type", string(sc.ScanType)).
			WithMetadata("schedule_type", string(sc.ScheduleType)))

	s.logger.Info("scan created", "id", sc.ID.String(), "name", sc.Name)
	return sc, nil
}

// validateScanSecurityInputs validates tags, scanner config, and cron expression.
func (s *Service) validateScanSecurityInputs(ctx context.Context, tenantID shared.ID, input CreateScanInput) error {
	if s.securityValidator == nil {
		return nil
	}

	if len(input.Tags) > 0 {
		result := s.securityValidator.ValidateIdentifiers(input.Tags, 50, "tags")
		if !result.Valid {
			s.logger.Warn("tags validation failed", "tenant_id", input.TenantID, "errors", result.Errors)
			return fmt.Errorf("%w: %s", shared.ErrValidation, result.Errors[0].Message)
		}
	}

	if input.ScannerConfig != nil {
		result := s.securityValidator.ValidateScannerConfig(ctx, tenantID, input.ScannerConfig)
		if !result.Valid {
			s.logger.Warn("scanner config validation failed",
				"tenant_id", input.TenantID,
				"errors", result.Errors)
			return fmt.Errorf("%w: %s", shared.ErrValidation, result.Errors[0].Message)
		}
	}

	if input.ScheduleCron != "" {
		if err := s.securityValidator.ValidateCronExpression(input.ScheduleCron); err != nil {
			s.logger.Warn("cron expression validation failed",
				"tenant_id", input.TenantID,
				"cron", input.ScheduleCron,
				"error", err)
			return fmt.Errorf("%w: %s", shared.ErrValidation, err.Error())
		}
	}

	return nil
}

// validateScanTargets validates and sanitizes scan targets with SSRF protection.
//
// Private addresses are refused, except where the tenant has a scan zone
// covering them (RFC-023 D6): those are scanned only by that zone's sensors.
func (s *Service) validateScanTargets(ctx context.Context, input CreateScanInput) ([]string, error) {
	if len(input.Targets) == 0 {
		return nil, nil
	}

	targetValidator := validator.NewTargetValidator(
		validator.WithAllowInternalIPs(false),
		validator.WithAllowLocalhost(false),
		validator.WithMaxTargets(1000),
	)
	result := targetValidator.ValidateTargets(input.Targets)

	var admitted []string
	if result.HasErrors && len(result.BlockedIPs) > 0 {
		var err error
		if admitted, err = s.admitZonedPrivateTargets(ctx, input.TenantID, result); err != nil {
			return nil, err
		}
	}

	if result.HasErrors {
		if len(result.BlockedIPs) > 0 {
			s.logger.Warn("SECURITY: blocked internal/localhost targets",
				"tenant_id", input.TenantID,
				"blocked_ips", result.BlockedIPs)
		}
		if len(result.Invalid) > 0 {
			firstError := result.Invalid[0]
			return nil, fmt.Errorf("%w: invalid target '%s': %s",
				shared.ErrValidation, firstError.Original, firstError.Error)
		}
		return nil, fmt.Errorf("%w: invalid targets provided", shared.ErrValidation)
	}

	validated := append(result.GetValidTargetStrings(), admitted...)
	if len(validated) == 0 {
		return nil, fmt.Errorf("%w: no valid targets provided", shared.ErrValidation)
	}

	s.logger.Info("targets validated",
		"tenant_id", input.TenantID,
		"total", result.TotalCount,
		"valid", result.ValidCount)

	return validated, nil
}

// validateScanAssetGroup validates a single asset group ID belongs to the tenant.
func (s *Service) validateScanAssetGroup(ctx context.Context, tenantID shared.ID, tenantIDStr, idStr string) (shared.ID, error) {
	id, err := shared.IDFromString(idStr)
	if err != nil {
		return shared.ID{}, fmt.Errorf("%w: invalid asset_group_id", shared.ErrValidation)
	}

	ag, err := s.assetGroupRepo.GetByID(ctx, id)
	if err != nil {
		return shared.ID{}, fmt.Errorf("asset group not found: %w", err)
	}
	if ag.TenantID() != tenantID {
		s.logger.Warn("SECURITY: cross-tenant asset group access attempt",
			"tenant_id", tenantIDStr,
			"asset_group_tenant_id", ag.TenantID().String())
		return shared.ID{}, fmt.Errorf("%w: asset group not found", shared.ErrNotFound)
	}

	return id, nil
}

// validateScanAssetGroups validates all asset group IDs.
func (s *Service) validateScanAssetGroups(ctx context.Context, tenantID shared.ID, input CreateScanInput) (shared.ID, []shared.ID, error) {
	hasAssetGroup := input.AssetGroupID != "" || len(input.AssetGroupIDs) > 0
	if !hasAssetGroup {
		return shared.ID{}, nil, nil
	}

	var assetGroupID shared.ID
	if input.AssetGroupID != "" {
		id, err := s.validateScanAssetGroup(ctx, tenantID, input.TenantID, input.AssetGroupID)
		if err != nil {
			return shared.ID{}, nil, err
		}
		assetGroupID = id
	}

	var assetGroupIDs []shared.ID
	if len(input.AssetGroupIDs) > 0 {
		assetGroupIDs = make([]shared.ID, 0, len(input.AssetGroupIDs))
		for _, idStr := range input.AssetGroupIDs {
			id, err := s.validateScanAssetGroup(ctx, tenantID, input.TenantID, idStr)
			if err != nil {
				return shared.ID{}, nil, err
			}
			assetGroupIDs = append(assetGroupIDs, id)
		}
		if assetGroupID.IsZero() && len(assetGroupIDs) > 0 {
			assetGroupID = assetGroupIDs[0]
		}
	}

	return assetGroupID, assetGroupIDs, nil
}

// createScanEntity creates the scan domain entity based on targets vs asset groups.
func (s *Service) createScanEntity(
	tenantID shared.ID, name string, scanType scan.ScanType,
	assetGroupID shared.ID, assetGroupIDs []shared.ID,
	validatedTargets []string, hasAssetGroup bool,
) (*scan.Scan, error) {
	var sc *scan.Scan
	var err error

	if len(validatedTargets) > 0 && !hasAssetGroup {
		sc, err = scan.NewScanWithTargets(tenantID, name, validatedTargets, scanType)
	} else {
		sc, err = scan.NewScan(tenantID, name, assetGroupID, scanType)
		if err == nil && len(validatedTargets) > 0 {
			sc.SetTargets(validatedTargets)
		}
	}
	if err != nil {
		return nil, err
	}

	if len(assetGroupIDs) > 0 {
		sc.SetAssetGroupIDs(assetGroupIDs)
	}

	return sc, nil
}

// configureScanType sets up workflow scan workflow or single scanner configuration.
func (s *Service) configureScanType(ctx context.Context, sc *scan.Scan, tenantID shared.ID, scanType scan.ScanType, input CreateScanInput) error {
	if scanType == scan.ScanTypeWorkflow {
		return s.configureWorkflowScan(ctx, sc, tenantID, input.ScanWorkflowID)
	}
	return s.configureSingleScan(ctx, sc, input.ScannerName, input.ScannerConfig, input.TargetsPerJob)
}

// configureWorkflowScan validates and sets up a workflow scan with a scan workflow.
func (s *Service) configureWorkflowScan(ctx context.Context, sc *scan.Scan, tenantID shared.ID, pipelineIDStr string) error {
	if pipelineIDStr == "" {
		return fmt.Errorf("%w: scan_workflow_id is required for workflow type", shared.ErrValidation)
	}
	scanWorkflowID, err := shared.IDFromString(pipelineIDStr)
	if err != nil {
		return fmt.Errorf("%w: invalid scan_workflow_id", shared.ErrValidation)
	}

	// A starter (system) workflow is usable by every tenant, read-only.
	pipelineTemplate, err := s.usableWorkflow(ctx, tenantID, scanWorkflowID)
	if err != nil {
		return err
	}

	steps, err := s.stepRepo.GetByScanWorkflowID(ctx, pipelineTemplate.ID)
	if err != nil {
		return fmt.Errorf("failed to get scan workflow steps: %w", err)
	}
	// A workflow no sensor here can run (or that runs only in CI) is
	// refused, naming the steps and why.
	pipelineTemplate.Steps = steps
	if err := s.requireWorkflowRunnable(ctx, tenantID, pipelineTemplate); err != nil {
		return err
	}
	for _, step := range steps {
		if step.Tool != "" {
			stepTool, err := s.toolRepo.GetByName(ctx, tenantID, step.Tool)
			if err != nil || stepTool == nil {
				return fmt.Errorf("%w: workflow step '%s' uses tool '%s' which is not found",
					shared.ErrValidation, step.StepKey, step.Tool)
			}
			if !stepTool.IsActive {
				return fmt.Errorf("%w: workflow step '%s' uses tool '%s' which is disabled",
					shared.ErrValidation, step.StepKey, step.Tool)
			}
			if stepTool.IsCollector() {
				return fmt.Errorf("%w: workflow step '%s' uses '%s', an asset collector: collectors run on their collector sensor's own schedule and cannot be scanned with",
					shared.ErrValidation, step.StepKey, step.Tool)
			}
			if stepTool.IsConnector() {
				return fmt.Errorf("%w: workflow step '%s' uses '%s', a connector: a connector runs as the scanner of a single scan, not as a workflow step",
					shared.ErrValidation, step.StepKey, step.Tool)
			}
		}
	}

	return sc.SetWorkflow(scanWorkflowID)
}

// configureSingleScan validates and sets up a single scanner scan.
func (s *Service) configureSingleScan(ctx context.Context, sc *scan.Scan, scannerName string, scannerConfig map[string]any, targetsPerJob int) error {
	if scannerName == "" {
		return fmt.Errorf("%w: scanner_name is required for single type", shared.ErrValidation)
	}

	scannerTool, err := s.toolRepo.GetByName(ctx, sc.TenantID, scannerName)
	if err != nil || scannerTool == nil {
		return fmt.Errorf("%w: scanner '%s' not found in tool registry", shared.ErrValidation, scannerName)
	}
	if !scannerTool.IsActive {
		return fmt.Errorf("%w: scanner '%s' is disabled", shared.ErrValidation, scannerName)
	}
	if scannerTool.IsCollector() {
		return fmt.Errorf("%w: '%s' is an asset collector, not a scanner: collectors run on their collector sensor's own schedule and cannot be scanned with", shared.ErrValidation, scannerName)
	}
	if scannerTool.IsConnector() {
		// A connector scan (RFC-047): its config names the connector
		// integration and the Tenable.sc policy and repository.
		if err := s.validateConnectorScanner(ctx, sc.TenantID, scannerConfig); err != nil {
			return err
		}
	}

	if err := s.refuseDisabledOptIns(ctx, sc.TenantID, scannerConfig); err != nil {
		return err
	}

	tpj := max(targetsPerJob, 1)
	return sc.SetSingleScanner(scannerName, scannerConfig, tpj)
}

// sameOnceRun reports whether sc already holds exactly this one-off run.
func sameOnceRun(sc *scan.Scan, runAt *time.Time, timezone string) bool {
	return sc.ScheduleType == scan.ScheduleOnce && sc.ScheduleRunAt != nil && runAt != nil &&
		sc.ScheduleRunAt.Equal(runAt.UTC().Truncate(time.Second)) && sc.ScheduleTimezone == timezone
}

// configureScanSchedule validates and sets the scan schedule.
func configureScanSchedule(sc *scan.Scan, input CreateScanInput) error {
	scheduleType := scan.ScheduleType(input.ScheduleType)
	if scheduleType == "" {
		scheduleType = scan.ScheduleManual
	}
	timezone := input.Timezone
	if timezone == "" {
		timezone = "UTC"
	}

	if err := validateTimezone(timezone); err != nil {
		return fmt.Errorf("%w: %s", shared.ErrValidation, err.Error())
	}

	if scheduleType == scan.ScheduleCrontab && input.ScheduleCron != "" {
		if err := validateCronParseable(input.ScheduleCron); err != nil {
			return fmt.Errorf("%w: invalid cron expression: %s", shared.ErrValidation, err.Error())
		}
	}

	if scheduleType == scan.ScheduleRRule {
		return sc.SetRRuleSchedule(input.ScheduleRRule, timezone)
	}
	if scheduleType == scan.ScheduleOnce {
		return sc.SetOnceSchedule(input.RunAt, timezone, time.Now())
	}
	return sc.SetSchedule(scheduleType, input.ScheduleCron, input.ScheduleDay, input.ScheduleTime, timezone)
}

// checkScanSensorAvailability logs a warning if no sensors are available for the scan.
func (s *Service) checkScanSensorAvailability(ctx context.Context, tenantID shared.ID, scanType scan.ScanType, input CreateScanInput) {
	toolToCheck := input.ScannerName
	if scanType == scan.ScanTypeWorkflow {
		toolToCheck = ""
	}
	sensorAvail := s.sensorSelector.CheckSensorAvailability(ctx, tenantID, toolToCheck, input.TenantRunner)
	if !sensorAvail.Available {
		s.logger.Warn("no sensor available for scan",
			"tenant_id", tenantID.String(),
			"tool", logger.SanitizeValue(toolToCheck),
			"message", sensorAvail.Message,
		)
	}
}

// PreviewScanCompatibility checks asset-scanner compatibility for a scan configuration.
// This is called before scan creation to show warnings about incompatible assets.
// Returns nil if no warning needed (100% compatible or no asset groups).
func (s *Service) PreviewScanCompatibility(
	ctx context.Context,
	tenantID shared.ID,
	scannerName string,
	assetGroupIDs []shared.ID,
) (*AssetCompatibilityPreview, error) {
	// Skip if no target mapping repo configured
	if s.targetMappingRepo == nil {
		return nil, nil
	}

	// Skip if no asset groups
	if len(assetGroupIDs) == 0 {
		return nil, nil
	}

	// Get tool's supported targets
	scannerTool, err := s.toolRepo.GetByName(ctx, tenantID, scannerName)
	if err != nil || scannerTool == nil {
		return nil, nil //nolint:nilerr // Tool not found is expected; skip compatibility check.
	}

	// Skip if tool has no supported_targets defined (scans all)
	if len(scannerTool.SupportedTargets) == 0 {
		return nil, nil
	}

	// Create filter service and get preview
	filterService := NewAssetFilterService(s.targetMappingRepo, s.assetGroupRepo)
	preview, err := filterService.PreviewCompatibility(ctx, scannerTool.SupportedTargets, assetGroupIDs)
	if err != nil {
		s.logger.Warn("failed to preview compatibility",
			"scanner", scannerName,
			"error", err)
		return nil, nil // Don't fail, just skip warning
	}

	// Only return warning if not fully compatible
	if preview.IsFullyCompatible {
		return nil, nil
	}

	return preview, nil
}

// =============================================================================
// Read Operations
// =============================================================================

// GetScan retrieves a scan by ID.
func (s *Service) GetScan(ctx context.Context, tenantID, scanID string) (*scan.Scan, error) {
	tid, err := shared.IDFromString(tenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}

	sid, err := shared.IDFromString(scanID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid scan id", shared.ErrValidation)
	}

	return s.scanRepo.GetByTenantAndID(ctx, tid, sid)
}

// ListScansInput represents the input for listing scans.
type ListScansInput struct {
	TenantID       string   `json:"tenant_id" validate:"required,uuid"`
	AssetGroupID   string   `json:"asset_group_id" validate:"omitempty,uuid"`
	ScanWorkflowID string   `json:"scan_workflow_id" validate:"omitempty,uuid"`
	ScanType       string   `json:"scan_type" validate:"omitempty,oneof=workflow single"`
	ScheduleType   string   `json:"schedule_type" validate:"omitempty,oneof=manual daily weekly monthly crontab rrule once"`
	Status         string   `json:"status" validate:"omitempty,oneof=active paused disabled"`
	Tags           []string `json:"tags"`
	Search         string   `json:"search" validate:"max=255"`
	// IncludeAdHoc also lists unsaved quick scans (Scan.AdHoc); by default the
	// list holds saved configurations only.
	IncludeAdHoc bool `json:"include_ad_hoc"`
	// Sort is one sort key, `field` or `-field` (scan.ListSortFields); an
	// unknown field is a validation error.
	Sort    string `json:"sort"`
	Page    int    `json:"page"`
	PerPage int    `json:"per_page"`
}

// ListScans lists scans with filters.
func (s *Service) ListScans(ctx context.Context, input ListScansInput) (pagination.Result[*scan.Scan], error) {
	tenantID, err := shared.IDFromString(input.TenantID)
	if err != nil {
		return pagination.Result[*scan.Scan]{}, fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}

	sort, err := scan.ParseListSort(input.Sort)
	if err != nil {
		return pagination.Result[*scan.Scan]{}, err
	}

	filter := scan.Filter{
		TenantID:     &tenantID,
		Tags:         input.Tags,
		Search:       input.Search,
		ExcludeAdHoc: !input.IncludeAdHoc,
		Sort:         sort,
	}

	if input.AssetGroupID != "" {
		agID, err := shared.IDFromString(input.AssetGroupID)
		if err == nil {
			filter.AssetGroupID = &agID
		}
	}

	if input.ScanWorkflowID != "" {
		pID, err := shared.IDFromString(input.ScanWorkflowID)
		if err == nil {
			filter.ScanWorkflowID = &pID
		}
	}

	if input.ScanType != "" {
		st := scan.ScanType(input.ScanType)
		filter.ScanType = &st
	}

	if input.ScheduleType != "" {
		sct := scan.ScheduleType(input.ScheduleType)
		filter.ScheduleType = &sct
	}

	if input.Status != "" {
		status := scan.Status(input.Status)
		filter.Status = &status
	}

	page := pagination.New(input.Page, input.PerPage)
	return s.scanRepo.List(ctx, filter, page)
}

// GetStats returns aggregated statistics for scans.
func (s *Service) GetStats(ctx context.Context, tenantID string) (*scan.Stats, error) {
	tid, err := shared.IDFromString(tenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}

	return s.scanRepo.GetStats(ctx, tid)
}

// =============================================================================
// Update Operations
// =============================================================================

// UpdateScanInput represents the input for updating a scan.
type UpdateScanInput struct {
	TenantID       string         `json:"tenant_id" validate:"required,uuid"`
	ScanID         string         `json:"scan_id" validate:"required,uuid"`
	Name           string         `json:"name" validate:"omitempty,min=1,max=200"`
	Description    string         `json:"description" validate:"max=1000"`
	ScanWorkflowID string         `json:"scan_workflow_id" validate:"omitempty,uuid"`
	ScannerName    string         `json:"scanner_name" validate:"max=100"`
	ScannerConfig  map[string]any `json:"scanner_config"`
	TargetsPerJob  *int           `json:"targets_per_job"`
	// TargetOptions: nil = unchanged (RFC-068).
	TargetOptions *scan.TargetOptions `json:"target_options"`
	ScheduleType  string              `json:"schedule_type" validate:"omitempty,oneof=manual daily weekly monthly crontab rrule once"`
	ScheduleCron  string              `json:"schedule_cron" validate:"max=100"`
	// ScheduleRRule is the RFC 5545 rule of an rrule schedule.
	ScheduleRRule string     `json:"schedule_rrule" validate:"max=500"`
	ScheduleDay   *int       `json:"schedule_day"`
	ScheduleTime  *time.Time `json:"schedule_time"`
	// RunAt is the one run of a once schedule.
	RunAt            *time.Time `json:"run_at"`
	Timezone         string     `json:"timezone" validate:"max=50"`
	Tags             []string   `json:"tags" validate:"max=20,dive,max=50"`
	TenantRunner     *bool      `json:"run_on_tenant_runner"`
	SensorPreference string     `json:"sensor_preference" validate:"omitempty,oneof=auto tenant platform"`
	// ProfileID: pointer with sentinel:
	//   nil           = leave unchanged
	//   pointer to "" = unlink profile
	//   pointer to id = link to profile
	ProfileID *string `json:"profile_id" validate:"omitempty"`
	// ScanZoneID: nil = leave unchanged, pointer to "" = Automatic routing,
	// pointer to id = pin the scan's targets to that zone.
	ScanZoneID *string `json:"scan_zone_id" validate:"omitempty"`
	// TimeoutSeconds: nil = leave unchanged, otherwise min=30 max=86400
	TimeoutSeconds *int `json:"timeout_seconds" validate:"omitempty,min=30,max=86400"`
	// Retry config: nil = leave unchanged
	MaxRetries          *int `json:"max_retries" validate:"omitempty,min=0,max=10"`
	RetryBackoffSeconds *int `json:"retry_backoff_seconds" validate:"omitempty,min=10,max=86400"`
}

// UpdateScan updates a scan.
func (s *Service) UpdateScan(ctx context.Context, input UpdateScanInput) (*scan.Scan, error) {
	s.logger.Info("updating scan", "scan_id", input.ScanID)

	sc, err := s.GetScan(ctx, input.TenantID, input.ScanID)
	if err != nil {
		return nil, err
	}
	// Editing a scan is acting on its targets: the editor must be allowed
	// to scan every direct target (D9). Group members are filtered per run.
	if err := s.refuseOutOfActScope(ctx, sc.TenantID, nil, sc.Targets); err != nil {
		return nil, err
	}

	// Update basic fields
	if input.Name != "" || input.Description != "" {
		name := sc.Name
		if input.Name != "" {
			name = input.Name
		}
		description := sc.Description
		if input.Description != "" {
			description = input.Description
		}
		if err := sc.Update(name, description); err != nil {
			return nil, err
		}
	}

	// Update workflow/scanner if provided
	if sc.ScanType == scan.ScanTypeWorkflow && input.ScanWorkflowID != "" {
		scanWorkflowID, err := shared.IDFromString(input.ScanWorkflowID)
		if err != nil {
			return nil, fmt.Errorf("%w: invalid scan_workflow_id", shared.ErrValidation)
		}
		tenantID, _ := shared.IDFromString(input.TenantID)
		if _, err := s.usableWorkflow(ctx, tenantID, scanWorkflowID); err != nil {
			return nil, err
		}
		if err := sc.SetWorkflow(scanWorkflowID); err != nil {
			return nil, err
		}
	} else if sc.ScanType == scan.ScanTypeSingle && input.ScannerName != "" {
		targetsPerJob := sc.TargetsPerJob
		if input.TargetsPerJob != nil {
			targetsPerJob = *input.TargetsPerJob
		}
		// A config saved back as it was shown masked keeps the stored
		// secrets instead of storing the mask (scan.RedactConfigSecrets).
		cfg := scan.RestoreRedactedConfigSecrets(input.ScannerConfig, sc.ScannerConfig)
		if err := s.refuseDisabledOptIns(ctx, sc.TenantID, cfg); err != nil {
			return nil, err
		}
		if _, connector := s.isConnectorScanner(ctx, sc.TenantID, input.ScannerName); connector {
			if err := s.validateConnectorScanner(ctx, sc.TenantID, cfg); err != nil {
				return nil, err
			}
		}
		if err := sc.SetSingleScanner(input.ScannerName, cfg, targetsPerJob); err != nil {
			return nil, err
		}
	}
	// The scan's wildcard selectors must still be valid.
	if err := s.refuseWildcardTargets(ctx, sc); err != nil {
		return nil, err
	}
	if input.TargetOptions != nil {
		if err := sc.SetTargetOptions(*input.TargetOptions); err != nil {
			return nil, err
		}
	}

	// Update schedule if provided. SetSchedule refuses what the scheduler
	// cannot honor (unparseable cron, unknown timezone); the security check
	// on the cron string is the one CreateScan runs, which updates skipped.
	if input.ScheduleType != "" {
		if input.ScheduleCron != "" && s.securityValidator != nil {
			if err := s.securityValidator.ValidateCronExpression(input.ScheduleCron); err != nil {
				return nil, fmt.Errorf("%w: %s", shared.ErrValidation, err.Error())
			}
		}
		scheduleType := scan.ScheduleType(input.ScheduleType)
		timezone := input.Timezone
		if timezone == "" {
			timezone = sc.ScheduleTimezone
		}
		var err error
		switch {
		case scheduleType == scan.ScheduleRRule:
			err = sc.SetRRuleSchedule(input.ScheduleRRule, timezone)
		case scheduleType == scan.ScheduleOnce && sameOnceRun(sc, input.RunAt, timezone):
			// The stored one-off run, sent back unchanged with other edits:
			// kept as is, even once it has run (its time is then past).
		case scheduleType == scan.ScheduleOnce:
			err = sc.SetOnceSchedule(input.RunAt, timezone, time.Now())
		default:
			err = sc.SetSchedule(scheduleType, input.ScheduleCron, input.ScheduleDay, input.ScheduleTime, timezone)
		}
		if err != nil {
			return nil, err
		}
	}

	// Update tags if provided
	if input.Tags != nil {
		sc.SetTags(input.Tags)
	}

	// Update tenant runner flag if provided
	if input.TenantRunner != nil {
		sc.SetRunOnTenantRunner(*input.TenantRunner)
	}

	// Update sensor preference if provided
	if input.SensorPreference != "" {
		sc.SetSensorPreference(scan.SensorPreference(input.SensorPreference))
	}

	// Update the scan zone picker if provided (sentinel: empty = Automatic)
	if input.ScanZoneID != nil {
		zoneID, err := s.resolveSelectedZone(ctx, sc.TenantID, *input.ScanZoneID)
		if err != nil {
			return nil, err
		}
		sc.SetScanZone(zoneID)
	}

	// Update timeout if provided (validation enforces min=30, max=86400)
	if input.TimeoutSeconds != nil {
		sc.SetTimeoutSeconds(*input.TimeoutSeconds)
	}

	// Update retry config if either field is provided
	if input.MaxRetries != nil || input.RetryBackoffSeconds != nil {
		maxRetries := sc.MaxRetries
		if input.MaxRetries != nil {
			maxRetries = *input.MaxRetries
		}
		backoff := sc.RetryBackoffSeconds
		if input.RetryBackoffSeconds != nil {
			backoff = *input.RetryBackoffSeconds
		}
		sc.SetRetryConfig(maxRetries, backoff)
	}

	// Update profile link if provided (sentinel: empty string = unlink)
	if input.ProfileID != nil {
		if *input.ProfileID == "" {
			sc.SetProfileID(nil)
		} else {
			profileID, err := shared.IDFromString(*input.ProfileID)
			if err != nil {
				return nil, fmt.Errorf("%w: invalid profile_id", shared.ErrValidation)
			}
			tenantID, _ := shared.IDFromString(input.TenantID)
			if s.profileRepo != nil {
				// GetAccessibleByID enforces tenant scope at SQL layer (defense-in-depth)
				if _, err := s.profileRepo.GetAccessibleByID(ctx, tenantID, profileID); err != nil {
					return nil, fmt.Errorf("scan profile not found: %w", err)
				}
			}
			sc.SetProfileID(&profileID)
		}
	}

	// Save to repository
	if err := s.scanRepo.Update(ctx, sc); err != nil {
		return nil, err
	}

	// Audit log: scan config updated
	s.logAudit(ctx, AuditContext{TenantID: input.TenantID},
		NewSuccessEvent(audit.ActionScanConfigUpdated, audit.ResourceTypeScanConfig, sc.ID.String()).
			WithResourceName(sc.Name).
			WithMessage(fmt.Sprintf("Scan config '%s' updated", sc.Name)))

	s.logger.Info("scan updated", "id", sc.ID.String())
	return sc, nil
}

// =============================================================================
// Delete Operations
// =============================================================================

// DeleteScan deletes a scan.
func (s *Service) DeleteScan(ctx context.Context, tenantID, scanID string) error {
	s.logger.Info("deleting scan", "scan_id", scanID)

	sc, err := s.GetScan(ctx, tenantID, scanID)
	if err != nil {
		return err
	}

	scanName := sc.Name

	if err := s.scanRepo.Delete(ctx, sc.TenantID, sc.ID); err != nil {
		return err
	}

	// Audit log: scan config deleted
	s.logAudit(ctx, AuditContext{TenantID: tenantID},
		NewSuccessEvent(audit.ActionScanConfigDeleted, audit.ResourceTypeScanConfig, scanID).
			WithResourceName(scanName).
			WithMessage(fmt.Sprintf("Scan config '%s' deleted", scanName)))

	s.logger.Info("scan deleted", "id", sc.ID.String())
	return nil
}

// =============================================================================
// Status Operations
// =============================================================================

// ActivateScan activates a scan.
func (s *Service) ActivateScan(ctx context.Context, tenantID, scanID string) (*scan.Scan, error) {
	sc, err := s.GetScan(ctx, tenantID, scanID)
	if err != nil {
		return nil, err
	}

	previousStatus := string(sc.Status)
	if err := sc.Activate(); err != nil {
		return nil, err
	}

	if err := s.scanRepo.Update(ctx, sc); err != nil {
		return nil, err
	}

	s.logger.Info("scan activated", "id", sc.ID.String())
	s.logAudit(ctx, AuditContext{TenantID: tenantID},
		NewSuccessEvent(audit.ActionScanConfigActivated, audit.ResourceTypeScanConfig, sc.ID.String()).
			WithResourceName(sc.Name).
			WithMetadata("previous_status", previousStatus))
	return sc, nil
}

// PauseScan pauses a scan.
func (s *Service) PauseScan(ctx context.Context, tenantID, scanID string) (*scan.Scan, error) {
	sc, err := s.GetScan(ctx, tenantID, scanID)
	if err != nil {
		return nil, err
	}

	previousStatus := string(sc.Status)
	if err := sc.Pause(); err != nil {
		return nil, err
	}

	if err := s.scanRepo.Update(ctx, sc); err != nil {
		return nil, err
	}

	s.logger.Info("scan paused", "id", sc.ID.String())
	s.logAudit(ctx, AuditContext{TenantID: tenantID},
		NewSuccessEvent(audit.ActionScanConfigPaused, audit.ResourceTypeScanConfig, sc.ID.String()).
			WithResourceName(sc.Name).
			WithMetadata("previous_status", previousStatus))
	return sc, nil
}

// DisableScan disables a scan.
func (s *Service) DisableScan(ctx context.Context, tenantID, scanID string) (*scan.Scan, error) {
	sc, err := s.GetScan(ctx, tenantID, scanID)
	if err != nil {
		return nil, err
	}

	previousStatus := string(sc.Status)
	if err := sc.Disable(); err != nil {
		return nil, err
	}

	if err := s.scanRepo.Update(ctx, sc); err != nil {
		return nil, err
	}

	s.logger.Info("scan disabled", "id", sc.ID.String())
	s.logAudit(ctx, AuditContext{TenantID: tenantID},
		NewSuccessEvent(audit.ActionScanConfigDisabled, audit.ResourceTypeScanConfig, sc.ID.String()).
			WithResourceName(sc.Name).
			WithMetadata("previous_status", previousStatus))
	return sc, nil
}

// =============================================================================
// Clone Operations
// =============================================================================

// CloneScan clones a scan with a new name. The person cloning becomes the
// clone's owner (created_by): its scheduled runs act with their scope, never
// as the system (research 21b H2, RFC-050 W2). Their act scope is checked on
// the clone's direct targets like on a create.
func (s *Service) CloneScan(ctx context.Context, tenantID, scanID, newName, actorID string) (*scan.Scan, error) {
	s.logger.Info("cloning scan", "scan_id", scanID, "new_name", newName)

	actor, err := shared.IDFromString(actorID)
	if err != nil || actor.IsZero() {
		return nil, ErrScanActorRequired
	}

	sc, err := s.GetScan(ctx, tenantID, scanID)
	if err != nil {
		return nil, err
	}
	if err := s.refuseOutOfActScope(ctx, sc.TenantID, &actor, sc.Targets); err != nil {
		return nil, err
	}

	// A clone is a new scan of the same targets: the same ownership check
	// as a create (RFC-036).
	if err := s.refuseUnownedTargets(ctx, sc.TenantID, "scan_clone", sc.Targets, IsTakeoverOnlyProbe(sc.ScannerName, sc.ScannerConfig)); err != nil {
		return nil, err
	}

	clone := sc.Clone(newName)
	clone.SetCreatedBy(actor)

	if err := s.scanRepo.Create(ctx, clone); err != nil {
		return nil, err
	}

	s.logger.Info("scan cloned", "original_id", sc.ID.String(), "clone_id", clone.ID.String())
	return clone, nil
}

// =============================================================================
// Bulk Operations
// =============================================================================

// BulkActionResult represents the result of a bulk action.
type BulkActionResult struct {
	Successful []string `json:"successful"` // IDs that were successfully updated
	Failed     []struct {
		ID    string `json:"id"`
		Error string `json:"error"`
	} `json:"failed"` // IDs that failed with error messages
}

// BulkActivate activates multiple scans.
func (s *Service) BulkActivate(ctx context.Context, tenantID string, scanIDs []string) (*BulkActionResult, error) {
	s.logger.Info("bulk activating scans", "count", len(scanIDs), "tenant_id", tenantID)
	return s.bulkStatusChange(ctx, tenantID, scanIDs, "activate")
}

// BulkPause pauses multiple scans.
func (s *Service) BulkPause(ctx context.Context, tenantID string, scanIDs []string) (*BulkActionResult, error) {
	s.logger.Info("bulk pausing scans", "count", len(scanIDs), "tenant_id", tenantID)
	return s.bulkStatusChange(ctx, tenantID, scanIDs, "pause")
}

// BulkDisable disables multiple scans.
func (s *Service) BulkDisable(ctx context.Context, tenantID string, scanIDs []string) (*BulkActionResult, error) {
	s.logger.Info("bulk disabling scans", "count", len(scanIDs), "tenant_id", tenantID)
	return s.bulkStatusChange(ctx, tenantID, scanIDs, "disable")
}

// BulkDelete deletes multiple scans.
func (s *Service) BulkDelete(ctx context.Context, tenantID string, scanIDs []string) (*BulkActionResult, error) {
	s.logger.Info("bulk deleting scans", "count", len(scanIDs), "tenant_id", tenantID)

	result := &BulkActionResult{
		Successful: make([]string, 0),
		Failed: make([]struct {
			ID    string `json:"id"`
			Error string `json:"error"`
		}, 0),
	}

	for _, scanID := range scanIDs {
		err := s.DeleteScan(ctx, tenantID, scanID)
		if err != nil {
			result.Failed = append(result.Failed, struct {
				ID    string `json:"id"`
				Error string `json:"error"`
			}{ID: scanID, Error: err.Error()})
		} else {
			result.Successful = append(result.Successful, scanID)
		}
	}

	s.logger.Info("bulk delete completed",
		"successful", len(result.Successful),
		"failed", len(result.Failed))

	return result, nil
}

// bulkStatusChange handles bulk status changes (activate/pause/disable).
func (s *Service) bulkStatusChange(ctx context.Context, tenantID string, scanIDs []string, action string) (*BulkActionResult, error) {
	result := &BulkActionResult{
		Successful: make([]string, 0),
		Failed: make([]struct {
			ID    string `json:"id"`
			Error string `json:"error"`
		}, 0),
	}

	for _, scanID := range scanIDs {
		var err error
		switch action {
		case "activate":
			_, err = s.ActivateScan(ctx, tenantID, scanID)
		case "pause":
			_, err = s.PauseScan(ctx, tenantID, scanID)
		case "disable":
			_, err = s.DisableScan(ctx, tenantID, scanID)
		}

		if err != nil {
			result.Failed = append(result.Failed, struct {
				ID    string `json:"id"`
				Error string `json:"error"`
			}{ID: scanID, Error: err.Error()})
		} else {
			result.Successful = append(result.Successful, scanID)
		}
	}

	s.logger.Info("bulk status change completed",
		"action", action,
		"successful", len(result.Successful),
		"failed", len(result.Failed))

	return result, nil
}

// =============================================================================
// Cascade Deactivation
// =============================================================================

// DeactivateScansByScanWorkflow pauses all active scans that use the specified scan workflow.
// This implements the ScanDeactivator interface for cascade deactivation.
// Scans are paused (not disabled) so they can be easily resumed when the scan workflow is reactivated.
// Returns the count of paused scans.
func (s *Service) DeactivateScansByScanWorkflow(ctx context.Context, scanWorkflowID shared.ID) (int, error) {
	// Find all scans using this scan workflow
	scans, err := s.scanRepo.ListByScanWorkflowID(ctx, scanWorkflowID)
	if err != nil {
		return 0, fmt.Errorf("failed to list scans by scan workflow: %w", err)
	}

	pausedCount := 0
	for _, sc := range scans {
		// Skip if already paused or disabled
		if sc.Status != scan.StatusActive {
			continue
		}

		// Pause the scan (not disable - so it can be resumed)
		if err := sc.Pause(); err != nil {
			s.logger.Warn("failed to pause scan for scan workflow",
				"scan_id", sc.ID.String(),
				"scan_workflow_id", scanWorkflowID.String(),
				"error", err)
			continue
		}

		if err := s.scanRepo.Update(ctx, sc); err != nil {
			s.logger.Warn("failed to save paused scan for scan workflow",
				"scan_id", sc.ID.String(),
				"scan_workflow_id", scanWorkflowID.String(),
				"error", err)
			continue
		}

		s.logger.Info("scan paused due to scan workflow deactivation",
			"scan_id", sc.ID.String(),
			"scan_name", sc.Name,
			"scan_workflow_id", scanWorkflowID.String())
		pausedCount++
	}

	return pausedCount, nil
}

package scan

import (
	"context"
	"fmt"
	"time"

	"github.com/openctemio/api/pkg/domain/audit"
	"github.com/openctemio/api/pkg/domain/scan"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/pagination"
	"github.com/openctemio/api/pkg/validator"
)

// =============================================================================
// Create Operations
// =============================================================================

// CreateScanInput represents the input for creating a scan.
// Either AssetGroupID/AssetGroupIDs OR Targets must be provided (can have all).
type CreateScanInput struct {
	TenantID        string         `json:"tenant_id" validate:"required,uuid"`
	Name            string         `json:"name" validate:"required,min=1,max=200"`
	Description     string         `json:"description" validate:"max=1000"`
	AssetGroupID    string         `json:"asset_group_id" validate:"omitempty,uuid"`       // Primary asset group (legacy)
	AssetGroupIDs   []string       `json:"asset_group_ids" validate:"omitempty,dive,uuid"` // Multiple asset groups (NEW)
	Targets         []string       `json:"targets" validate:"omitempty,max=1000"`          // Direct targets
	ScanType        string         `json:"scan_type" validate:"required,oneof=workflow single"`
	PipelineID      string         `json:"pipeline_id" validate:"omitempty,uuid"`
	ScannerName     string         `json:"scanner_name" validate:"max=100"`
	ScannerConfig   map[string]any `json:"scanner_config"`
	TargetsPerJob   int            `json:"targets_per_job"`
	ScheduleType    string         `json:"schedule_type" validate:"omitempty,oneof=manual daily weekly monthly crontab"`
	ScheduleCron    string         `json:"schedule_cron" validate:"max=100"`
	ScheduleDay     *int           `json:"schedule_day"`
	ScheduleTime    *time.Time     `json:"schedule_time"`
	Timezone        string         `json:"timezone" validate:"max=50"`
	Tags            []string       `json:"tags" validate:"max=20,dive,max=50"`
	TenantRunner    bool           `json:"run_on_tenant_runner"`
	AgentPreference string         `json:"agent_preference" validate:"omitempty,oneof=auto tenant platform"` // Agent selection mode: auto (default), tenant, platform
	CreatedBy       string         `json:"created_by" validate:"omitempty,uuid"`
}

// CreateScanResult represents the result of creating a scan.
// It includes the scan entity and optional compatibility warnings.
type CreateScanResult struct {
	Scan                 *scan.Scan                 `json:"scan"`
	CompatibilityWarning *AssetCompatibilityPreview `json:"compatibility_warning,omitempty"`
}

// CreateScan creates a new scan.
//
//nolint:cyclop // Scan creation requires validation of many input fields
func (s *Service) CreateScan(ctx context.Context, input CreateScanInput) (*scan.Scan, error) {
	s.logger.Info("creating scan", "name", input.Name, "tenant_id", input.TenantID)

	tenantID, err := shared.IDFromString(input.TenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}

	// Validate tags format (only alphanumeric, dash, underscore allowed)
	if s.securityValidator != nil && len(input.Tags) > 0 {
		result := s.securityValidator.ValidateIdentifiers(input.Tags, 50, "tags")
		if !result.Valid {
			s.logger.Warn("tags validation failed", "tenant_id", input.TenantID, "errors", result.Errors)
			return nil, fmt.Errorf("%w: %s", shared.ErrValidation, result.Errors[0].Message)
		}
	}

	// Security validation: validate scanner config
	if s.securityValidator != nil && input.ScannerConfig != nil {
		result := s.securityValidator.ValidateScannerConfig(ctx, tenantID, input.ScannerConfig)
		if !result.Valid {
			s.logger.Warn("scanner config validation failed",
				"tenant_id", input.TenantID,
				"errors", result.Errors)
			return nil, fmt.Errorf("%w: %s", shared.ErrValidation, result.Errors[0].Message)
		}
	}

	// Security validation: validate cron expression
	if s.securityValidator != nil && input.ScheduleCron != "" {
		if err := s.securityValidator.ValidateCronExpression(input.ScheduleCron); err != nil {
			s.logger.Warn("cron expression validation failed",
				"tenant_id", input.TenantID,
				"cron", input.ScheduleCron,
				"error", err)
			return nil, fmt.Errorf("%w: %s", shared.ErrValidation, err.Error())
		}
	}

	// Validate: must have either asset_group_id/asset_group_ids or targets
	hasAssetGroup := input.AssetGroupID != "" || len(input.AssetGroupIDs) > 0
	hasTargets := len(input.Targets) > 0
	if !hasAssetGroup && !hasTargets {
		return nil, fmt.Errorf("%w: either asset_group_id/asset_group_ids or targets must be provided", shared.ErrValidation)
	}

	// Validate and sanitize targets if provided (SECURITY: SSRF protection)
	var validatedTargets []string
	if hasTargets {
		targetValidator := validator.NewTargetValidator(
			validator.WithAllowInternalIPs(false), // Block internal IPs (SSRF protection)
			validator.WithAllowLocalhost(false),   // Block localhost
			validator.WithMaxTargets(1000),        // Limit number of targets
		)
		validationResult := targetValidator.ValidateTargets(input.Targets)

		if validationResult.HasErrors {
			// Log security event for blocked IPs
			if len(validationResult.BlockedIPs) > 0 {
				s.logger.Warn("SECURITY: blocked internal/localhost targets",
					"tenant_id", input.TenantID,
					"blocked_ips", validationResult.BlockedIPs)
			}

			// Return first error message
			if len(validationResult.Invalid) > 0 {
				firstError := validationResult.Invalid[0]
				return nil, fmt.Errorf("%w: invalid target '%s': %s",
					shared.ErrValidation, firstError.Original, firstError.Error)
			}
			return nil, fmt.Errorf("%w: invalid targets provided", shared.ErrValidation)
		}

		validatedTargets = validationResult.GetValidTargetStrings()
		if len(validatedTargets) == 0 {
			return nil, fmt.Errorf("%w: no valid targets provided", shared.ErrValidation)
		}

		s.logger.Info("targets validated",
			"tenant_id", input.TenantID,
			"total", validationResult.TotalCount,
			"valid", validationResult.ValidCount)
	}

	// Parse and validate asset_group_id/asset_group_ids if provided
	var assetGroupID shared.ID
	var assetGroupIDs []shared.ID
	if hasAssetGroup {
		// Validate primary asset_group_id if provided
		if input.AssetGroupID != "" {
			var err error
			assetGroupID, err = shared.IDFromString(input.AssetGroupID)
			if err != nil {
				return nil, fmt.Errorf("%w: invalid asset_group_id", shared.ErrValidation)
			}

			// Verify asset group exists AND belongs to tenant
			ag, err := s.assetGroupRepo.GetByID(ctx, assetGroupID)
			if err != nil {
				return nil, fmt.Errorf("asset group not found: %w", err)
			}
			if ag.TenantID() != tenantID {
				s.logger.Warn("SECURITY: cross-tenant asset group access attempt",
					"tenant_id", input.TenantID,
					"asset_group_tenant_id", ag.TenantID().String())
				return nil, fmt.Errorf("%w: asset group not found", shared.ErrNotFound)
			}
		}

		// Validate multiple asset_group_ids if provided
		if len(input.AssetGroupIDs) > 0 {
			assetGroupIDs = make([]shared.ID, 0, len(input.AssetGroupIDs))
			for _, idStr := range input.AssetGroupIDs {
				id, err := shared.IDFromString(idStr)
				if err != nil {
					return nil, fmt.Errorf("%w: invalid asset_group_id in list: %s", shared.ErrValidation, idStr)
				}

				// Verify each asset group exists AND belongs to tenant
				ag, err := s.assetGroupRepo.GetByID(ctx, id)
				if err != nil {
					return nil, fmt.Errorf("asset group not found: %s", idStr)
				}
				if ag.TenantID() != tenantID {
					s.logger.Warn("SECURITY: cross-tenant asset group access attempt",
						"tenant_id", input.TenantID,
						"asset_group_tenant_id", ag.TenantID().String())
					return nil, fmt.Errorf("%w: asset group not found", shared.ErrNotFound)
				}
				assetGroupIDs = append(assetGroupIDs, id)
			}

			// If no primary asset_group_id was set, use the first from the list
			if assetGroupID.IsZero() && len(assetGroupIDs) > 0 {
				assetGroupID = assetGroupIDs[0]
			}
		}
	}

	// Parse scan type
	scanType := scan.ScanType(input.ScanType)
	if scanType != scan.ScanTypeWorkflow && scanType != scan.ScanTypeSingle {
		return nil, fmt.Errorf("%w: invalid scan_type", shared.ErrValidation)
	}

	// Create scan - use validated targets if no asset group
	var sc *scan.Scan
	if len(validatedTargets) > 0 && !hasAssetGroup {
		// Create scan with direct targets (no asset group)
		sc, err = scan.NewScanWithTargets(tenantID, input.Name, validatedTargets, scanType)
		if err != nil {
			return nil, err
		}
	} else {
		// Create scan with asset group (existing path)
		sc, err = scan.NewScan(tenantID, input.Name, assetGroupID, scanType)
		if err != nil {
			return nil, err
		}
		// If we have both asset_group and targets, add validated targets too
		if len(validatedTargets) > 0 {
			sc.SetTargets(validatedTargets)
		}
	}

	// Set multiple asset group IDs if provided
	if len(assetGroupIDs) > 0 {
		sc.SetAssetGroupIDs(assetGroupIDs)
	}

	sc.Description = input.Description

	// Set workflow or single scanner
	if scanType == scan.ScanTypeWorkflow {
		if input.PipelineID == "" {
			return nil, fmt.Errorf("%w: pipeline_id is required for workflow type", shared.ErrValidation)
		}
		pipelineID, err := shared.IDFromString(input.PipelineID)
		if err != nil {
			return nil, fmt.Errorf("%w: invalid pipeline_id", shared.ErrValidation)
		}
		// Verify pipeline exists
		pipelineTemplate, err := s.templateRepo.GetByTenantAndID(ctx, tenantID, pipelineID)
		if err != nil {
			return nil, fmt.Errorf("pipeline not found: %w", err)
		}

		// Validate all pipeline steps have valid tools
		steps, err := s.stepRepo.GetByPipelineID(ctx, pipelineTemplate.ID)
		if err != nil {
			return nil, fmt.Errorf("failed to get pipeline steps: %w", err)
		}
		for _, step := range steps {
			if step.Tool != "" {
				stepTool, err := s.toolRepo.GetByName(ctx, step.Tool)
				if err != nil || stepTool == nil {
					return nil, fmt.Errorf("%w: pipeline step '%s' uses tool '%s' which is not found",
						shared.ErrValidation, step.StepKey, step.Tool)
				}
				if !stepTool.IsActive {
					return nil, fmt.Errorf("%w: pipeline step '%s' uses tool '%s' which is disabled",
						shared.ErrValidation, step.StepKey, step.Tool)
				}
			}
		}

		if err := sc.SetWorkflow(pipelineID); err != nil {
			return nil, err
		}
	} else {
		if input.ScannerName == "" {
			return nil, fmt.Errorf("%w: scanner_name is required for single type", shared.ErrValidation)
		}

		// Validate tool exists and is active
		scannerTool, err := s.toolRepo.GetByName(ctx, input.ScannerName)
		if err != nil || scannerTool == nil {
			return nil, fmt.Errorf("%w: scanner '%s' not found in tool registry", shared.ErrValidation, input.ScannerName)
		}
		if !scannerTool.IsActive {
			return nil, fmt.Errorf("%w: scanner '%s' is disabled", shared.ErrValidation, input.ScannerName)
		}

		targetsPerJob := max(input.TargetsPerJob, 1)
		if err := sc.SetSingleScanner(input.ScannerName, input.ScannerConfig, targetsPerJob); err != nil {
			return nil, err
		}
	}

	// Set schedule
	scheduleType := scan.ScheduleType(input.ScheduleType)
	if scheduleType == "" {
		scheduleType = scan.ScheduleManual
	}
	timezone := input.Timezone
	if timezone == "" {
		timezone = "UTC"
	}

	// Validate timezone is a valid IANA timezone
	if err := validateTimezone(timezone); err != nil {
		return nil, fmt.Errorf("%w: %s", shared.ErrValidation, err.Error())
	}

	// Additional cron validation: ensure cron can be parsed by the scheduler
	if scheduleType == scan.ScheduleCrontab && input.ScheduleCron != "" {
		if err := validateCronParseable(input.ScheduleCron); err != nil {
			return nil, fmt.Errorf("%w: invalid cron expression: %s", shared.ErrValidation, err.Error())
		}
	}

	if err := sc.SetSchedule(scheduleType, input.ScheduleCron, input.ScheduleDay, input.ScheduleTime, timezone); err != nil {
		return nil, err
	}

	// Set tags and routing
	if len(input.Tags) > 0 {
		sc.SetTags(input.Tags)
	}
	sc.SetRunOnTenantRunner(input.TenantRunner)

	// Check agent availability - log warning if no agents available
	// We allow scan creation even without agents so scans can be scheduled
	// and executed when an agent comes online
	toolToCheck := input.ScannerName
	if scanType == scan.ScanTypeWorkflow {
		// For workflow scans, we just check general agent availability
		// Each step will be checked when scheduled
		toolToCheck = ""
	}
	agentAvail := s.agentSelector.CheckAgentAvailability(ctx, tenantID, toolToCheck, input.TenantRunner)
	if !agentAvail.Available {
		s.logger.Warn("no agent available for scan",
			"tenant_id", tenantID.String(),
			"tool", toolToCheck,
			"message", agentAvail.Message,
		)
		// Don't block scan creation - allow scheduling for when agent comes online
	}

	// Set agent preference
	if input.AgentPreference != "" {
		sc.SetAgentPreference(scan.AgentPreference(input.AgentPreference))
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

// PreviewScanCompatibility checks asset-scanner compatibility for a scan configuration.
// This is called before scan creation to show warnings about incompatible assets.
// Returns nil if no warning needed (100% compatible or no asset groups).
func (s *Service) PreviewScanCompatibility(
	ctx context.Context,
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
	scannerTool, err := s.toolRepo.GetByName(ctx, scannerName)
	if err != nil || scannerTool == nil {
		return nil, nil // Tool not found, skip compatibility check
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
	TenantID     string   `json:"tenant_id" validate:"required,uuid"`
	AssetGroupID string   `json:"asset_group_id" validate:"omitempty,uuid"`
	PipelineID   string   `json:"pipeline_id" validate:"omitempty,uuid"`
	ScanType     string   `json:"scan_type" validate:"omitempty,oneof=workflow single"`
	ScheduleType string   `json:"schedule_type" validate:"omitempty,oneof=manual daily weekly monthly crontab"`
	Status       string   `json:"status" validate:"omitempty,oneof=active paused disabled"`
	Tags         []string `json:"tags"`
	Search       string   `json:"search" validate:"max=255"`
	Page         int      `json:"page"`
	PerPage      int      `json:"per_page"`
}

// ListScans lists scans with filters.
func (s *Service) ListScans(ctx context.Context, input ListScansInput) (pagination.Result[*scan.Scan], error) {
	tenantID, err := shared.IDFromString(input.TenantID)
	if err != nil {
		return pagination.Result[*scan.Scan]{}, fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}

	filter := scan.Filter{
		TenantID: &tenantID,
		Tags:     input.Tags,
		Search:   input.Search,
	}

	if input.AssetGroupID != "" {
		agID, err := shared.IDFromString(input.AssetGroupID)
		if err == nil {
			filter.AssetGroupID = &agID
		}
	}

	if input.PipelineID != "" {
		pID, err := shared.IDFromString(input.PipelineID)
		if err == nil {
			filter.PipelineID = &pID
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
	TenantID        string         `json:"tenant_id" validate:"required,uuid"`
	ScanID          string         `json:"scan_id" validate:"required,uuid"`
	Name            string         `json:"name" validate:"omitempty,min=1,max=200"`
	Description     string         `json:"description" validate:"max=1000"`
	PipelineID      string         `json:"pipeline_id" validate:"omitempty,uuid"`
	ScannerName     string         `json:"scanner_name" validate:"max=100"`
	ScannerConfig   map[string]any `json:"scanner_config"`
	TargetsPerJob   *int           `json:"targets_per_job"`
	ScheduleType    string         `json:"schedule_type" validate:"omitempty,oneof=manual daily weekly monthly crontab"`
	ScheduleCron    string         `json:"schedule_cron" validate:"max=100"`
	ScheduleDay     *int           `json:"schedule_day"`
	ScheduleTime    *time.Time     `json:"schedule_time"`
	Timezone        string         `json:"timezone" validate:"max=50"`
	Tags            []string       `json:"tags" validate:"max=20,dive,max=50"`
	TenantRunner    *bool          `json:"run_on_tenant_runner"`
	AgentPreference string         `json:"agent_preference" validate:"omitempty,oneof=auto tenant platform"`
}

// UpdateScan updates a scan.
func (s *Service) UpdateScan(ctx context.Context, input UpdateScanInput) (*scan.Scan, error) {
	s.logger.Info("updating scan", "scan_id", input.ScanID)

	sc, err := s.GetScan(ctx, input.TenantID, input.ScanID)
	if err != nil {
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
	if sc.ScanType == scan.ScanTypeWorkflow && input.PipelineID != "" {
		pipelineID, err := shared.IDFromString(input.PipelineID)
		if err != nil {
			return nil, fmt.Errorf("%w: invalid pipeline_id", shared.ErrValidation)
		}
		tenantID, _ := shared.IDFromString(input.TenantID)
		if _, err := s.templateRepo.GetByTenantAndID(ctx, tenantID, pipelineID); err != nil {
			return nil, fmt.Errorf("pipeline not found: %w", err)
		}
		if err := sc.SetWorkflow(pipelineID); err != nil {
			return nil, err
		}
	} else if sc.ScanType == scan.ScanTypeSingle && input.ScannerName != "" {
		targetsPerJob := sc.TargetsPerJob
		if input.TargetsPerJob != nil {
			targetsPerJob = *input.TargetsPerJob
		}
		if err := sc.SetSingleScanner(input.ScannerName, input.ScannerConfig, targetsPerJob); err != nil {
			return nil, err
		}
	}

	// Update schedule if provided
	if input.ScheduleType != "" {
		scheduleType := scan.ScheduleType(input.ScheduleType)
		timezone := input.Timezone
		if timezone == "" {
			timezone = sc.ScheduleTimezone
		}
		if err := sc.SetSchedule(scheduleType, input.ScheduleCron, input.ScheduleDay, input.ScheduleTime, timezone); err != nil {
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

	// Update agent preference if provided
	if input.AgentPreference != "" {
		sc.SetAgentPreference(scan.AgentPreference(input.AgentPreference))
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

	if err := s.scanRepo.Delete(ctx, sc.ID); err != nil {
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

// CloneScan clones a scan with a new name.
func (s *Service) CloneScan(ctx context.Context, tenantID, scanID, newName string) (*scan.Scan, error) {
	s.logger.Info("cloning scan", "scan_id", scanID, "new_name", newName)

	sc, err := s.GetScan(ctx, tenantID, scanID)
	if err != nil {
		return nil, err
	}

	clone := sc.Clone(newName)

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

// DeactivateScansByPipeline pauses all active scans that use the specified pipeline.
// This implements the ScanDeactivator interface for cascade deactivation.
// Scans are paused (not disabled) so they can be easily resumed when the pipeline is reactivated.
// Returns the count of paused scans.
func (s *Service) DeactivateScansByPipeline(ctx context.Context, pipelineID shared.ID) (int, error) {
	// Find all scans using this pipeline
	scans, err := s.scanRepo.ListByPipelineID(ctx, pipelineID)
	if err != nil {
		return 0, fmt.Errorf("failed to list scans by pipeline: %w", err)
	}

	pausedCount := 0
	for _, sc := range scans {
		// Skip if already paused or disabled
		if sc.Status != scan.StatusActive {
			continue
		}

		// Pause the scan (not disable - so it can be resumed)
		if err := sc.Pause(); err != nil {
			s.logger.Warn("failed to pause scan for pipeline",
				"scan_id", sc.ID.String(),
				"pipeline_id", pipelineID.String(),
				"error", err)
			continue
		}

		if err := s.scanRepo.Update(ctx, sc); err != nil {
			s.logger.Warn("failed to save paused scan for pipeline",
				"scan_id", sc.ID.String(),
				"pipeline_id", pipelineID.String(),
				"error", err)
			continue
		}

		s.logger.Info("scan paused due to pipeline deactivation",
			"scan_id", sc.ID.String(),
			"scan_name", sc.Name,
			"pipeline_id", pipelineID.String())
		pausedCount++
	}

	return pausedCount, nil
}

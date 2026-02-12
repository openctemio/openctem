package scan

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/openctemio/api/internal/metrics"
	"github.com/openctemio/api/pkg/domain/audit"
	"github.com/openctemio/api/pkg/domain/command"
	"github.com/openctemio/api/pkg/domain/pipeline"
	"github.com/openctemio/api/pkg/domain/scan"
	"github.com/openctemio/api/pkg/domain/shared"
)

// =============================================================================
// Trigger Operations
// =============================================================================

// TriggerScanExecInput represents the input for triggering a scan execution.
type TriggerScanExecInput struct {
	TenantID    string         `json:"tenant_id" validate:"required,uuid"`
	ScanID      string         `json:"scan_id" validate:"required,uuid"`
	TriggeredBy string         `json:"triggered_by" validate:"omitempty,uuid"`
	Context     map[string]any `json:"context"`
}

// TriggerScan triggers a scan execution.
func (s *Service) TriggerScan(ctx context.Context, input TriggerScanExecInput) (*pipeline.Run, error) {
	s.logger.Info("triggering scan", "scan_id", input.ScanID)

	sc, err := s.GetScan(ctx, input.TenantID, input.ScanID)
	if err != nil {
		return nil, err
	}

	if !sc.CanTrigger() {
		return nil, fmt.Errorf("%w: scan is not active", shared.ErrValidation)
	}

	// NOTE: Concurrent run limits are now checked atomically in CreateRunIfUnderLimit
	// to prevent race conditions where multiple triggers bypass the limit.

	// Validate tools are still available and active before triggering
	// (Tools may have been disabled or removed since scan was created)
	if err := s.validateToolsAtTriggerTime(ctx, sc); err != nil {
		return nil, err
	}

	// Check agent availability before triggering - must have an online agent
	toolToCheck := ""
	if sc.ScanType == scan.ScanTypeSingle && sc.ScannerName != "" {
		toolToCheck = sc.ScannerName
	}
	agentAvail := s.agentSelector.CheckAgentAvailability(ctx, sc.TenantID, toolToCheck, sc.RunOnTenantRunner)
	if !agentAvail.Available {
		return nil, shared.NewDomainError(
			"NO_AGENT_AVAILABLE",
			agentAvail.Message,
			shared.ErrValidation,
		)
	}

	var run *pipeline.Run

	// Execute based on scan type
	if sc.ScanType == scan.ScanTypeWorkflow {
		run, err = s.triggerWorkflow(ctx, sc, input.TriggeredBy, input.Context)
	} else {
		run, err = s.triggerSingleScan(ctx, sc, input.TriggeredBy, input.Context)
	}

	if err != nil {
		return nil, err
	}

	// Record the run
	sc.RecordRun(run.ID, string(run.Status))
	if err := s.scanRepo.Update(ctx, sc); err != nil {
		s.logger.Warn("failed to record run in scan", "error", err)
	}

	// Audit log: scan triggered
	s.logAudit(ctx, AuditContext{TenantID: input.TenantID, ActorID: input.TriggeredBy},
		NewSuccessEvent(audit.ActionScanConfigTriggered, audit.ResourceTypeScanConfig, sc.ID.String()).
			WithResourceName(sc.Name).
			WithMessage(fmt.Sprintf("Scan config '%s' triggered", sc.Name)).
			WithMetadata("run_id", run.ID.String()).
			WithMetadata("scan_type", string(sc.ScanType)))

	s.logger.Info("scan triggered", "scan_id", sc.ID.String(), "run_id", run.ID.String())
	return run, nil
}

// triggerWorkflow triggers a workflow pipeline execution.
func (s *Service) triggerWorkflow(ctx context.Context, sc *scan.Scan, triggeredBy string, runContext map[string]any) (*pipeline.Run, error) {
	if sc.PipelineID == nil {
		return nil, fmt.Errorf("%w: pipeline_id is required for workflow", shared.ErrValidation)
	}

	// Get pipeline template
	template, err := s.templateRepo.GetByID(ctx, *sc.PipelineID)
	if err != nil {
		return nil, shared.NewDomainError(
			"PIPELINE_NOT_FOUND",
			fmt.Sprintf("Pipeline template '%s' not found. It may have been deleted.", sc.PipelineID.String()),
			shared.ErrNotFound,
		)
	}

	// Verify template is active
	if !template.IsActive {
		return nil, shared.NewDomainError(
			"PIPELINE_DISABLED",
			fmt.Sprintf("Pipeline template '%s' is disabled. Please enable it or use a different pipeline.", template.Name),
			shared.ErrValidation,
		)
	}

	// Get pipeline steps
	steps, err := s.stepRepo.GetByPipelineID(ctx, template.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to get pipeline steps: %w", err)
	}

	// Validate pipeline has steps
	if len(steps) == 0 {
		return nil, shared.NewDomainError(
			"PIPELINE_EMPTY",
			fmt.Sprintf("Pipeline '%s' has no steps. Please add at least one step.", template.Name),
			shared.ErrValidation,
		)
	}

	// Build context
	if runContext == nil {
		runContext = make(map[string]any)
	}
	runContext["scan_id"] = sc.ID.String()
	runContext["asset_group_id"] = sc.AssetGroupID.String()
	runContext["routing_tags"] = sc.Tags
	runContext["tenant_runner_only"] = sc.RunOnTenantRunner

	// Create pipeline run
	run, err := pipeline.NewRun(template.ID, sc.TenantID, nil, pipeline.TriggerTypeManual, triggeredBy, runContext)
	if err != nil {
		return nil, fmt.Errorf("failed to create pipeline run: %w", err)
	}
	run.SetTotalSteps(len(steps))
	run.ScanID = &sc.ID // Link run to scan for concurrent limit tracking

	// Atomically check concurrent limits and create run to prevent race conditions
	if err := s.runRepo.CreateRunIfUnderLimit(ctx, run, MaxConcurrentRunsPerScan, MaxConcurrentRunsPerTenant); err != nil {
		return nil, err // Error already includes proper domain error for limit exceeded
	}

	// Create step runs
	for _, step := range steps {
		stepRun := pipeline.NewStepRun(run.ID, step.ID, step.StepKey, step.StepOrder, step.MaxRetries)
		if err := s.stepRunRepo.Create(ctx, stepRun); err != nil {
			s.logger.Warn("failed to create step run", "error", err)
		}
		run.AddStepRun(stepRun)
	}

	// Start the run
	run.Start()
	if err := s.runRepo.Update(ctx, run); err != nil {
		s.logger.Warn("failed to update run status", "error", err)
	}

	// Schedule first runnable steps
	if err := s.scheduleWorkflowSteps(ctx, run, steps); err != nil {
		s.logger.Warn("failed to schedule workflow steps", "error", err)
	}

	return run, nil
}

// QuickScanTemplateID is the system template ID for quick/single scans.
// This template is created during database migration/seed.
const QuickScanTemplateID = "00000000-0000-0000-0000-000000000001"

// triggerSingleScan triggers a single scanner execution.
func (s *Service) triggerSingleScan(ctx context.Context, sc *scan.Scan, triggeredBy string, runContext map[string]any) (*pipeline.Run, error) {
	// Build context
	if runContext == nil {
		runContext = make(map[string]any)
	}
	runContext["scan_id"] = sc.ID.String()
	runContext["asset_group_id"] = sc.AssetGroupID.String()
	runContext["scanner_name"] = sc.ScannerName
	runContext["scanner_config"] = sc.ScannerConfig
	runContext["targets_per_job"] = sc.TargetsPerJob
	runContext["routing_tags"] = sc.Tags
	runContext["tenant_runner_only"] = sc.RunOnTenantRunner

	// Smart filtering: filter assets based on scanner compatibility
	filteringResult, err := s.filterAssetsForSingleScan(ctx, sc)
	if err != nil {
		s.logger.Warn("failed to filter assets, proceeding without filtering", "error", err, "scan_id", sc.ID.String())
	} else if filteringResult != nil {
		runContext["filtering_result"] = filteringResult
		if filteringResult.WasFiltered {
			s.logger.Info("smart filtering applied",
				"scan_id", sc.ID.String(),
				"scanner", sc.ScannerName,
				"total", filteringResult.TotalAssets,
				"scanned", filteringResult.ScannedAssets,
				"skipped", filteringResult.SkippedAssets,
				"compatibility_percent", filteringResult.CompatibilityPercent)
		}
	}

	// Use the system quick scan template for tracking
	quickScanTemplateID, _ := shared.IDFromString(QuickScanTemplateID)

	// Create a pipeline run using the system template
	run, err := pipeline.NewRun(quickScanTemplateID, sc.TenantID, nil, pipeline.TriggerTypeManual, triggeredBy, runContext)
	if err != nil {
		return nil, fmt.Errorf("failed to create run: %w", err)
	}
	run.SetTotalSteps(1)
	run.Start()
	run.ScanID = &sc.ID // Link run to scan for concurrent limit tracking

	// Atomically check concurrent limits and create run to prevent race conditions
	if err := s.runRepo.CreateRunIfUnderLimit(ctx, run, MaxConcurrentRunsPerScan, MaxConcurrentRunsPerTenant); err != nil {
		return nil, err // Error already includes proper domain error for limit exceeded
	}

	// Create command for the scanner
	if err := s.createScannerCommand(ctx, sc, run); err != nil {
		run.Fail("Failed to create command: " + err.Error())
		_ = s.runRepo.Update(ctx, run)
		return nil, fmt.Errorf("failed to create scanner command: %w", err)
	}

	return run, nil
}

// scheduleWorkflowSteps schedules runnable workflow steps.
func (s *Service) scheduleWorkflowSteps(ctx context.Context, run *pipeline.Run, steps []*pipeline.Step) error {
	for _, step := range steps {
		if step.StepOrder == 1 {
			// Queue first step
			if err := s.queueWorkflowStep(ctx, run, step); err != nil {
				return err
			}
		}
	}
	return nil
}

// queueWorkflowStep queues a workflow step for execution.
func (s *Service) queueWorkflowStep(ctx context.Context, run *pipeline.Run, step *pipeline.Step) error {
	// Find the step run first to include in payload
	var stepRunID string
	stepRuns, _ := s.stepRunRepo.GetByPipelineRunID(ctx, run.ID)
	for _, sr := range stepRuns {
		if sr.StepID == step.ID {
			stepRunID = sr.ID.String()
			break
		}
	}

	// Create command for the step with consistent field names for pipeline progression
	payload, _ := json.Marshal(map[string]any{
		"pipeline_run_id":       run.ID.String(),
		"step_run_id":           stepRunID,
		"step_id":               step.ID.String(),
		"step_key":              step.StepKey,
		"step_config":           step.Config,
		"required_capabilities": step.Capabilities,
		"preferred_tool":        step.Tool,
		"timeout_seconds":       step.TimeoutSeconds,
		"context":               run.Context,
	})

	cmd, err := command.NewCommand(run.TenantID, command.CommandTypeScan, command.CommandPriorityNormal, payload)
	if err != nil {
		return fmt.Errorf("failed to create command: %w", err)
	}

	if err := s.commandRepo.Create(ctx, cmd); err != nil {
		return fmt.Errorf("failed to create command: %w", err)
	}

	// Update step run status to queued
	for _, sr := range stepRuns {
		if sr.StepID == step.ID {
			sr.CommandID = &cmd.ID
			sr.Queue()
			if err := s.stepRunRepo.Update(ctx, sr); err != nil {
				s.logger.Warn("failed to update step run", "error", err)
			}
			break
		}
	}

	return nil
}

// EmbeddedTemplate represents a template embedded in scan command payload.
// This is the format sent to agents for custom templates.
type EmbeddedTemplate struct {
	ID           string `json:"id"`
	Name         string `json:"name"`
	TemplateType string `json:"template_type"`
	Content      string `json:"content"`      // Base64 encoded content
	ContentHash  string `json:"content_hash"` // SHA256 hash for verification
}

// createScannerCommand creates a command for a single scanner execution.
// Uses AgentSelector to determine whether to use tenant or platform agents.
func (s *Service) createScannerCommand(ctx context.Context, sc *scan.Scan, run *pipeline.Run) error {
	payloadMap := map[string]any{
		"run_id":             run.ID.String(),
		"scan_id":            sc.ID.String(),
		"scanner_name":       sc.ScannerName,
		"scanner_config":     sc.ScannerConfig,
		"asset_group_id":     sc.AssetGroupID.String(),
		"targets_per_job":    sc.TargetsPerJob,
		"routing_tags":       sc.Tags,
		"tenant_runner_only": sc.RunOnTenantRunner,
		"agent_preference":   string(sc.AgentPreference),
		"context":            run.Context,
	}

	// Embed custom templates if configured
	if templates, err := s.resolveCustomTemplates(ctx, sc); err != nil {
		s.logger.Warn("failed to resolve custom templates, proceeding without them",
			"error", err, "scan_id", sc.ID.String())
	} else if len(templates) > 0 {
		payloadMap["custom_templates"] = templates
		s.logger.Info("embedded custom templates in scan command",
			"scan_id", sc.ID.String(),
			"template_count", len(templates))
	}

	payload, _ := json.Marshal(payloadMap)

	cmd, err := command.NewCommand(sc.TenantID, command.CommandTypeScan, command.CommandPriorityNormal, payload)
	if err != nil {
		return err
	}

	// Determine whether to use platform agents based on AgentSelector
	usePlatform, err := s.shouldUsePlatformAgent(ctx, sc)
	if err != nil {
		s.logger.Warn("failed to determine agent selection, falling back to tenant only",
			"error", err, "scan_id", sc.ID.String())
		usePlatform = false
	}

	if usePlatform {
		// Calculate initial queue priority based on command priority
		initialPriority := s.calculateInitialPriority(cmd.Priority)
		cmd.SetPlatformJob(initialPriority)
	}

	return s.commandRepo.Create(ctx, cmd)
}

// resolveCustomTemplates resolves custom templates from scanner_config.
// Uses lazy sync: checks if template sources need sync and syncs them on-demand.
func (s *Service) resolveCustomTemplates(ctx context.Context, sc *scan.Scan) ([]EmbeddedTemplate, error) {
	if s.scannerTemplateRepo == nil {
		return nil, nil
	}

	// Check if scanner_config has custom_template_ids
	templateIDsRaw, ok := sc.ScannerConfig["custom_template_ids"]
	if !ok {
		return nil, nil
	}

	// Parse template IDs
	var templateIDs []string
	switch v := templateIDsRaw.(type) {
	case []string:
		templateIDs = v
	case []any:
		for _, id := range v {
			if str, ok := id.(string); ok {
				templateIDs = append(templateIDs, str)
			}
		}
	default:
		return nil, nil
	}

	if len(templateIDs) == 0 {
		return nil, nil
	}

	// Convert to shared.ID
	ids := make([]shared.ID, 0, len(templateIDs))
	for _, idStr := range templateIDs {
		id, err := shared.IDFromString(idStr)
		if err != nil {
			s.logger.Warn("invalid template ID in scanner_config", "template_id", idStr, "error", err)
			continue
		}
		ids = append(ids, id)
	}

	if len(ids) == 0 {
		return nil, nil
	}

	// Lazy sync: Check if any template sources need sync before fetching templates
	if err := s.lazySyncTemplatesIfNeeded(ctx, sc.TenantID); err != nil {
		// Log warning but continue - we can still use cached templates
		s.logger.Warn("lazy sync failed, using cached templates",
			"tenant_id", sc.TenantID.String(),
			"error", err)
	}

	// Fetch templates from database
	templates, err := s.scannerTemplateRepo.ListByIDs(ctx, sc.TenantID, ids)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch templates: %w", err)
	}

	// Convert to embedded format
	embedded := make([]EmbeddedTemplate, 0, len(templates))
	for _, tpl := range templates {
		// Only include active templates
		if !tpl.Status.IsUsable() {
			s.logger.Warn("skipping non-active template",
				"template_id", tpl.ID.String(),
				"template_name", tpl.Name,
				"status", string(tpl.Status))
			continue
		}

		embedded = append(embedded, EmbeddedTemplate{
			ID:           tpl.ID.String(),
			Name:         tpl.Name,
			TemplateType: string(tpl.TemplateType),
			Content:      base64.StdEncoding.EncodeToString(tpl.Content), // Base64 encode for safe JSON transport
			ContentHash:  tpl.ContentHash,
		})
	}

	return embedded, nil
}

// lazySyncTemplatesIfNeeded checks if any template sources need sync and syncs them.
// This is called on-demand when a scan uses custom templates (lazy sync pattern).
func (s *Service) lazySyncTemplatesIfNeeded(ctx context.Context, tenantID shared.ID) error {
	if s.templateSourceRepo == nil || s.templateSyncer == nil {
		return nil
	}

	// Get sources that need sync for this tenant
	sources, err := s.templateSourceRepo.ListEnabledForSync(ctx, tenantID)
	if err != nil {
		return fmt.Errorf("failed to list sources needing sync: %w", err)
	}

	if len(sources) == 0 {
		return nil
	}

	s.logger.Info("lazy syncing template sources",
		"tenant_id", tenantID.String(),
		"source_count", len(sources))

	// Sync each source that needs it
	var syncErrors []error
	for _, source := range sources {
		// Check if source needs sync (cache expired)
		if !source.NeedsSync() {
			continue
		}

		s.logger.Debug("syncing template source",
			"source_id", source.ID.String(),
			"source_name", source.Name,
			"source_type", string(source.SourceType))

		result, err := s.templateSyncer.SyncSource(ctx, source)
		if err != nil {
			syncErrors = append(syncErrors, fmt.Errorf("sync %s failed: %w", source.Name, err))
			continue
		}

		// Record metrics
		metrics.TemplateSyncsTotal.WithLabelValues(tenantID.String(), string(source.SourceType)).Inc()
		if result.Success {
			metrics.TemplateSyncsSuccessTotal.WithLabelValues(tenantID.String()).Inc()
			s.logger.Info("template source synced",
				"source_id", source.ID.String(),
				"source_name", source.Name,
				"templates_found", result.TemplatesFound,
				"templates_added", result.TemplatesAdded)
		} else {
			metrics.TemplateSyncsFailedTotal.WithLabelValues(tenantID.String()).Inc()
		}
	}

	if len(syncErrors) > 0 {
		return fmt.Errorf("some syncs failed: %v", syncErrors)
	}

	return nil
}

// shouldUsePlatformAgent determines whether to route this scan to platform agents.
func (s *Service) shouldUsePlatformAgent(ctx context.Context, sc *scan.Scan) (bool, error) {
	// If explicitly set to tenant only, never use platform
	if sc.RunOnTenantRunner || sc.AgentPreference == scan.AgentPreferenceTenant {
		return false, nil
	}

	// If explicitly set to platform only, always use platform
	if sc.AgentPreference == scan.AgentPreferencePlatform {
		// Check if tenant can use platform agents
		if s.agentSelector != nil {
			canUse, reason := s.agentSelector.CanUsePlatformAgents(ctx, sc.TenantID)
			if !canUse {
				return false, fmt.Errorf("platform agents not available: %s", reason)
			}
		}
		return true, nil
	}

	// For "auto" mode, use AgentSelector to determine
	if s.agentSelector != nil {
		result, err := s.agentSelector.SelectAgent(ctx, SelectAgentRequest{
			TenantID:     sc.TenantID,
			Capabilities: []string{sc.ScannerName},
			Tool:         sc.ScannerName,
			Mode:         SelectTenantFirst,
			AllowQueue:   true,
		})
		if err != nil {
			return false, err
		}

		// If no tenant agent available, use platform if allowed
		if result.Agent == nil || result.IsPlatform {
			return true, nil
		}
	}

	return false, nil
}

// calculateInitialPriority calculates the initial queue priority for a platform job.
func (s *Service) calculateInitialPriority(priority command.CommandPriority) int {
	switch priority {
	case command.CommandPriorityCritical:
		return 1000
	case command.CommandPriorityHigh:
		return 750
	case command.CommandPriorityNormal:
		return 500
	case command.CommandPriorityLow:
		return 250
	default:
		return 500
	}
}

// validateToolsAtTriggerTime validates that all tools required by the scan are still available.
// This catches cases where tools have been disabled or removed between scan creation and trigger.
func (s *Service) validateToolsAtTriggerTime(ctx context.Context, sc *scan.Scan) error {
	switch sc.ScanType {
	case scan.ScanTypeSingle:
		return s.validateSingleScanTool(ctx, sc.ScannerName)
	case scan.ScanTypeWorkflow:
		return s.validateWorkflowStepTools(ctx, sc)
	}
	return nil
}

// validateSingleScanTool checks that the scanner tool is available and active.
func (s *Service) validateSingleScanTool(ctx context.Context, scannerName string) error {
	if scannerName == "" {
		return nil
	}

	tool, err := s.toolRepo.GetByName(ctx, scannerName)
	if err != nil {
		return shared.NewDomainError(
			"TOOL_NOT_FOUND",
			fmt.Sprintf("Scanner '%s' is no longer available. Please update scan configuration.", scannerName),
			shared.ErrValidation,
		)
	}
	if !tool.IsActive {
		return shared.NewDomainError(
			"TOOL_DISABLED",
			fmt.Sprintf("Scanner '%s' is currently disabled. Please enable it or use a different scanner.", scannerName),
			shared.ErrValidation,
		)
	}

	return nil
}

// validateWorkflowStepTools validates all tools required by workflow pipeline steps.
func (s *Service) validateWorkflowStepTools(ctx context.Context, sc *scan.Scan) error {
	if sc.PipelineID == nil {
		return shared.NewDomainError(
			"PIPELINE_NOT_SET",
			"Workflow scan has no pipeline configured",
			shared.ErrValidation,
		)
	}

	steps, err := s.stepRepo.GetByPipelineID(ctx, *sc.PipelineID)
	if err != nil {
		return fmt.Errorf("failed to get pipeline steps: %w", err)
	}

	for _, step := range steps {
		if err := s.validateStepTool(ctx, sc.TenantID, step); err != nil {
			return err
		}
	}

	return nil
}

// validateStepTool validates a single pipeline step's tool configuration.
func (s *Service) validateStepTool(ctx context.Context, tenantID shared.ID, step *pipeline.Step) error {
	switch {
	case step.Tool != "":
		tool, err := s.toolRepo.GetByName(ctx, step.Tool)
		if err != nil {
			return shared.NewDomainError(
				"TOOL_NOT_FOUND",
				fmt.Sprintf("Tool '%s' used by step '%s' is no longer available. Please update the pipeline.", step.Tool, step.StepKey),
				shared.ErrValidation,
			)
		}
		if !tool.IsActive {
			return shared.NewDomainError(
				"TOOL_DISABLED",
				fmt.Sprintf("Tool '%s' used by step '%s' is currently disabled. Please enable it or use a different tool.", step.Tool, step.StepKey),
				shared.ErrValidation,
			)
		}
	case len(step.Capabilities) > 0:
		matchingTool, err := s.toolRepo.FindByCapabilities(ctx, tenantID, step.Capabilities)
		if err != nil || matchingTool == nil {
			return shared.NewDomainError(
				"NO_MATCHING_TOOL",
				fmt.Sprintf("No active tool found for step '%s' with capabilities %v. Please configure a tool for this step.", step.StepKey, step.Capabilities),
				shared.ErrValidation,
			)
		}
		if !matchingTool.IsActive {
			return shared.NewDomainError(
				"TOOL_DISABLED",
				fmt.Sprintf("Tool '%s' matching step '%s' capabilities is disabled.", matchingTool.Name, step.StepKey),
				shared.ErrValidation,
			)
		}
	default:
		return shared.NewDomainError(
			"STEP_INVALID",
			fmt.Sprintf("Step '%s' has no tool or capabilities configured. Please edit the pipeline and configure a scanner for this step.", step.StepKey),
			shared.ErrValidation,
		)
	}

	return nil
}

// filterAssetsForSingleScan applies smart filtering based on scanner-asset compatibility.
// Returns FilteringResult showing which assets will be scanned vs skipped.
func (s *Service) filterAssetsForSingleScan(ctx context.Context, sc *scan.Scan) (*FilteringResult, error) {
	// Skip if no target mapping repo configured
	if s.targetMappingRepo == nil {
		return nil, nil
	}

	// Get scanner tool to check supported targets
	scannerTool, err := s.toolRepo.GetByName(ctx, sc.ScannerName)
	if err != nil {
		return nil, fmt.Errorf("get scanner tool: %w", err)
	}

	// If tool has no supported targets defined, scan all assets (no filtering)
	if len(scannerTool.SupportedTargets) == 0 {
		return nil, nil
	}

	// Get asset type counts from asset group
	assetTypeCounts, err := s.assetGroupRepo.CountAssetsByType(ctx, sc.AssetGroupID)
	if err != nil {
		return nil, fmt.Errorf("count assets by type: %w", err)
	}

	if len(assetTypeCounts) == 0 {
		return nil, nil
	}

	// Create filter service and apply filtering
	filterService := NewAssetFilterService(s.targetMappingRepo, s.assetGroupRepo)
	result, err := filterService.FilterAssetsForScan(ctx, scannerTool.SupportedTargets, scannerTool.Name, assetTypeCounts)
	if err != nil {
		return nil, fmt.Errorf("filter assets: %w", err)
	}

	return result, nil
}

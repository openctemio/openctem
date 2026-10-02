package scan

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/openctemio/openctem/api/internal/app/scope"
	"github.com/openctemio/openctem/api/internal/metrics"
	"github.com/openctemio/openctem/api/pkg/domain/audit"
	"github.com/openctemio/openctem/api/pkg/domain/command"
	"github.com/openctemio/openctem/api/pkg/domain/pipeline"
	"github.com/openctemio/openctem/api/pkg/domain/scan"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/pagination"
	"github.com/openctemio/openctem/api/pkg/sensorproto/legacyv1"
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
		// Give the user a specific, actionable error message based on the current state.
		var msg string
		switch sc.Status {
		case scan.StatusPaused:
			msg = fmt.Sprintf("Cannot trigger scan '%s' because it is paused. Resume the scan first to trigger it.", sc.Name)
		case scan.StatusDisabled:
			msg = fmt.Sprintf("Cannot trigger scan '%s' because it is disabled. Activate the scan first to trigger it.", sc.Name)
		default:
			msg = fmt.Sprintf("Cannot trigger scan '%s' (current status: %s). Only active scans can be triggered.", sc.Name, sc.Status)
		}
		return nil, shared.NewDomainError("SCAN_NOT_TRIGGERABLE", msg, shared.ErrValidation)
	}

	// NOTE: Concurrent run limits are now checked atomically in CreateRunIfUnderLimit
	// to prevent race conditions where multiple triggers bypass the limit.

	// Validate tools are still available and active before triggering
	// (Tools may have been disabled or removed since scan was created)
	if err := s.validateToolsAtTriggerTime(ctx, sc); err != nil {
		return nil, err
	}

	// Check sensor availability before triggering - must have an online sensor
	toolToCheck := ""
	if sc.ScanType == scan.ScanTypeSingle && sc.ScannerName != "" {
		toolToCheck = sc.ScannerName
	}
	sensorAvail := s.sensorSelector.CheckSensorAvailability(ctx, sc.TenantID, toolToCheck, sc.RunOnTenantRunner)
	if !sensorAvail.Available {
		return nil, shared.NewDomainError(
			"NO_SENSOR_AVAILABLE",
			sensorAvail.Message,
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
	// Resolve the targets server-side (direct targets + asset-group members,
	// minus scope exclusions) and carry them to the step commands; sensors do
	// not resolve asset groups, so without this a group scan scans nothing.
	resolved, err := s.resolveScanTargets(ctx, sc)
	if err != nil {
		return nil, err
	}
	if err := recordResolvedTargets(sc, resolved, runContext); err != nil {
		return nil, err
	}
	targets := resolved.Targets
	zones, err := s.loadZones(ctx, sc.TenantID)
	if err != nil {
		return nil, err
	}
	if _, err := selectedZone(sc, zones); err != nil {
		return nil, err // pinned to a deleted zone: fail closed
	}
	if len(zones) > 0 {
		// A workflow stays inside one zone; see routeWorkflowTargets.
		if targets, err = s.routeWorkflowTargets(ctx, sc, zones, targets, runContext); err != nil {
			return nil, err
		}
	}
	if len(targets) > 0 {
		runContext["targets"] = targets
	}

	// Create pipeline run
	run, err := pipeline.NewRun(template.ID, sc.TenantID, nil, pipeline.TriggerTypeManual, triggeredBy, runContext)
	if err != nil {
		return nil, fmt.Errorf("failed to create pipeline run: %w", err)
	}
	run.SetTotalSteps(len(steps))
	run.ScanID = &sc.ID // Link run to scan for concurrent limit tracking
	if sc.ProfileID != nil {
		run.ScanProfileID = sc.ProfileID // Propagate scan profile for quality gate evaluation
	}

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

	// Resolve what this run actually scans, server-side: direct targets plus
	// asset-group members, minus scope exclusions (fail closed).
	resolved, err := s.resolveScanTargets(ctx, sc)
	if err != nil {
		return nil, err
	}
	if err := recordResolvedTargets(sc, resolved, runContext); err != nil {
		return nil, err
	}

	// Scan zones (RFC-023): once the tenant has zones, a network scanner's
	// targets are routed to the narrowest zone, batched, and pinned to a
	// healthy sensor of that zone. Without zones nothing below changes.
	zones, err := s.loadZones(ctx, sc.TenantID)
	if err != nil {
		return nil, err
	}
	if _, err := selectedZone(sc, zones); err != nil {
		return nil, err // pinned to a deleted zone: fail closed
	}
	var plan *zonePlan
	if len(zones) > 0 && s.toolReachesNetwork(ctx, sc.ScannerName) {
		if plan, err = s.planZoneDispatch(ctx, sc, zones, resolved.Targets); err != nil {
			return nil, err
		}
		if err := recordZonePlan(sc, plan, runContext); err != nil {
			return nil, err
		}
	}

	// Decide platform vs tenant sensors now, before any run or command
	// exists: an explicit 'platform' preference that cannot be honored
	// refuses the trigger instead of quietly becoming a tenant job (RFC-023
	// D14). The decision is recorded in the run.
	routing, err := s.decideSensorRouting(ctx, sc, resolved.Targets, plan)
	if err != nil {
		return nil, err
	}
	routing.record(runContext)

	// Outside zones too, a scanner that reads one target per job gets one
	// command per target, not one command that scans only the first.
	if plan == nil {
		if plan, err = perTargetPlan(sc, resolved.Targets); err != nil {
			return nil, err
		}
		if plan != nil {
			recordPerTargetPlan(plan, runContext)
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
	if sc.ProfileID != nil {
		run.ScanProfileID = sc.ProfileID // Propagate scan profile for quality gate evaluation
	}

	// Atomically check concurrent limits and create run to prevent race conditions
	if err := s.runRepo.CreateRunIfUnderLimit(ctx, run, MaxConcurrentRunsPerScan, MaxConcurrentRunsPerTenant); err != nil {
		return nil, err // Error already includes proper domain error for limit exceeded
	}

	// A single scan still needs a step run. The completion machinery
	// (OnStepCompleted / OnStepFailed) works by looking the step up on the run
	// by step_key; a run with no step rows can never be advanced, so before
	// this it could only ever end by being reaped as a timeout — including when
	// the scanner had reported a real, specific error.
	stepRun := s.createSingleScanStepRun(ctx, run)

	// Create the command(s) for the scanner
	if plan != nil {
		err = s.createZoneCommands(ctx, sc, run, stepRun, plan, routing.usePlatform())
	} else {
		err = s.createScannerCommand(ctx, sc, run, stepRun, resolved.Targets, routing.usePlatform())
	}
	if err != nil {
		run.Fail("Failed to create command: " + err.Error())
		_ = s.runRepo.Update(ctx, run)
		return nil, fmt.Errorf("failed to create scanner command: %w", err)
	}

	return run, nil
}

// createSingleScanStepRun creates the one step run that tracks a single-scanner
// execution, using the quick-scan template's seeded step.
//
// Returns nil when the step cannot be resolved or stored. That is not fatal —
// the scan itself still dispatches — but the run then has no step to complete,
// so it falls back to being reaped by MarkTimedOutRuns. The warning is the
// signal that the seeded template is missing.
func (s *Service) createSingleScanStepRun(ctx context.Context, run *pipeline.Run) *pipeline.StepRun {
	steps, err := s.stepRepo.GetByPipelineID(ctx, run.PipelineID)
	if err != nil || len(steps) == 0 {
		s.logger.Warn("quick scan template has no steps; run cannot report completion",
			"run_id", run.ID.String(), "pipeline_id", run.PipelineID.String(), "error", err)
		return nil
	}

	// steps[0] is the lowest step_order: GetByPipelineID sorts ASC. A single
	// scan dispatches one scanner command, so one step run is what completion
	// is measured against — matching the SetTotalSteps(1) above.
	step := steps[0]
	stepRun := pipeline.NewStepRun(run.ID, step.ID, step.StepKey, step.StepOrder, step.MaxRetries)
	if err := s.stepRunRepo.Create(ctx, stepRun); err != nil {
		s.logger.Warn("failed to create step run for single scan",
			"run_id", run.ID.String(), "error", err)
		return nil
	}
	run.AddStepRun(stepRun)
	return stepRun
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
	payloadMap := map[string]any{
		pipeline.PayloadKeyPipelineRunID: run.ID.String(),
		pipeline.PayloadKeyStepRunID:     stepRunID,
		pipeline.PayloadKeyStepKey:       step.StepKey,
		"step_id":                        step.ID.String(),
		"step_config":                    step.Config,
		"required_capabilities":          step.Capabilities,
		"preferred_tool":                 step.Tool,
		"timeout_seconds":                step.TimeoutSeconds,
		"context":                        run.Context,
	}
	// Surface direct targets at the top level of the payload — sensor executors
	// read job.Payload["targets"], not the nested run context. Without this a
	// workflow driven by ad-hoc targets (QuickScan) would receive none.
	if targets, ok := run.Context["targets"]; ok {
		payloadMap["targets"] = targets
	}
	payload, _ := json.Marshal(payloadMap)

	cmd, err := command.NewCommand(run.TenantID, command.CommandTypeScan, command.CommandPriorityNormal, payload)
	if err != nil {
		return fmt.Errorf("failed to create command: %w", err)
	}
	if zoneID := pipeline.ScanZoneFromContext(run.Context); zoneID != nil {
		cmd.SetScanZone(*zoneID) // only the zone's sensors may claim it
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
// This is the format sent to sensors for custom templates.
type EmbeddedTemplate struct {
	ID           string `json:"id"`
	Name         string `json:"name"`
	TemplateType string `json:"template_type"`
	Content      string `json:"content"`      // Base64 encoded content
	ContentHash  string `json:"content_hash"` // SHA256 hash for verification
}

// createScannerCommand creates a command for a single scanner execution.
// Uses SensorSelector to determine whether to use tenant or platform sensors.
//
// stepRun may be nil — see createSingleScanStepRun. When it is present the
// payload carries the keys the command handler needs to report the step back
// (`pipeline_run_id`, `step_key`, `step_run_id`); `run_id` is kept because the
// sensor SDK reads it.
func (s *Service) createScannerCommand(ctx context.Context, sc *scan.Scan, run *pipeline.Run, stepRun *pipeline.StepRun, targets []string, usePlatform bool) error {
	templates := s.customTemplatesForScan(ctx, sc)
	payloadMap := s.scannerPayload(sc, run, stepRun, sc.ScannerConfig, run.Context, targets, templates)
	payload, _ := json.Marshal(payloadMap)

	cmd, err := command.NewCommand(sc.TenantID, command.CommandTypeScan, command.CommandPriorityNormal, payload)
	if err != nil {
		return err
	}

	// usePlatform was decided before the run was created (decideSensorRouting).
	if usePlatform {
		// Calculate initial queue priority based on command priority
		initialPriority := s.calculateInitialPriority(cmd.Priority)
		cmd.SetPlatformJob(initialPriority)
	}

	if err := s.commandRepo.Create(ctx, cmd); err != nil {
		return err
	}

	// Link the step run to the command it is waiting on, matching the workflow
	// path. Without the link a step stays 'pending' forever in the UI even
	// after the command has been dispatched.
	if stepRun != nil {
		stepRun.CommandID = &cmd.ID
		stepRun.Queue()
		if err := s.stepRunRepo.Update(ctx, stepRun); err != nil {
			s.logger.Warn("failed to link step run to command",
				"run_id", run.ID.String(), "command_id", cmd.ID.String(), "error", err)
		}
	}

	return nil
}

// scannerPayload builds the protocol-v1 payload of a single-scanner command.
func (s *Service) scannerPayload(
	sc *scan.Scan, run *pipeline.Run, stepRun *pipeline.StepRun,
	scannerConfig map[string]any, runContext map[string]any,
	targets []string, templates []EmbeddedTemplate,
) map[string]any {
	payloadMap := map[string]any{
		"run_id":                            run.ID.String(),
		"scan_id":                           sc.ID.String(),
		"scanner_name":                      sc.ScannerName,
		"scanner_config":                    scannerConfig,
		"asset_group_id":                    sc.AssetGroupID.String(),
		"targets_per_job":                   sc.TargetsPerJob,
		"routing_tags":                      sc.Tags,
		"tenant_runner_only":                sc.RunOnTenantRunner,
		legacyv1.PayloadKeySensorPreference: string(sc.SensorPreference),
		"context":                           runContext,
		// The sensor SDK (ScanCommandPayload) reads `scanner`, `config` and a
		// single `target`, not `scanner_name`/`scanner_config` — send both sets
		// so the command dispatches correctly (contract drift previously left
		// the sensor with an empty scanner: "scanner not found").
		"scanner": sc.ScannerName,
		"config":  scannerConfig,
	}
	// The command handler reads `pipeline_run_id` + `step_key` to route a
	// finished command back into the pipeline; a payload carrying only `run_id`
	// is silently treated as "not a pipeline command" and the run is never
	// advanced, completed, or failed.
	if stepRun != nil {
		payloadMap[pipeline.PayloadKeyPipelineRunID] = run.ID.String()
		payloadMap[pipeline.PayloadKeyStepKey] = stepRun.StepKey
		payloadMap[pipeline.PayloadKeyStepRunID] = stepRun.ID.String()
	}
	applyTargetsToPayload(payloadMap, sc.ScannerName, targets)
	if len(templates) > 0 {
		payloadMap["custom_templates"] = templates
	}
	return payloadMap
}

// customTemplatesForScan resolves the scan's custom templates once per run.
// A failure is logged and the scan proceeds without them.
func (s *Service) customTemplatesForScan(ctx context.Context, sc *scan.Scan) []EmbeddedTemplate {
	templates, err := s.resolveCustomTemplates(ctx, sc)
	if err != nil {
		s.logger.Warn("failed to resolve custom templates, proceeding without them",
			"error", err, "scan_id", sc.ID.String())
		return nil
	}
	if len(templates) > 0 {
		s.logger.Info("embedded custom templates in scan command",
			"scan_id", sc.ID.String(),
			"template_count", len(templates))
	}
	return templates
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

const (
	sensorRoutingTenant   = "tenant"
	sensorRoutingPlatform = "platform"

	runContextKeySensorRouting = "sensor_routing"
)

// sensorRouting is the trigger-time decision between tenant and shared
// platform sensors, and why.
type sensorRouting struct {
	Routing string // sensorRoutingTenant or sensorRoutingPlatform
	Warning string // set when the decision was not the one asked for
}

func (r sensorRouting) usePlatform() bool { return r.Routing == sensorRoutingPlatform }

// record writes the decision into the run context (shown as the run's
// dispatch.sensor_routing, with any warning in dispatch.warnings).
func (r sensorRouting) record(runContext map[string]any) {
	runContext[runContextKeySensorRouting] = r.Routing
	if r.Warning == "" {
		return
	}
	warnings, _ := runContext["dispatch_warnings"].([]string)
	runContext["dispatch_warnings"] = append(warnings, r.Warning)
}

// decideSensorRouting decides once, before the run is created, whether the
// scan's commands go to shared platform sensors. Nothing falls back silently
// (RFC-023 D14): an explicit 'platform' preference that cannot be honored —
// internal targets, asset groups, or a tenant without platform access — is
// returned as a validation error and the trigger is refused. In 'auto' mode
// a failed sensor lookup keeps the job on tenant sensors (where auto mode
// starts anyway) and says so in the run.
//
// With a zone plan only the unzoned batches can go to platform sensors; zoned
// targets stay on their zone's sensors, so an explicit 'platform' preference
// with any zoned target is refused as well.
func (s *Service) decideSensorRouting(ctx context.Context, sc *scan.Scan, targets []string, plan *zonePlan) (sensorRouting, error) {
	if plan != nil {
		targets = targets[:0:0]
		for _, b := range plan.Batches {
			if b.Zone != nil {
				if sc.SensorPreference == scan.SensorPreferencePlatform {
					return sensorRouting{}, shared.NewDomainError("PLATFORM_SENSOR_REFUSED", fmt.Sprintf(
						"sensor_preference is 'platform', but target(s) of scan %q are inside scan zone %q and are scanned only by that zone's sensors; set sensor_preference to 'tenant' or 'auto'",
						sc.Name, b.Zone.Name), shared.ErrValidation)
				}
				continue
			}
			targets = append(targets, b.Targets...)
		}
	}
	usePlatform, err := s.shouldUsePlatformSensor(ctx, sc, targets)
	if err != nil {
		if sc.SensorPreference == scan.SensorPreferencePlatform {
			return sensorRouting{}, err
		}
		s.logger.Warn("sensor selection failed; job queued for tenant sensors",
			"error", err, "scan_id", sc.ID.String())
		return sensorRouting{
			Routing: sensorRoutingTenant,
			Warning: "sensor selection failed; the job is queued for tenant sensors only",
		}, nil
	}
	if usePlatform {
		return sensorRouting{Routing: sensorRoutingPlatform}, nil
	}
	return sensorRouting{Routing: sensorRoutingTenant}, nil
}

// shouldUsePlatformSensor determines whether to route this scan to shared
// platform sensors. Shared infrastructure must never receive a tenant's
// internal targets or asset groups, and is only used when the tenant may use
// it: in auto mode a busy tenant fleet means the job waits for a tenant sensor,
// it is not silently moved to shared sensors (RFC-023 D14).
func (s *Service) shouldUsePlatformSensor(ctx context.Context, sc *scan.Scan, targets []string) (bool, error) {
	// If explicitly set to tenant only, never use platform
	if sc.RunOnTenantRunner || sc.SensorPreference == scan.SensorPreferenceTenant {
		return false, nil
	}
	internal := sc.HasAssetGroup() || hasInternalTarget(targets)

	// If explicitly set to platform only, the tenant must be allowed and the
	// targets must be public.
	if sc.SensorPreference == scan.SensorPreferencePlatform {
		if internal {
			return false, shared.NewDomainError("PLATFORM_SENSOR_REFUSED",
				"sensor_preference is 'platform', but shared platform sensors never scan asset groups or internal targets; set sensor_preference to 'tenant' or 'auto', or scan only public targets",
				shared.ErrValidation)
		}
		if s.sensorSelector != nil {
			canUse, reason := s.sensorSelector.CanUsePlatformSensors(ctx, sc.TenantID)
			if !canUse {
				return false, shared.NewDomainError("PLATFORM_SENSOR_REFUSED",
					fmt.Sprintf("sensor_preference is 'platform', but platform sensors are not available to this tenant: %s", reason),
					shared.ErrValidation)
			}
		}
		return true, nil
	}

	// Auto: tenant sensors first. Shared sensors only if the tenant may use them
	// and nothing in the scan is internal; otherwise the job waits.
	if s.sensorSelector == nil || internal {
		return false, nil
	}
	result, err := s.sensorSelector.SelectSensor(ctx, SelectSensorRequest{
		TenantID:     sc.TenantID,
		Capabilities: []string{sc.ScannerName},
		Tool:         sc.ScannerName,
		Mode:         SelectTenantFirst,
		AllowQueue:   true,
	})
	if err != nil {
		return false, err
	}
	if (result.Sensor != nil && !result.IsPlatform) || result.TenantBusy {
		return false, nil
	}
	canUse, _ := s.sensorSelector.CanUsePlatformSensors(ctx, sc.TenantID)
	return canUse, nil
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

// recordResolvedTargets stores what the run will scan in its context (counts
// and warnings, not the list itself), and refuses a run that would scan
// nothing: every target excluded by scope, or no target at all (an empty
// asset group and no direct targets). A command with no targets is never
// dispatched.
func recordResolvedTargets(sc *scan.Scan, r *resolvedTargets, runContext map[string]any) error {
	runContext["resolved_target_count"] = len(r.Targets)
	if r.Excluded > 0 {
		runContext["excluded_target_count"] = r.Excluded
	}
	if len(r.Warnings) > 0 {
		runContext["dispatch_warnings"] = r.Warnings
	}
	if r.Unconfirmed > 0 {
		runContext["unconfirmed_target_count"] = r.Unconfirmed
	}
	if len(r.Targets) == 0 && r.Unconfirmed > 0 && r.Excluded == 0 {
		return shared.NewDomainError("ALL_TARGETS_UNCONFIRMED",
			fmt.Sprintf("Every target of scan %q is an asset whose ownership is not confirmed yet; nothing to scan. Review their attribution first.", sc.Name),
			shared.ErrValidation)
	}
	if len(r.Targets) == 0 && r.Excluded > 0 {
		return shared.NewDomainError("ALL_TARGETS_EXCLUDED",
			fmt.Sprintf("Every target of scan %q is excluded by scope; nothing to scan.", sc.Name),
			shared.ErrValidation)
	}
	if len(r.Targets) == 0 {
		msg := fmt.Sprintf("Scan %q resolves to no targets: it has no direct targets and its asset group(s) have no assets. Add assets to the group or targets to the scan.", sc.Name)
		if len(r.Warnings) > 0 {
			msg += " (" + strings.Join(r.Warnings, "; ") + ")"
		}
		return shared.NewDomainError("NO_TARGETS", msg, shared.ErrValidation)
	}
	return nil
}

// listGroupExclusionCandidates materializes an asset group's members into scope
// exclusion candidates (id + name). Paginated to keep memory bounded.
func (s *Service) listGroupExclusionCandidates(ctx context.Context, groupID shared.ID) ([]scope.ExclusionCandidate, error) {
	const perPage = 500
	page := pagination.New(1, perPage)
	candidates := make([]scope.ExclusionCandidate, 0)

	for {
		res, err := s.assetGroupRepo.GetGroupAssets(ctx, groupID, page, nil)
		if err != nil {
			return nil, err
		}
		for _, ga := range res.Data {
			candidates = append(candidates, scope.ExclusionCandidate{
				ID:     ga.ID,
				Values: []string{ga.Name},
			})
		}
		if len(res.Data) == 0 || int64(page.Page*perPage) >= res.Total {
			break
		}
		page.Page++
	}
	return candidates, nil
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

	// Get asset type counts across every asset group of the scan
	assetTypeCounts := map[string]int64{}
	listed := map[shared.ID]bool{}
	for _, groupID := range sc.GetAllAssetGroupIDs() {
		if listed[groupID] {
			continue
		}
		listed[groupID] = true
		counts, err := s.assetGroupRepo.CountAssetsByType(ctx, groupID)
		if err != nil {
			return nil, fmt.Errorf("count assets by type: %w", err)
		}
		for t, n := range counts {
			assetTypeCounts[t] += n
		}
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

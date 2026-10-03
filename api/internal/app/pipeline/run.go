package pipeline

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/openctemio/openctem/api/internal/metrics"
	"github.com/openctemio/openctem/api/pkg/domain/audit"
	"github.com/openctemio/openctem/api/pkg/domain/command"
	"github.com/openctemio/openctem/api/pkg/domain/pipeline"
	"github.com/openctemio/openctem/api/pkg/domain/scanprofile"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/pagination"
	"github.com/openctemio/openctem/api/pkg/sensorproto/legacyv1"
)

// ========== Run Operations (Orchestration) ==========

// TriggerPipelineInput represents the input for triggering a pipeline.
type TriggerPipelineInput struct {
	TenantID    string         `json:"tenant_id" validate:"required,uuid"`
	TemplateID  string         `json:"template_id" validate:"required,uuid"`
	AssetID     string         `json:"asset_id" validate:"omitempty,uuid"`
	TriggerType string         `json:"trigger_type" validate:"omitempty,oneof=manual schedule webhook api"`
	TriggeredBy string         `json:"triggered_by"`
	Context     map[string]any `json:"context"`
}

// TriggerPipeline starts a new pipeline run.
// Uses atomic CreateRunIfUnderLimit to prevent race conditions in concurrent run limits.
// If the template is a system template, it will be auto-cloned for the tenant first.
func (s *Service) TriggerPipeline(ctx context.Context, input TriggerPipelineInput) (*pipeline.Run, error) {
	s.logger.Info("triggering pipeline", "template_id", input.TemplateID)

	// Get template with steps
	template, err := s.GetTemplateWithSteps(ctx, input.TemplateID)
	if err != nil {
		return nil, err
	}

	// SECURITY: GetTemplateWithSteps loads by ID without tenant scoping, so we
	// must verify the caller may use this template before triggering it.
	// A template is usable iff it is a system template (shared, auto-cloned
	// below) or it belongs to the caller's tenant. Without this check a user
	// could trigger another tenant's private pipeline by guessing its ID.
	if !template.IsSystemTemplate && template.TenantID.String() != input.TenantID {
		s.logger.Warn("SECURITY: cross-tenant pipeline trigger attempt",
			"template_id", template.ID.String(),
			"template_tenant_id", template.TenantID.String(),
			"caller_tenant_id", input.TenantID)
		return nil, shared.ErrNotFound
	}

	// Handle system templates: auto-clone for the tenant
	// System templates cannot be triggered directly - they must be cloned first
	// to ensure proper tenant isolation and tracking
	if template.IsSystemTemplate {
		s.logger.Info("triggering system template - checking for existing clone",
			"system_template_id", template.ID.String(),
			"tenant_id", input.TenantID)

		tenantUUID, _ := shared.IDFromString(input.TenantID)

		// Check if tenant already has a clone of this system template
		// Look for a template with the same name (system templates use consistent names)
		existingClone, err := s.templateRepo.GetByName(ctx, tenantUUID, template.Name, template.Version)
		if err == nil && existingClone != nil && !existingClone.IsSystemTemplate {
			// Found existing clone - use it
			s.logger.Info("using existing clone of system template",
				"clone_id", existingClone.ID.String(),
				"system_template_id", template.ID.String())

			// Get clone with steps
			template, err = s.templateRepo.GetWithSteps(ctx, existingClone.ID)
			if err != nil {
				return nil, fmt.Errorf("failed to get cloned template with steps: %w", err)
			}

			// SECURITY: Validate tools for existing clone too
			// Tools may have been disabled/removed since the clone was created
			if err := s.ValidateToolReferences(ctx, template, tenantUUID); err != nil {
				return nil, fmt.Errorf("cloned template uses unavailable tools: %w", err)
			}
		} else {
			// No existing clone - validate tools BEFORE cloning to avoid creating orphan clones
			s.logger.Info("validating system template tools before cloning",
				"system_template_id", template.ID.String())

			if err := s.ValidateToolReferences(ctx, template, tenantUUID); err != nil {
				return nil, fmt.Errorf("system template uses unavailable tools: %w", err)
			}

			// Create clone
			s.logger.Info("auto-cloning system template for trigger",
				"system_template_id", template.ID.String())

			cloneInput := CloneSystemTemplateInput{
				TenantID:         input.TenantID,
				SystemTemplateID: input.TemplateID,
				NewName:          template.Name, // Keep same name
			}

			clonedTemplate, err := s.CloneSystemTemplate(ctx, cloneInput)
			if err != nil {
				return nil, fmt.Errorf("failed to clone system template: %w", err)
			}

			template = clonedTemplate
			s.logger.Info("created new clone for system template",
				"cloned_template_id", template.ID.String())
		}
	}

	// Verify template is active
	if !template.IsActive {
		return nil, shared.NewDomainError("INACTIVE", "pipeline template is not active", shared.ErrValidation)
	}

	// Validate steps
	if err := template.ValidateSteps(); err != nil {
		return nil, err
	}

	tenantID, _ := shared.IDFromString(input.TenantID)

	// Validate tool references - ensure all required tools are available and active
	if err := s.ValidateToolReferences(ctx, template, tenantID); err != nil {
		s.logger.Warn("pipeline tool validation failed",
			"template_id", template.ID.String(),
			"error", err)
		return nil, err
	}

	var assetID *shared.ID
	if input.AssetID != "" {
		aid, err := shared.IDFromString(input.AssetID)
		if err == nil {
			assetID = &aid
		}
	}

	triggerType := pipeline.TriggerType(input.TriggerType)
	if triggerType == "" {
		triggerType = pipeline.TriggerTypeManual
	}

	// The run's targets reach every step command; check them the way a scan
	// trigger does (private-range policy, scope exclusions, scan zones).
	runContext, err := s.gateRunContext(ctx, tenantID, input.Context)
	if err != nil {
		s.logger.Warn("pipeline run refused by the target gate",
			"template_id", template.ID.String(), "error", err)
		return nil, err
	}

	// Create pipeline run
	run, err := pipeline.NewRun(template.ID, tenantID, assetID, triggerType, input.TriggeredBy, runContext)
	if err != nil {
		return nil, err
	}
	run.SetTotalSteps(len(template.Steps))

	// FIXED: Use atomic CreateRunIfUnderLimit to prevent race conditions
	// This atomically checks concurrent run limits AND creates the run in a single transaction.
	// Previously, the check-then-create pattern allowed race conditions where multiple
	// concurrent triggers could bypass the limits.
	if err := s.runRepo.CreateRunIfUnderLimit(ctx, run, MaxConcurrentRunsPerPipeline, MaxConcurrentRunsPerTenant); err != nil {
		return nil, err
	}

	// Create step runs
	for _, step := range template.Steps {
		stepRun := pipeline.NewStepRun(run.ID, step.ID, step.StepKey, step.StepOrder, step.MaxRetries)
		if err := s.stepRunRepo.Create(ctx, stepRun); err != nil {
			return nil, err
		}
		run.AddStepRun(stepRun)
	}

	// Start the pipeline
	run.Start()
	if err := s.runRepo.Update(ctx, run); err != nil {
		return nil, err
	}

	// Record metrics
	metrics.PipelineRunsTotal.WithLabelValues(tenantID.String(), "running").Inc()
	metrics.PipelineRunsInProgress.WithLabelValues(tenantID.String()).Inc()

	// Schedule initial runnable steps (no dependencies)
	// This creates commands that sensors will poll and execute
	if err := s.scheduleRunnableSteps(ctx, run, template); err != nil {
		s.logger.Error("failed to schedule initial steps", "error", err)
	}

	// Audit log: pipeline triggered
	s.logAudit(ctx, AuditContext{TenantID: input.TenantID, ActorID: input.TriggeredBy},
		NewSuccessEvent(audit.ActionPipelineRunTriggered, audit.ResourceTypePipelineRun, run.ID.String()).
			WithResourceName(template.Name).
			WithMessage(fmt.Sprintf("Pipeline '%s' triggered", template.Name)).
			WithMetadata("trigger_type", string(triggerType)).
			WithMetadata("template_id", template.ID.String()))

	return run, nil
}

// scheduleRunnableSteps creates commands for steps that are ready to run.
// Sensors will poll these commands and execute them.
// Respects MaxParallelSteps setting to limit concurrent step execution.
func (s *Service) scheduleRunnableSteps(ctx context.Context, run *pipeline.Run, template *pipeline.Template) error {
	s.logger.Info("scheduling runnable steps", "run_id", run.ID.String())

	// Get completed step keys
	stepRuns, err := s.stepRunRepo.GetByPipelineRunID(ctx, run.ID)
	if err != nil {
		return err
	}

	// A dependency gates a step only by SUCCEEDING. Every terminal step used
	// to count as "completed" here, so a step whose dependency had failed
	// (or been skipped, or timed out) was queued anyway.
	succeededSteps := make(map[string]bool)
	runningSteps := 0
	for _, sr := range stepRuns {
		if sr.IsComplete() {
			if sr.IsSuccess() {
				succeededSteps[sr.StepKey] = true
			}
		} else if sr.IsRunning() || sr.IsQueued() {
			runningSteps++
		}
	}
	completedSteps := succeededSteps

	// Get max parallel steps from template settings (default 3)
	maxParallel := template.Settings.MaxParallelSteps
	if maxParallel <= 0 {
		maxParallel = 3
	}

	// Get runnable steps (no pending dependencies)
	runnableSteps := template.GetRunnableSteps(completedSteps)

	for _, step := range runnableSteps {
		// Check if we've reached the max parallel limit
		if runningSteps >= maxParallel {
			s.logger.Info("max parallel steps reached, skipping remaining",
				"run_id", run.ID.String(),
				"running", runningSteps,
				"max", maxParallel)
			break
		}
		stepRun := run.GetStepRun(step.StepKey)
		if stepRun == nil {
			// Get from DB if not loaded
			stepRun, err = s.stepRunRepo.GetByStepKey(ctx, run.ID, step.StepKey)
			if err != nil {
				continue
			}
		}

		// Skip if already processed
		if !stepRun.IsPending() {
			continue
		}

		// Evaluate condition
		shouldRun := s.evaluateCondition(ctx, step, run, template)
		stepRun.SetConditionResult(shouldRun)

		if !shouldRun {
			stepRun.Skip("Condition not met")
			// FIXED: Don't silently suppress errors - log them instead
			if err := s.stepRunRepo.Update(ctx, stepRun); err != nil {
				s.logger.Error("failed to update skipped step run", "step_key", step.StepKey, "error", err)
			}
			continue
		}

		// Queue the step - create a command that sensors can poll
		if err := s.queueStepForExecutionWithSettings(ctx, run, step, stepRun, template.Settings); err != nil {
			s.logger.Error("failed to queue step", "step_key", step.StepKey, "error", err)
			stepRun.Fail("Failed to queue: "+err.Error(), "QUEUE_ERROR")
			// FIXED: Don't silently suppress errors - log them instead
			if updateErr := s.stepRunRepo.Update(ctx, stepRun); updateErr != nil {
				s.logger.Error("failed to update failed step run", "step_key", step.StepKey, "error", updateErr)
			}
		} else {
			// Successfully queued, increment running count
			runningSteps++
		}
	}

	return nil
}

// queueStepForExecutionWithSettings creates a command with specific settings.
func (s *Service) queueStepForExecutionWithSettings(ctx context.Context, run *pipeline.Run, step *pipeline.Step, stepRun *pipeline.StepRun, settings pipeline.Settings) error {
	s.logger.Info("queueing step for execution", "step_key", step.StepKey, "tool", step.Tool, "sensor_preference", settings.SensorPreference)

	// Security validation: Last line of defense before sending to sensor
	if s.securityValidator != nil {
		result := s.securityValidator.ValidateStepConfig(ctx, run.TenantID, step.Tool, step.Capabilities, step.Config)
		if !result.Valid {
			s.logger.Error("SECURITY: step config validation failed at queue time",
				"run_id", run.ID.String(),
				"step_key", step.StepKey,
				"errors", result.Errors)
			return fmt.Errorf("security validation failed: %s", result.Errors[0].Message)
		}
	}

	payload, err := stepCommandPayload(run, step, stepRun, settings)
	if err != nil {
		return fmt.Errorf("step %s: %w", step.StepKey, err)
	}

	// Final payload validation before sending to sensor
	if s.securityValidator != nil {
		result := s.securityValidator.ValidateCommandPayload(ctx, run.TenantID, payload)
		if !result.Valid {
			s.logger.Error("SECURITY: command payload validation failed",
				"run_id", run.ID.String(),
				"step_key", step.StepKey,
				"errors", result.Errors)
			return fmt.Errorf("security validation failed: %s", result.Errors[0].Message)
		}
	}

	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	// Create command
	cmd, err := command.NewCommand(run.TenantID, command.CommandTypeScan, command.CommandPriorityNormal, payloadBytes)
	if err != nil {
		return err
	}

	// A run routed to a scan zone (RFC-023) keeps every step inside it: the
	// command is stamped with the zone and left to the zone's sensors (the
	// claim predicate enforces it), never pinned elsewhere or sent to
	// platform sensors.
	if zoneID := pipeline.ScanZoneFromContext(run.Context); zoneID != nil {
		cmd.SetScanZone(*zoneID)
		if err := s.commandRepo.Create(ctx, cmd); err != nil {
			return err
		}
		stepRun.Queue()
		stepRun.CommandID = &cmd.ID
		return s.stepRunRepo.Update(ctx, stepRun)
	}

	// Determine sensor routing based on preference
	usePlatform, sensorID := s.determineSensorRouting(ctx, run.TenantID, step.Tool, settings.SensorPreference)

	//nolint:gocritic // if-else chain is clearer than switch for bool+pointer conditions
	if usePlatform {
		// Route to platform sensors
		initialPriority := s.calculatePipelineInitialPriority(cmd.Priority)
		cmd.SetPlatformJob(initialPriority)
		s.logger.Info("routing step to platform sensors", "step_key", step.StepKey)
	} else if sensorID != nil {
		// Route to specific tenant sensor
		cmd.SetSensorID(*sensorID)
		s.logger.Info("routing step to tenant sensor", "step_key", step.StepKey, "sensor_id", sensorID.String())
	} else {
		// No specific sensor, command available to any tenant sensor
		s.logger.Info("no specific sensor assigned, command available to all tenant sensors", "step_key", step.StepKey)
	}

	if err := s.commandRepo.Create(ctx, cmd); err != nil {
		return err
	}

	// Mark step as queued
	stepRun.Queue()
	stepRun.CommandID = &cmd.ID
	return s.stepRunRepo.Update(ctx, stepRun)
}

// determineSensorRouting determines whether to use platform sensors and which specific sensor to use.
func (s *Service) determineSensorRouting(ctx context.Context, tenantID shared.ID, tool string, pref pipeline.SensorPreference) (usePlatform bool, sensorID *shared.ID) {
	// If explicitly set to tenant only, never use platform
	if pref == pipeline.SensorPreferenceTenant {
		// Try to find a tenant sensor with the required tool
		if tool != "" {
			foundSensor, err := s.sensorRepo.FindAvailableWithTool(ctx, tenantID, tool)
			if err == nil && foundSensor != nil {
				return false, &foundSensor.ID
			}
		}
		return false, nil
	}

	// If explicitly set to platform only, always use platform
	if pref == pipeline.SensorPreferencePlatform {
		// Check if tenant can use platform sensors
		if s.sensorSelector != nil {
			canUse, _ := s.sensorSelector.CanUsePlatformSensors(ctx, tenantID)
			if canUse {
				return true, nil
			}
		}
		// Fall through to try tenant sensors if platform not available
	}

	// For "auto" mode (or platform fallback), use SensorSelector if available
	if s.sensorSelector != nil {
		result, err := s.sensorSelector.SelectSensor(ctx, SelectSensorRequest{
			TenantID:     tenantID,
			Capabilities: []string{tool},
			Tool:         tool,
			Mode:         SelectTenantFirst,
			AllowQueue:   true,
		})
		if err == nil {
			if result.IsPlatform {
				return true, nil
			}
			if result.Sensor != nil {
				return false, &result.Sensor.ID
			}
		}
	}

	// Fallback: try to find tenant sensor
	if tool != "" {
		foundSensor, err := s.sensorRepo.FindAvailableWithTool(ctx, tenantID, tool)
		if err == nil && foundSensor != nil {
			return false, &foundSensor.ID
		}
	}

	return false, nil
}

// calculatePipelineInitialPriority calculates the initial queue priority for platform jobs.
func (s *Service) calculatePipelineInitialPriority(cmdPriority command.CommandPriority) int {
	switch cmdPriority {
	case command.CommandPriorityCritical:
		return 100
	case command.CommandPriorityHigh:
		return 75
	case command.CommandPriorityNormal:
		return 50
	case command.CommandPriorityLow:
		return 25
	default:
		return 50
	}
}

// refreshStepRuns reloads the run's step runs from the database. Two final
// steps of a workflow can finish at the same moment: each handler loaded the
// run before the other's step was saved, saw the other step still running,
// and neither finished the run, which then hung until the run timeout. Every
// step write is committed before this read, so the later of two concurrent
// handlers always sees both steps done (and finishRun lets only one of them
// record the outcome).
func (s *Service) refreshStepRuns(ctx context.Context, run *pipeline.Run) {
	fresh, err := s.stepRunRepo.GetByPipelineRunID(ctx, run.ID)
	if err != nil {
		s.logger.Error("failed to reload step runs; settling from the loaded copy",
			"run_id", run.ID.String(), "error", err)
		return
	}
	run.StepRuns = fresh
}

// skipBlockedSteps skips every pending step whose dependency finished without
// succeeding, transitively, so a failed step does not leave its dependents
// pending forever (the run could then never complete).
func (s *Service) skipBlockedSteps(ctx context.Context, run *pipeline.Run, template *pipeline.Template) {
	for changed := true; changed; {
		changed = false
		for _, step := range template.Steps {
			sr := run.GetStepRun(step.StepKey)
			if sr == nil || !sr.IsPending() {
				continue
			}
			dep := step.BlockedByDependency(run)
			if dep == "" {
				continue
			}
			sr.Skip(fmt.Sprintf("dependency %q did not succeed", dep))
			if err := s.stepRunRepo.Update(ctx, sr); err != nil {
				s.logger.Error("failed to skip blocked step", "step_key", step.StepKey, "error", err)
			}
			changed = true
		}
	}
}

// recordScanRun writes a pipeline run's terminal outcome back onto the scan that
// spawned it, so the scan's own last_run_at/last_run_status/counters stop
// reading "never run" after a run that just finished. No-op for workflow runs
// with no ScanID or when no recorder is wired; best-effort, since the run itself
// is already recorded and a scan-summary write must not fail the completion.
func (s *Service) recordScanRun(ctx context.Context, run *pipeline.Run, status string) {
	if s.scanRunRecorder == nil || run == nil || run.ScanID == nil {
		return
	}
	if err := s.scanRunRecorder.RecordRun(ctx, *run.ScanID, run.ID, status); err != nil {
		s.logger.Warn("failed to record run outcome on scan",
			"scan_id", run.ScanID.String(), "run_id", run.ID.String(), "status", status, "error", err)
	}
}

// finishRun moves the run to a terminal status. It reports whether THIS call
// made the transition: the repository refuses to move a run that already
// finished, so when two callers race (parallel final steps, a completion
// against a cancel or the timeout reaper) exactly one of them records the
// outcome on the scan, in metrics and in the audit log.
func (s *Service) finishRun(ctx context.Context, run *pipeline.Run, status pipeline.RunStatus, message string) bool {
	err := s.runRepo.UpdateStatus(ctx, run.ID, status, message)
	if errors.Is(err, pipeline.ErrRunAlreadyFinished) {
		s.logger.Info("run already finished; not recording it again",
			"run_id", run.ID.String(), "status", string(status))
		return false
	}
	if err != nil {
		s.logger.Error("failed to update run status", "run_id", run.ID.String(), "status", string(status), "error", err)
		return false
	}
	metrics.PipelineRunsInProgress.WithLabelValues(run.TenantID.String()).Dec()
	metrics.PipelineRunsTotal.WithLabelValues(run.TenantID.String(), string(status)).Inc()
	s.recordScanRun(ctx, run, string(status))
	return true
}

// OnStepStarted is called when a sensor starts the command of a step. The
// step run becomes running, with started_at and the sensor, so a run shows
// which step is executing and how long each step took. Before this nothing
// called it: a step went from queued straight to completed and its
// started_at stayed empty.
func (s *Service) OnStepStarted(ctx context.Context, runID, stepKey string, sensorID, commandID shared.ID) error {
	rid, err := shared.IDFromString(runID)
	if err != nil {
		return err
	}
	stepRun, err := s.stepRunRepo.GetByStepKey(ctx, rid, stepKey)
	if err != nil {
		return err
	}
	if stepRun == nil {
		return nil
	}
	return s.stepRunRepo.AssignSensor(ctx, stepRun.ID, sensorID, commandID)
}

// OnStepCompleted is called when a sensor reports step completion.
// This triggers scheduling of dependent steps.
func (s *Service) OnStepCompleted(ctx context.Context, runID, stepKey string, findingsCount int, output map[string]any) error {
	s.logger.Info("step completed", "run_id", runID, "step_key", stepKey, "findings", findingsCount)

	rid, err := shared.IDFromString(runID)
	if err != nil {
		return err
	}

	// Get the run with step runs
	run, err := s.runRepo.GetWithStepRuns(ctx, rid)
	if err != nil {
		return err
	}

	// A run that already reached a terminal state (canceled by the user, reaped
	// as a timeout, failed) stays there. Without this a sensor that kept
	// working after a cancel flipped the canceled run to "completed" and the
	// scan counted it as a successful run.
	if run.IsComplete() {
		s.logger.Info("ignoring step result for a run that already finished",
			"run_id", runID, "step_key", stepKey, "run_status", string(run.Status))
		return nil
	}

	// Update step run status
	stepRun := run.GetStepRun(stepKey)

	// A zone-routed scan runs one command per batch under this step: the step
	// finishes with the last batch, and fails if any batch failed.
	if b := s.checkStepBatches(ctx, run, stepRun); b.batched {
		if b.wait {
			return nil
		}
		if b.failed > 0 {
			return s.failStep(ctx, run, stepRun, b.summary(), errCodeBatchFailed, false)
		}
		findingsCount = b.findings
	}

	if stepRun != nil {
		stepRun.Complete(findingsCount, output)
		// FIXED: Don't silently suppress errors - log them instead
		if err := s.stepRunRepo.Update(ctx, stepRun); err != nil {
			s.logger.Error("failed to update step run status", "step_key", stepKey, "error", err)
		}
		// Record step metric
		metrics.StepRunsTotal.WithLabelValues(run.TenantID.String(), stepKey, "completed").Inc()
	}

	// Get template with steps
	template, err := s.templateRepo.GetWithSteps(ctx, run.PipelineID)
	if err != nil {
		return err
	}
	s.refreshStepRuns(ctx, run)
	s.skipBlockedSteps(ctx, run, template)

	// Update run statistics.
	//
	// findingsCount is deliberately NOT added on top: stepRun.Complete stored it
	// on the step run a few lines above, and calculateRunStats sums exactly those
	// step runs — so adding it again counts this step's findings twice. A live
	// scan that produced 2 findings recorded total_findings = 4, and the same
	// doubled number reached the audit log and the "completed successfully with N
	// findings" message. OnStepFailed always did it this way.
	completed, failed, skipped, findings := s.calculateRunStats(run)
	// FIXED: Don't silently suppress errors - log them instead
	if err := s.runRepo.UpdateStats(ctx, run.ID, completed, failed, skipped, findings); err != nil {
		s.logger.Error("failed to update run stats", "run_id", run.ID.String(), "error", err)
	}

	// Check if pipeline is complete
	if completed+failed+skipped >= run.TotalSteps {
		// Evaluate Quality Gate if configured
		qgResult := s.evaluateQualityGate(ctx, run)
		if qgResult != nil {
			run.SetQualityGateResult(qgResult)
			// FIXED: Don't silently suppress errors - log them instead
			if err := s.runRepo.Update(ctx, run); err != nil {
				s.logger.Error("failed to update run with quality gate result", "run_id", run.ID.String(), "error", err)
			}
		}

		if failed > 0 {
			if !s.finishRun(ctx, run, pipeline.RunStatusFailed, "Pipeline completed with failures") {
				return nil
			}
			// Audit log: pipeline failed
			s.logAudit(ctx, AuditContext{TenantID: run.TenantID.String()},
				NewFailureEvent(audit.ActionPipelineRunFailed, audit.ResourceTypePipelineRun, run.ID.String(),
					fmt.Errorf("pipeline completed with %d step failures", failed)).
					WithMessage(fmt.Sprintf("Pipeline run failed with %d step failures", failed)).
					WithMetadata("completed_steps", completed).
					WithMetadata("failed_steps", failed).
					WithMetadata("total_findings", findings).
					WithMetadata("quality_gate_passed", qgResult == nil || qgResult.Passed))
		} else {
			if !s.finishRun(ctx, run, pipeline.RunStatusCompleted, "") {
				return nil
			}
			if s.runCompleted != nil {
				run.Status = pipeline.RunStatusCompleted
				run.TotalFindings = findings
				s.runCompleted(ctx, run)
			}
			// Audit log: pipeline completed
			s.logAudit(ctx, AuditContext{TenantID: run.TenantID.String()},
				NewSuccessEvent(audit.ActionPipelineRunCompleted, audit.ResourceTypePipelineRun, run.ID.String()).
					WithMessage(fmt.Sprintf("Pipeline run completed successfully with %d findings", findings)).
					WithMetadata("completed_steps", completed).
					WithMetadata("total_findings", findings).
					WithMetadata("quality_gate_passed", qgResult == nil || qgResult.Passed))
		}
		return nil
	}

	// Schedule newly runnable steps (dependent steps whose dependencies are now complete)
	return s.scheduleRunnableSteps(ctx, run, template)
}

// OnStepFailed is called when a sensor reports step failure.
func (s *Service) OnStepFailed(ctx context.Context, runID, stepKey, errorMessage, errorCode string) error {
	s.logger.Info("step failed", "run_id", runID, "step_key", stepKey, "error", errorMessage)

	rid, err := shared.IDFromString(runID)
	if err != nil {
		return err
	}

	// Get the run
	run, err := s.runRepo.GetWithStepRuns(ctx, rid)
	if err != nil {
		return err
	}

	// A run that already reached a terminal state (canceled by the user, reaped
	// as a timeout, failed) stays there. Without this a sensor that kept
	// working after a cancel flipped the canceled run to "completed" and the
	// scan counted it as a successful run. Checked before the batch logic so a
	// late batch result cannot settle a finished run either.
	if run.IsComplete() {
		s.logger.Info("ignoring step result for a run that already finished",
			"run_id", runID, "step_key", stepKey, "run_status", string(run.Status))
		return nil
	}

	stepRun := run.GetStepRun(stepKey)
	allowRetry := true
	if b := s.checkStepBatches(ctx, run, stepRun); b.batched {
		if b.wait {
			return nil // the batch's error stays on its command; the last batch reports
		}
		// A retry would re-dispatch the step through the generic step path,
		// without zone routing: a batched step is failed, not retried.
		allowRetry = false
		errorMessage, errorCode = b.summary(), errCodeBatchFailed
	}
	return s.failStep(ctx, run, stepRun, errorMessage, errorCode, allowRetry)
}

// failStep records a step failure and settles the run.
func (s *Service) failStep(ctx context.Context, run *pipeline.Run, stepRun *pipeline.StepRun, errorMessage, errorCode string, allowRetry bool) error {
	if stepRun != nil {
		stepKey := stepRun.StepKey
		// A failure a retry cannot fix (no such scanner on the sensor, target
		// refused, nothing to scan, no sensor) is recorded with its class and
		// never retried (D7): it used to be retried up to max_retries with
		// the same result, and then reported as a generic failure.
		code, retryable := pipeline.ClassifyStepFailure(errorCode, errorMessage)
		errorCode = code
		// Check if retry is possible
		if allowRetry && retryable && stepRun.CanRetry() {
			stepRun.PrepareRetry()
			// FIXED: Don't silently suppress errors - log them instead
			if err := s.stepRunRepo.Update(ctx, stepRun); err != nil {
				s.logger.Error("failed to update step run for retry", "step_key", stepKey, "error", err)
			}
			// Record retry metric
			metrics.StepRetryTotal.WithLabelValues(run.TenantID.String(), stepKey).Inc()

			// Get template and reschedule
			template, err := s.templateRepo.GetWithSteps(ctx, run.PipelineID)
			if err == nil {
				if err := s.scheduleRunnableSteps(ctx, run, template); err != nil {
					s.logger.Error("failed to reschedule steps after retry", "run_id", run.ID.String(), "error", err)
				}
			}
			return nil
		}

		stepRun.Fail(errorMessage, errorCode)
		// FIXED: Don't silently suppress errors - log them instead
		if err := s.stepRunRepo.Update(ctx, stepRun); err != nil {
			s.logger.Error("failed to update step run status to failed", "step_key", stepKey, "error", err)
		}
		// Record failed step metric
		metrics.StepRunsTotal.WithLabelValues(run.TenantID.String(), stepKey, "failed").Inc()
	}

	// Get template to check fail_fast setting
	template, err := s.templateRepo.GetWithSteps(ctx, run.PipelineID)
	if err != nil {
		return err
	}
	s.refreshStepRuns(ctx, run)
	s.skipBlockedSteps(ctx, run, template)

	// Update run statistics
	completed, failed, skipped, findings := s.calculateRunStats(run)
	// FIXED: Don't silently suppress errors - log them instead
	if err := s.runRepo.UpdateStats(ctx, run.ID, completed, failed, skipped, findings); err != nil {
		s.logger.Error("failed to update run stats", "run_id", run.ID.String(), "error", err)
	}

	// If fail_fast, mark run as failed
	if template.Settings.FailFast {
		s.finishRun(ctx, run, pipeline.RunStatusFailed, "Pipeline failed: "+errorMessage)
		return nil
	}

	// Check if pipeline is complete
	if completed+failed+skipped >= run.TotalSteps {
		s.finishRun(ctx, run, pipeline.RunStatusFailed, "Pipeline completed with failures")
		return nil
	}

	// Continue with other steps
	return s.scheduleRunnableSteps(ctx, run, template)
}

// errCodeBatchFailed is the step error code when a zone batch failed.
const errCodeBatchFailed = "BATCH_FAILED"

// stepBatches is what the zone batches of one step amount to (RFC-023).
type stepBatches struct {
	batched    bool // the step has more than one command
	wait       bool // another batch is still active, or another caller finalizes
	total      int
	failed     int
	findings   int
	firstError string
}

func (b stepBatches) summary() string {
	msg := fmt.Sprintf("%d of %d scan batches failed", b.failed, b.total)
	if b.firstError != "" {
		msg += ": " + b.firstError
	}
	return msg
}

// checkStepBatches reports whether stepRun is a batched step and, if so,
// whether this caller should record its outcome now. A step with zero or one
// command is not batched and keeps the original single-command behavior.
func (s *Service) checkStepBatches(ctx context.Context, run *pipeline.Run, stepRun *pipeline.StepRun) stepBatches {
	gate, ok := s.commandRepo.(command.StepBatchGate)
	if !ok || stepRun == nil {
		return stepBatches{}
	}
	st, err := gate.StepBatchState(ctx, run.TenantID, stepRun.ID)
	if err != nil {
		s.logger.Error("failed to read step batches; settling the step from this command alone",
			"run_id", run.ID.String(), "step_key", stepRun.StepKey, "error", err)
		return stepBatches{}
	}
	if st.Total <= 1 {
		return stepBatches{}
	}
	b := stepBatches{batched: true, total: st.Total, failed: st.Failed, findings: st.Findings, firstError: st.FirstError}
	if st.Active > 0 {
		s.logger.Info("scan batch finished; waiting for the others",
			"run_id", run.ID.String(), "step_key", stepRun.StepKey, "active", st.Active, "total", st.Total)
		b.wait = true
		return b
	}
	claimed, err := gate.ClaimStepFinalization(ctx, stepRun.ID)
	if err != nil {
		s.logger.Error("failed to claim step finalization", "run_id", run.ID.String(), "error", err)
		b.wait = true
		return b
	}
	b.wait = !claimed
	return b
}

// calculateRunStats calculates run statistics from step runs.
func (s *Service) calculateRunStats(run *pipeline.Run) (completed, failed, skipped, findings int) {
	for _, sr := range run.StepRuns {
		switch sr.Status {
		case pipeline.StepRunStatusCompleted:
			completed++
			findings += sr.FindingsCount
		case pipeline.StepRunStatusFailed:
			failed++
		case pipeline.StepRunStatusSkipped:
			skipped++
		}
	}
	return
}

// evaluateQualityGate evaluates the quality gate for a completed pipeline run.
// Returns nil if quality gate is not configured or dependencies are not available.
func (s *Service) evaluateQualityGate(ctx context.Context, run *pipeline.Run) *scanprofile.QualityGateResult {
	// Check if QG dependencies are available
	if s.scanProfileRepo == nil || s.findingRepo == nil {
		return nil
	}

	// Check if run has a scan profile
	if run.ScanProfileID == nil {
		return nil
	}

	// Get the scan profile
	profile, err := s.scanProfileRepo.GetByID(ctx, *run.ScanProfileID)
	if err != nil {
		s.logger.Warn("failed to get scan profile for quality gate evaluation",
			"error", err,
			"profile_id", run.ScanProfileID.String(),
			"run_id", run.ID.String())
		return nil
	}

	// Verify tenant ownership
	if !profile.TenantID.Equals(run.TenantID) {
		s.logger.Warn("scan profile tenant mismatch",
			"profile_tenant", profile.TenantID.String(),
			"run_tenant", run.TenantID.String())
		return nil
	}

	// Check if quality gate is enabled
	if !profile.QualityGate.Enabled {
		return nil
	}

	// Get finding counts for this run
	// For pipeline runs, we need to aggregate findings from all step runs
	// The run.TotalFindings contains the count, but we need severity breakdown
	// We'll use the finding repository to get counts by severity

	// Note: We need a scan session ID or run ID to query findings.
	// For pipeline runs, findings are typically associated with a scan_session_id in the context.
	// Let's check if there's a scan_id we can use
	var scanID string
	if run.ScanID != nil {
		scanID = run.ScanID.String()
	} else if run.Context != nil {
		// Try to get scan_id from context
		if sid, ok := run.Context["scan_id"].(string); ok {
			scanID = sid
		}
	}

	if scanID == "" {
		s.logger.Debug("no scan_id available for quality gate evaluation", "run_id", run.ID.String())
		return nil
	}

	// Get finding counts by severity
	severityCounts, err := s.findingRepo.CountBySeverityForScan(ctx, run.TenantID, scanID)
	if err != nil {
		s.logger.Warn("failed to get finding counts for quality gate",
			"error", err,
			"scan_id", scanID,
			"run_id", run.ID.String())
		return nil
	}

	// Convert to FindingCounts
	counts := scanprofile.FindingCounts{
		Critical: severityCounts.Critical,
		High:     severityCounts.High,
		Medium:   severityCounts.Medium,
		Low:      severityCounts.Low,
		Info:     severityCounts.Info,
		Total:    severityCounts.Total,
	}

	// Evaluate quality gate
	result := profile.QualityGate.Evaluate(counts)

	s.logger.Info("quality gate evaluated",
		"run_id", run.ID.String(),
		"passed", result.Passed,
		"breaches", len(result.Breaches),
		"counts", counts)

	return result
}

// evaluateCondition evaluates a step's condition.
func (s *Service) evaluateCondition(_ context.Context, step *pipeline.Step, run *pipeline.Run, _ *pipeline.Template) bool {
	return step.ConditionMet(run)
}

// GetRun retrieves a pipeline run by ID.
func (s *Service) GetRun(ctx context.Context, tenantID, runID string) (*pipeline.Run, error) {
	tid, err := shared.IDFromString(tenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}

	rid, err := shared.IDFromString(runID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid run id", shared.ErrValidation)
	}

	return s.runRepo.GetByTenantAndID(ctx, tid, rid)
}

// GetRunWithSteps retrieves a pipeline run with its step runs.
func (s *Service) GetRunWithSteps(ctx context.Context, runID string) (*pipeline.Run, error) {
	rid, err := shared.IDFromString(runID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid run id", shared.ErrValidation)
	}

	return s.runRepo.GetWithStepRuns(ctx, rid)
}

// ListRunsInput represents the input for listing runs.
type ListRunsInput struct {
	TenantID   string `json:"tenant_id" validate:"required,uuid"`
	PipelineID string `json:"pipeline_id" validate:"omitempty,uuid"`
	AssetID    string `json:"asset_id" validate:"omitempty,uuid"`
	Status     string `json:"status" validate:"omitempty,oneof=pending running completed failed canceled timeout"`
	Page       int    `json:"page"`
	PerPage    int    `json:"per_page"`
}

// ListRuns lists pipeline runs with filters.
func (s *Service) ListRuns(ctx context.Context, input ListRunsInput) (pagination.Result[*pipeline.Run], error) {
	tenantID, err := shared.IDFromString(input.TenantID)
	if err != nil {
		return pagination.Result[*pipeline.Run]{}, fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}

	filter := pipeline.RunFilter{
		TenantID: &tenantID,
	}

	if input.PipelineID != "" {
		pid, err := shared.IDFromString(input.PipelineID)
		if err == nil {
			filter.PipelineID = &pid
		}
	}

	if input.AssetID != "" {
		aid, err := shared.IDFromString(input.AssetID)
		if err == nil {
			filter.AssetID = &aid
		}
	}

	if input.Status != "" {
		st := pipeline.RunStatus(input.Status)
		filter.Status = &st
	}

	page := pagination.New(input.Page, input.PerPage)
	return s.runRepo.List(ctx, filter, page)
}

// CancelRun cancels a pipeline run and all its in-flight commands.
func (s *Service) CancelRun(ctx context.Context, tenantID, runID string) error {
	run, err := s.GetRun(ctx, tenantID, runID)
	if err != nil {
		return err
	}

	if run.IsComplete() {
		return shared.NewDomainError("INVALID_STATE", "pipeline run is already complete", shared.ErrValidation)
	}

	// Through the guarded status transition, not a full-row write of the copy
	// read above: if the run finished in the meantime the cancel is refused
	// instead of turning a completed run into a canceled one (and counting it
	// on the scan a second time).
	err = s.runRepo.UpdateStatus(ctx, run.ID, pipeline.RunStatusCanceled, "Canceled by user")
	if errors.Is(err, pipeline.ErrRunAlreadyFinished) {
		return shared.NewDomainError("INVALID_STATE", "pipeline run is already complete", shared.ErrValidation)
	}
	if err != nil {
		return err
	}
	run.Cancel()
	metrics.PipelineRunsInProgress.WithLabelValues(run.TenantID.String()).Dec()
	metrics.PipelineRunsTotal.WithLabelValues(run.TenantID.String(), string(pipeline.RunStatusCanceled)).Inc()
	s.recordScanRun(ctx, run, string(pipeline.RunStatusCanceled))

	// Cancel all in-flight commands belonging to this run so sensors stop work.
	if s.commandRepo != nil {
		canceled, cancelErr := s.commandRepo.CancelByPipelineRunID(ctx, run.TenantID, run.ID)
		if cancelErr != nil {
			// Non-fatal: run is already canceled, commands will eventually be reaped by JobRecoveryController
			s.logger.Warn("failed to cancel commands for pipeline run",
				"run_id", runID,
				"error", cancelErr)
		} else if canceled > 0 {
			s.logger.Info("canceled in-flight commands", "run_id", runID, "count", canceled)
		}
	}

	// Audit log: run canceled
	s.logAudit(ctx, AuditContext{TenantID: tenantID},
		NewSuccessEvent(audit.ActionPipelineRunCanceled, audit.ResourceTypePipelineRun, runID).
			WithMessage("Pipeline run canceled"))

	return nil
}

// CompleteStepRun marks a step run as completed (called by sensor).
func (s *Service) CompleteStepRun(ctx context.Context, stepRunID string, findingsCount int, output map[string]any) error {
	srid, err := shared.IDFromString(stepRunID)
	if err != nil {
		return fmt.Errorf("%w: invalid step run id", shared.ErrValidation)
	}

	return s.stepRunRepo.Complete(ctx, srid, findingsCount, output)
}

// FailStepRun marks a step run as failed (called by sensor).
func (s *Service) FailStepRun(ctx context.Context, stepRunID, errorMessage, errorCode string) error {
	srid, err := shared.IDFromString(stepRunID)
	if err != nil {
		return fmt.Errorf("%w: invalid step run id", shared.ErrValidation)
	}

	return s.stepRunRepo.UpdateStatus(ctx, srid, pipeline.StepRunStatusFailed, errorMessage, errorCode)
}

// stepCommandPayload is the command payload of one pipeline step. The
// step's settings go under PayloadKeyConfig, the key the sensor reads (see
// pipeline.NormalizeStepConfig); a setting the sensor would refuse fails the
// step before a command is created.
func stepCommandPayload(run *pipeline.Run, step *pipeline.Step, stepRun *pipeline.StepRun, settings pipeline.Settings) (map[string]any, error) {
	config, err := pipeline.NormalizeStepConfig(step.Tool, step.Config)
	if err != nil {
		return nil, err
	}
	payload := map[string]any{
		"pipeline_run_id":                   run.ID.String(),
		"step_run_id":                       stepRun.ID.String(),
		"step_id":                           step.ID.String(),
		"step_key":                          step.StepKey,
		pipeline.PayloadKeyConfig:           config,
		"required_capabilities":             step.Capabilities,
		"preferred_tool":                    step.Tool,
		"timeout_seconds":                   step.TimeoutSeconds,
		"context":                           run.Context,
		legacyv1.PayloadKeySensorPreference: string(settings.SensorPreference),
	}
	// The sensor SDK runs the scanner named in `scanner` (ScanCommandPayload);
	// a step carrying only preferred_tool failed with "scanner not found: ".
	if step.Tool != "" {
		payload["scanner"] = step.Tool
	}
	// Step targets come from the run context (direct targets); the sensor
	// reads them at the top level.
	if targets, ok := run.Context["targets"]; ok {
		payload["targets"] = targets
	}

	if run.AssetID != nil {
		payload["asset_id"] = run.AssetID.String()
	}
	return payload, nil
}

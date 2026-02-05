package pipeline

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/openctemio/api/internal/metrics"
	"github.com/openctemio/api/pkg/domain/audit"
	"github.com/openctemio/api/pkg/domain/command"
	"github.com/openctemio/api/pkg/domain/pipeline"
	"github.com/openctemio/api/pkg/domain/scanprofile"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/pagination"
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

	// Create pipeline run
	run, err := pipeline.NewRun(template.ID, tenantID, assetID, triggerType, input.TriggeredBy, input.Context)
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
	// This creates commands that agents will poll and execute
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
// Agents will poll these commands and execute them.
// Respects MaxParallelSteps setting to limit concurrent step execution.
func (s *Service) scheduleRunnableSteps(ctx context.Context, run *pipeline.Run, template *pipeline.Template) error {
	s.logger.Info("scheduling runnable steps", "run_id", run.ID.String())

	// Get completed step keys
	stepRuns, err := s.stepRunRepo.GetByPipelineRunID(ctx, run.ID)
	if err != nil {
		return err
	}

	completedSteps := make(map[string]bool)
	runningSteps := 0
	for _, sr := range stepRuns {
		if sr.IsComplete() {
			completedSteps[sr.StepKey] = true
		} else if sr.IsRunning() || sr.IsQueued() {
			runningSteps++
		}
	}

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

		// Queue the step - create a command that agents can poll
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
	s.logger.Info("queueing step for execution", "step_key", step.StepKey, "tool", step.Tool, "agent_preference", settings.AgentPreference)

	// Security validation: Last line of defense before sending to agent
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

	// Create command payload with step info
	payload := map[string]any{
		"pipeline_run_id":       run.ID.String(),
		"step_run_id":           stepRun.ID.String(),
		"step_id":               step.ID.String(),
		"step_key":              step.StepKey,
		"step_config":           step.Config,
		"required_capabilities": step.Capabilities,
		"preferred_tool":        step.Tool,
		"timeout_seconds":       step.TimeoutSeconds,
		"context":               run.Context,
		"agent_preference":      string(settings.AgentPreference),
	}

	if run.AssetID != nil {
		payload["asset_id"] = run.AssetID.String()
	}

	// Final payload validation before sending to agent
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

	// Determine agent routing based on preference
	usePlatform, agentID := s.determineAgentRouting(ctx, run.TenantID, step.Tool, settings.AgentPreference)

	//nolint:gocritic // if-else chain is clearer than switch for bool+pointer conditions
	if usePlatform {
		// Route to platform agents
		initialPriority := s.calculatePipelineInitialPriority(cmd.Priority)
		cmd.SetPlatformJob(initialPriority)
		s.logger.Info("routing step to platform agents", "step_key", step.StepKey)
	} else if agentID != nil {
		// Route to specific tenant agent
		cmd.SetAgentID(*agentID)
		s.logger.Info("routing step to tenant agent", "step_key", step.StepKey, "agent_id", agentID.String())
	} else {
		// No specific agent, command available to any tenant agent
		s.logger.Info("no specific agent assigned, command available to all tenant agents", "step_key", step.StepKey)
	}

	if err := s.commandRepo.Create(ctx, cmd); err != nil {
		return err
	}

	// Mark step as queued
	stepRun.Queue()
	stepRun.CommandID = &cmd.ID
	return s.stepRunRepo.Update(ctx, stepRun)
}

// determineAgentRouting determines whether to use platform agents and which specific agent to use.
func (s *Service) determineAgentRouting(ctx context.Context, tenantID shared.ID, tool string, pref pipeline.AgentPreference) (usePlatform bool, agentID *shared.ID) {
	// If explicitly set to tenant only, never use platform
	if pref == pipeline.AgentPreferenceTenant {
		// Try to find a tenant agent with the required tool
		if tool != "" {
			foundAgent, err := s.agentRepo.FindAvailableWithTool(ctx, tenantID, tool)
			if err == nil && foundAgent != nil {
				return false, &foundAgent.ID
			}
		}
		return false, nil
	}

	// If explicitly set to platform only, always use platform
	if pref == pipeline.AgentPreferencePlatform {
		// Check if tenant can use platform agents
		if s.agentSelector != nil {
			canUse, _ := s.agentSelector.CanUsePlatformAgents(ctx, tenantID)
			if canUse {
				return true, nil
			}
		}
		// Fall through to try tenant agents if platform not available
	}

	// For "auto" mode (or platform fallback), use AgentSelector if available
	if s.agentSelector != nil {
		result, err := s.agentSelector.SelectAgent(ctx, SelectAgentRequest{
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
			if result.Agent != nil {
				return false, &result.Agent.ID
			}
		}
	}

	// Fallback: try to find tenant agent
	if tool != "" {
		foundAgent, err := s.agentRepo.FindAvailableWithTool(ctx, tenantID, tool)
		if err == nil && foundAgent != nil {
			return false, &foundAgent.ID
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

// OnStepCompleted is called when an agent reports step completion.
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

	// Update step run status
	stepRun := run.GetStepRun(stepKey)
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

	// Update run statistics
	completed, failed, skipped, findings := s.calculateRunStats(run)
	// FIXED: Don't silently suppress errors - log them instead
	if err := s.runRepo.UpdateStats(ctx, run.ID, completed, failed, skipped, findings+findingsCount); err != nil {
		s.logger.Error("failed to update run stats", "run_id", run.ID.String(), "error", err)
	}

	// Check if pipeline is complete
	if completed+failed+skipped >= run.TotalSteps {
		metrics.PipelineRunsInProgress.WithLabelValues(run.TenantID.String()).Dec()

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
			// FIXED: Don't silently suppress errors - log them instead
			if err := s.runRepo.UpdateStatus(ctx, run.ID, pipeline.RunStatusFailed, "Pipeline completed with failures"); err != nil {
				s.logger.Error("failed to update run status to failed", "run_id", run.ID.String(), "error", err)
			}
			metrics.PipelineRunsTotal.WithLabelValues(run.TenantID.String(), "failed").Inc()
			// Audit log: pipeline failed
			s.logAudit(ctx, AuditContext{TenantID: run.TenantID.String()},
				NewFailureEvent(audit.ActionPipelineRunFailed, audit.ResourceTypePipelineRun, run.ID.String(),
					fmt.Errorf("pipeline completed with %d step failures", failed)).
					WithMessage(fmt.Sprintf("Pipeline run failed with %d step failures", failed)).
					WithMetadata("completed_steps", completed).
					WithMetadata("failed_steps", failed).
					WithMetadata("total_findings", findings+findingsCount).
					WithMetadata("quality_gate_passed", qgResult == nil || qgResult.Passed))
		} else {
			// FIXED: Don't silently suppress errors - log them instead
			if err := s.runRepo.UpdateStatus(ctx, run.ID, pipeline.RunStatusCompleted, ""); err != nil {
				s.logger.Error("failed to update run status to completed", "run_id", run.ID.String(), "error", err)
			}
			metrics.PipelineRunsTotal.WithLabelValues(run.TenantID.String(), "completed").Inc()
			// Audit log: pipeline completed
			s.logAudit(ctx, AuditContext{TenantID: run.TenantID.String()},
				NewSuccessEvent(audit.ActionPipelineRunCompleted, audit.ResourceTypePipelineRun, run.ID.String()).
					WithMessage(fmt.Sprintf("Pipeline run completed successfully with %d findings", findings+findingsCount)).
					WithMetadata("completed_steps", completed).
					WithMetadata("total_findings", findings+findingsCount).
					WithMetadata("quality_gate_passed", qgResult == nil || qgResult.Passed))
		}
		return nil
	}

	// Schedule newly runnable steps (dependent steps whose dependencies are now complete)
	return s.scheduleRunnableSteps(ctx, run, template)
}

// OnStepFailed is called when an agent reports step failure.
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

	// Update step run status
	stepRun := run.GetStepRun(stepKey)
	if stepRun != nil {
		// Check if retry is possible
		if stepRun.CanRetry() {
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

	// Update run statistics
	completed, failed, skipped, findings := s.calculateRunStats(run)
	// FIXED: Don't silently suppress errors - log them instead
	if err := s.runRepo.UpdateStats(ctx, run.ID, completed, failed, skipped, findings); err != nil {
		s.logger.Error("failed to update run stats", "run_id", run.ID.String(), "error", err)
	}

	// Get template to check fail_fast setting
	template, err := s.templateRepo.GetWithSteps(ctx, run.PipelineID)
	if err != nil {
		return err
	}

	// If fail_fast, mark run as failed
	if template.Settings.FailFast {
		metrics.PipelineRunsInProgress.WithLabelValues(run.TenantID.String()).Dec()
		metrics.PipelineRunsTotal.WithLabelValues(run.TenantID.String(), "failed").Inc()
		// FIXED: Don't silently suppress errors - log them instead
		if err := s.runRepo.UpdateStatus(ctx, run.ID, pipeline.RunStatusFailed, "Pipeline failed: "+errorMessage); err != nil {
			s.logger.Error("failed to update run status to failed (fail_fast)", "run_id", run.ID.String(), "error", err)
		}
		return nil
	}

	// Check if pipeline is complete
	if completed+failed+skipped >= run.TotalSteps {
		metrics.PipelineRunsInProgress.WithLabelValues(run.TenantID.String()).Dec()
		metrics.PipelineRunsTotal.WithLabelValues(run.TenantID.String(), "failed").Inc()
		// FIXED: Don't silently suppress errors - log them instead
		if err := s.runRepo.UpdateStatus(ctx, run.ID, pipeline.RunStatusFailed, "Pipeline completed with failures"); err != nil {
			s.logger.Error("failed to update run status to failed (complete)", "run_id", run.ID.String(), "error", err)
		}
		return nil
	}

	// Continue with other steps
	return s.scheduleRunnableSteps(ctx, run, template)
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
func (s *Service) evaluateCondition(ctx context.Context, step *pipeline.Step, run *pipeline.Run, template *pipeline.Template) bool {
	switch step.Condition.Type {
	case pipeline.ConditionTypeAlways:
		return true
	case pipeline.ConditionTypeNever:
		return false
	case pipeline.ConditionTypeAssetType:
		// Check if asset type matches
		assetType, ok := run.Context["asset_type"].(string)
		return ok && assetType == step.Condition.Value
	case pipeline.ConditionTypeExpression:
		// TODO: Implement expression evaluation
		return true
	case pipeline.ConditionTypeStepResult:
		// Check previous step result
		prevStepRun := run.GetStepRun(step.Condition.Value)
		return prevStepRun != nil && prevStepRun.IsSuccess()
	default:
		return true
	}
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

// CancelRun cancels a pipeline run.
func (s *Service) CancelRun(ctx context.Context, tenantID, runID string) error {
	run, err := s.GetRun(ctx, tenantID, runID)
	if err != nil {
		return err
	}

	if run.IsComplete() {
		return shared.NewDomainError("INVALID_STATE", "pipeline run is already complete", shared.ErrValidation)
	}

	run.Cancel()
	if err := s.runRepo.Update(ctx, run); err != nil {
		return err
	}

	// Audit log: run cancelled
	s.logAudit(ctx, AuditContext{TenantID: tenantID},
		NewSuccessEvent(audit.ActionPipelineRunCancelled, audit.ResourceTypePipelineRun, runID).
			WithMessage("Pipeline run cancelled"))

	return nil
}

// CompleteStepRun marks a step run as completed (called by agent).
func (s *Service) CompleteStepRun(ctx context.Context, stepRunID string, findingsCount int, output map[string]any) error {
	srid, err := shared.IDFromString(stepRunID)
	if err != nil {
		return fmt.Errorf("%w: invalid step run id", shared.ErrValidation)
	}

	return s.stepRunRepo.Complete(ctx, srid, findingsCount, output)
}

// FailStepRun marks a step run as failed (called by agent).
func (s *Service) FailStepRun(ctx context.Context, stepRunID, errorMessage, errorCode string) error {
	srid, err := shared.IDFromString(stepRunID)
	if err != nil {
		return fmt.Errorf("%w: invalid step run id", shared.ErrValidation)
	}

	return s.stepRunRepo.UpdateStatus(ctx, srid, pipeline.StepRunStatusFailed, errorMessage, errorCode)
}

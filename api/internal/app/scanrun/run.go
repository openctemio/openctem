package scanrun

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"

	"github.com/openctemio/openctem/api/pkg/domain/scanrun"
	"github.com/openctemio/openctem/api/pkg/domain/scanworkflow"

	scanapp "github.com/openctemio/openctem/api/internal/app/scan"
	"github.com/openctemio/openctem/api/internal/metrics"
	"github.com/openctemio/openctem/api/pkg/domain/audit"
	"github.com/openctemio/openctem/api/pkg/domain/command"
	"github.com/openctemio/openctem/api/pkg/domain/scanprofile"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/stage"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/pagination"
)

// ========== Run Operations (Orchestration) ==========

// TriggerRunInput represents the input for triggering a scan workflow.
type TriggerRunInput struct {
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
func (s *Service) TriggerPipeline(ctx context.Context, input TriggerRunInput) (*scanrun.Run, error) {
	s.logger.Info("triggering scan run", "template_id", input.TemplateID)

	// Get template with steps
	template, err := s.GetTemplateWithSteps(ctx, input.TemplateID)
	if err != nil {
		return nil, err
	}

	// SECURITY: GetTemplateWithSteps loads by ID without tenant scoping, so we
	// must verify the caller may use this template before triggering it.
	// A template is usable iff it is a system template (shared, auto-cloned
	// below) or it belongs to the caller's tenant. Without this check a user
	// could trigger another tenant's private scan workflow by guessing its ID.
	if !template.IsSystemTemplate && template.TenantID.String() != input.TenantID {
		s.logger.Warn("SECURITY: cross-tenant scan run trigger attempt",
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

	if template.RetiredAt != nil {
		return nil, scanworkflow.ErrScanWorkflowRetired
	}

	// Verify template is active
	if !template.IsActive {
		return nil, shared.NewDomainError("INACTIVE", "this scan workflow is not active", shared.ErrValidation)
	}

	// Validate steps
	if err := template.ValidateSteps(); err != nil {
		return nil, err
	}

	tenantID, _ := shared.IDFromString(input.TenantID)

	// Validate tool references - ensure all required tools are available and active
	if err := s.ValidateToolReferences(ctx, template, tenantID); err != nil {
		s.logger.Warn("scan workflow tool validation failed",
			"template_id", template.ID.String(),
			"error", err)
		return nil, err
	}

	// The run's asset_id is stored on the run and copied into every step
	// command's payload, so it must be a live asset of this tenant that the
	// caller may see (scan_runs.asset_id references assets(id) without
	// the tenant; research doc 21b, C4). A workflow trigger has no user in
	// the context and gets the tenant check only. A malformed id is refused
	// rather than silently dropped; a refused one answers like an unknown one.
	var assetID *shared.ID
	if input.AssetID != "" {
		aid, err := shared.IDFromString(input.AssetID)
		if err != nil {
			return nil, fmt.Errorf("%w: invalid asset id", shared.ErrValidation)
		}
		if s.assetRefChecker == nil {
			return nil, ErrRunAssetNotFound
		}
		if err := s.assetRefChecker.AssertAssetRef(ctx, tenantID, aid); err != nil {
			return nil, ErrRunAssetNotFound
		}
		assetID = &aid
	}

	triggerType := scanworkflow.TriggerType(input.TriggerType)
	if triggerType == "" {
		triggerType = scanworkflow.TriggerTypeManual
	}

	// The run's targets reach every step command; check them the way a scan
	// trigger does (private-range policy, scope exclusions, scan zones).
	runContext, err := s.gateRunContext(ctx, tenantID, input.TriggeredBy, input.Context)
	if err != nil {
		s.logger.Warn("scan workflow run refused by the target gate",
			"template_id", template.ID.String(), "error", err)
		return nil, err
	}

	// Create scan run
	run, err := scanrun.NewRun(template.ID, tenantID, assetID, triggerType, input.TriggeredBy, runContext)
	if err != nil {
		return nil, err
	}
	run.SetTotalSteps(len(template.Steps))
	if err := scanrun.PinWorkflow(ctx, s.versions, run, template); err != nil {
		return nil, err
	}

	// FIXED: Use atomic CreateRunIfUnderLimit to prevent race conditions
	// This atomically checks concurrent run limits AND creates the run in a single transaction.
	// Previously, the check-then-create pattern allowed race conditions where multiple
	// concurrent triggers could bypass the limits.
	if err := s.runRepo.CreateRunIfUnderLimit(ctx, run, MaxConcurrentRunsPerScanWorkflow, MaxConcurrentRunsPerTenant); err != nil {
		return nil, err
	}

	// Create step runs
	for _, step := range template.Steps {
		stepRun := scanrun.NewStepRunForStep(run.ID, step)
		if err := s.stepRunRepo.Create(ctx, stepRun); err != nil {
			return nil, err
		}
		run.AddStepRun(stepRun)
	}

	// Start the scan workflow
	run.Start()
	if err := s.runRepo.Update(ctx, run); err != nil {
		return nil, err
	}

	// Record metrics
	metrics.ScanRunsTotal.WithLabelValues("running").Inc()
	metrics.ScanRunsInProgress.WithLabelValues().Inc()

	// Schedule initial runnable steps (no dependencies)
	// This creates commands that sensors will poll and execute
	if err := s.scheduleRunnableSteps(ctx, run, template); err != nil {
		s.logger.Error("failed to schedule initial steps", "error", err)
	}

	// Audit log: scan workflow triggered
	s.logAudit(ctx, AuditContext{TenantID: input.TenantID, ActorID: input.TriggeredBy},
		NewSuccessEvent(audit.ActionScanRunTriggered, audit.ResourceTypeScanRun, run.ID.String()).
			WithResourceName(template.Name).
			WithMessage(fmt.Sprintf("Scan workflow '%s' triggered", template.Name)).
			WithMetadata("trigger_type", string(triggerType)).
			WithMetadata("template_id", template.ID.String()))

	return run, nil
}

// scheduleRunnableSteps creates commands for steps that are ready to run.
// Sensors will poll these commands and execute them.
// Respects MaxParallelSteps setting to limit concurrent step execution.
func (s *Service) scheduleRunnableSteps(ctx context.Context, run *scanrun.Run, template *scanworkflow.Workflow) error {
	s.logger.Info("scheduling runnable steps", "run_id", run.ID.String())

	// Get completed step keys
	stepRuns, err := s.stepRunRepo.GetByScanRunID(ctx, run.ID)
	if err != nil {
		return err
	}

	// A dependency gates a step only by producing results (completed, or
	// partial: some batches failed, the others' results are kept). Every
	// terminal step used to count as "completed" here, so a step whose
	// dependency had failed (or been skipped, or timed out) was queued anyway.
	succeededSteps := make(map[string]bool)
	runningSteps := 0
	for _, sr := range stepRuns {
		if sr.IsComplete() {
			if sr.Status.ProducedResults() {
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
	settledInline := false

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
			stepRun.Skip(step.ConditionSkipReason())
			// FIXED: Don't silently suppress errors - log them instead
			if err := s.stepRunRepo.Update(ctx, stepRun); err != nil {
				s.logger.Error("failed to update skipped step run", "step_key", step.StepKey, "error", err)
			}
			continue
		}

		// Queue the step - create a command that sensors can poll
		err := s.queueStepForExecutionWithSettings(ctx, run, step, stepRun, template.Settings, predecessorsOf(template, step))
		var noInputs *noInputsError
		switch {
		case err == nil:
			runningSteps++
		case errors.Is(err, errStageDeferred):
			// A predecessor's report is still being ingested: the step stays
			// pending and is planned when the ingest commits (OnCommandIngested).
			s.logger.Info("chained step waits for its predecessors' ingest",
				"run_id", run.ID.String(), "step_key", step.StepKey)
		case errors.Is(err, errStageAlreadyPlanned):
			// Another planner (a concurrent completion) planned it.
		case errors.As(err, &noInputs):
			// Planned, and nothing passed: settled without a command, so its
			// successors run on what they have.
			stepRun.Complete(0, map[string]any{"no_inputs": true})
			stepRun.SkipReason = noInputs.Error()
			if uerr := s.stepRunRepo.Update(ctx, stepRun); uerr != nil {
				s.logger.Error("failed to settle a step with no inputs", "step_key", step.StepKey, "error", uerr)
			}
			settledInline = true
		default:
			s.logger.Error("failed to queue step", "step_key", step.StepKey, "error", err)
			s.failQueuedStep(ctx, stepRun, step.StepKey, err)
			settledInline = true
		}
	}

	// A step settled here (no inputs, or a step that could not be queued)
	// can unblock or end the run: advance again. Each pass settles at
	// least one step, so this ends.
	if settledInline {
		return s.advanceRun(ctx, run, template)
	}
	return nil
}

// predecessorsOf returns the steps of the template that step depends on.
func predecessorsOf(template *scanworkflow.Workflow, step *scanworkflow.Step) []*scanworkflow.Step {
	if template == nil || len(step.DependsOn) == 0 {
		return nil
	}
	out := make([]*scanworkflow.Step, 0, len(step.DependsOn))
	for _, dep := range step.DependsOn {
		for _, t := range template.Steps {
			if t.StepKey == dep {
				out = append(out, t)
				break
			}
		}
	}
	return out
}

// queueStepForExecutionWithSettings creates a command with specific settings.
//
// preds are the steps it depends on: when they produce asset types its
// stage takes, its targets come from the hop router (hop_router.go) and the
// sentinel errors errStageDeferred, errStageAlreadyPlanned and
// *noInputsError tell the scheduler to wait, to leave it, or to settle it.
func (s *Service) queueStepForExecutionWithSettings(ctx context.Context, run *scanrun.Run, step *scanworkflow.Step, stepRun *scanrun.StepRun, settings scanworkflow.Settings, preds []*scanworkflow.Step) error {
	// The tool the step runs: its pinned tool, or the implementation of its
	// capability the planner picks (F1: a capability-only step used to
	// reach the sensor with no scanner). Every check below and the payload
	// read the resolved tool.
	resolved, err := scanapp.ResolveStepTool(ctx, s.toolRepo, run.TenantID, step)
	if err != nil {
		return fmt.Errorf("step %s: %w", step.StepKey, err)
	}
	step = resolved.WithTool(step)
	// The step run records what it runs: the capability and the tool the
	// planner picked (written with the queued state below).
	stepRun.Tool = resolved.Name
	stepRun.Capability = resolved.Capability()
	s.logger.Info("queueing step for execution", "step_key", step.StepKey, "tool", step.Tool,
		"capability", stepRun.Capability, "pinned", resolved.Pinned, "sensor_preference", settings.SensorPreference)

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

	// The step's tool is handed only the run's targets it can scan; a step
	// left with none fails here (INCOMPATIBLE_TARGETS), before any sensor
	// sees it.
	chained := s.hops != nil && resolved.HasStage && len(feedingPredecessors(run, resolved.Stage, preds)) > 0
	var stepTargets *scanapp.StepTargets
	if f, ok := s.targetGate.(StepTargetFilter); ok {
		st, ferr := f.FilterStepTargets(ctx, run.TenantID, step.Tool, run.Context)
		if ferr != nil {
			var de *shared.DomainError
			if !chained || !errors.As(ferr, &de) || (de.Code != "INCOMPATIBLE_TARGETS" && de.Code != scanapp.CodeStepTargetsRefused) {
				return fmt.Errorf("step %s: %w", step.StepKey, ferr)
			}
			// A chained step may take no seed: its targets come from
			// what its predecessors found (the hop gate checks those at
			// the step's tier).
			st = &scanapp.StepTargets{Targets: []string{}}
		}
		stepTargets = st
		if st != nil && st.Refused > 0 {
			s.logger.Info("step targets the tool cannot scan were left out",
				"run_id", run.ID.String(), "step_key", step.StepKey, "refused", st.Refused, "reason", st.Reason)
		}
	}

	// The hop router: seeds, plus what the predecessors produced that passes
	// the per-hop gate; recorded once per (run, stage).
	planned, err := s.planStage(ctx, run, step, resolved, preds, stepTargets)
	if err != nil {
		return fmt.Errorf("step %s: %w", step.StepKey, err)
	}
	stepTargets = planned

	// Where the step's commands may run. No command is pinned to one
	// sensor (research/49 W27): a zone-routed run's commands are stamped
	// with the zone, the others go to the platform queue or to any tenant
	// sensor that has the tool; the claim predicates (zone, tool, grant,
	// refusals, freeze) decide who takes each one.
	zoneID := scanrun.ScanZoneFromContext(run.Context)
	usePlatform := false
	if zoneID == nil {
		usePlatform = s.stepUsesPlatform(ctx, run, step, settings.SensorPreference)
	}

	// A large step is cut into chunks of the capability's size, so every
	// eligible sensor takes a share; the step settles with its last chunk
	// (checkStepBatches). A step that fits one chunk stays one command.
	chunks := stepChunks(resolved, stepTargets)
	created := make([]*command.Command, 0, len(chunks))
	for _, chunk := range chunks {
		cmd, err := s.stepCommand(ctx, run, step, stepRun, chunk, stageKeyOf(resolved))
		if err == nil {
			// An active stage holds its hosts while a sensor runs the
			// chunk, so no other sensor hits them at the same time.
			cmd.HostKeys = chunkHostKeys(resolved.Stage, resolved.HasStage, chunkTargets(chunk, run.Context))
			// What the step's targets were gated with: the claim gates
			// them again with it (claim-time scope re-check).
			cmd.DispatchGate = stepDispatchGate(run, resolved)
		}
		if err == nil {
			if zoneID != nil {
				cmd.SetScanZone(*zoneID)
			} else if usePlatform {
				cmd.SetPlatformJob(s.calculateScanRunInitialPriority(cmd.Priority))
			}
			err = s.commandRepo.Create(ctx, cmd)
		}
		if err != nil {
			s.cancelStepCommands(ctx, created)
			return err
		}
		created = append(created, cmd)
	}
	s.logger.Info("step queued", "step_key", step.StepKey, "commands", len(created),
		"zone_routed", zoneID != nil, "platform", usePlatform)

	// Mark step as queued
	stepRun.Queue()
	stepRun.CommandID = &created[0].ID
	return s.stepRunRepo.Update(ctx, stepRun)
}

// stepDispatchGate is the gate record of a step's commands: the run
// actor's act scope (seeds and chained hops are both checked against it),
// the stage's tier and passive flag (a chained hop is gated at the stage's
// tier; seeds at the tool's, never lower), or the tool's tier for a step
// outside the stage catalog.
func stepDispatchGate(run *scanrun.Run, resolved scanapp.StepTool) *command.DispatchGate {
	g := &command.DispatchGate{Tier: int(scanapp.ProbeTier(resolved.Name)), ActScope: true}
	if resolved.HasStage {
		g.Tier = int(resolved.Stage.Tier)
		g.Passive = resolved.Stage.Tier.Passive()
	}
	if actor := runActor(run); actor != nil {
		g.Actor = actor.String()
	}
	return g
}

// stageKeyOf is the catalog stage a resolved step runs ("" when none).
func stageKeyOf(resolved scanapp.StepTool) stage.Key {
	if !resolved.HasStage {
		return ""
	}
	return resolved.Stage.Key
}

// stepChunks cuts a step's targets into the chunks its commands carry:
// pieces of the capability's chunk size for a tool that takes a target
// list (stage.ChunkSizeFor), else one chunk with every target. A step with
// no explicit target list is one chunk (nil targets).
func stepChunks(resolved scanapp.StepTool, st *scanapp.StepTargets) []*scanapp.StepTargets {
	size := 0
	if resolved.HasStage {
		size = resolved.Stage.ChunkSizeFor(resolved.Name)
	}
	if st == nil || size <= 0 || len(st.Targets) <= size {
		return []*scanapp.StepTargets{st}
	}
	out := make([]*scanapp.StepTargets, 0, (len(st.Targets)+size-1)/size)
	for i := 0; i < len(st.Targets); i += size {
		end := min(i+size, len(st.Targets))
		out = append(out, &scanapp.StepTargets{Targets: st.Targets[i:end:end], Refused: st.Refused, Reason: st.Reason})
	}
	return out
}

// stepCommand builds one command of a step for the given chunk of its
// targets, after the payload passed the security validator.
func (s *Service) stepCommand(ctx context.Context, run *scanrun.Run, step *scanworkflow.Step, stepRun *scanrun.StepRun,
	chunk *scanapp.StepTargets, key stage.Key,
) (*command.Command, error) {
	payload, err := scanapp.StepCommandPayload(run, step, step.Tool, stepRun.ID.String(), chunk)
	if err != nil {
		return nil, fmt.Errorf("step %s: %w", step.StepKey, err)
	}
	if err := s.applyWebScope(ctx, run.TenantID, key, payload); err != nil {
		return nil, fmt.Errorf("step %s: %w", step.StepKey, err)
	}

	// Final payload validation before sending to sensor
	if s.securityValidator != nil {
		result := s.securityValidator.ValidateCommandPayload(ctx, run.TenantID, payload)
		if !result.Valid {
			s.logger.Error("SECURITY: command payload validation failed",
				"run_id", run.ID.String(),
				"step_key", step.StepKey,
				"errors", result.Errors)
			return nil, fmt.Errorf("security validation failed: %s", result.Errors[0].Message)
		}
	}

	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	cmd, err := command.NewCommand(run.TenantID, command.CommandTypeScan, command.CommandPriorityNormal, payloadBytes)
	if err != nil {
		return nil, err
	}
	// The command names its step run, so the reports bound to it are
	// attributed to the step (scan provenance, chained outputs) and the
	// step settles with its last command.
	cmd.SetStepRunID(stepRun.ID)
	return cmd, nil
}

// cancelStepCommands cancels the commands of a step already created when a
// later one cannot be, so a step that reports a queue failure leaves no
// chunk running.
func (s *Service) cancelStepCommands(ctx context.Context, cmds []*command.Command) {
	for _, c := range cmds {
		c.Cancel()
		if err := s.commandRepo.Update(ctx, c); err != nil {
			s.logger.Warn("failed to cancel step command", "command_id", c.ID.String(), "error", err)
		}
	}
}

// routeToPlatform decides whether a step's commands go to the platform
// queue (true) or to the tenant's own sensors (false). It never picks a
// sensor: any tenant sensor that has the tool may claim the command.
func (s *Service) routeToPlatform(ctx context.Context, tenantID shared.ID, tool string, pref scanworkflow.SensorPreference) bool {
	switch pref {
	case scanworkflow.SensorPreferenceTenant:
		return false
	case scanworkflow.SensorPreferencePlatform:
		if s.sensorSelector != nil {
			if canUse, _ := s.sensorSelector.CanUsePlatformSensors(ctx, tenantID); canUse {
				return true
			}
		}
		// Platform not available: fall back to the tenant's sensors.
	}
	// Auto: the selector prefers the tenant's sensors and goes to the
	// platform when none of them has the tool.
	if s.sensorSelector != nil {
		result, err := s.sensorSelector.SelectSensor(ctx, SelectSensorRequest{
			TenantID:     tenantID,
			Capabilities: []string{tool},
			Tool:         tool,
			Mode:         SelectTenantFirst,
			AllowQueue:   true,
		})
		if err == nil && result != nil && result.IsPlatform {
			return true
		}
	}
	return false
}

// stepUsesPlatform reports whether a step of run goes to platform sensors.
// A run started from a scan carries the scan's trigger-time decision
// (sensor_routing), made with the platform checks; it wins over the
// workflow's own preference. A run with no decision (started from a
// workflow directly) follows the workflow's preference.
func (s *Service) stepUsesPlatform(ctx context.Context, run *scanrun.Run, step *scanworkflow.Step, pref scanworkflow.SensorPreference) bool {
	switch scanrun.SensorRoutingFromContext(run.Context) {
	case scanrun.SensorRoutingTenant:
		return false
	case scanrun.SensorRoutingPlatform:
		return true
	case scanrun.SensorRoutingAuto:
		return s.routeToPlatform(ctx, run.TenantID, step.Tool, scanworkflow.SensorPreferenceAuto)
	}
	// A scan that runs on the tenant's own sensors only
	// (scans.run_on_tenant_runner, carried in the run context) never goes
	// to platform sensors, whatever the template says.
	if tenantRunnerOnly(run.Context) {
		pref = scanworkflow.SensorPreferenceTenant
	}
	return s.routeToPlatform(ctx, run.TenantID, step.Tool, pref)
}

// calculateScanRunInitialPriority calculates the initial queue priority for platform jobs.
func (s *Service) calculateScanRunInitialPriority(cmdPriority command.CommandPriority) int {
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
func (s *Service) refreshStepRuns(ctx context.Context, run *scanrun.Run) {
	fresh, err := s.stepRunRepo.GetByScanRunID(ctx, run.ID)
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
func (s *Service) skipBlockedSteps(ctx context.Context, run *scanrun.Run, template *scanworkflow.Workflow) {
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

// recordScanRun refreshes the run summary of the scan that spawned a run that
// just finished (the summary is recomputed from the runs, so status is only
// logged). No-op for workflow runs with no ScanID or when no recorder is
// wired; best-effort, since the run itself is already recorded and a
// scan-summary write must not fail the completion.
func (s *Service) recordScanRun(ctx context.Context, run *scanrun.Run, status string) {
	if s.scanRunRecorder == nil || run == nil || run.ScanID == nil {
		return
	}
	if err := s.scanRunRecorder.RefreshRunSummary(ctx, run.TenantID, *run.ScanID); err != nil {
		s.logger.Warn("failed to record run outcome on scan",
			"scan_id", run.ScanID.String(), "run_id", run.ID.String(), "status", status, "error", err)
	}
}

// finishRun moves the run to a terminal status. It reports whether THIS call
// made the transition: the repository refuses to move a run that already
// finished, so when two callers race (parallel final steps, a completion
// against a cancel or the timeout reaper) exactly one of them records the
// outcome on the scan, in metrics and in the audit log.
//
// A run that settles completed, partial or failed is handed to the
// run-settled callback (the `scan_completed` automation trigger, which
// filters on the outcome), with findings as its finding count.
func (s *Service) finishRun(ctx context.Context, run *scanrun.Run, status scanrun.RunStatus, message string, findings int) bool {
	err := s.runRepo.UpdateStatus(ctx, run.ID, status, message)
	if errors.Is(err, scanrun.ErrRunAlreadyFinished) {
		s.logger.Info("run already finished; not recording it again",
			"run_id", run.ID.String(), "status", string(status))
		return false
	}
	if err != nil {
		s.logger.Error("failed to update run status", "run_id", run.ID.String(), "status", string(status), "error", err)
		return false
	}
	metrics.ScanRunsInProgress.WithLabelValues().Dec()
	metrics.ScanRunsTotal.WithLabelValues(string(status)).Inc()
	s.recordScanRun(ctx, run, string(status))
	if s.runCompleted != nil {
		run.Status = status
		run.TotalFindings = findings
		s.runCompleted(ctx, run)
	}
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
	if err := s.stepRunRepo.AssignSensor(ctx, stepRun.ID, sensorID, commandID); err != nil {
		return err
	}
	s.notifyRunByID(ctx, rid)
	return nil
}

// OnStepCompleted is called when a sensor reports step completion.
// This triggers scheduling of dependent steps.
func (s *Service) OnStepCompleted(ctx context.Context, runID, stepKey string, findingsCount int, output map[string]any) error {
	return s.OnStepCompletedWithSkips(ctx, runID, stepKey, findingsCount, output, 0, "")
}

// OnStepCompletedWithSkips is OnStepCompleted for a command that completed
// with skipped targets: its sensor's local policy removed skipped of them
// (refused, or a name that did not resolve) and ran on the rest. The step
// ends partial with skippedSummary as its message (the results are kept),
// and so does the run; a skipped target is not retried, since the sensor
// would refuse it again.
func (s *Service) OnStepCompletedWithSkips(ctx context.Context, runID, stepKey string, findingsCount int, output map[string]any, skipped int, skippedSummary string) error {
	rid, err := shared.IDFromString(runID)
	if err != nil {
		return err
	}
	// The run id is parsed and the step key cleaned: both come from the
	// sensor's command result.
	s.logger.Info("step completed", "run_id", rid.String(), "step_key", logger.SanitizeValue(stepKey),
		"findings", findingsCount, "skipped_targets", skipped)

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
	if s.stepAlreadyFinished(run, stepRun, "completed") {
		return nil
	}

	// A zone-routed scan runs one command per batch under this step: the step
	// finishes with the last batch. If every batch failed the step fails; if
	// some failed and others completed it ends partial with the results it
	// has (RFC-046 D5).
	if b := s.checkStepBatches(ctx, run, stepRun); b.batched {
		if b.wait {
			return nil
		}
		if b.failed > 0 {
			return s.settleBatchedStep(ctx, run, stepRun, b)
		}
		findingsCount = b.findings
		skipped = b.skipped
		if skipped > 0 {
			skippedSummary = fmt.Sprintf("Completed with %d target(s) skipped by the sensor's local policy (see the tasks)", skipped)
		}
	}

	if stepRun != nil && skipped > 0 {
		stepRun.Partial(findingsCount, skippedSummary, scanrun.ErrCodeTargetsSkipped)
		if err := s.stepRunRepo.Update(ctx, stepRun); err != nil {
			s.logger.Error("failed to record partial step run", "step_key", stepKey, "error", err)
		}
		metrics.StepRunsTotal.WithLabelValues(stepKey, "partial").Inc()
	} else if stepRun != nil {
		stepRun.Complete(findingsCount, output)
		// FIXED: Don't silently suppress errors - log them instead
		if err := s.stepRunRepo.Update(ctx, stepRun); err != nil {
			s.logger.Error("failed to update step run status", "step_key", stepKey, "error", err)
		}
		// Record step metric
		metrics.StepRunsTotal.WithLabelValues(stepKey, "completed").Inc()
	}

	template, err := s.runWorkflow(ctx, run)
	if err != nil {
		return err
	}
	return s.advanceRun(ctx, run, template)
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
	if s.stepAlreadyFinished(run, stepRun, "failed") {
		return nil
	}
	if b := s.checkStepBatches(ctx, run, stepRun); b.batched {
		if b.wait {
			return nil // the batch's error stays on its command; the last batch reports
		}
		return s.settleBatchedStep(ctx, run, stepRun, b)
	}
	return s.failStep(ctx, run, stepRun, errorMessage, errorCode)
}

// stepAlreadyFinished reports (and logs) a result for a step run that already
// reached a terminal state. A finished step is final, like a finished run: a
// duplicate completion (a sensor retrying its report, a second command of the
// same step) or a failure that arrives after the step completed must not
// overwrite its outcome, recount its findings or settle the run a second time.
// The repository refuses such a write too (ErrStepRunAlreadyFinished); this
// check keeps the caller from acting on a result it is about to discard.
func (s *Service) stepAlreadyFinished(run *scanrun.Run, stepRun *scanrun.StepRun, outcome string) bool {
	if stepRun == nil || !stepRun.IsComplete() {
		return false
	}
	s.logger.Info("ignoring step result for a step that already finished",
		"run_id", run.ID.String(), "step_key", stepRun.StepKey,
		"step_status", string(stepRun.Status), "reported", outcome)
	return true
}

// settleBatchedStep records the outcome of a batched step once its last batch
// finished and at least one batch failed: failed when every batch failed,
// partial when some batches completed (their results are kept). A batched
// step is never retried as a step: a retry would re-dispatch it through the
// generic step path, without zone routing.
func (s *Service) settleBatchedStep(ctx context.Context, run *scanrun.Run, stepRun *scanrun.StepRun, b stepBatches) error {
	if b.failed >= b.total {
		return s.failStep(ctx, run, stepRun, b.summary(), errCodeBatchFailed)
	}
	if stepRun != nil {
		stepRun.Partial(b.findings, b.summary(), errCodeBatchFailed)
		if err := s.stepRunRepo.Update(ctx, stepRun); err != nil {
			s.logger.Error("failed to record partial step run", "step_key", stepRun.StepKey, "error", err)
		}
		metrics.StepRunsTotal.WithLabelValues(stepRun.StepKey, "partial").Inc()
	}
	template, err := s.runWorkflow(ctx, run)
	if err != nil {
		return err
	}
	return s.advanceRun(ctx, run, template)
}

// failStep records a step failure and settles the run.
//
// The failure is classified (D7): a failure a retry cannot fix (no such
// scanner on the sensor, target refused, nothing to scan, no sensor) keeps
// its class code, which the run-level retry controller never retries. Retries
// happen at run level only; the step-level retry that used to sit here could
// never fire (StepRun.CanRetry needs a step that is already failed, and a
// failure arrives while the step is still running).
func (s *Service) failStep(ctx context.Context, run *scanrun.Run, stepRun *scanrun.StepRun, errorMessage, errorCode string) error {
	if stepRun != nil {
		code, _ := scanrun.ClassifyStepFailure(errorCode, errorMessage)
		stepRun.Fail(errorMessage, code)
		// FIXED: Don't silently suppress errors - log them instead
		if err := s.stepRunRepo.Update(ctx, stepRun); err != nil {
			s.logger.Error("failed to update step run status to failed", "step_key", stepRun.StepKey, "error", err)
		}
		// Record failed step metric
		metrics.StepRunsTotal.WithLabelValues(stepRun.StepKey, "failed").Inc()
	}

	// Get template to check fail_fast setting
	template, err := s.runWorkflow(ctx, run)
	if err != nil {
		return err
	}

	// If fail_fast, mark run as failed
	if template.Settings.FailFast {
		s.refreshStepRuns(ctx, run)
		st := s.calculateRunStats(run)
		s.updateRunStats(ctx, run, st)
		s.finishRun(ctx, run, scanrun.RunStatusFailed, "Scan workflow failed: "+errorMessage, st.findings)
		return nil
	}

	return s.advanceRun(ctx, run, template)
}

// advanceRun runs after a step settled: it skips the steps whose dependencies
// can no longer succeed, records the run's counters, and either settles the
// run (every step finished) or schedules the steps that became runnable.
func (s *Service) advanceRun(ctx context.Context, run *scanrun.Run, template *scanworkflow.Workflow) error {
	// Whatever advancing does (next steps queued, skips, the run settled),
	// the live run map hears about it once it is done.
	defer s.notifyRun(run.TenantID, run.ID)
	s.refreshStepRuns(ctx, run)
	s.skipBlockedSteps(ctx, run, template)

	// Findings are summed from the stored step runs only (calculateRunStats):
	// adding the reported count on top used to count a step's findings twice.
	st := s.calculateRunStats(run)
	s.updateRunStats(ctx, run, st)

	if st.settled() < run.TotalSteps {
		// Schedule newly runnable steps (dependent steps whose dependencies are now complete)
		return s.scheduleRunnableSteps(ctx, run, template)
	}
	s.settleRun(ctx, run, st)
	return nil
}

// settleRun records the outcome of a run whose steps have all finished:
// completed when no step failed or ended partial, failed when no step
// produced results, partial otherwise (RFC-046 D5: some work done, some
// lost; the results are kept and the run is not retried as a whole).
func (s *Service) settleRun(ctx context.Context, run *scanrun.Run, st runStats) {
	qgResult := s.evaluateQualityGate(ctx, run)
	if qgResult != nil {
		run.SetQualityGateResult(qgResult)
		// FIXED: Don't silently suppress errors - log them instead
		if err := s.runRepo.Update(ctx, run); err != nil {
			s.logger.Error("failed to update run with quality gate result", "run_id", run.ID.String(), "error", err)
		}
	}
	qgPassed := qgResult == nil || qgResult.Passed

	// Targets zone routing could not place were never scanned (22c B7): a
	// run whose steps all finished but left targets out is partial, not
	// completed. Targets refused by policy (exclusions, ownership, act
	// scope) are not counted: the run did what it was allowed to do.
	outcome := st.outcome()
	uncovered := uncoveredTargetCount(run.Context)
	partialMsg := fmt.Sprintf("Scan run completed partially: %d of %d steps did not finish all their work", st.failed+st.partial, run.TotalSteps)
	if outcome == scanrun.RunStatusCompleted && uncovered > 0 {
		outcome = scanrun.RunStatusPartial
		partialMsg = fmt.Sprintf("Scan run completed, but %d target(s) were not scanned: no scan zone or sensor could reach them (see uncovered_targets)", uncovered)
	}

	switch outcome {
	case scanrun.RunStatusCompleted:
		if !s.finishRun(ctx, run, scanrun.RunStatusCompleted, "", st.findings) {
			return
		}

		s.logAudit(ctx, AuditContext{TenantID: run.TenantID.String()},
			NewSuccessEvent(audit.ActionScanRunCompleted, audit.ResourceTypeScanRun, run.ID.String()).
				WithMessage(fmt.Sprintf("Scan run completed successfully with %d findings", st.findings)).
				WithMetadata("completed_steps", st.completed).
				WithMetadata("total_findings", st.findings).
				WithMetadata("quality_gate_passed", qgPassed))
	case scanrun.RunStatusPartial:
		if !s.finishRun(ctx, run, scanrun.RunStatusPartial, partialMsg, st.findings) {
			return
		}
		s.logAudit(ctx, AuditContext{TenantID: run.TenantID.String()},
			NewSuccessEvent(audit.ActionScanRunPartial, audit.ResourceTypeScanRun, run.ID.String()).
				WithMessage(fmt.Sprintf("Scan run completed partially with %d findings (%d steps failed, %d partial)",
					st.findings, st.failed, st.partial)).
				WithMetadata("completed_steps", st.completed).
				WithMetadata("partial_steps", st.partial).
				WithMetadata("failed_steps", st.failed).
				WithMetadata("uncovered_targets", uncovered).
				WithMetadata("total_findings", st.findings).
				WithMetadata("quality_gate_passed", qgPassed))
	default:
		if !s.finishRun(ctx, run, scanrun.RunStatusFailed, failedRunMessage(run), st.findings) {
			return
		}
		s.logAudit(ctx, AuditContext{TenantID: run.TenantID.String()},
			NewFailureEvent(audit.ActionScanRunFailed, audit.ResourceTypeScanRun, run.ID.String(),
				fmt.Errorf("scan run completed with %d step failures", st.failed)).
				WithMessage(fmt.Sprintf("Scan run failed with %d step failures", st.failed)).
				WithMetadata("completed_steps", st.completed).
				WithMetadata("failed_steps", st.failed).
				WithMetadata("total_findings", st.findings).
				WithMetadata("quality_gate_passed", qgPassed))
	}
}

// failedRunMessage says why a run failed: the first failed step, its reason
// and its code (NO_MATCHING_TOOL, INCOMPATIBLE_TARGETS, ...), so the run
// shows the cause without opening its steps.
func failedRunMessage(run *scanrun.Run) string {
	for _, sr := range run.StepRuns {
		if sr == nil || sr.Status != scanrun.StepRunStatusFailed {
			continue
		}
		name := sr.StepName
		if name == "" {
			name = sr.StepKey
		}
		msg := fmt.Sprintf("Step %q failed", name)
		if sr.ErrorMessage != "" {
			msg += ": " + sr.ErrorMessage
		}
		if sr.ErrorCode != "" {
			msg += " (" + sr.ErrorCode + ")"
		}
		return msg
	}
	return "Scan run completed with failures"
}

// uncoveredTargetCount is how many targets the run's zone routing could not
// place (the scan trigger records them): the zone summary's count, else the
// length of the (bounded) uncovered list.
func uncoveredTargetCount(runContext map[string]any) int {
	if routing, ok := runContext["zone_routing"].(map[string]any); ok {
		switch n := routing["uncovered_targets"].(type) {
		case int:
			if n > 0 {
				return n
			}
		case float64:
			if n > 0 {
				return int(n)
			}
		}
	}
	if v := reflect.ValueOf(runContext["uncovered_targets"]); v.IsValid() && v.Kind() == reflect.Slice {
		return v.Len()
	}
	return 0
}

// updateRunStats stores the run's step counters. A partial step is stored
// under failed_steps: the columns say how many steps finished all their work
// and how many did not, and still add up to the steps that settled.
func (s *Service) updateRunStats(ctx context.Context, run *scanrun.Run, st runStats) {
	// FIXED: Don't silently suppress errors - log them instead
	if err := s.runRepo.UpdateStats(ctx, run.ID, st.completed, st.failed+st.partial, st.skipped, st.findings); err != nil {
		s.logger.Error("failed to update run stats", "run_id", run.ID.String(), "error", err)
	}
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
	skipped    int // targets the completed batches' sensors skipped
	firstError string
}

func (b stepBatches) summary() string {
	msg := fmt.Sprintf("%d of %d scan batches failed", b.failed, b.total)
	if b.firstError != "" {
		msg += ": " + b.firstError
	}
	if b.skipped > 0 {
		msg += fmt.Sprintf("; %d target(s) skipped by the sensor's local policy", b.skipped)
	}
	return msg
}

// checkStepBatches reports whether stepRun is a batched step and, if so,
// whether this caller should record its outcome now. A step with zero or one
// command is not batched and keeps the original single-command behavior.
func (s *Service) checkStepBatches(ctx context.Context, run *scanrun.Run, stepRun *scanrun.StepRun) stepBatches {
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
	b := stepBatches{batched: true, total: st.Total, failed: st.Failed, findings: st.Findings, skipped: st.Skipped, firstError: st.FirstError}
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

// runStats counts a run's step runs by outcome.
type runStats struct {
	completed, partial, failed, skipped, findings int
}

// settled is how many steps reached an outcome that counts towards the run
// finishing.
func (st runStats) settled() int {
	return st.completed + st.partial + st.failed + st.skipped
}

// outcome is the run's status once every step settled: completed when no
// step failed or ended partial, failed when no step produced results,
// partial otherwise.
func (st runStats) outcome() scanrun.RunStatus {
	switch {
	case st.failed == 0 && st.partial == 0:
		return scanrun.RunStatusCompleted
	case st.completed == 0 && st.partial == 0:
		return scanrun.RunStatusFailed
	default:
		return scanrun.RunStatusPartial
	}
}

// calculateRunStats calculates run statistics from step runs.
func (s *Service) calculateRunStats(run *scanrun.Run) runStats {
	var st runStats
	for _, sr := range run.StepRuns {
		switch sr.Status {
		case scanrun.StepRunStatusCompleted:
			st.completed++
			st.findings += sr.FindingsCount
		case scanrun.StepRunStatusPartial:
			st.partial++
			st.findings += sr.FindingsCount
		case scanrun.StepRunStatusFailed:
			st.failed++
		case scanrun.StepRunStatusSkipped:
			st.skipped++
		}
	}
	return st
}

// evaluateQualityGate evaluates the quality gate for a completed scan run.
// Returns nil if quality gate is not configured or dependencies are not available.
func (s *Service) evaluateQualityGate(ctx context.Context, run *scanrun.Run) *scanprofile.QualityGateResult {
	// Check if QG dependencies are available
	if s.scanProfileRepo == nil || s.findingRepo == nil {
		return nil
	}

	// Check if run has a scan profile
	if run.ScanProfileID == nil {
		return nil
	}

	// Get the scan profile
	profile, err := s.scanProfileRepo.GetByTenantAndID(ctx, run.TenantID, *run.ScanProfileID)
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
	// For scan runs, we need to aggregate findings from all step runs
	// The run.TotalFindings contains the count, but we need severity breakdown
	// We'll use the finding repository to get counts by severity

	// Note: We need a scan session ID or run ID to query findings.
	// For scan runs, findings are typically associated with a scan_session_id in the context.
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
func (s *Service) evaluateCondition(_ context.Context, step *scanworkflow.Step, run *scanrun.Run, _ *scanworkflow.Workflow) bool {
	return step.ConditionMet(run)
}

// GetRun retrieves a scan run by ID.
func (s *Service) GetRun(ctx context.Context, tenantID, runID string) (*scanrun.Run, error) {
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

// GetRunWithSteps retrieves a scan run with its step runs.
func (s *Service) GetRunWithSteps(ctx context.Context, runID string) (*scanrun.Run, error) {
	rid, err := shared.IDFromString(runID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid run id", shared.ErrValidation)
	}

	return s.runRepo.GetWithStepRuns(ctx, rid)
}

// GetRunWithStepsForTenant returns a run of tenantID with its step runs. A
// run of another tenant is not found.
func (s *Service) GetRunWithStepsForTenant(ctx context.Context, tenantID, runID string) (*scanrun.Run, error) {
	if _, err := s.GetRun(ctx, tenantID, runID); err != nil {
		return nil, err
	}
	return s.GetRunWithSteps(ctx, runID)
}

// RunTasks is a run's tasks as the runs page shows them.
type RunTasks struct {
	Summary scanrun.TaskSummary
	Items   []scanrun.Task
	// Truncated is true when the run has more tasks than Items holds.
	Truncated bool
	// NextCursor continues after Items (GET /scan-runs/{id}/tasks) when
	// Truncated; empty otherwise.
	NextCursor string
}

// DefaultRunTaskPageSize is the page size of a run's task list.
const DefaultRunTaskPageSize = 50

// RunTaskPage is one page of a run's tasks.
type RunTaskPage struct {
	Items []scanrun.Task
	// NextCursor continues after Items; empty on the last page.
	NextCursor string
}

// ListRunTasksPage returns one page of the tasks of run runID of tenantID, in
// dispatch order, after cursor (from the first task when empty). A run of
// another tenant is not found; a malformed cursor or a page size outside
// 1..scanrun.MaxRunTasks is a validation error.
func (s *Service) ListRunTasksPage(ctx context.Context, tenantID, runID, cursor string, limit int) (*RunTaskPage, error) {
	if limit == 0 {
		limit = DefaultRunTaskPageSize
	}
	if limit < 1 || limit > scanrun.MaxRunTasks {
		return nil, fmt.Errorf("%w: per_page must be between 1 and %d", shared.ErrValidation, scanrun.MaxRunTasks)
	}
	var after *scanrun.TaskCursor
	if cursor != "" {
		c, err := scanrun.DecodeTaskCursor(cursor)
		if err != nil {
			return nil, err
		}
		after = &c
	}
	// The run is read for the caller's tenant first: another tenant's run id
	// answers not found, exactly like GET /scan-runs/{id}.
	run, err := s.GetRun(ctx, tenantID, runID)
	if err != nil {
		return nil, err
	}
	pager, ok := s.commandRepo.(scanrun.TaskPager)
	if !ok {
		return &RunTaskPage{}, nil
	}
	// One extra row says whether another page follows.
	items, err := pager.ListRunTasksAfter(ctx, run.TenantID, run.ID, after, limit+1)
	if err != nil {
		return nil, err
	}
	page := &RunTaskPage{Items: items}
	if len(items) > limit {
		page.Items = items[:limit]
		page.NextCursor = scanrun.TaskCursorAfter(page.Items[limit-1]).Encode()
	}
	return page, nil
}

// GetRunTasks returns up to scanrun.MaxRunTasks tasks of a run of tenantID
// and the summary of all of them. Nil when the repository cannot read tasks.
// The caller must already have read the run for tenantID.
func (s *Service) GetRunTasks(ctx context.Context, run *scanrun.Run) (*RunTasks, error) {
	reader, ok := s.commandRepo.(scanrun.TaskReader)
	if !ok || run == nil {
		return nil, nil
	}
	items, sum, err := reader.ListRunTasks(ctx, run.TenantID, run.ID, scanrun.MaxRunTasks)
	if err != nil {
		return nil, err
	}
	out := &RunTasks{Summary: sum, Items: items, Truncated: sum.Total > len(items)}
	if out.Truncated && len(items) > 0 {
		out.NextCursor = scanrun.TaskCursorAfter(items[len(items)-1]).Encode()
	}
	return out, nil
}

// RunScanNames returns the name of the scan of each run in runs that belongs
// to a scan of tenantID, keyed by scan id. Nil when the repository cannot
// name scans. Every run must belong to tenantID; the read is scoped to it.
func (s *Service) RunScanNames(ctx context.Context, tenantID string, runs []*scanrun.Run) (map[shared.ID]string, error) {
	namer, ok := s.runRepo.(scanrun.RunScanNamer)
	if !ok || len(runs) == 0 {
		return nil, nil
	}
	tid, err := shared.IDFromString(tenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}
	seen := make(map[shared.ID]struct{}, len(runs))
	ids := make([]shared.ID, 0, len(runs))
	for _, r := range runs {
		if r.ScanID == nil {
			continue
		}
		if _, dup := seen[*r.ScanID]; dup {
			continue
		}
		seen[*r.ScanID] = struct{}{}
		ids = append(ids, *r.ScanID)
	}
	return namer.ScanNames(ctx, tid, ids)
}

// RunTaskSummaries returns the task summary of each run in runs that has
// tasks, keyed by run id. Every run must belong to tenantID; the read is
// scoped to it.
func (s *Service) RunTaskSummaries(ctx context.Context, tenantID string, runs []*scanrun.Run) (map[shared.ID]scanrun.TaskSummary, error) {
	reader, ok := s.commandRepo.(scanrun.TaskReader)
	if !ok || len(runs) == 0 {
		return nil, nil
	}
	tid, err := shared.IDFromString(tenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}
	ids := make([]shared.ID, 0, len(runs))
	for _, r := range runs {
		ids = append(ids, r.ID)
	}
	return reader.TaskSummaries(ctx, tid, ids)
}

// ListRunsInput represents the input for listing runs.
type ListRunsInput struct {
	TenantID       string `json:"tenant_id" validate:"required,uuid"`
	ScanWorkflowID string `json:"scan_workflow_id" validate:"omitempty,uuid"`
	ScanID         string `json:"scan_id" validate:"omitempty,uuid"`
	AssetID        string `json:"asset_id" validate:"omitempty,uuid"`
	Status         string `json:"status" validate:"omitempty,oneof=pending running completed partial failed canceled timeout blocked"`
	// Kinds narrows to these run kinds (scan, quick, retest, ...).
	Kinds []string `json:"kind"`
	// IncludeSystem lists system runs too (hidden by default).
	IncludeSystem bool `json:"include_system"`
	// ExcludeKinds leaves these kinds out (set by the handler, not the
	// client: runs about a finding the caller may not see).
	ExcludeKinds []string `json:"-"`
	// Sort is one sort key, `field` or `-field` (scanrun.RunListSortFields);
	// an unknown field is a validation error.
	Sort    string `json:"sort"`
	Page    int    `json:"page"`
	PerPage int    `json:"per_page"`
}

// ListRuns lists scan runs with filters.
func (s *Service) ListRuns(ctx context.Context, input ListRunsInput) (pagination.Result[*scanrun.Run], error) {
	tenantID, err := shared.IDFromString(input.TenantID)
	if err != nil {
		return pagination.Result[*scanrun.Run]{}, fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}

	sort, err := scanrun.ParseRunListSort(input.Sort)
	if err != nil {
		return pagination.Result[*scanrun.Run]{}, err
	}

	filter := scanrun.RunFilter{
		TenantID: &tenantID,
		Sort:     sort,
	}

	// A filter id that does not parse is refused: silently dropping it would
	// answer with every run of the tenant instead of the narrowed list.
	for _, f := range []struct {
		name, raw string
		dst       **shared.ID
	}{
		{"scan_workflow_id", input.ScanWorkflowID, &filter.ScanWorkflowID},
		{"scan_id", input.ScanID, &filter.ScanID},
		{"asset_id", input.AssetID, &filter.AssetID},
	} {
		if f.raw == "" {
			continue
		}
		id, err := shared.IDFromString(f.raw)
		if err != nil {
			return pagination.Result[*scanrun.Run]{}, fmt.Errorf("%w: invalid %s", shared.ErrValidation, f.name)
		}
		*f.dst = &id
	}

	for _, k := range input.Kinds {
		kind := scanrun.RunKind(k)
		if !kind.IsValid() {
			return pagination.Result[*scanrun.Run]{}, fmt.Errorf("%w: invalid kind", shared.ErrValidation)
		}
		filter.Kinds = append(filter.Kinds, kind)
	}
	for _, k := range input.ExcludeKinds {
		filter.ExcludeKinds = append(filter.ExcludeKinds, scanrun.RunKind(k))
	}
	// System runs are housekeeping: hidden unless asked for or named.
	filter.ExcludeSystem = !input.IncludeSystem && len(filter.Kinds) == 0

	if input.Status != "" {
		st := scanrun.RunStatus(input.Status)
		if !st.IsValid() {
			return pagination.Result[*scanrun.Run]{}, fmt.Errorf("%w: invalid status", shared.ErrValidation)
		}
		filter.Status = &st
	}

	page := pagination.New(input.Page, input.PerPage)
	return s.runRepo.List(ctx, filter, page)
}

// CancelRun cancels a scan run, its open step runs and its open commands
// (RFC-046 §8, D12). The sensors holding those commands are told to stop on
// their next heartbeat (cancel_command_ids); an offline sensor is told when
// it comes back and reports what it runs, and its canceled commands are never
// re-queued by the expired-lease sweep.
//
// Idempotent: canceling a run that is already canceled succeeds and closes
// anything a previous attempt left open, without recording the run again.
// Canceling a run that finished otherwise is INVALID_STATE. A run of another
// tenant is not found.
func (s *Service) CancelRun(ctx context.Context, tenantID, runID string) error {
	run, err := s.GetRun(ctx, tenantID, runID)
	if err != nil {
		return err
	}

	if run.Status == scanrun.RunStatusCanceled {
		s.closeCanceledRun(ctx, run)
		return nil
	}
	if run.IsComplete() {
		return shared.NewDomainError("INVALID_STATE", "scan run is already complete", shared.ErrValidation)
	}

	// Through the guarded status transition, not a full-row write of the copy
	// read above: if the run finished in the meantime the cancel is refused
	// instead of turning a completed run into a canceled one (and counting it
	// on the scan a second time).
	err = s.runRepo.UpdateStatus(ctx, run.ID, scanrun.RunStatusCanceled, "Canceled by user")
	if errors.Is(err, scanrun.ErrRunAlreadyFinished) {
		// Another cancel won the race: same outcome, nothing more to record.
		if cur, gerr := s.GetRun(ctx, tenantID, runID); gerr == nil && cur.Status == scanrun.RunStatusCanceled {
			s.closeCanceledRun(ctx, cur)
			return nil
		}
		return shared.NewDomainError("INVALID_STATE", "scan run is already complete", shared.ErrValidation)
	}
	if err != nil {
		return err
	}
	run.Cancel()
	metrics.ScanRunsInProgress.WithLabelValues().Dec()
	metrics.ScanRunsTotal.WithLabelValues(string(scanrun.RunStatusCanceled)).Inc()
	s.recordScanRun(ctx, run, string(scanrun.RunStatusCanceled))

	closure := s.closeCanceledRun(ctx, run)
	s.notifyRun(run.TenantID, run.ID)
	// A canceled run finished too: automations listening for finished runs
	// hear about it (research/62 P0-11).
	if s.runCompleted != nil {
		s.runCompleted(ctx, run)
	}

	event := NewSuccessEvent(audit.ActionScanRunCanceled, audit.ResourceTypeScanRun, runID).
		WithMessage("Scan run canceled").
		WithMetadata("canceled_steps", closure.Steps).
		WithMetadata("canceled_commands", closure.Commands).
		WithMetadata("sensors_told_to_stop", len(closure.Sensors))
	if run.ScanID != nil {
		event = event.WithMetadata("scan_id", run.ScanID.String())
	}
	s.logAudit(ctx, AuditContext{TenantID: tenantID}, event)

	return nil
}

// closeCanceledRun ends the open step runs and commands of a canceled run.
// Best effort: the run is already canceled, and a failure here is retried by
// canceling again (idempotent) or settled by the timeout reaper.
func (s *Service) closeCanceledRun(ctx context.Context, run *scanrun.Run) scanrun.CanceledRunClosure {
	if closer, ok := s.runRepo.(scanrun.CanceledRunCloser); ok {
		closure, err := closer.CloseCanceledRun(ctx, run.TenantID, run.ID)
		if err != nil {
			s.logger.Warn("failed to close the canceled run's steps and commands",
				"run_id", run.ID.String(), "error", err)
			return scanrun.CanceledRunClosure{}
		}
		if closure.Steps > 0 || closure.Commands > 0 {
			s.logger.Info("closed canceled run", "run_id", run.ID.String(),
				"steps", closure.Steps, "commands", closure.Commands, "sensors", len(closure.Sensors))
		}
		return closure
	}
	// Repositories without the closer: commands only, as before.
	if s.commandRepo == nil {
		return scanrun.CanceledRunClosure{}
	}
	n, err := s.commandRepo.CancelByScanRunID(ctx, run.TenantID, run.ID)
	if err != nil {
		s.logger.Warn("failed to cancel commands for scan run", "run_id", run.ID.String(), "error", err)
		return scanrun.CanceledRunClosure{}
	}
	return scanrun.CanceledRunClosure{Commands: n}
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

	return s.stepRunRepo.UpdateStatus(ctx, srid, scanrun.StepRunStatusFailed, errorMessage, errorCode)
}

// tenantRunnerOnly reports whether the run's scan may run only on the
// tenant's own sensors (the scan trigger records it as tenant_runner_only).
func tenantRunnerOnly(runContext map[string]any) bool {
	v, _ := runContext["tenant_runner_only"].(bool)
	return v
}

// AdvanceRun re-evaluates a run right after its trigger queued the first
// steps (scan.RunAdvancer): a step that could not be queued is failed, its
// dependents are skipped, and a run in which nothing else can run settles at
// once with that step's reason.
func (s *Service) AdvanceRun(ctx context.Context, run *scanrun.Run) error {
	if run == nil {
		return fmt.Errorf("%w: run is required", shared.ErrValidation)
	}
	template, err := s.runWorkflow(ctx, run)
	if err != nil {
		return fmt.Errorf("load the run's workflow: %w", err)
	}
	if template == nil {
		return fmt.Errorf("%w: the run's workflow", shared.ErrNotFound)
	}
	return s.advanceRun(ctx, run, template)
}

// QueueRunStep queues one step of a run: the dispatcher a scan's workflow
// trigger hands its first steps to, so every step command of every run is
// built by queueStepForExecutionWithSettings (research/27 P0-2). A step that
// cannot be queued is failed with the reason's code and the error returned.
func (s *Service) QueueRunStep(ctx context.Context, run *scanrun.Run, step *scanworkflow.Step) error {
	if run == nil || step == nil {
		return fmt.Errorf("%w: run and step are required", shared.ErrValidation)
	}
	template, err := s.runWorkflow(ctx, run)
	if err != nil {
		return fmt.Errorf("load the run's template: %w", err)
	}
	if template == nil {
		return fmt.Errorf("%w: the run's template", shared.ErrNotFound)
	}
	stepRun := run.GetStepRun(step.StepKey)
	if stepRun == nil {
		if stepRun, err = s.stepRunRepo.GetByStepKey(ctx, run.ID, step.StepKey); err != nil {
			return fmt.Errorf("load step run %s: %w", step.StepKey, err)
		}
	}
	if qerr := s.queueStepForExecutionWithSettings(ctx, run, step, stepRun, template.Settings, predecessorsOf(template, step)); qerr != nil {
		if errors.Is(qerr, errStageAlreadyPlanned) {
			return nil // queued by a concurrent call
		}
		s.failQueuedStep(ctx, stepRun, step.StepKey, qerr)
		s.notifyRun(run.TenantID, run.ID)
		return qerr
	}
	s.notifyRun(run.TenantID, run.ID)
	return nil
}

// failQueuedStep records a step that could not be queued: failed, with the
// domain code of the reason (INCOMPATIBLE_TARGETS, NO_MATCHING_TOOL, ...) or
// QUEUE_ERROR.
func (s *Service) failQueuedStep(ctx context.Context, stepRun *scanrun.StepRun, stepKey string, err error) {
	if stepRun == nil {
		return
	}
	code := "QUEUE_ERROR"
	var de *shared.DomainError
	if errors.As(err, &de) && de.Code != "" {
		code = de.Code
	}
	stepRun.Fail("Failed to queue: "+err.Error(), code)
	if uerr := s.stepRunRepo.Update(ctx, stepRun); uerr != nil {
		s.logger.Error("failed to update failed step run", "step_key", stepKey, "error", uerr)
	}
}

// NotifyRunsReaped hands the runs the timeout controller ended (timed out,
// partial at the deadline, failed for lack of a sensor) to the run-finished
// callback, like a run that settled on its own. Each run is read in its own
// tenant.
func (s *Service) NotifyRunsReaped(ctx context.Context, reaped []scanrun.ReapedRun) {
	if s.runCompleted == nil {
		return
	}
	for _, r := range reaped {
		run, err := s.runRepo.GetByTenantAndID(ctx, r.TenantID, r.RunID)
		if err != nil || run == nil || run.TenantID != r.TenantID || !run.IsComplete() {
			continue
		}
		s.runCompleted(ctx, run)
	}
}

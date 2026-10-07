package scan

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/scanrun"
	"github.com/openctemio/openctem/api/pkg/domain/scanworkflow"

	"github.com/openctemio/openctem/api/internal/app/scope"
	"github.com/openctemio/openctem/api/internal/metrics"
	"github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/domain/assetgroup"
	"github.com/openctemio/openctem/api/pkg/domain/audit"
	"github.com/openctemio/openctem/api/pkg/domain/command"
	"github.com/openctemio/openctem/api/pkg/domain/scan"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
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
	// RetryAttempt is set by the retry controller: the new run is created
	// with it, so the retry budget is enforced even when the run finishes
	// before anything could update it afterwards.
	RetryAttempt int `json:"-"`
	// TriggerType is recorded on the run; empty means manual. The scheduler
	// sends schedule (every run used to be recorded as manual).
	TriggerType scanworkflow.TriggerType `json:"-"`
	// SkipIfRunning refuses the trigger with ErrScanRunInProgress while the
	// scan has an active run (overlap policy for scheduled runs, D4: skip the
	// occurrence and record that it was skipped, never pile runs up).
	SkipIfRunning bool `json:"-"`
	// ScheduledFor is the schedule occurrence the scheduler claimed; the run
	// records it and a scan gets at most one run per occurrence
	// (scanrun.ErrOccurrenceAlreadyRun otherwise). nil for every other trigger.
	ScheduledFor *time.Time `json:"-"`
	// FreezeOverride starts the scan although a freeze window is active.
	// The HTTP layer sets it only when the caller asked for it and holds
	// scans:freeze:override; it is audited and never honored for a
	// scheduled run.
	FreezeOverride bool `json:"-"`
	// Interactive is a member's own "Run now" (POST /scans/{id}/trigger).
	// Pausing a scan turns its schedule off; it does not stop a member from
	// running it by hand. Automatic triggers (schedule, retry, automations)
	// still need the scan active. A disabled scan runs for nobody.
	Interactive bool `json:"-"`
}

// ErrScanRunInProgress is returned when a trigger with SkipIfRunning finds
// the scan's previous run still active.
var ErrScanRunInProgress = scanrun.ErrScanRunActive

// ErrScanActorRequired is returned when a scan would be created (clone,
// import) without the person who owns it.
var ErrScanActorRequired = fmt.Errorf("%w: the acting user is required", shared.ErrValidation)

// ErrScanHasNoOwner is returned when a scheduled run is due for a scan with
// no owner (created_by). Such a run would act as the unrestricted system, so
// it is refused (research 21b H2/H3, RFC-050 SP-3).
var ErrScanHasNoOwner = shared.NewDomainError("SCAN_HAS_NO_OWNER",
	"This scan has no owner, so its scheduled runs are refused. Clone or re-save it as a member to take ownership.",
	shared.ErrValidation)

// ErrScanOwnerInactive is returned when a scheduled run is due for a scan
// whose owner is no longer an active member; the scan is paused.
var ErrScanOwnerInactive = shared.NewDomainError("SCAN_OWNER_INACTIVE",
	"This scan's owner is disabled or left the organization, so the scan was paused. Reassign it to resume.",
	shared.ErrValidation)

// OwnerActivity reports whether a user is an active member of a tenant with
// an active account (postgres.AccessControlRepository.IsActiveTenantMember).
type OwnerActivity interface {
	IsActiveTenantMember(ctx context.Context, tenantID, userID shared.ID) (bool, error)
}

// SetOwnerActivity wires the owner check of scheduled runs.
func (s *Service) SetOwnerActivity(o OwnerActivity) { s.ownerActivity = o }

// refuseOwnerlessSchedule stops a scheduled run that would act for nobody:
// a scan without an owner is refused, a scan whose owner is no longer active
// is paused and refused. A lookup error refuses (fail closed).
func (s *Service) refuseOwnerlessSchedule(ctx context.Context, sc *scan.Scan) error {
	if sc.CreatedBy == nil || sc.CreatedBy.IsZero() {
		s.logAudit(ctx, AuditContext{TenantID: sc.TenantID.String()},
			NewFailureEvent(audit.ActionScanConfigTriggered, audit.ResourceTypeScanConfig, sc.ID.String(), ErrScanHasNoOwner).
				WithResourceName(sc.Name).WithMessage("Scheduled run refused: the scan has no owner"))
		return ErrScanHasNoOwner
	}
	if s.ownerActivity == nil {
		return nil
	}
	active, err := s.ownerActivity.IsActiveTenantMember(ctx, sc.TenantID, *sc.CreatedBy)
	if err != nil {
		return fmt.Errorf("check scan owner, run refused: %w", err)
	}
	if active {
		return nil
	}
	if perr := sc.Pause(); perr == nil {
		if uerr := s.scanRepo.Update(ctx, sc); uerr != nil {
			s.logger.Warn("failed to pause a scan whose owner is inactive", "scan_id", sc.ID.String(), "error", uerr)
		}
	}
	s.logAudit(ctx, AuditContext{TenantID: sc.TenantID.String()},
		NewFailureEvent(audit.ActionScanConfigTriggered, audit.ResourceTypeScanConfig, sc.ID.String(), ErrScanOwnerInactive).
			WithResourceName(sc.Name).WithMessage("Scheduled run refused and scan paused: the owner is not an active member"))
	return ErrScanOwnerInactive
}

// TriggerScan triggers a scan execution.
func (s *Service) TriggerScan(ctx context.Context, input TriggerScanExecInput) (*scanrun.Run, error) {
	s.logger.Info("triggering scan", "scan_id", input.ScanID)

	sc, err := s.GetScan(ctx, input.TenantID, input.ScanID)
	if err != nil {
		return nil, err
	}
	if input.TriggerType == "" {
		input.TriggerType = scanworkflow.TriggerTypeManual
	}

	run, err := s.triggerLoadedScan(ctx, sc, input)
	if err != nil {
		// A refusal becomes a blocked run with its reason; either way the
		// scan's summary is recomputed from its runs (a run that failed
		// while starting is one of them).
		s.recordBlockedRun(ctx, sc, input, input.TriggerType, err)
		s.refreshRunSummary(ctx, sc)
		return nil, err
	}
	s.refreshRunSummary(ctx, sc)

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

// triggerLoadedScan runs every trigger gate and dispatches the scan's run.
// An error before the run exists is a refusal (TriggerScan records it as a
// blocked run); one after is wrapped with afterRunCreated.
func (s *Service) triggerLoadedScan(ctx context.Context, sc *scan.Scan, input TriggerScanExecInput) (*scanrun.Run, error) {
	if !sc.CanTrigger() && !(input.Interactive && sc.Status == scan.StatusPaused) {
		// Give the user a specific, actionable error message based on the current state.
		var msg string
		switch sc.Status {
		case scan.StatusPaused:
			msg = fmt.Sprintf("Scan '%s' is paused: its schedule is off and automatic runs are refused. Resume it, or run it by hand.", sc.Name)
		case scan.StatusDisabled:
			msg = fmt.Sprintf("Cannot trigger scan '%s' because it is disabled. Activate the scan first to trigger it.", sc.Name)
		default:
			msg = fmt.Sprintf("Cannot trigger scan '%s' (current status: %s). Only active scans can be triggered.", sc.Name, sc.Status)
		}
		return nil, shared.NewDomainError("SCAN_NOT_TRIGGERABLE", msg, shared.ErrValidation)
	}

	// NOTE: Concurrent run limits are now checked atomically in CreateRunIfUnderLimit
	// to prevent race conditions where multiple triggers bypass the limit.
	// This early check only saves the work of resolving targets for an
	// occurrence that will be skipped; the guarantee is the same check in
	// CreateRunIfUnderLimit, under the scan row lock, for every scheduled run.
	if input.SkipIfRunning {
		active, err := s.runRepo.CountActiveByScanID(ctx, sc.ID)
		if err != nil {
			return nil, fmt.Errorf("failed to check active runs: %w", err)
		}
		if active > 0 {
			return nil, ErrScanRunInProgress
		}
	}
	triggerType := input.TriggerType
	// A scheduled run acts as the scan's owner: refuse when there is none
	// and pause when the owner is no longer an active member.
	if triggerType == scanworkflow.TriggerTypeSchedule {
		if err := s.refuseOwnerlessSchedule(ctx, sc); err != nil {
			return nil, err
		}
	}

	// The organization's sensor opt-ins (research/25 D3): interactsh is
	// removed for this run, custom templates refuse the trigger.
	optInWarning, err := s.applyOptInsAtTrigger(ctx, sc)
	if err != nil {
		return nil, err
	}
	if optInWarning != "" {
		if input.Context == nil {
			input.Context = map[string]any{}
		}
		warnings, _ := input.Context["dispatch_warnings"].([]string)
		input.Context["dispatch_warnings"] = append(warnings, optInWarning)
	}

	// Validate tools are still available and active before triggering
	// (Tools may have been disabled or removed since scan was created)
	if err := s.validateToolsAtTriggerTime(ctx, sc); err != nil {
		return nil, err
	}
	// A tool no online sensor may run refuses the trigger with the reason,
	// rather than queueing jobs nobody claims.
	if err := s.checkScanToolsDispatchable(ctx, sc); err != nil {
		return nil, err
	}

	// A wildcard pattern: its root domain for a discovery tool, refused for
	// any other (scans saved before this rule, or edited in the database).
	sc, err = s.applyWildcardTargets(ctx, sc)
	if err != nil {
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

	// Execute based on scan type
	if sc.ScanType == scan.ScanTypeWorkflow {
		return s.triggerWorkflow(ctx, sc, triggerType, input.TriggeredBy, input.Context, input.RetryAttempt, input.ScheduledFor, input.FreezeOverride)
	}
	return s.triggerSingleScan(ctx, sc, triggerType, input.TriggeredBy, input.Context, input.RetryAttempt, input.ScheduledFor, input.FreezeOverride)
}

// triggerWorkflow triggers a workflow scan workflow execution.
func (s *Service) triggerWorkflow(ctx context.Context, sc *scan.Scan, triggerType scanworkflow.TriggerType, triggeredBy string, runContext map[string]any, retryAttempt int, scheduledFor *time.Time, freezeOverride bool) (*scanrun.Run, error) {
	if sc.ScanWorkflowID == nil {
		return nil, fmt.Errorf("%w: scan_workflow_id is required for workflow", shared.ErrValidation)
	}

	// Get scan workflow
	template, err := s.templateRepo.GetByID(ctx, *sc.ScanWorkflowID)
	if err != nil {
		return nil, shared.NewDomainError(
			"PIPELINE_NOT_FOUND",
			fmt.Sprintf("ScanRun template '%s' not found. It may have been deleted.", sc.ScanWorkflowID.String()),
			shared.ErrNotFound,
		)
	}

	// Verify template is active
	if !template.IsActive {
		return nil, shared.NewDomainError(
			"PIPELINE_DISABLED",
			fmt.Sprintf("ScanRun template '%s' is disabled. Please enable it or use a different pipeline.", template.Name),
			shared.ErrValidation,
		)
	}

	// Get workflow steps
	steps, err := s.stepRepo.GetByScanWorkflowID(ctx, template.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to get pipeline steps: %w", err)
	}

	// Validate scan workflow has steps
	if len(steps) == 0 {
		return nil, shared.NewDomainError(
			"PIPELINE_EMPTY",
			fmt.Sprintf("ScanRun '%s' has no steps. Please add at least one step.", template.Name),
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
	// The zone of the run is the routing decision below, never a value from
	// the trigger context a caller sent: it stamps every step command and
	// decides which freeze windows apply.
	delete(runContext, scanrun.RunContextKeyScanZoneID)
	delete(runContext, scanrun.RunContextKeySensorRouting)
	// Who the run acts for (act scope of chained stages): the person who
	// triggered it, else the scan's owner. Never sent to a sensor.
	if actor := userIDPtr(triggeredBy); actor != nil {
		runContext[RunContextKeyActor] = actor.String()
	} else if sc.CreatedBy != nil {
		runContext[RunContextKeyActor] = sc.CreatedBy.String()
	}
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
	s.planRolloverFirst(ctx, sc, triggerType, resolved, runContext)
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

	var zoneIDs []shared.ID
	if zid := scanrun.ScanZoneFromContext(runContext); zid != nil {
		zoneIDs = []shared.ID{*zid}
	} else {
		// The scan's sensor preference decides, with the checks a single
		// scan gets; the workflow's own preference does not (research/62
		// SG-11). Every step of the run follows this decision.
		routing, err := s.decideWorkflowRouting(ctx, sc, targets)
		if err != nil {
			return nil, err
		}
		routing.record(runContext)
	}
	override, err := s.checkFreeze(ctx, sc, freezeRequest{triggerType, triggeredBy, freezeOverride}, zoneIDs, workflowActive(steps))
	if err != nil {
		return nil, err
	}

	// Create scan run
	run, err := scanrun.NewRun(template.ID, sc.TenantID, nil, triggerType, triggeredBy, runContext)
	if err != nil {
		return nil, fmt.Errorf("failed to create pipeline run: %w", err)
	}
	run.FreezeOverride = override
	run.SetTotalSteps(len(steps))
	run.RetryAttempt = retryAttempt
	run.ScheduledFor = scheduledFor
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
		stepRun := scanrun.NewStepRunForStep(run.ID, step)
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
	if err := s.scheduleWorkflowSteps(ctx, run, steps, template.Settings.MaxParallelSteps); err != nil {
		var de *shared.DomainError
		if errors.As(err, &de) && de.Code == codeWorkflowCannotStart {
			return nil, afterRunCreated(err) // the run is already failed with the reason
		}
		s.logger.Warn("failed to schedule workflow steps", "error", err)
	}

	return run, nil
}

// QuickScanTemplateID is the system template ID for quick/single scans.
// This template is created during database migration/seed.
const QuickScanTemplateID = "00000000-0000-0000-0000-000000000001"

// triggerSingleScan triggers a single scanner execution.
func (s *Service) triggerSingleScan(ctx context.Context, sc *scan.Scan, triggerType scanworkflow.TriggerType, triggeredBy string, runContext map[string]any, retryAttempt int, scheduledFor *time.Time, freezeOverride bool) (*scanrun.Run, error) {
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
	// Proof can be lost after the scan was saved: re-check at every run.
	if err := s.refuseUnprovenIntrusive(ctx, sc.TenantID, sc.ScannerName, resolved.Targets); err != nil {
		return nil, err
	}
	s.planRolloverFirst(ctx, sc, triggerType, resolved, runContext)

	// A connector scan (RFC-047) is one command for the connector's sensor;
	// the sensor's zone routing and platform routing below do not apply.
	if _, connector := s.isConnectorScanner(ctx, sc.TenantID, sc.ScannerName); connector {
		return s.triggerConnectorScan(ctx, sc, resolved, triggerType, triggeredBy, runContext, retryAttempt, scheduledFor, freezeOverride)
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
	if len(zones) > 0 && s.toolReachesNetwork(ctx, sc.TenantID, sc.ScannerName) {
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

	// Targets for the tenant's sensors outside any zone go only where a
	// sensor's reported local policy accepts them (research/25 §3.6).
	if !routing.usePlatform() {
		if err := s.applyUnzonedPreflight(ctx, sc, plan, resolved.Targets, runContext); err != nil {
			return nil, err
		}
	}

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

	override, err := s.checkFreeze(ctx, sc, freezeRequest{triggerType, triggeredBy, freezeOverride}, planZoneIDs(plan), singleScanActive(sc))
	if err != nil {
		return nil, err
	}

	// Use the system quick scan template for tracking
	quickScanTemplateID, _ := shared.IDFromString(QuickScanTemplateID)

	// Create a scan run using the system template
	run, err := scanrun.NewRun(quickScanTemplateID, sc.TenantID, nil, triggerType, triggeredBy, runContext)
	if err != nil {
		return nil, fmt.Errorf("failed to create run: %w", err)
	}
	run.FreezeOverride = override
	run.SetTotalSteps(1)
	run.RetryAttempt = retryAttempt
	run.ScheduledFor = scheduledFor
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
		return nil, afterRunCreated(fmt.Errorf("failed to create scanner command: %w", err))
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
func (s *Service) createSingleScanStepRun(ctx context.Context, run *scanrun.Run) *scanrun.StepRun {
	steps, err := s.stepRepo.GetByScanWorkflowID(ctx, run.ScanWorkflowID)
	if err != nil || len(steps) == 0 {
		s.logger.Warn("quick scan template has no steps; run cannot report completion",
			"run_id", run.ID.String(), "scan_workflow_id", run.ScanWorkflowID.String(), "error", err)
		return nil
	}

	// steps[0] is the lowest step_order: GetByScanWorkflowID sorts ASC. A single
	// scan dispatches one scanner command, so one step run is what completion
	// is measured against — matching the SetTotalSteps(1) above.
	step := steps[0]
	stepRun := scanrun.NewStepRunForStep(run.ID, step)
	if err := s.stepRunRepo.Create(ctx, stepRun); err != nil {
		s.logger.Warn("failed to create step run for single scan",
			"run_id", run.ID.String(), "error", err)
		return nil
	}
	run.AddStepRun(stepRun)
	return stepRun
}

// scheduleWorkflowSteps starts a new workflow run: every step without
// dependencies whose condition holds is queued, up to the template's parallel
// limit (the scan run service starts the rest as dependencies succeed).
//
// It used to queue only steps with step_order == 1: a workflow whose
// independent steps had other orders ran them one after another, a workflow
// numbered from 0 or 2 never started at all (and hung until the run timeout),
// and step conditions were ignored for the first step.
func (s *Service) scheduleWorkflowSteps(ctx context.Context, run *scanrun.Run, steps []*scanworkflow.Step, maxParallel int) error {
	if maxParallel <= 0 {
		maxParallel = 3
	}
	queued, roots := 0, 0
	for _, step := range steps { // sorted by step_order
		if len(step.DependsOn) > 0 {
			continue
		}
		roots++
		if !step.ConditionMet(run) {
			s.skipWorkflowStep(ctx, run, step, step.ConditionSkipReason())
			continue
		}
		if queued >= maxParallel {
			continue // started by the scan run service as slots free up
		}
		if s.stepQueuer == nil {
			return ErrStepQueuerUnavailable
		}
		if err := s.stepQueuer.QueueRunStep(ctx, run, step); err != nil {
			return err
		}
		queued++
	}
	if queued == 0 {
		msg := "workflow has no step without dependencies; nothing can start"
		if roots > 0 {
			msg = "no step started: the condition of every first step was false"
		}
		run.Fail(msg)
		if err := s.runRepo.UpdateStatus(ctx, run.ID, scanrun.RunStatusFailed, msg); err != nil {
			s.logger.Warn("failed to fail a run that cannot start", "run_id", run.ID.String(), "error", err)
		}
		return shared.NewDomainError(codeWorkflowCannotStart, msg, shared.ErrValidation)
	}
	return nil
}

// codeWorkflowCannotStart: a workflow run in which no step can start.
const codeWorkflowCannotStart = "WORKFLOW_CANNOT_START"

// skipWorkflowStep marks a step run skipped at trigger time.
func (s *Service) skipWorkflowStep(ctx context.Context, run *scanrun.Run, step *scanworkflow.Step, reason string) {
	stepRuns, err := s.stepRunRepo.GetByScanRunID(ctx, run.ID)
	if err != nil {
		s.logger.Warn("failed to load step runs", "run_id", run.ID.String(), "error", err)
		return
	}
	for _, sr := range stepRuns {
		if sr.StepID == step.ID {
			sr.Skip(reason)
			if err := s.stepRunRepo.Update(ctx, sr); err != nil {
				s.logger.Warn("failed to skip step run", "step_key", step.StepKey, "error", err)
			}
			if inRun := run.GetStepRun(step.StepKey); inRun != nil {
				inRun.Skip(reason)
			}
			return
		}
	}
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
// (`scan_run_id`, `step_key`, `scan_run_step_id`); `run_id` is kept because the
// sensor SDK reads it.
func (s *Service) createScannerCommand(ctx context.Context, sc *scan.Scan, run *scanrun.Run, stepRun *scanrun.StepRun, targets []string, usePlatform bool) error {
	templates := s.customTemplatesForScan(ctx, sc)
	payloadMap := s.scannerPayload(sc, run, stepRun, sc.ScannerConfig, run.Context, targets, templates)
	payload, _ := json.Marshal(payloadMap)

	cmd, err := command.NewCommand(sc.TenantID, command.CommandTypeScan, command.CommandPriorityNormal, payload)
	if err != nil {
		return err
	}
	cmd.FreezeOverride = run.FreezeOverride

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

// scannerPayload builds the payload of a single-scanner command.
func (s *Service) scannerPayload(
	sc *scan.Scan, run *scanrun.Run, stepRun *scanrun.StepRun,
	scannerConfig map[string]any, runContext map[string]any,
	targets []string, templates []EmbeddedTemplate,
) map[string]any {
	payloadMap := map[string]any{
		"run_id":             run.ID.String(),
		"scan_id":            sc.ID.String(),
		"scanner_name":       sc.ScannerName,
		"scanner_config":     scannerConfig,
		"asset_group_id":     sc.AssetGroupID.String(),
		"targets_per_job":    sc.TargetsPerJob,
		"routing_tags":       sc.Tags,
		"tenant_runner_only": sc.RunOnTenantRunner,
		"context":            StepRunContext(runContext, nil),
		// The sensor SDK (ScanCommandPayload) reads `scanner`, `config` and a
		// single `target`, not `scanner_name`/`scanner_config` — send both sets
		// so the command dispatches correctly (contract drift previously left
		// the sensor with an empty scanner: "scanner not found").
		"scanner": sc.ScannerName,
		"config":  scannerConfig,
	}
	// The command handler reads `scan_run_id` + `step_key` to route a
	// finished command back into the scan workflow; a payload carrying only `run_id`
	// is silently treated as "not a scan workflow command" and the run is never
	// advanced, completed, or failed.
	if stepRun != nil {
		payloadMap[scanrun.PayloadKeyScanRunID] = run.ID.String()
		payloadMap[scanrun.PayloadKeyStepKey] = stepRun.StepKey
		payloadMap[scanrun.PayloadKeyStepRunID] = stepRun.ID.String()
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
		metrics.TemplateSyncsTotal.WithLabelValues(string(source.SourceType)).Inc()
		if result.Success {
			metrics.TemplateSyncsSuccessTotal.WithLabelValues().Inc()
			s.logger.Info("template source synced",
				"source_id", source.ID.String(),
				"source_name", source.Name,
				"templates_found", result.TemplatesFound,
				"templates_added", result.TemplatesAdded)
		} else {
			metrics.TemplateSyncsFailedTotal.WithLabelValues().Inc()
		}
	}

	if len(syncErrors) > 0 {
		return fmt.Errorf("some syncs failed: %v", syncErrors)
	}

	return nil
}

const (
	sensorRoutingTenant   = scanrun.SensorRoutingTenant
	sensorRoutingPlatform = scanrun.SensorRoutingPlatform
	sensorRoutingAuto     = scanrun.SensorRoutingAuto

	runContextKeySensorRouting = scanrun.RunContextKeySensorRouting
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

// decideWorkflowRouting is decideSensorRouting for a workflow scan, whose
// steps use different tools. 'platform' is checked and refused exactly as
// for a single scan. In 'auto' mode the run may reach platform sensors only
// when nothing in it is internal, every target is proven where the operator
// requires it and the tenant may use them; each step then goes there only
// when no tenant sensor has its tool. Otherwise the run stays on the
// tenant's sensors.
func (s *Service) decideWorkflowRouting(ctx context.Context, sc *scan.Scan, targets []string) (sensorRouting, error) {
	switch {
	case sc.RunOnTenantRunner || sc.SensorPreference == scan.SensorPreferenceTenant:
		return sensorRouting{Routing: sensorRoutingTenant}, nil
	case sc.SensorPreference == scan.SensorPreferencePlatform:
		return s.decideSensorRouting(ctx, sc, targets, nil)
	}
	if s.sensorSelector == nil || sc.HasAssetGroup() || hasInternalTarget(targets) {
		return sensorRouting{Routing: sensorRoutingTenant}, nil
	}
	if s.platformNeedsProof() {
		unproven, err := s.unverified(ctx, sc.TenantID, targets)
		if err != nil {
			s.logger.Warn("target proof lookup failed; run kept on tenant sensors",
				"error", err, "scan_id", sc.ID.String())
			return sensorRouting{Routing: sensorRoutingTenant,
				Warning: "target proof lookup failed; the run is queued for tenant sensors only"}, nil
		}
		if len(unproven) > 0 {
			return sensorRouting{Routing: sensorRoutingTenant}, nil
		}
	}
	if canUse, _ := s.sensorSelector.CanUsePlatformSensors(ctx, sc.TenantID); !canUse {
		return sensorRouting{Routing: sensorRoutingTenant}, nil
	}
	return sensorRouting{Routing: sensorRoutingAuto}, nil
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

	// Platform sensors probe from the platform's addresses: with the
	// operator's proof requirement every target must be at or under a
	// verified domain of the tenant (RFC-054 §8.1).
	var unproven []string
	if s.platformNeedsProof() && !internal {
		var err error
		if unproven, err = s.unverified(ctx, sc.TenantID, targets); err != nil {
			return false, err
		}
	}

	// If explicitly set to platform only, the tenant must be allowed and the
	// targets must be public.
	if sc.SensorPreference == scan.SensorPreferencePlatform {
		if internal {
			return false, shared.NewDomainError("PLATFORM_SENSOR_REFUSED",
				"sensor_preference is 'platform', but shared platform sensors never scan asset groups or internal targets; set sensor_preference to 'tenant' or 'auto', or scan only public targets",
				shared.ErrValidation)
		}
		if err := proofError("platform sensors probe only verified domains", unproven); err != nil {
			return false, err
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

	// Auto: tenant sensors first. Shared sensors only if the tenant may use them,
	// nothing in the scan is internal and every target is proven where the
	// operator requires it; otherwise the job waits.
	if s.sensorSelector == nil || internal || len(unproven) > 0 {
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
		return s.validateSingleScanTool(ctx, sc.TenantID, sc.ScannerName)
	case scan.ScanTypeWorkflow:
		return s.validateWorkflowStepTools(ctx, sc)
	}
	return nil
}

// validateSingleScanTool checks that the scanner tool is available and active.
func (s *Service) validateSingleScanTool(ctx context.Context, tenantID shared.ID, scannerName string) error {
	if scannerName == "" {
		return nil
	}

	tool, err := s.toolRepo.GetByName(ctx, tenantID, scannerName)
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
	if tool.IsCollector() {
		return shared.NewDomainError(
			"TOOL_NOT_SCANNER",
			fmt.Sprintf("'%s' is an asset collector, not a scanner: it runs on its collector sensor's own schedule. Use a scanner.", scannerName),
			shared.ErrValidation,
		)
	}
	if tool.IsConnector() && s.connectorScans == nil {
		return ErrConnectorScansUnavailable
	}

	return s.checkTenantToolEnabled(ctx, tenantID, tool)
}

// validateWorkflowStepTools validates all tools required by workflow workflow steps.
func (s *Service) validateWorkflowStepTools(ctx context.Context, sc *scan.Scan) error {
	if sc.ScanWorkflowID == nil {
		return shared.NewDomainError(
			"PIPELINE_NOT_SET",
			"Workflow scan has no pipeline configured",
			shared.ErrValidation,
		)
	}

	steps, err := s.stepRepo.GetByScanWorkflowID(ctx, *sc.ScanWorkflowID)
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

// validateStepTool validates a single workflow step's tool configuration.
func (s *Service) validateStepTool(ctx context.Context, tenantID shared.ID, step *scanworkflow.Step) error {
	switch {
	case step.Tool != "":
		tool, err := s.toolRepo.GetByName(ctx, tenantID, step.Tool)
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
		if tool.IsCollector() {
			return shared.NewDomainError(
				"TOOL_NOT_SCANNER",
				fmt.Sprintf("'%s' used by step '%s' is an asset collector, not a scanner: it runs on its collector sensor's own schedule. Use a scanner.", step.Tool, step.StepKey),
				shared.ErrValidation,
			)
		}
		if tool.IsConnector() {
			return shared.NewDomainError(
				"TOOL_NOT_SCANNER",
				fmt.Sprintf("'%s' used by step '%s' is a connector, not a scanner: it runs on its integration's connector commands. Use a scanner.", step.Tool, step.StepKey),
				shared.ErrValidation,
			)
		}
		if err := s.checkTenantToolEnabled(ctx, tenantID, tool); err != nil {
			return err
		}
	case len(step.Capabilities) > 0:
		// The planner's own rule (step_plan.go), so a step that validates
		// is a step the dispatcher can name a scanner for (F1).
		resolved, err := ResolveStepTool(ctx, s.toolRepo, tenantID, step)
		if err != nil {
			return err
		}
		// The tenant may have turned the resolved platform tool off.
		if matchingTool, gerr := s.toolRepo.GetPlatformToolByName(ctx, resolved.Name); gerr == nil && matchingTool != nil {
			if err := s.checkTenantToolEnabled(ctx, tenantID, matchingTool); err != nil {
				return err
			}
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
	if r.Archived > 0 {
		runContext["archived_target_count"] = r.Archived
	}
	if len(r.Warnings) > 0 {
		prev, _ := runContext["dispatch_warnings"].([]string)
		runContext["dispatch_warnings"] = append(prev, r.Warnings...)
	}
	if r.Unconfirmed > 0 {
		runContext["unconfirmed_target_count"] = r.Unconfirmed
	}
	if r.Incompatible > 0 {
		runContext["incompatible_target_count"] = r.Incompatible
	}
	if r.TierExceeded > 0 {
		runContext["tier_exceeded_target_count"] = r.TierExceeded
	}
	if len(r.TargetTypes) > 0 {
		runContext[RunContextKeyTargetTypes] = r.TargetTypes
	}
	if len(r.Targets) == 0 && r.Incompatible > 0 && r.Unconfirmed == 0 && r.Excluded == 0 {
		return shared.NewDomainError(codeNoCompatibleTargets,
			fmt.Sprintf("Scan %q has no target its scanner can scan: %s. Pick a scanner for these asset types or change the asset group.", sc.Name, r.IncompatibleReason),
			shared.ErrValidation)
	}
	if len(r.Targets) == 0 && r.TierExceeded > 0 && r.Unconfirmed == 0 && r.Excluded == 0 {
		return shared.NewDomainError(codeTierExceeds,
			fmt.Sprintf("No target of scan %q may be probed at this scanner's tier: the scope entries covering them allow less. Raise the entry's tier in Scoping > Targets, or use a less intrusive scanner.", sc.Name),
			shared.ErrValidation)
	}
	if len(r.Targets) == 0 && r.Unconfirmed > 0 && r.Excluded == 0 {
		return shared.NewDomainError("ALL_TARGETS_UNCONFIRMED",
			fmt.Sprintf("No target of scan %q is authorized for active scanning; nothing to scan. Confirm their ownership on each asset's Ownership tab, or cover them with a scope target in Scoping > Targets.", sc.Name),
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

// groupScanMember is a group member to dispatch: the asset id, the name the
// scanner is handed, and every value scope exclusions are tested against.
type groupScanMember struct {
	ID          shared.ID
	Name        string
	MatchValues []string
	// Type is the stored (type, sub_type) the scanner type gate reads.
	Type asset.TypeRef
}

// groupScanMemberPage is the keyset page size for group members; the
// repository caps it at 1000.
const groupScanMemberPage = 1000

// listGroupScanMembers reads an asset group's scannable members, one asset
// each, in keyset pages: only assets of the scan's tenant, archived assets
// left out and counted. Offset paging over a list ordered by name could skip
// or repeat members when two shared a sort key or the group changed mid-read.
func (s *Service) listGroupScanMembers(ctx context.Context, tenantID, groupID shared.ID) ([]groupScanMember, int, error) {
	var (
		out      []groupScanMember
		archived int
		q        = assetgroup.ScanMemberQuery{TenantID: tenantID, GroupID: groupID, Limit: groupScanMemberPage}
	)
	for {
		page, err := s.assetGroupRepo.ListScanMembers(ctx, q)
		if err != nil {
			return nil, 0, err
		}
		archived += int(page.ArchivedCount)
		for _, m := range page.Members {
			out = append(out, groupScanMember{
				ID:          m.ID,
				Name:        m.Name,
				MatchValues: scope.AssetExclusionValues(m.Type, m.Name, m.Properties),
				Type:        asset.TypeRef{Type: asset.AssetType(m.Type), SubType: m.SubType},
			})
		}
		// Stop before materializing a huge group: exclusions only remove
		// targets, so this many members can never fit in one run.
		if len(out) > 2*maxResolvedTargets {
			return nil, 0, fmt.Errorf("%w: asset group %s has more than %d scannable assets, more than the %d targets allowed per run",
				shared.ErrValidation, groupID, 2*maxResolvedTargets, maxResolvedTargets)
		}
		// An empty page ends the read; a short one does not, so a repository
		// that clamps the page size cannot cut the group short.
		if len(page.Members) == 0 {
			return out, archived, nil
		}
		last := page.Members[len(page.Members)-1]
		q.AfterName, q.AfterID = last.Name, last.ID
	}
}

// filterAssetsForSingleScan applies smart filtering based on scanner-asset compatibility.
// Returns FilteringResult showing which assets will be scanned vs skipped.
func (s *Service) filterAssetsForSingleScan(ctx context.Context, sc *scan.Scan) (*FilteringResult, error) {
	// Skip if no target mapping repo configured
	if s.targetMappingRepo == nil {
		return nil, nil
	}

	// Get scanner tool to check supported targets
	scannerTool, err := s.toolRepo.GetByName(ctx, sc.TenantID, sc.ScannerName)
	if err != nil {
		return nil, fmt.Errorf("get scanner tool: %w", err)
	}

	// If tool has no supported targets defined, scan all assets (no filtering)
	if len(scannerTool.SupportedTargets) == 0 {
		return nil, nil
	}

	// Get asset type counts across every asset group of the scan
	assetTypeCounts := map[asset.TypeRef]int64{}
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

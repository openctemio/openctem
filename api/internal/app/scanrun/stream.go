package scanrun

// Stage streaming: a chained step takes the results of its predecessor
// task by task, as each task's report is ingested, instead of waiting for
// the whole predecessor step. Design: docs/rfcs/RFC-137-stage-streaming.md;
// architecture: docs/architecture/scan-stages.md §3.6.
//
// Every gate stays where it is: each wave goes through the same hop router
// path (deriveStage: type contract, strict parse, hop limit, fan-out caps,
// the one target gate, zone, delta gating) and the same dispatch
// (dispatchStep: placement, chunking, host keys, claim-time gate, deadline
// admission), so a sensor still receives a signed job with an explicit
// target list. Only the timing changes.
//
// The stream of a stage is its plan row (scan_run_stage_plans): opened by
// the first wave, extended by later waves under a per-stage lock, closed by
// the closing wave once the predecessor finished and its last report was
// ingested. A target is decided once per stage and run: a wave dispatches
// only the planned targets it inserted. A streamed step settles only after
// its stream closed and its last command finished (checkStepBatches,
// settleClosedStream): whoever sees both last records the outcome.

import (
	"context"
	"errors"
	"fmt"
	"time"

	scanapp "github.com/openctemio/openctem/api/internal/app/scan"
	"github.com/openctemio/openctem/api/internal/metrics"
	"github.com/openctemio/openctem/api/pkg/domain/attribution"
	"github.com/openctemio/openctem/api/pkg/domain/command"
	"github.com/openctemio/openctem/api/pkg/domain/scanrun"
	"github.com/openctemio/openctem/api/pkg/domain/scanworkflow"
	"github.com/openctemio/openctem/api/pkg/domain/stage"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// WithStageStreaming turns stage streaming on (the platform switch,
// SCAN_STAGE_STREAMING). A workflow can still keep every stage behind its
// predecessors (Settings.StageBarrier).
func WithStageStreaming(on bool) Option {
	return func(s *Service) { s.streaming = on }
}

// How a step that a successor streams from is cut: into about streamSplit
// chunks, none smaller than streamMinChunk targets (and never larger than
// the capability's chunk size), so the successor starts on the first
// quarter of the hosts instead of waiting for all of them. A hop costs
// seconds (claim, sign, report, ingest); a barrier on a large step costs
// minutes.
const (
	streamSplit    = 4
	streamMinChunk = 10
)

// queueOpts are the variants of queueing a step.
type queueOpts struct {
	// stream: the step starts while its feeding predecessor still runs.
	stream bool
	// splitForStream: a successor streams from the step; cut it smaller.
	splitForStream bool
}

// streamChunkSize is the chunk size of a step of n targets that a
// successor streams from, for a capability chunk size of size.
func streamChunkSize(size, n int) int {
	if size <= streamMinChunk || n <= streamMinChunk {
		return size
	}
	c := (n + streamSplit - 1) / streamSplit
	return min(max(c, streamMinChunk), size)
}

// streamingFor reports whether the run's workflow streams: the platform
// switch is on, the workflow does not keep its stages behind barriers, and
// the stores can hold a stream and count a step's commands.
func (s *Service) streamingFor(template *scanworkflow.Workflow) bool {
	if !s.streaming || s.hops == nil || template == nil || template.Settings.StageBarrier {
		return false
	}
	if _, ok := s.hops.(scanrun.StageStreamStore); !ok {
		return false
	}
	_, ok := s.commandRepo.(command.StepBatchGate)
	return ok
}

// streamStage is the step's stage when it may take its input as a stream:
// a catalog stage below intrusive (an intrusive stage is never fed derived
// targets), and not a web stage that picks endpoints since the run started
// (the selection reads the whole crawl).
func streamStage(step *scanworkflow.Step) (stage.Stage, bool) {
	st, ok := stage.ForStep(step.Tool, step.Capabilities)
	if !ok || st.Tier >= stage.TierIntrusive {
		return st, false
	}
	if webConsumers[st.Key] && scanworkflow.EndpointSelectorOf(step.Config) != scanworkflow.EndpointSelectorAll {
		return st, false
	}
	return st, true
}

// streamSource is the one predecessor a pending step may stream from now:
// every other dependency finished with results (completed), and this one
// is queued or running and its stage feeds the step's. Nil when there is
// none (no dependency left: the barrier path plans the step; two or more
// unfinished: the step waits).
func streamSource(run *scanrun.Run, template *scanworkflow.Workflow, step *scanworkflow.Step, completed map[string]bool) *scanworkflow.Step {
	st, ok := streamStage(step)
	if !ok {
		return nil
	}
	preds := predecessorsOf(template, step)
	if len(preds) != len(step.DependsOn) {
		return nil // a dependency the template does not have
	}
	var src *scanworkflow.Step
	for _, p := range preds {
		if completed[p.StepKey] {
			continue
		}
		if src != nil {
			return nil
		}
		src = p
	}
	if src == nil {
		return nil
	}
	sr := run.GetStepRun(src.StepKey)
	if sr == nil || !(sr.IsQueued() || sr.IsRunning()) {
		return nil
	}
	ps, ok := stage.ForStep(src.Tool, src.Capabilities)
	if !ok || !stage.Feeds(ps, st) {
		return nil
	}
	return src
}

// feedsStream reports whether a successor of the step may stream from it.
func feedsStream(template *scanworkflow.Workflow, step *scanworkflow.Step) bool {
	if template == nil || step == nil {
		return false
	}
	ps, ok := stage.ForStep(step.Tool, step.Capabilities)
	if !ok {
		return false
	}
	for _, t := range template.Steps {
		for _, dep := range t.DependsOn {
			if dep != step.StepKey {
				continue
			}
			if st, ok := streamStage(t); ok && stage.Feeds(ps, st) {
				return true
			}
		}
	}
	return false
}

// sourceFinishedATask reports whether the step run has a completed command
// (only a finished task has results to stream).
func (s *Service) sourceFinishedATask(ctx context.Context, run *scanrun.Run, sr *scanrun.StepRun) bool {
	gate, ok := s.commandRepo.(command.StepBatchGate)
	if !ok || sr == nil {
		return false
	}
	b, err := gate.StepBatchState(ctx, run.TenantID, sr.ID)
	if err != nil {
		s.logger.Warn("stage streaming: read the source step's commands", "run_id", run.ID.String(),
			"step_key", logger.SanitizeValue(sr.StepKey), "error", err)
		return false
	}
	return b.Total-b.Active-b.Failed > 0
}

// streamStepOpen reports whether the step run's stage streamed and whether
// its stream is still open. False, false without a stream store.
func (s *Service) streamStepOpen(ctx context.Context, run *scanrun.Run, stepRun *scanrun.StepRun) (streamed, open bool) {
	store, ok := s.hops.(scanrun.StageStreamStore)
	if !ok || stepRun == nil {
		return false, false
	}
	p, found, err := store.StageStream(ctx, run.TenantID, run.ID, stepRun.StepKey)
	if err != nil {
		// Unknown: keep the step open (a later completion, the closing wave
		// or the stall repair settles it) rather than settle it early.
		s.logger.Warn("stage streaming: read the stage's stream", "run_id", run.ID.String(),
			"step_key", logger.SanitizeValue(stepRun.StepKey), "error", err)
		return true, true
	}
	if !found {
		return false, false
	}
	return p.Streamed, p.StreamOpen
}

// streamPass is what advanceStreams did: the steps it owns this pass (the
// barrier pass leaves them) and whether it settled one (the run must be
// advanced again).
type streamPass struct {
	handled map[string]bool
	settled bool
	started int
}

// advanceStreams runs before the barrier scheduling of a run: it plans a
// wave of every open stream (the closing wave once every dependency of the
// step finished), and starts streaming the pending steps whose one
// unfinished dependency already finished a task.
func (s *Service) advanceStreams(ctx context.Context, run *scanrun.Run, template *scanworkflow.Workflow,
	completed map[string]bool, running, maxParallel int,
) streamPass {
	pass := streamPass{handled: map[string]bool{}}
	if !s.streamingFor(template) {
		return pass
	}
	plans, err := s.hops.ListStagePlans(ctx, run.TenantID, run.ID)
	if err != nil {
		s.logger.Warn("stage streaming: list the run's stage plans", "run_id", run.ID.String(), "error", err)
		return pass
	}
	byKey := make(map[string]scanrun.StagePlan, len(plans))
	for _, p := range plans {
		byKey[p.StageKey] = p
	}
	for _, step := range template.Steps {
		sr := run.GetStepRun(step.StepKey)
		if sr == nil {
			continue
		}
		if p, planned := byKey[step.StepKey]; planned {
			if !p.Streamed {
				continue
			}
			pass.handled[step.StepKey] = true
			if !p.StreamOpen {
				continue
			}
			if s.streamWave(ctx, run, template, step, sr, p, allDependenciesFinished(run, step)) {
				pass.settled = true
			}
			continue
		}
		if !sr.IsPending() || running+pass.started >= maxParallel {
			continue
		}
		src := streamSource(run, template, step, completed)
		if src == nil || !s.sourceFinishedATask(ctx, run, run.GetStepRun(src.StepKey)) {
			continue
		}
		// A step its condition, the scan's intensity or the run's depth
		// skips is left to the barrier pass, which records the skip.
		if !s.evaluateCondition(ctx, step, run, template) || scanapp.IntensitySkipReason(run, step) != "" || depthSkipReason(run, step) != "" {
			continue
		}
		pass.handled[step.StepKey] = true
		if s.startStream(ctx, run, template, step, sr, src) {
			pass.settled = true
		}
		if sr.IsQueued() {
			pass.started++
		}
	}
	return pass
}

// allDependenciesFinished reports whether every dependency of the step
// reached a terminal state (results or not).
func allDependenciesFinished(run *scanrun.Run, step *scanworkflow.Step) bool {
	for _, dep := range step.DependsOn {
		sr := run.GetStepRun(dep)
		if sr == nil || !sr.IsComplete() {
			return false
		}
	}
	return true
}

// startStream queues a pending step on its seeds and what its source's
// finished tasks produced (the first wave). It returns whether it settled
// the step.
func (s *Service) startStream(ctx context.Context, run *scanrun.Run, template *scanworkflow.Workflow,
	step *scanworkflow.Step, sr *scanrun.StepRun, src *scanworkflow.Step,
) bool {
	err := s.queueStepForExecutionWithSettings(ctx, run, step, sr, template.Settings, predecessorsOf(template, step),
		queueOpts{stream: true, splitForStream: feedsStream(template, step)})
	var noInputs *noInputsError
	var tooClose *deadlineTooCloseError
	switch {
	case err == nil:
		metrics.ScanStageStreamWaves.WithLabelValues("start", "dispatched").Inc()
		s.observeFirstSuccessor(run, src)
		s.logger.Info("streamed step started before its predecessor finished",
			"run_id", run.ID.String(), "step_key", logger.SanitizeValue(step.StepKey), "source", logger.SanitizeValue(src.StepKey))
	case errors.Is(err, errStreamWaiting):
		metrics.ScanStageStreamWaves.WithLabelValues("start", "empty").Inc()
	case errors.Is(err, errStageDeferred):
		metrics.ScanStageStreamWaves.WithLabelValues("start", "deferred").Inc()
	case errors.Is(err, errStageAlreadyPlanned):
	case errors.As(err, &tooClose):
		s.settleStepDeadlineTooClose(ctx, run, sr, step.StepKey, tooClose)
		return true
	case errors.As(err, &noInputs):
		s.settleNoInputs(ctx, sr, step.StepKey, noInputs)
		return true
	default:
		s.logger.Error("failed to start a streamed step", "step_key", logger.SanitizeValue(step.StepKey), "error", logger.SanitizeError(err))
		s.failQueuedStep(ctx, sr, step.StepKey, err)
		return true
	}
	return false
}

// observeFirstSuccessor records how long after its source started a
// successor got its first targets.
func (s *Service) observeFirstSuccessor(run *scanrun.Run, src *scanworkflow.Step) {
	sr := run.GetStepRun(src.StepKey)
	if sr == nil {
		return
	}
	from := sr.StartedAt
	if from == nil {
		from = sr.QueuedAt
	}
	if from != nil {
		metrics.ScanStageTimeToFirstSuccessor.WithLabelValues("stream").Observe(time.Since(*from).Seconds())
	}
}

// streamWave plans one later wave of an open stream and dispatches the
// targets it added; closing (every dependency finished) closes the stream
// afterwards and settles the step when nothing of it is still running. It
// returns whether it settled the step. Failures are logged: the next
// ingest, completion or the stall repair runs the wave again.
func (s *Service) streamWave(ctx context.Context, run *scanrun.Run, template *scanworkflow.Workflow,
	step *scanworkflow.Step, sr *scanrun.StepRun, plan scanrun.StagePlan, closing bool,
) bool {
	store, _ := s.hops.(scanrun.StageStreamStore)
	if sr.IsComplete() {
		// Settled another way (deadline, failure, cancel): nothing more comes.
		_, _ = store.CloseStageStream(ctx, run.TenantID, run.ID, step.StepKey)
		return false
	}
	ok, err := s.planAndDispatchWave(ctx, run, template, step, sr, closing)
	if err != nil {
		outcome := "error"
		if errors.Is(err, errStageDeferred) {
			outcome = "deferred"
		}
		metrics.ScanStageStreamWaves.WithLabelValues(waveKind(closing), outcome).Inc()
		if outcome == "error" {
			s.logger.Warn("stage streaming: wave not planned", "run_id", run.ID.String(),
				"step_key", logger.SanitizeValue(step.StepKey), "closing", closing, "error", logger.SanitizeError(err))
		}
		return false
	}
	if !ok || !closing {
		return false
	}
	closed, err := store.CloseStageStream(ctx, run.TenantID, run.ID, step.StepKey)
	if err != nil {
		s.logger.Warn("stage streaming: close the stream", "run_id", run.ID.String(), "step_key", logger.SanitizeValue(step.StepKey), "error", err)
		return false
	}
	if !closed {
		return false
	}
	s.observeBarrierSaved(run, step, plan)
	return s.settleClosedStream(ctx, run, template, sr)
}

func waveKind(closing bool) string {
	if closing {
		return "close"
	}
	return "wave"
}

// observeBarrierSaved records how much earlier the step got its first
// targets than the barrier would have handed them (when its last
// dependency finished).
func (s *Service) observeBarrierSaved(run *scanrun.Run, step *scanworkflow.Step, plan scanrun.StagePlan) {
	if plan.FirstDispatchAt == nil {
		return
	}
	var last time.Time
	for _, dep := range step.DependsOn {
		if d := run.GetStepRun(dep); d != nil && d.CompletedAt != nil && d.CompletedAt.After(last) {
			last = *d.CompletedAt
		}
	}
	if saved := last.Sub(*plan.FirstDispatchAt); !last.IsZero() && saved > 0 {
		metrics.ScanStageBarrierWaitSaved.Observe(saved.Seconds())
	}
}

// planAndDispatchWave plans a wave under the stage's lock and dispatches
// what it added. It returns false (and no error) when the stream closed
// meanwhile.
func (s *Service) planAndDispatchWave(ctx context.Context, run *scanrun.Run, template *scanworkflow.Workflow,
	step *scanworkflow.Step, sr *scanrun.StepRun, closing bool,
) (bool, error) {
	store, _ := s.hops.(scanrun.StageStreamStore)
	preds := predecessorsOf(template, step)
	step = stepAtDepth(run, step)
	resolved, err := scanapp.ResolveStepTool(ctx, s.toolRepo, run.TenantID, step)
	if err != nil {
		return false, fmt.Errorf("resolve the step's tool: %w", err)
	}
	step = resolved.WithTool(step)
	if !resolved.HasStage {
		return true, nil // nothing to stream into; the close settles the step
	}
	if s.securityValidator != nil {
		if res := s.securityValidator.ValidateStepConfig(ctx, run.TenantID, step.Tool, step.Capabilities, step.Config); !res.Valid {
			return false, fmt.Errorf("security validation failed: %s", res.Errors[0].Message)
		}
	}
	st := resolved.Stage
	wantsPlatform := scanrun.ScanZoneFromContext(run.Context) == nil && s.stepUsesPlatform(ctx, run, step, template.Settings.SensorPreference)
	placement := attribution.PlacementTenant
	if wantsPlatform {
		placement = attribution.PlacementPlatform
	}
	gctx := attribution.WithPlacement(ctx, placement)

	release, err := store.LockStageStream(ctx, run.TenantID, run.ID, step.StepKey)
	if err != nil {
		return false, err
	}
	defer release()
	plan, found, err := store.StageStream(ctx, run.TenantID, run.ID, step.StepKey)
	if err != nil {
		return false, err
	}
	if !found || !plan.StreamOpen {
		return false, nil
	}
	decided, err := store.StageTargets(ctx, run.TenantID, run.ID, step.StepKey)
	if err != nil {
		return false, err
	}
	seen := map[string]bool{}
	prior := map[string]scanrun.RunTarget{}
	var seedList []string
	for _, t := range decided {
		if t.Origin == scanrun.TargetOriginSeed {
			seen[t.TargetKey] = true
			seedList = append(seedList, t.TargetKey)
			continue
		}
		prior[t.TargetKey] = t
	}
	skipped := map[string]int{}
	feeding := feedingPredecessors(run, st, preds, true)
	d, err := s.deriveStage(gctx, run, step, st, feeding, seen, prior, seedList, template.Settings.DeltaGating, skipped, !closing)
	if err != nil {
		return false, err
	}
	// The plan's counts are recomputed on every wave: the reasons stored
	// as targets are counted from the targets, the others (invalid names,
	// duplicates, origins, the seeds' types) come from this full read.
	for _, r := range d.rows {
		if r.Decision == scanrun.TargetSkipped {
			skipped[r.Reason]--
		}
	}
	if n := plan.Skipped["incompatible_type"]; n > 0 {
		skipped["incompatible_type"] = n
	}
	inputs := len(seedList) + plan.Skipped["incompatible_type"] + d.inputs + len(prior)
	added, err := store.SaveStageWave(ctx, &scanrun.StagePlan{TenantID: run.TenantID, RunID: run.ID, StageKey: step.StepKey,
		Inputs: inputs, Skipped: skipped}, d.rows)
	if err != nil {
		return false, err
	}
	if len(added) == 0 {
		metrics.ScanStageStreamWaves.WithLabelValues(waveKind(closing), "empty").Inc()
		return true, nil
	}
	err = s.dispatchStep(ctx, run, step, resolved, sr, &scanapp.StepTargets{Targets: added}, wantsPlatform, feedsStream(template, step))
	var tooClose *deadlineTooCloseError
	if err != nil {
		// Never lost silently: the targets are recorded as unfinished, so
		// the next run plans them first and coverage never counts them.
		s.recordUnfinished(ctx, run, step.StepKey, added)
		if errors.As(err, &tooClose) {
			metrics.ScanStageStreamWaves.WithLabelValues(waveKind(closing), "deadline").Inc()
			return true, nil
		}
		return true, fmt.Errorf("dispatch the wave: %w", err)
	}
	metrics.ScanStageStreamWaves.WithLabelValues(waveKind(closing), "dispatched").Inc()
	if plan.Waves == 0 {
		for _, p := range feeding {
			for _, pr := range preds {
				if pr.StepKey == p.key {
					s.observeFirstSuccessor(run, pr)
				}
			}
		}
	}
	s.logger.Info("streamed step: wave dispatched", "run_id", run.ID.String(), "step_key", logger.SanitizeValue(step.StepKey),
		"targets", len(added), "closing", closing)
	return true, nil
}

func (s *Service) recordUnfinished(ctx context.Context, run *scanrun.Run, stepKey string, targets []string) {
	rec, ok := s.runRepo.(scanrun.UnfinishedTargetRecorder)
	if !ok || len(targets) == 0 {
		return
	}
	if err := rec.AddUnfinishedTargets(ctx, run.TenantID, run.ID, targets); err != nil {
		s.logger.Error("stage streaming: record a wave's targets as unfinished", "run_id", run.ID.String(),
			"step_key", logger.SanitizeValue(stepKey), "error", err)
	}
}

// settleClosedStream records the outcome of a streamed step whose stream
// just closed, when none of its commands is still active (otherwise the
// last command's completion records it). A step that never dispatched is
// settled with no inputs. It returns whether it settled the step; the
// caller advances the run.
func (s *Service) settleClosedStream(ctx context.Context, run *scanrun.Run, template *scanworkflow.Workflow, sr *scanrun.StepRun) bool {
	gate, ok := s.commandRepo.(command.StepBatchGate)
	if !ok {
		return false
	}
	st, err := gate.StepBatchState(ctx, run.TenantID, sr.ID)
	if err != nil {
		s.logger.Warn("stage streaming: read the step's commands", "run_id", run.ID.String(), "step_key", logger.SanitizeValue(sr.StepKey), "error", err)
		return false
	}
	if st.Total == 0 {
		summary := "no target to scan"
		if store, ok := s.hops.(scanrun.StageStreamStore); ok {
			if p, found, err := store.StageStream(ctx, run.TenantID, run.ID, sr.StepKey); err == nil && found {
				summary = skipSummary(p.Skipped)
			}
		}
		s.settleNoInputs(ctx, sr, sr.StepKey, &noInputsError{summary: summary})
		return true
	}
	if st.Active > 0 {
		return false
	}
	claimed, err := gate.ClaimStepFinalization(ctx, sr.ID)
	if err != nil || !claimed {
		return false
	}
	b := stepBatches{batched: true, total: st.Total, failed: st.Failed, findings: st.Findings, skipped: st.Skipped, unresolved: st.Unresolvable,
		gaps: st.Gaps, firstError: st.FirstError, reachBatches: st.ReachBatches, reachTargets: st.ReachTargets, reached: st.Reached, unreached: st.Unreached}
	failed := s.recordBatchedOutcome(ctx, sr, b)
	if failed && template.Settings.FailFast {
		s.refreshStepRuns(ctx, run)
		rs := s.calculateRunStats(run)
		s.updateRunStats(ctx, run, rs)
		s.finishRun(ctx, run, scanrun.RunStatusFailed, "Scan workflow failed: "+sr.ErrorMessage, rs.findings)
	}
	return true
}

// recordBatchedOutcome records the outcome of a batched step whose batches
// all finished, the way a last batch's completion does, without advancing
// the run. It returns whether the step failed.
func (s *Service) recordBatchedOutcome(ctx context.Context, sr *scanrun.StepRun, b stepBatches) bool {
	outcome, failed := "completed", false
	p := b.partial()
	switch {
	case b.failed >= b.total:
		code, _ := scanrun.ClassifyStepFailure(errCodeBatchFailed, b.summary())
		sr.Fail(b.summary(), code)
		outcome, failed = "failed", true
	case b.failed > 0:
		sr.Partial(b.findings, b.summary(), errCodeBatchFailed)
		outcome = "partial"
	case p.failsStep(b.findings):
		sr.Fail(p.UnreachableMessage, scanrun.FailureTargetUnreachable)
		outcome, failed = "failed", true
	case p.incomplete():
		msg, code := p.message()
		sr.Partial(b.findings, msg, code)
		sr.Output = p.withNotes(sr.Output)
		outcome = "partial"
	default:
		sr.Complete(b.findings, p.withNotes(nil))
	}
	if err := s.stepRunRepo.Update(ctx, sr); err != nil {
		s.logger.Error("failed to record a streamed step's outcome", "step_key", logger.SanitizeValue(sr.StepKey), "error", err)
	}
	metrics.StepRunsTotal.WithLabelValues(sr.StepKey, outcome).Inc()
	return failed
}

// streamAfterTask advances the run after a task of a batched step finished
// while others of it still run, when a successor may stream from the step:
// its results are handed on now instead of with the step's last task.
func (s *Service) streamAfterTask(ctx context.Context, run *scanrun.Run, stepKey string) {
	template, err := s.runWorkflow(ctx, run)
	if err != nil || !s.streamingFor(template) {
		return
	}
	var step *scanworkflow.Step
	for _, t := range template.Steps {
		if t.StepKey == stepKey {
			step = t
			break
		}
	}
	if step == nil || !feedsStream(template, step) {
		return
	}
	if err := s.advanceRun(ctx, run, template); err != nil {
		s.logger.Warn("stage streaming: advance after a task", "run_id", run.ID.String(), "error", err)
	}
}

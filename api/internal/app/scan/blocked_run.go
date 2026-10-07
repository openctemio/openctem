package scan

import (
	"context"
	"errors"

	"github.com/openctemio/openctem/api/pkg/domain/pipeline"
	"github.com/openctemio/openctem/api/pkg/domain/scan"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// A trigger that is refused before anything is dispatched (scope gate, freeze
// window, unavailable tool or sensor, no target, paused scan, ...) is recorded
// as a run with status blocked, its refusal code and message. Before, a
// refused manual trigger left no trace on the scan, and a refused scheduled
// trigger moved last_run_at with no run behind it, so the list read "Last
// run: today" beside "Runs: 0".
//
// Threat model: the blocked run is written only after the scan was loaded
// for the caller's tenant (GetScan is tenant-scoped) and the route's
// permission check passed, so a caller can add a blocked run only to a scan
// they may trigger. The run stores the refusal and the scan id, never the
// caller's trigger context. The message is one of our own domain messages.

// codeTriggerRefused is the refusal code of a refusal that carried no code.
const codeTriggerRefused = "TRIGGER_REFUSED"

// maxRefusalMessage bounds the stored message.
const maxRefusalMessage = 2000

// runStartError marks a trigger failure that happened after the run row was
// written: that run already records the failure, so no blocked run is added.
type runStartError struct{ err error }

func (e *runStartError) Error() string { return e.err.Error() }
func (e *runStartError) Unwrap() error { return e.err }

// afterRunCreated wraps a failure of a trigger whose run already exists.
func afterRunCreated(err error) error {
	if err == nil {
		return nil
	}
	return &runStartError{err: err}
}

// refusal returns the code and message of a refused trigger, and false when
// err is not a refusal: an internal failure (logged, not recorded), a failure
// after the run was created, or an outcome the scheduler records itself (an
// occurrence skipped because the previous run is active, D4, or already run).
func refusal(err error) (code, message string, ok bool) {
	if err == nil {
		return "", "", false
	}
	var started *runStartError
	if errors.As(err, &started) ||
		errors.Is(err, ErrScanRunInProgress) ||
		errors.Is(err, pipeline.ErrOccurrenceAlreadyRun) {
		return "", "", false
	}
	if fe := AsFrozen(err); fe != nil {
		return CodeScanFrozen, fe.Error(), true
	}
	var de *shared.DomainError
	if errors.As(err, &de) {
		return de.Code, de.Message, true
	}
	if errors.Is(err, shared.ErrValidation) || errors.Is(err, shared.ErrForbidden) || errors.Is(err, shared.ErrConflict) {
		return codeTriggerRefused, err.Error(), true
	}
	return "", "", false
}

// recordBlockedRun records a refused trigger as a blocked run of the scan.
// Best-effort: a failure is logged and the refusal is returned as before.
func (s *Service) recordBlockedRun(ctx context.Context, sc *scan.Scan, input TriggerScanExecInput, triggerType pipeline.TriggerType, cause error) {
	code, message, ok := refusal(cause)
	if !ok {
		return
	}
	if message == "" {
		message = "The trigger was refused (" + code + ")."
	}
	if r := []rune(message); len(r) > maxRefusalMessage {
		message = string(r[:maxRefusalMessage])
	}
	run, err := pipeline.NewRun(blockedRunPipelineID(sc, code), sc.TenantID, nil, triggerType, input.TriggeredBy,
		map[string]any{"scan_id": sc.ID.String()})
	if err != nil {
		s.logger.Warn("failed to build blocked run", "scan_id", sc.ID.String(), "error", err)
		return
	}
	run.ScanID = &sc.ID
	run.RetryAttempt = input.RetryAttempt
	run.ScheduledFor = input.ScheduledFor
	run.Block(code, message)
	if err := s.runRepo.Create(ctx, run); err != nil {
		s.logger.Warn("failed to record blocked run", "scan_id", sc.ID.String(), "code", code, "error", err)
		return
	}
	s.logger.Info("scan trigger refused; recorded as a blocked run",
		"scan_id", sc.ID.String(), "run_id", run.ID.String(), "code", code)
}

// blockedRunPipelineID is the template a blocked run points at: the
// workflow's own template, unless the refusal is that it is gone.
func blockedRunPipelineID(sc *scan.Scan, code string) shared.ID {
	if sc.ScanType == scan.ScanTypeWorkflow && sc.PipelineID != nil && code != "PIPELINE_NOT_FOUND" {
		return *sc.PipelineID
	}
	id, _ := shared.IDFromString(QuickScanTemplateID)
	return id
}

// refreshRunSummary recomputes the scan's last run and counters from its
// runs. Best-effort: the summary is a cache, the next refresh repairs it.
func (s *Service) refreshRunSummary(ctx context.Context, sc *scan.Scan) {
	if err := s.scanRepo.RefreshRunSummary(ctx, sc.TenantID, sc.ID); err != nil {
		s.logger.Warn("failed to refresh scan run summary", "scan_id", sc.ID.String(), "error", err)
	}
}

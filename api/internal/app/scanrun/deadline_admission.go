package scanrun

// Deadline admission (research/122, RFC-046 §6.3 as amended): a run's
// deadline is a policy cap, and a step that cannot do anything useful in the
// time left is not dispatched, so no command is started only to be
// canceled. Its targets are recorded as the run's unfinished targets and
// roll over to the next scheduled run.

import (
	"context"
	"fmt"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/scanrun"
	"github.com/openctemio/openctem/api/pkg/domain/toolbudget"
)

// deadlineTooCloseError: the step was not dispatched because its run's
// deadline is closer than the least useful time of its tool.
type deadlineTooCloseError struct {
	left, need time.Duration
	targets    []string
}

func (e *deadlineTooCloseError) Error() string {
	return fmt.Sprintf("not started: %s left before the run's deadline, the step needs at least %s",
		e.left.Round(time.Second), e.need.Round(time.Second))
}

// deadlineTooClose returns the refusal when run has a deadline and less
// than tool's least useful time is left before it at now; nil otherwise.
func deadlineTooClose(run *scanrun.Run, tool string, now time.Time) *deadlineTooCloseError {
	if run == nil || run.DeadlineAt == nil {
		return nil
	}
	left := run.DeadlineAt.Sub(now)
	need := toolbudget.For(tool).MinUseful()
	if left >= need {
		return nil
	}
	if left < 0 {
		left = 0
	}
	return &deadlineTooCloseError{left: left, need: need}
}

// settleStepDeadlineTooClose fails the step with DEADLINE_TOO_CLOSE (not
// retried: the run's clock only gets shorter) and records its targets as
// the run's unfinished targets.
func (s *Service) settleStepDeadlineTooClose(ctx context.Context, run *scanrun.Run, stepRun *scanrun.StepRun, stepKey string, e *deadlineTooCloseError) {
	if rec, ok := s.runRepo.(scanrun.UnfinishedTargetRecorder); ok && len(e.targets) > 0 {
		if err := rec.AddUnfinishedTargets(ctx, run.TenantID, run.ID, e.targets); err != nil {
			s.logger.Error("failed to record the targets of a step not started before the deadline",
				"run_id", run.ID.String(), "step_key", stepKey, "error", err)
		}
	}
	s.logger.Info("step not started: the run's deadline is too close",
		"run_id", run.ID.String(), "step_key", stepKey, "left", e.left, "need", e.need, "targets", len(e.targets))
	stepRun.Fail(e.Error(), scanrun.FailureDeadlineTooClose)
	if err := s.stepRunRepo.Update(ctx, stepRun); err != nil {
		s.logger.Error("failed to settle a step not started before the deadline", "step_key", stepKey, "error", err)
	}
}

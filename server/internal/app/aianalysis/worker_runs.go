package aianalysis

import (
	"context"
	"fmt"

	auditapp "github.com/openctemio/openctem/server/internal/app/audit"
	aidom "github.com/openctemio/openctem/server/pkg/domain/aianalysis"
	"github.com/openctemio/openctem/server/pkg/domain/audit"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
	"github.com/openctemio/openctem/server/pkg/logger"
)

// JobCanceler cancels an analysis job that is still open (the command
// queue).
type JobCanceler interface {
	CancelAnalysisJob(ctx context.Context, tenantID, commandID shared.ID) error
}

// SetJobCanceler wires the command queue the deadline sweep cancels the
// jobs of overdue runs in (nil: jobs are left to expire on their own).
func (s *Service) SetJobCanceler(c JobCanceler) { s.jobs = c }

// ChangeExecutor sets where an AI agent's runs execute: built in (the
// platform calls the model) or on the organization's AI workers. Other
// executors are not available. The change is audited with the executor
// before and after.
func (s *Service) ChangeExecutor(ctx context.Context, id shared.ID, executor string, actx auditapp.AuditContext) (*aidom.AIAgent, error) {
	tid, err := tenantOf(actx)
	if err != nil {
		return nil, err
	}
	if _, err := actorOf(actx); err != nil {
		return nil, err
	}
	e := aidom.Executor(executor)
	if e != aidom.ExecutorBuiltin && e != aidom.ExecutorTenantWorker {
		return nil, fmt.Errorf("%w: an AI agent runs built in or on the organization's AI workers", shared.ErrValidation)
	}
	a, err := s.aiAgents.Get(ctx, tid, id)
	if err != nil {
		return nil, err
	}
	if a.Executor == e {
		return a, nil
	}
	if err := s.aiAgents.SetExecutor(ctx, tid, id, e); err != nil {
		return nil, err
	}
	out, err := s.aiAgents.Get(ctx, tid, id)
	if err != nil {
		return nil, err
	}
	s.log(ctx, actx, audit.ActionAIAgentExecutorChanged, out, fmt.Sprintf("AI agent %q now runs %s", out.Name, runsOn(e)),
		map[string]any{"from": string(a.Executor), "to": string(e)})
	return out, nil
}

func runsOn(e aidom.Executor) string {
	if e == aidom.ExecutorTenantWorker {
		return "on the organization's AI workers"
	}
	return "built in"
}

// settleBatch bounds one deadline sweep.
const settleBatch = 200

// EndStaleWorkerRuns ends the runs on AI workers that can no longer get a
// result, so none waits forever (a system job, every minute): a run past
// its deadline fails deadline_exceeded and its job, if still open, is
// canceled so no worker spends on it; a run whose job expired fails
// deadline_exceeded, one whose job failed fails worker_error, one whose job
// was canceled ends canceled, and one whose job is gone fails
// worker_unavailable. A result that arrives later is not applied (the run is
// no longer live). It returns how many runs it ended.
func (s *Service) EndStaleWorkerRuns(ctx context.Context) (int, error) {
	settled, err := s.runs.SettleWorkerRuns(ctx, settleBatch)
	if err != nil {
		return 0, err
	}
	for _, r := range settled {
		s.logger.Info("AI worker run ended without a result", "run_id", r.ID.String(), "status", string(r.Status), "error_code", r.ErrorCode)
		if r.ErrorCode != aidom.ErrorDeadlineExceeded || r.CommandID == nil || s.jobs == nil {
			continue
		}
		if err := s.jobs.CancelAnalysisJob(ctx, r.TenantID, *r.CommandID); err != nil {
			s.logger.Debug("analysis job of an overdue run not canceled", "run_id", r.ID.String(), "error", logger.SanitizeError(err))
		}
	}
	return len(settled), nil
}

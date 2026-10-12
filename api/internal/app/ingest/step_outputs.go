package ingest

// What a command-bound sensor report wrote, for chaining scan stages
// (research/27 P0-3; docs/architecture/scan-stages.md). The step run comes
// from the report's server-side binding (the command it names, assigned to
// the submitting sensor and open), never from the report body, so a sensor
// cannot attribute its output to another step, run or tenant.

import (
	"context"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// StepOutputRecorder records the assets a step run's reports wrote
// (*postgres.ScanHopRepository). Tenant-scoped: a step run or asset of
// another tenant writes nothing.
type StepOutputRecorder interface {
	RecordStepOutputs(ctx context.Context, tenantID, stepRunID shared.ID, assetIDs []shared.ID) (int, error)
}

// SetStepOutputRecorder wires stage chaining's output record. Nil-safe:
// unwired, chained stages find no outputs and run on their seeds.
func (s *Service) SetStepOutputRecorder(r StepOutputRecorder) { s.stepOutputs = r }

// CommandIngestedHook is told when every segment of a report bound to a
// command was ingested (protocol v2 commits asynchronously, after the
// command may have completed): a chained step waiting for that ingest is
// planned then.
type CommandIngestedHook func(ctx context.Context, tenantID, commandID shared.ID)

// SetCommandIngestedHook wires the hook. Nil-safe.
func (s *Service) SetCommandIngestedHook(h CommandIngestedHook) { s.commandIngested = h }

// recordStepOutputs records what a command-bound report of a workflow step
// wrote: every asset this ingest created or updated. Best-effort: a failure
// is logged and the chained stage then has fewer targets, never more.
func (s *Service) recordStepOutputs(ctx context.Context, tenantID shared.ID, binding Binding, scope *alterScope) {
	if s.stepOutputs == nil || binding.Kind != BindingCommand || binding.StepRunID == nil || scope == nil || len(scope.seen) == 0 {
		return
	}
	ids := make([]shared.ID, 0, len(scope.seen))
	for id := range scope.seen {
		ids = append(ids, id)
	}
	if _, err := s.stepOutputs.RecordStepOutputs(ctx, tenantID, *binding.StepRunID, ids); err != nil {
		s.logger.Warn("ingest: chained-stage outputs not recorded",
			"tenant_id", tenantID.String(), "scan_run_step_id", binding.StepRunID.String(), "assets", len(ids),
			"error", logger.SanitizeError(err))
	}
}

// commandIngestedNow calls the hook for a report that just finished.
func (s *Service) commandIngestedNow(ctx context.Context, tenantID shared.ID, commandID *shared.ID) {
	if s.commandIngested == nil || commandID == nil {
		return
	}
	s.commandIngested(ctx, tenantID, *commandID)
}

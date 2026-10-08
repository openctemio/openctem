package scanrun

import (
	"context"
	"fmt"
	"time"

	retestdom "github.com/openctemio/openctem/api/pkg/domain/retest"
	"github.com/openctemio/openctem/api/pkg/domain/scanrun"
	"github.com/openctemio/openctem/api/pkg/domain/scanworkflow"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Standalone runs (research/62 P0-3, SW1): sensor work that executes no scan
// workflow (a finding retest today) still belongs to one run the user can
// find in Runs, with its tasks, logs and outcome. Such a run has one step,
// keyed by its kind; the service that owns the work (retest) creates it
// before dispatching and settles it when the work settles. The scan run
// service does not drive it from command results: its commands carry the
// run id (tasks and logs) but no step key.

// StandaloneRunInput describes a standalone run.
type StandaloneRunInput struct {
	TenantID shared.ID
	Kind     scanrun.RunKind
	// Subject names what the run is about, e.g. {"finding_id", "retest_id"}.
	Subject map[string]any
	// StepName labels the run's one step ("Retest").
	StepName    string
	TriggerType scanworkflow.TriggerType
	// TriggeredBy is the requesting user id, or "" for system work.
	TriggeredBy string
}

// StartStandaloneRun records a running standalone run and its one step. The
// caller tags the commands it dispatches with the returned run id and step
// run id.
func (s *Service) StartStandaloneRun(ctx context.Context, in StandaloneRunInput) (*scanrun.Run, *scanrun.StepRun, error) {
	if in.TenantID.IsZero() {
		return nil, nil, fmt.Errorf("%w: tenant is required", shared.ErrValidation)
	}
	if !in.Kind.IsValid() || in.Kind == scanrun.RunKindScan || in.Kind == scanrun.RunKindQuick || in.Kind == scanrun.RunKindTest {
		return nil, nil, fmt.Errorf("%w: a standalone run cannot be of kind %q", shared.ErrValidation, in.Kind)
	}
	trigger := in.TriggerType
	if trigger == "" {
		trigger = scanworkflow.TriggerTypeSystem
	}
	now := time.Now()
	run := &scanrun.Run{
		ID:          shared.NewID(),
		TenantID:    in.TenantID,
		Kind:        in.Kind,
		Subject:     in.Subject,
		TriggerType: trigger,
		TriggeredBy: in.TriggeredBy,
		Status:      scanrun.RunStatusRunning,
		Context:     map[string]any{},
		TotalSteps:  1,
		StartedAt:   &now,
		CreatedAt:   now,
	}
	if err := s.runRepo.Create(ctx, run); err != nil {
		return nil, nil, fmt.Errorf("record %s run: %w", in.Kind, err)
	}
	step := scanrun.NewStepRun(run.ID, shared.ID{}, string(in.Kind), 1, 0)
	step.StepName = in.StepName
	step.Queue()
	if err := s.stepRunRepo.Create(ctx, step); err != nil {
		return nil, nil, fmt.Errorf("record %s step: %w", in.Kind, err)
	}
	run.AddStepRun(step)
	return run, step, nil
}

// StandaloneOutcome settles a standalone run.
type StandaloneOutcome struct {
	// Succeeded: the work produced its answer (a retest that reached a
	// verdict, fixed or still present). Otherwise the run fails with Message
	// and Code (the reason the work produced no answer).
	Succeeded bool
	Message   string
	Code      string
}

// FinishStandaloneRun settles a standalone run and its step. A run of another
// tenant is not found; a run that already finished stays as it is.
func (s *Service) FinishStandaloneRun(ctx context.Context, tenantID, runID shared.ID, out StandaloneOutcome) error {
	run, err := s.runRepo.GetByTenantAndID(ctx, tenantID, runID)
	if err != nil {
		return err
	}
	if !run.ScanWorkflowID.IsZero() || run.IsComplete() {
		return nil
	}
	steps, err := s.stepRunRepo.GetByScanRunID(ctx, run.ID)
	if err != nil {
		return err
	}
	for _, step := range steps {
		if step.IsComplete() {
			continue
		}
		if out.Succeeded {
			step.Complete(0, nil)
		} else {
			step.Fail(out.Message, out.Code)
		}
		if err := s.stepRunRepo.Update(ctx, step); err != nil {
			s.logger.Error("failed to settle standalone step", "run_id", run.ID.String(), "error", err)
		}
	}
	if out.Succeeded {
		run.Complete()
		run.CompletedSteps = 1
	} else {
		run.Fail(out.Message)
		run.FailedSteps = 1
	}
	return s.runRepo.Update(ctx, run)
}

// StartRetestRun records a finding retest as a run (retest.RunRecorder).
func (s *Service) StartRetestRun(ctx context.Context, rt *retestdom.Retest) (shared.ID, shared.ID, error) {
	trigger, by := scanworkflow.TriggerTypeSystem, ""
	if rt.Trigger == retestdom.TriggerManual {
		trigger = scanworkflow.TriggerTypeManual
		if rt.RequestedBy != nil {
			by = rt.RequestedBy.String()
		}
	}
	run, step, err := s.StartStandaloneRun(ctx, StandaloneRunInput{
		TenantID:    rt.TenantID,
		Kind:        scanrun.RunKindRetest,
		Subject:     map[string]any{"finding_id": rt.FindingID.String(), "retest_id": rt.ID.String()},
		StepName:    "Retest",
		TriggerType: trigger,
		TriggeredBy: by,
	})
	if err != nil {
		return shared.ID{}, shared.ID{}, err
	}
	return run.ID, step.ID, nil
}

// FinishRetestRun settles a retest's run (retest.RunRecorder).
func (s *Service) FinishRetestRun(ctx context.Context, tenantID, runID shared.ID, succeeded bool, message, code string) error {
	return s.FinishStandaloneRun(ctx, tenantID, runID, StandaloneOutcome{Succeeded: succeeded, Message: message, Code: code})
}

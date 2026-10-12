package controller

import (
	"context"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/command"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/pagination"
)

// recordingCommandRepo records which recovery/expiry methods Reconcile calls.
type recordingCommandRepo struct {
	calledFindQueueExpiredPlatformJobs bool

	recoverStuckJobs           int64
	recoverStuckTenantCommands int64
	releasedPending            int64
	failExhaustedCommands      int64
}

func (r *recordingCommandRepo) ReleasePendingFromUnavailableSensors(context.Context) (int64, error) {
	return r.releasedPending, nil
}

func (r *recordingCommandRepo) RecoverStuckJobs(_ context.Context, _, _ int) (int64, error) {
	return r.recoverStuckJobs, nil
}

func (r *recordingCommandRepo) RecoverStuckTenantCommands(_ context.Context, _, _ int) (int64, error) {
	return r.recoverStuckTenantCommands, nil
}

func (r *recordingCommandRepo) FindQueueExpiredPlatformJobs(_ context.Context, _ int) ([]*command.Command, error) {
	r.calledFindQueueExpiredPlatformJobs = true
	return nil, nil
}

func (r *recordingCommandRepo) FailExhaustedCommands(_ context.Context, _ int) (int64, error) {
	return r.failExhaustedCommands, nil
}

// --- remaining command.Repository surface: unused by JobRecoveryController ---

func (r *recordingCommandRepo) Create(context.Context, *command.Command) error { return nil }
func (r *recordingCommandRepo) GetByID(context.Context, shared.ID) (*command.Command, error) {
	return nil, nil
}

func (r *recordingCommandRepo) GetByTenantAndID(context.Context, shared.ID, shared.ID) (*command.Command, error) {
	return nil, nil
}

func (r *recordingCommandRepo) GetPendingForSensor(context.Context, shared.ID, *shared.ID, []string, int) ([]*command.Command, error) {
	return nil, nil
}

func (r *recordingCommandRepo) ClaimForSensor(context.Context, shared.ID, shared.ID, string) (bool, error) {
	return false, nil
}

func (r *recordingCommandRepo) List(context.Context, command.Filter, pagination.Pagination) (pagination.Result[*command.Command], error) {
	return pagination.Result[*command.Command]{}, nil
}
func (r *recordingCommandRepo) Update(context.Context, *command.Command) error     { return nil }
func (r *recordingCommandRepo) Delete(context.Context, shared.ID, shared.ID) error { return nil }
func (r *recordingCommandRepo) FindExpired(context.Context) ([]*command.Command, error) {
	return nil, nil
}

func (r *recordingCommandRepo) GetByAuthTokenHash(context.Context, string) (*command.Command, error) {
	return nil, nil
}

func (r *recordingCommandRepo) CountActivePlatformJobsByTenant(context.Context, shared.ID) (int, error) {
	return 0, nil
}

func (r *recordingCommandRepo) CountQueuedPlatformJobsByTenant(context.Context, shared.ID) (int, error) {
	return 0, nil
}
func (r *recordingCommandRepo) CountQueuedPlatformJobs(context.Context) (int, error) { return 0, nil }
func (r *recordingCommandRepo) GetQueuedPlatformJobs(context.Context, int) ([]*command.Command, error) {
	return nil, nil
}

func (r *recordingCommandRepo) GetNextPlatformJob(context.Context, shared.ID, []string, []string) (*command.Command, error) {
	return nil, nil
}
func (r *recordingCommandRepo) UpdateQueuePriorities(context.Context) (int64, error) { return 0, nil }
func (r *recordingCommandRepo) GetQueuePosition(context.Context, shared.ID) (*command.QueuePosition, error) {
	return nil, nil
}

func (r *recordingCommandRepo) ListPlatformJobsByTenant(context.Context, shared.ID, pagination.Pagination) (pagination.Result[*command.Command], error) {
	return pagination.Result[*command.Command]{}, nil
}

func (r *recordingCommandRepo) ListPlatformJobsAdmin(context.Context, *shared.ID, *shared.ID, *command.CommandStatus, pagination.Pagination) (pagination.Result[*command.Command], error) {
	return pagination.Result[*command.Command]{}, nil
}

func (r *recordingCommandRepo) GetPlatformJobsBySensor(context.Context, shared.ID, *command.CommandStatus) ([]*command.Command, error) {
	return nil, nil
}

func (r *recordingCommandRepo) GetStatsByTenant(context.Context, shared.ID) (command.CommandStats, error) {
	return command.CommandStats{}, nil
}

func (r *recordingCommandRepo) CancelByScanRunID(context.Context, shared.ID, shared.ID) (int64, error) {
	return 0, nil
}

var _ command.Repository = (*recordingCommandRepo)(nil)

// NOTE: this file used to also assert that Reconcile never calls
// CommandRepository.ExpireOldCommands — a raw `UPDATE commands SET
// status='expired' WHERE status='pending' AND expires_at < NOW()` that ran on
// the same 60s tick over a strict subset of the rows FindExpired matches, with
// no scan workflow notification. Whenever it won that race, FindExpired no longer
// matched the row and the owning run was never told its step died.
//
// ExpireOldCommands has since been deleted from command.Repository, its postgres
// implementation and the command service, so the guarantee is now enforced by
// the compiler rather than by a test. app/command.ExpirationChecker is the only
// expiry path and it calls scanrun.OnStepFailed(..., "COMMAND_EXPIRED").

// TestJobRecoveryController_DoesNotExpirePlatformJobs pins the same removal one
// step over, for the platform-job queue.
//
// This controller used to run a raw `UPDATE commands SET status='expired' ...
// WHERE is_platform_job AND status='pending' AND queued_at < ...`. Platform jobs
// are created by scan/scan workflow dispatch carrying scan_run_id + step_key and
// with expires_at NULL, so FindExpired never covered them: that raw UPDATE was
// the only thing that ever reaped them, and it notified nobody. The step stayed
// 'queued' until ScanTimeoutController eventually reported a generic timeout
// instead of "expired in queue".
//
// Expiry now belongs to app/command.ExpirationChecker, which calls
// scanrun.OnStepFailed(..., "PLATFORM_JOB_EXPIRED_IN_QUEUE"). Reconcile must
// not expire platform jobs itself — not even by reading the candidates.
func TestJobRecoveryController_DoesNotExpirePlatformJobs(t *testing.T) {
	repo := &recordingCommandRepo{}
	c := NewJobRecoveryController(repo, &JobRecoveryControllerConfig{
		Logger: logger.NewNop(),
	})

	if _, err := c.Reconcile(context.Background()); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}

	if repo.calledFindQueueExpiredPlatformJobs {
		t.Fatal("JobRecoveryController.Reconcile expired platform jobs: expiring a platform " +
			"job here cannot call pipeline OnStepFailed, so the owning run is left waiting on a " +
			"step that is already dead - app/command.ExpirationChecker owns this")
	}
}

// TestJobRecoveryController_ReportsOnlyItsOwnWork guards the item count after the
// removals: no expiry result — neither the tenant-command expiry that
// ExpireOldCommands used to return nor any platform-job expiry — may be folded
// into this controller's count.
func TestJobRecoveryController_ReportsOnlyItsOwnWork(t *testing.T) {
	repo := &recordingCommandRepo{
		recoverStuckJobs:           1,
		recoverStuckTenantCommands: 2,
		releasedPending:            8,
		failExhaustedCommands:      4,
	}
	c := NewJobRecoveryController(repo, &JobRecoveryControllerConfig{Logger: logger.NewNop()})

	got, err := c.Reconcile(context.Background())
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if want := 15; got != want {
		t.Fatalf("processed count = %d, want %d (an inflated count means a foreign expiry path is still counted here)", got, want)
	}
}

// exhaustingCommandRepo also implements command.ExhaustedFailer.
type exhaustingCommandRepo struct {
	recordingCommandRepo
	exhausted []*command.Command
}

func (r *exhaustingCommandRepo) FailExhaustedCommandsReturning(context.Context, int) ([]*command.Command, error) {
	return r.exhausted, nil
}

type stepFailure struct{ runID, stepKey, msg, code string }

type recordingSteps struct{ got []stepFailure }

func (s *recordingSteps) OnStepFailed(_ context.Context, runID, stepKey, msg, code string) error {
	s.got = append(s.got, stepFailure{runID, stepKey, msg, code})
	return nil
}

// A poison command (dispatch attempts exhausted) used to be failed by a raw
// UPDATE that told nobody: its run hung until the run timeout and then said
// "no result reported before timeout". Now its step fails with the reason.
func TestJobRecovery_ExhaustedCommandFailsItsPipelineStep(t *testing.T) {
	runID := shared.NewID().String()
	repo := &exhaustingCommandRepo{exhausted: []*command.Command{
		{ID: shared.NewID(), DispatchAttempts: 3,
			Payload: []byte(`{"scan_run_id":"` + runID + `","step_key":"quick_scan"}`)},
		{ID: shared.NewID(), DispatchAttempts: 3, Payload: []byte(`{"kind":"not a pipeline command"}`)},
	}}
	steps := &recordingSteps{}
	c := NewJobRecoveryController(repo, &JobRecoveryControllerConfig{Logger: logger.NewNop()})
	c.SetStepFailureNotifier(steps)

	if _, err := c.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(steps.got) != 1 {
		t.Fatalf("pipeline notified %d times, want 1 (the pipeline command only)", len(steps.got))
	}
	if got := steps.got[0]; got.runID != runID || got.stepKey != "quick_scan" || got.code != "COMMAND_EXHAUSTED" {
		t.Fatalf("notified %+v, want run %s step quick_scan code COMMAND_EXHAUSTED", got, runID)
	}
}

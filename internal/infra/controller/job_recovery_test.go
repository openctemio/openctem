package controller

import (
	"context"
	"testing"

	"github.com/openctemio/api/pkg/domain/command"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/logger"
	"github.com/openctemio/api/pkg/pagination"
)

// recordingCommandRepo records which recovery/expiry methods Reconcile calls.
type recordingCommandRepo struct {
	calledFindQueueExpiredPlatformJobs bool

	recoverStuckJobs           int64
	recoverStuckTenantCommands int64
	failExhaustedCommands      int64
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

func (r *recordingCommandRepo) GetPendingForAgent(context.Context, shared.ID, *shared.ID, []string, int) ([]*command.Command, error) {
	return nil, nil
}

func (r *recordingCommandRepo) ClaimForAgent(context.Context, shared.ID, shared.ID, string) (bool, error) {
	return false, nil
}

func (r *recordingCommandRepo) List(context.Context, command.Filter, pagination.Pagination) (pagination.Result[*command.Command], error) {
	return pagination.Result[*command.Command]{}, nil
}
func (r *recordingCommandRepo) Update(context.Context, *command.Command) error { return nil }
func (r *recordingCommandRepo) Delete(context.Context, shared.ID) error        { return nil }
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

func (r *recordingCommandRepo) GetPlatformJobsByAgent(context.Context, shared.ID, *command.CommandStatus) ([]*command.Command, error) {
	return nil, nil
}

func (r *recordingCommandRepo) GetStatsByTenant(context.Context, shared.ID) (command.CommandStats, error) {
	return command.CommandStats{}, nil
}

func (r *recordingCommandRepo) CancelByPipelineRunID(context.Context, shared.ID, shared.ID) (int64, error) {
	return 0, nil
}

var _ command.Repository = (*recordingCommandRepo)(nil)

// NOTE: this file used to also assert that Reconcile never calls
// CommandRepository.ExpireOldCommands — a raw `UPDATE commands SET
// status='expired' WHERE status='pending' AND expires_at < NOW()` that ran on
// the same 60s tick over a strict subset of the rows FindExpired matches, with
// no pipeline notification. Whenever it won that race, FindExpired no longer
// matched the row and the owning run was never told its step died.
//
// ExpireOldCommands has since been deleted from command.Repository, its postgres
// implementation and the command service, so the guarantee is now enforced by
// the compiler rather than by a test. app/command.ExpirationChecker is the only
// expiry path and it calls pipeline.OnStepFailed(..., "COMMAND_EXPIRED").

// TestJobRecoveryController_DoesNotExpirePlatformJobs pins the same removal one
// step over, for the platform-job queue.
//
// This controller used to run a raw `UPDATE commands SET status='expired' ...
// WHERE is_platform_job AND status='pending' AND queued_at < ...`. Platform jobs
// are created by scan/pipeline dispatch carrying pipeline_run_id + step_key and
// with expires_at NULL, so FindExpired never covered them: that raw UPDATE was
// the only thing that ever reaped them, and it notified nobody. The step stayed
// 'queued' until ScanTimeoutController eventually reported a generic timeout
// instead of "expired in queue".
//
// Expiry now belongs to app/command.ExpirationChecker, which calls
// pipeline.OnStepFailed(..., "PLATFORM_JOB_EXPIRED_IN_QUEUE"). Reconcile must
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
		failExhaustedCommands:      4,
	}
	c := NewJobRecoveryController(repo, &JobRecoveryControllerConfig{Logger: logger.NewNop()})

	got, err := c.Reconcile(context.Background())
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if want := 7; got != want {
		t.Fatalf("processed count = %d, want %d (an inflated count means a foreign expiry path is still counted here)", got, want)
	}
}

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
	calledExpireOldCommands bool

	recoverStuckJobs           int64
	recoverStuckTenantCommands int64
	expireOldPlatformJobs      int64
	failExhaustedCommands      int64
}

func (r *recordingCommandRepo) RecoverStuckJobs(_ context.Context, _, _ int) (int64, error) {
	return r.recoverStuckJobs, nil
}

func (r *recordingCommandRepo) RecoverStuckTenantCommands(_ context.Context, _, _ int) (int64, error) {
	return r.recoverStuckTenantCommands, nil
}

func (r *recordingCommandRepo) ExpireOldPlatformJobs(_ context.Context, _ int) (int64, error) {
	return r.expireOldPlatformJobs, nil
}

func (r *recordingCommandRepo) FailExhaustedCommands(_ context.Context, _ int) (int64, error) {
	return r.failExhaustedCommands, nil
}

func (r *recordingCommandRepo) ExpireOldCommands(_ context.Context) (int64, error) {
	r.calledExpireOldCommands = true
	return 7, nil
}

// --- remaining command.Repository surface: unused by JobRecoveryController ---

func (r *recordingCommandRepo) Create(context.Context, *command.Command) error { return nil }
func (r *recordingCommandRepo) GetByID(context.Context, shared.ID) (*command.Command, error) {
	return nil, nil
}

func (r *recordingCommandRepo) GetByTenantAndID(context.Context, shared.ID, shared.ID) (*command.Command, error) {
	return nil, nil
}

func (r *recordingCommandRepo) GetPendingForAgent(context.Context, shared.ID, *shared.ID, int) ([]*command.Command, error) {
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

// TestJobRecoveryController_DoesNotExpireRegularCommands pins the removal of a
// duplicate expiry path.
//
// app/command.ExpirationChecker is the owner of regular-command expiry: it ticks
// every 60s, selects status IN ('pending','acknowledged') AND expires_at < now
// via FindExpired, marks each row expired, and calls
// pipeline.OnStepFailed(..., "COMMAND_EXPIRED") so the owning pipeline run is
// told its step died.
//
// This controller ticked on the same 60s interval and additionally ran
// CommandRepository.ExpireOldCommands — a raw `UPDATE commands SET
// status='expired' WHERE status='pending' AND expires_at < NOW()`, a strict
// subset of the same rows and with no pipeline notification. Whenever it won the
// race, FindExpired no longer matched the row and the run was never notified.
//
// Reconcile must therefore never touch ExpireOldCommands.
func TestJobRecoveryController_DoesNotExpireRegularCommands(t *testing.T) {
	repo := &recordingCommandRepo{}
	c := NewJobRecoveryController(repo, &JobRecoveryControllerConfig{
		Logger: logger.NewNop(),
	})

	if _, err := c.Reconcile(context.Background()); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}

	if repo.calledExpireOldCommands {
		t.Fatal("JobRecoveryController.Reconcile called ExpireOldCommands: " +
			"this races app/command.ExpirationChecker on the same 60s tick and, when it " +
			"wins, expires the command without ever calling pipeline OnStepFailed - the " +
			"pipeline run is left hanging with no COMMAND_EXPIRED step failure")
	}
}

// TestJobRecoveryController_ReportsOnlyItsOwnWork guards the item count after the
// removal: the ExpireOldCommands result (7 above) must not be folded in.
func TestJobRecoveryController_ReportsOnlyItsOwnWork(t *testing.T) {
	repo := &recordingCommandRepo{
		recoverStuckJobs:           1,
		recoverStuckTenantCommands: 2,
		expireOldPlatformJobs:      3,
		failExhaustedCommands:      4,
	}
	c := NewJobRecoveryController(repo, &JobRecoveryControllerConfig{Logger: logger.NewNop()})

	got, err := c.Reconcile(context.Background())
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if want := 10; got != want {
		t.Fatalf("processed count = %d, want %d (an inflated count means a foreign expiry path is still counted here)", got, want)
	}
}

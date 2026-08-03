package command

import (
	"context"
	"encoding/json"
	"testing"

	commanddom "github.com/openctemio/api/pkg/domain/command"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/logger"
)

// A platform job that times out in the dispatch queue used to be reaped by a raw
// UPDATE in JobRecoveryController. Platform jobs carry pipeline_run_id +
// step_key and are created with expires_at NULL, so FindExpired never covered
// them and that UPDATE was the only thing that ever ended them — silently. The
// owning run kept waiting on a step that was already dead, until
// ScanTimeoutController reported a generic timeout minutes or hours later.
//
// These tests pin that expiring a queued platform job notifies the run, and with
// which code.

// stubCommandRepo embeds the interface so only the methods under test need
// bodies; anything else would nil-panic loudly rather than pass quietly.
type stubCommandRepo struct {
	commanddom.Repository

	expired      []*commanddom.Command
	queueExpired []*commanddom.Command
	updated      []*commanddom.Command
}

func (s *stubCommandRepo) FindExpired(context.Context) ([]*commanddom.Command, error) {
	return s.expired, nil
}

func (s *stubCommandRepo) FindQueueExpiredPlatformJobs(context.Context, int) ([]*commanddom.Command, error) {
	return s.queueExpired, nil
}

func (s *stubCommandRepo) Update(_ context.Context, cmd *commanddom.Command) error {
	s.updated = append(s.updated, cmd)
	return nil
}

type recordedStepFailure struct {
	runID, stepKey, message, code string
}

type stubStepFailer struct {
	calls []recordedStepFailure
}

func (s *stubStepFailer) OnStepFailed(_ context.Context, runID, stepKey, message, code string) error {
	s.calls = append(s.calls, recordedStepFailure{runID, stepKey, message, code})
	return nil
}

func newPipelinePlatformJob(t *testing.T, runID, stepKey string) *commanddom.Command {
	t.Helper()

	payload, err := json.Marshal(map[string]string{
		"pipeline_run_id": runID,
		"step_key":        stepKey,
	})
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}

	cmd, err := commanddom.NewCommand(shared.NewID(), commanddom.CommandTypeScan,
		commanddom.CommandPriorityNormal, payload)
	if err != nil {
		t.Fatalf("NewCommand: %v", err)
	}
	cmd.SetPlatformJob(0)
	return cmd
}

func newCheckerUnderTest(repo commanddom.Repository, failer stepFailer) *ExpirationChecker {
	return &ExpirationChecker{
		commandRepo:     repo,
		pipelineService: failer,
		logger:          logger.NewNop(),
		maxQueueMinutes: 60,
		stopCh:          make(chan struct{}),
	}
}

func TestCheckAndExpireQueuedPlatformJobs_NotifiesOwningRun(t *testing.T) {
	runID := shared.NewID().String()
	job := newPipelinePlatformJob(t, runID, "recon")

	repo := &stubCommandRepo{queueExpired: []*commanddom.Command{job}}
	failer := &stubStepFailer{}

	newCheckerUnderTest(repo, failer).checkAndExpireQueuedPlatformJobs()

	if len(failer.calls) != 1 {
		t.Fatalf("OnStepFailed called %d times, want 1: expiring a platform job without telling "+
			"its run leaves the run waiting on a step that is already dead, until an unrelated "+
			"timeout controller reports a generic failure", len(failer.calls))
	}
	got := failer.calls[0]
	if got.runID != runID || got.stepKey != "recon" {
		t.Errorf("notified run/step = %q/%q, want %q/recon", got.runID, got.stepKey, runID)
	}
	if got.code != "PLATFORM_JOB_EXPIRED_IN_QUEUE" {
		t.Errorf("error code = %q, want PLATFORM_JOB_EXPIRED_IN_QUEUE: the run should record why "+
			"the step died, not a generic timeout", got.code)
	}
}

func TestCheckAndExpireQueuedPlatformJobs_MarksJobExpired(t *testing.T) {
	job := newPipelinePlatformJob(t, shared.NewID().String(), "recon")

	repo := &stubCommandRepo{queueExpired: []*commanddom.Command{job}}
	newCheckerUnderTest(repo, &stubStepFailer{}).checkAndExpireQueuedPlatformJobs()

	if len(repo.updated) != 1 {
		t.Fatalf("Update called %d times, want 1: an unexpired job stays in the queue forever", len(repo.updated))
	}
	if repo.updated[0].Status != commanddom.CommandStatusExpired {
		t.Errorf("status = %q, want expired", repo.updated[0].Status)
	}
	if repo.updated[0].ErrorMessage == "" {
		t.Error("error_message empty: the job row should say why it ended, so an operator " +
			"reading the command does not have to infer it")
	}
}

// A queued platform job with no pipeline payload (a bare command) must expire
// without the notification path erroring or panicking.
func TestCheckAndExpireQueuedPlatformJobs_NonPipelineJobIsStillExpired(t *testing.T) {
	cmd, err := commanddom.NewCommand(shared.NewID(), commanddom.CommandTypeScan,
		commanddom.CommandPriorityNormal, json.RawMessage(`{"target":"example.test"}`))
	if err != nil {
		t.Fatalf("NewCommand: %v", err)
	}
	cmd.SetPlatformJob(0)

	repo := &stubCommandRepo{queueExpired: []*commanddom.Command{cmd}}
	failer := &stubStepFailer{}
	newCheckerUnderTest(repo, failer).checkAndExpireQueuedPlatformJobs()

	if len(repo.updated) != 1 {
		t.Fatalf("Update called %d times, want 1", len(repo.updated))
	}
	if len(failer.calls) != 0 {
		t.Errorf("OnStepFailed called %d times for a job with no pipeline_run_id, want 0", len(failer.calls))
	}
}

// The pre-existing expires_at path must keep its own code, so the two causes
// stay distinguishable in the run's failure record.
func TestCheckAndExpire_KeepsCommandExpiredCode(t *testing.T) {
	runID := shared.NewID().String()
	cmd := newPipelinePlatformJob(t, runID, "recon")

	repo := &stubCommandRepo{expired: []*commanddom.Command{cmd}}
	failer := &stubStepFailer{}
	newCheckerUnderTest(repo, failer).checkAndExpire()

	if len(failer.calls) != 1 {
		t.Fatalf("OnStepFailed called %d times, want 1", len(failer.calls))
	}
	if failer.calls[0].code != "COMMAND_EXPIRED" {
		t.Errorf("error code = %q, want COMMAND_EXPIRED", failer.calls[0].code)
	}
}

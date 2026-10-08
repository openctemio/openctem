package handler

import (
	"context"
	"encoding/json"
	"sync"
	"testing"

	"github.com/openctemio/openctem/api/internal/app/command"
	"github.com/openctemio/openctem/api/internal/app/validation"
	commanddom "github.com/openctemio/openctem/api/pkg/domain/command"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

type runSettleRecorder struct {
	mu    sync.Mutex
	codes []string
}

func (r *runSettleRecorder) FinishValidationRun(_ context.Context, _, _ shared.ID, succeeded bool, _, code string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !succeeded {
		r.codes = append(r.codes, code)
	}
	return nil
}

func (r *runSettleRecorder) n() int { r.mu.Lock(); defer r.mu.Unlock(); return len(r.codes) }

// The command handler is the claim-time re-check's failure observer: a
// validate or retest command failed with SCOPE_CHANGED settles its
// validation run or retest as a sensor's failure would.
func TestOnCommandFailed_SettlesValidationRunAndRetest(t *testing.T) {
	var _ command.FailureObserver = (*CommandHandler)(nil)
	runs := &runSettleRecorder{}
	settler := &settleRecorder{}
	h := &CommandHandler{logger: logger.NewNop()}
	h.SetValidationRuns(runs)
	h.SetRetestHooks(&advisoryRecorder{}, settler)
	tenantID := shared.NewID()

	payload, _ := json.Marshal(validation.ValidateCommandPayload{FindingID: shared.NewID().String(), ScanRunID: shared.NewID().String()})
	validate, _ := commanddom.NewCommand(tenantID, commanddom.CommandTypeValidate, commanddom.CommandPriorityNormal, payload)
	validate.Fail("SCOPE_CHANGED: a (excluded)")
	h.OnCommandFailed(context.Background(), validate, validate.ErrorMessage, command.FailureScopeChanged)
	waitFor(t, func() bool { return runs.n() == 1 })
	if runs.codes[0] != command.FailureScopeChanged {
		t.Fatalf("validation run settled with %v", runs.codes)
	}

	retest, _ := commanddom.NewCommand(tenantID, commanddom.CommandTypeRetest, commanddom.CommandPriorityNormal, json.RawMessage(`{"scanner":"nuclei"}`))
	retest.Fail("SCOPE_CHANGED: a (excluded)")
	h.OnCommandFailed(context.Background(), retest, retest.ErrorMessage, command.FailureScopeChanged)
	waitFor(t, func() bool { return settler.n() == 1 })
}

package handler

import (
	"context"
	"encoding/json"
	"sync"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/internal/app/validation"
	commanddom "github.com/openctemio/openctem/api/pkg/domain/command"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

type advisoryRecorder struct {
	mu    sync.Mutex
	calls int
}

func (a *advisoryRecorder) IngestAdvisory(context.Context, shared.ID, shared.ID, *shared.ID, validation.Evidence) (validation.IngestResult, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.calls++
	return validation.IngestResult{}, nil
}

func (a *advisoryRecorder) n() int { a.mu.Lock(); defer a.mu.Unlock(); return a.calls }

type settleRecorder struct {
	mu       sync.Mutex
	commands []shared.ID
	tenants  []shared.ID
}

func (s *settleRecorder) OnCommandFinished(_ context.Context, tenantID, commandID shared.ID) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.commands = append(s.commands, commandID)
	s.tenants = append(s.tenants, tenantID)
}

func (s *settleRecorder) n() int { s.mu.Lock(); defer s.mu.Unlock(); return len(s.commands) }

func retestValidateCommand(t *testing.T, tenantID shared.ID, outcome string) *commanddom.Command {
	t.Helper()
	payload, _ := json.Marshal(validation.ValidateCommandPayload{
		FindingID: shared.NewID().String(), ExecutorKind: "nuclei", Technique: "T1190",
		TemplateID: "exposed-panel", RetestID: shared.NewID().String(),
	})
	cmd, err := commanddom.NewCommand(tenantID, commanddom.CommandTypeValidate, commanddom.CommandPriorityNormal, payload)
	if err != nil {
		t.Fatal(err)
	}
	result, _ := json.Marshal(map[string]any{"metadata": map[string]any{"outcome": outcome}})
	cmd.Complete(result)
	return cmd
}

// A retest check's result must never go through the validation verdict rule:
// "not_detected" there downgrades the finding even when the host was just down
// (RFC-039 §2.3 D-a). It is recorded advisory-only and handed to the retest
// service, which reads both checks together.
func TestTriggerValidationEvidence_RetestCheckIsAdvisoryAndSettles(t *testing.T) {
	applied := &captureIngester{}
	advisory := &advisoryRecorder{}
	settler := &settleRecorder{}
	h := &CommandHandler{logger: logger.NewNop()}
	h.SetValidationIngest(applied)
	h.SetRetestHooks(advisory, settler)

	tenantID := shared.NewID()
	cmd := retestValidateCommand(t, tenantID, "not_detected")
	h.triggerValidationEvidence(cmd)

	waitFor(t, func() bool { return advisory.n() == 1 && settler.n() == 1 })
	time.Sleep(20 * time.Millisecond)
	if calls, _, _, _ := applied.snapshot(); calls != 0 {
		t.Fatalf("retest evidence was applied to the finding %d time(s); it must be advisory only", calls)
	}
	if settler.commands[0] != cmd.ID || settler.tenants[0] != tenantID {
		t.Errorf("settle called with (%s, %s), want the command's own tenant and id", settler.tenants[0], settler.commands[0])
	}
}

// A failed retest check settles its retest too (it ends unknown).
func TestTriggerRetestSettle_OnFailedCommand(t *testing.T) {
	settler := &settleRecorder{}
	h := &CommandHandler{logger: logger.NewNop()}
	h.SetRetestHooks(&advisoryRecorder{}, settler)
	cmd := retestValidateCommand(t, shared.NewID(), "")
	h.triggerRetestSettle(cmd)
	waitFor(t, func() bool { return settler.n() == 1 })

	// A plain validation command (no retest) is not a retest's business.
	plain := validateCommand(t, shared.NewID(), shared.NewID(), "detected")
	h.triggerRetestSettle(plain)
	time.Sleep(20 * time.Millisecond)
	if settler.n() != 1 {
		t.Errorf("a non-retest command was handed to the retest service")
	}
}

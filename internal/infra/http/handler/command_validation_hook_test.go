package handler

import (
	"context"
	"encoding/json"
	"sync"
	"testing"
	"time"

	"github.com/openctemio/api/internal/app/validation"
	commanddom "github.com/openctemio/api/pkg/domain/command"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/logger"
)

type captureIngester struct {
	mu       sync.Mutex
	calls    int
	tenantID shared.ID
	finding  shared.ID
	ev       validation.Evidence
}

func (c *captureIngester) Ingest(_ context.Context, tenantID, findingID shared.ID, _ *shared.ID, ev validation.Evidence) (validation.IngestResult, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.calls++
	c.tenantID = tenantID
	c.finding = findingID
	c.ev = ev
	return validation.IngestResult{StatusChanged: true}, nil
}

func (c *captureIngester) snapshot() (int, shared.ID, shared.ID, validation.Evidence) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.calls, c.tenantID, c.finding, c.ev
}

func validateCommand(t *testing.T, tenantID, findingID shared.ID, outcome string) *commanddom.Command {
	t.Helper()
	payload, _ := json.Marshal(validation.ValidateCommandPayload{
		FindingID:    findingID.String(),
		ExecutorKind: "safe-check",
		Technique:    "T1046",
		Target:       validation.ValidateTargetPayload{Type: "domain", Address: "example.com"},
	})
	cmd, err := commanddom.NewCommand(tenantID, commanddom.CommandTypeValidate, commanddom.CommandPriorityNormal, payload)
	if err != nil {
		t.Fatalf("new command: %v", err)
	}
	result, _ := json.Marshal(validation.ValidateResultPayload{Outcome: outcome, Summary: "port closed"})
	cmd.Complete(result)
	return cmd
}

// validateCommandMetadataResult builds a validate command whose result nests the
// verdict under `metadata` — the shape the SDK command poller produces from an
// agent's CommandExecutionResult.Metadata.
func validateCommandMetadataResult(t *testing.T, tenantID, findingID shared.ID, outcome string) *commanddom.Command {
	t.Helper()
	payload, _ := json.Marshal(validation.ValidateCommandPayload{
		FindingID:    findingID.String(),
		ExecutorKind: "safe-check",
		Technique:    "T1046",
	})
	cmd, err := commanddom.NewCommand(tenantID, commanddom.CommandTypeValidate, commanddom.CommandPriorityNormal, payload)
	if err != nil {
		t.Fatalf("new command: %v", err)
	}
	result, _ := json.Marshal(map[string]any{
		"status": "completed",
		"metadata": map[string]any{
			"outcome": outcome,
			"summary": "port closed",
		},
	})
	cmd.Complete(result)
	return cmd
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("condition not met before timeout")
}

func TestTriggerValidationEvidence_MapsResultToIngestWithCommandTenant(t *testing.T) {
	ing := &captureIngester{}
	h := &CommandHandler{logger: logger.NewNop()}
	h.SetValidationIngest(ing)

	tenantID := shared.NewID()
	findingID := shared.NewID()
	cmd := validateCommand(t, tenantID, findingID, "not_detected")

	h.triggerValidationEvidence(cmd)

	waitFor(t, func() bool {
		calls, _, _, _ := ing.snapshot()
		return calls == 1
	})

	_, gotTenant, gotFinding, ev := ing.snapshot()
	if gotTenant != tenantID {
		t.Errorf("ingest tenant = %s, want command tenant %s", gotTenant, tenantID)
	}
	if gotFinding != findingID {
		t.Errorf("ingest finding = %s, want %s", gotFinding, findingID)
	}
	if ev.Outcome != validation.OutcomeNotDetected {
		t.Errorf("evidence outcome = %q, want not_detected", ev.Outcome)
	}
	if ev.ExecutorKind != "safe-check" {
		t.Errorf("evidence executor kind = %q, want safe-check", ev.ExecutorKind)
	}
}

func TestTriggerValidationEvidence_ReadsOutcomeFromMetadata(t *testing.T) {
	ing := &captureIngester{}
	h := &CommandHandler{logger: logger.NewNop()}
	h.SetValidationIngest(ing)

	tenantID := shared.NewID()
	findingID := shared.NewID()
	cmd := validateCommandMetadataResult(t, tenantID, findingID, "detected")

	h.triggerValidationEvidence(cmd)

	waitFor(t, func() bool {
		calls, _, _, _ := ing.snapshot()
		return calls == 1
	})

	_, gotTenant, gotFinding, ev := ing.snapshot()
	if gotTenant != tenantID || gotFinding != findingID {
		t.Errorf("ingest tenant/finding = %s/%s, want %s/%s", gotTenant, gotFinding, tenantID, findingID)
	}
	if ev.Outcome != validation.OutcomeDetected {
		t.Errorf("evidence outcome = %q, want detected (from metadata)", ev.Outcome)
	}
}

func TestTriggerValidationEvidence_IgnoresNonValidateCommand(t *testing.T) {
	ing := &captureIngester{}
	h := &CommandHandler{logger: logger.NewNop()}
	h.SetValidationIngest(ing)

	payload, _ := json.Marshal(map[string]any{"scan_id": "x"})
	cmd, _ := commanddom.NewCommand(shared.NewID(), commanddom.CommandTypeScan, commanddom.CommandPriorityNormal, payload)
	cmd.Complete(nil)

	h.triggerValidationEvidence(cmd)

	// Give any (erroneous) goroutine a chance to run.
	time.Sleep(50 * time.Millisecond)
	if calls, _, _, _ := ing.snapshot(); calls != 0 {
		t.Errorf("ingest called %d times for a scan command, want 0", calls)
	}
}

func TestTriggerValidationEvidence_SkipsWhenNoOutcome(t *testing.T) {
	ing := &captureIngester{}
	h := &CommandHandler{logger: logger.NewNop()}
	h.SetValidationIngest(ing)

	// Validate command that completed with an empty result → no verdict.
	tenantID := shared.NewID()
	findingID := shared.NewID()
	cmd := validateCommand(t, tenantID, findingID, "")

	h.triggerValidationEvidence(cmd)

	time.Sleep(50 * time.Millisecond)
	if calls, _, _, _ := ing.snapshot(); calls != 0 {
		t.Errorf("ingest called %d times with no outcome, want 0", calls)
	}
}

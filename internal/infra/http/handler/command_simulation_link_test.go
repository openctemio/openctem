package handler

import (
	"encoding/json"
	"testing"

	"github.com/openctemio/api/internal/app/validation"
	commanddom "github.com/openctemio/api/pkg/domain/command"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/logger"
)

// triggerValidationEvidence passed nil for the simulation run id, so every row
// this path wrote had simulation_run_id NULL. On the live database that was all
// 5 of them — every one executor_kind=safe-check, i.e. every one produced BY a
// simulation and none traceable back to one. The API exposes the field, so
// "which evidence did this run produce?" answered empty.
//
// The value was never missing: payload.SimulationRunID is the same field the
// sibling triggerSimulationFinalize already reads to decide which run to
// finalize. The two paths simply disagreed about whether it existed.
//
// Note the old mock signature was `_ *shared.ID` — it discarded the argument,
// which is exactly why no test could see this. A mock that ignores a parameter
// cannot fail when the parameter is wrong.

func simulationValidateCommand(t *testing.T, tenantID, findingID shared.ID, simRunID string) *commanddom.Command {
	t.Helper()

	payload, err := json.Marshal(validation.ValidateCommandPayload{
		FindingID:       findingID.String(),
		SimulationRunID: simRunID,
		ExecutorKind:    "safe-check",
		Technique:       "T1046",
		Target:          validation.ValidateTargetPayload{Type: "domain", Address: "example.com"},
	})
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}

	cmd, err := commanddom.NewCommand(tenantID, commanddom.CommandTypeValidate,
		commanddom.CommandPriorityNormal, payload)
	if err != nil {
		t.Fatalf("new command: %v", err)
	}
	result, err := json.Marshal(validation.ValidateResultPayload{
		Outcome: "not_detected", Summary: "port closed",
	})
	if err != nil {
		t.Fatalf("marshal result: %v", err)
	}
	cmd.Complete(result)
	return cmd
}

func TestTriggerValidationEvidence_CarriesTheSimulationLink(t *testing.T) {
	ing := &captureIngester{}
	h := &CommandHandler{logger: logger.NewNop()}
	h.SetValidationIngest(ing)

	simRunID := shared.NewID()
	cmd := simulationValidateCommand(t, shared.NewID(), shared.NewID(), simRunID.String())

	h.triggerValidationEvidence(cmd)
	waitFor(t, func() bool { calls, _, _, _ := ing.snapshot(); return calls == 1 })

	got := ing.simRun()
	if got == nil {
		t.Fatal("evidence was ingested with a nil simulation run id even though the " +
			"command payload carries one. The row lands with simulation_run_id NULL " +
			"and the run it came from can never be traced to it")
	}
	if *got != simRunID {
		t.Errorf("simulation_run_id = %s, want %s", got, simRunID)
	}
}

// Validation that is not part of a simulation must stay unlinked — inventing a
// link would be worse than missing one.
func TestTriggerValidationEvidence_NoSimulationStaysNil(t *testing.T) {
	ing := &captureIngester{}
	h := &CommandHandler{logger: logger.NewNop()}
	h.SetValidationIngest(ing)

	cmd := simulationValidateCommand(t, shared.NewID(), shared.NewID(), "")

	h.triggerValidationEvidence(cmd)
	waitFor(t, func() bool { calls, _, _, _ := ing.snapshot(); return calls == 1 })

	if got := ing.simRun(); got != nil {
		t.Errorf("simulation_run_id = %s for a command with no simulation; a "+
			"fabricated link is worse than an absent one", got)
	}
}

// A malformed id costs the link, not the finding update. Dropping the evidence
// would turn a cosmetic provenance problem into a lost validation result.
func TestTriggerValidationEvidence_MalformedSimulationIDStillIngests(t *testing.T) {
	ing := &captureIngester{}
	h := &CommandHandler{logger: logger.NewNop()}
	h.SetValidationIngest(ing)

	cmd := simulationValidateCommand(t, shared.NewID(), shared.NewID(), "not-a-uuid")

	h.triggerValidationEvidence(cmd)
	waitFor(t, func() bool { calls, _, _, _ := ing.snapshot(); return calls == 1 })

	if got := ing.simRun(); got != nil {
		t.Errorf("an unparseable simulation_run_id produced a link: %s", got)
	}
	calls, _, _, ev := ing.snapshot()
	if calls != 1 {
		t.Fatalf("ingest calls = %d, want 1: the evidence must survive a bad link", calls)
	}
	if ev.Outcome != validation.Outcome("not_detected") {
		t.Errorf("outcome = %q, want not_detected — the verdict must be unaffected", ev.Outcome)
	}
}

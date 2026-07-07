package validation

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	commanddom "github.com/openctemio/api/pkg/domain/command"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/logger"
)

type fakeCommandCreator struct {
	created *commanddom.Command
	err     error
}

func (f *fakeCommandCreator) Create(_ context.Context, cmd *commanddom.Command) error {
	if f.err != nil {
		return f.err
	}
	f.created = cmd
	return nil
}

func TestCommandDispatcher_Dispatch_BuildsValidateCommand(t *testing.T) {
	cc := &fakeCommandCreator{}
	d := NewCommandDispatcher(cc, logger.NewNop())

	tenant := shared.NewID()
	finding := shared.NewID()
	assetID := shared.NewID()
	job := ValidationJob{
		JobID:          shared.NewID(),
		TenantID:       tenant,
		FindingID:      finding,
		ExecutorKind:   KindSafeCheck,
		Technique:      "T1046",
		Target:         Target{AssetID: assetID, Type: "domain", Address: "example.com"},
		TimeoutSeconds: 120,
	}

	cmdID, err := d.Dispatch(context.Background(), job)
	if err != nil {
		t.Fatalf("Dispatch: %v", err)
	}
	if cc.created == nil {
		t.Fatal("no command created")
	}
	if cc.created.Type != commanddom.CommandTypeValidate {
		t.Errorf("command type = %q, want validate", cc.created.Type)
	}
	if cc.created.TenantID != tenant {
		t.Errorf("command tenant = %s, want %s", cc.created.TenantID, tenant)
	}
	if cmdID != cc.created.ID {
		t.Errorf("returned id %s != created id %s", cmdID, cc.created.ID)
	}

	var p ValidateCommandPayload
	if err := json.Unmarshal(cc.created.Payload, &p); err != nil {
		t.Fatalf("payload not valid JSON: %v", err)
	}
	if p.FindingID != finding.String() {
		t.Errorf("payload finding = %q, want %q", p.FindingID, finding.String())
	}
	if p.ExecutorKind != "safe-check" {
		t.Errorf("payload executor_kind = %q, want safe-check", p.ExecutorKind)
	}
	if p.Target.Address != "example.com" {
		t.Errorf("payload target address = %q, want example.com", p.Target.Address)
	}
	if p.Technique != "T1046" {
		t.Errorf("payload technique = %q, want T1046", p.Technique)
	}

	hasValidate := false
	for _, c := range p.RequiredCapabilities {
		if c == "validate" {
			hasValidate = true
		}
	}
	if !hasValidate {
		t.Errorf("required_capabilities %v missing 'validate' (agent routing)", p.RequiredCapabilities)
	}
}

func TestCommandDispatcher_Dispatch_RejectsZeroIDs(t *testing.T) {
	d := NewCommandDispatcher(&fakeCommandCreator{}, logger.NewNop())
	if _, err := d.Dispatch(context.Background(), ValidationJob{}); err == nil {
		t.Fatal("expected validation error for zero tenant/finding ids")
	}
}

// RFC-012: a job may carry a simulation run instead of a finding. The payload
// then sets simulation_run_id and leaves finding_id empty.
func TestCommandDispatcher_Dispatch_SimulationJob(t *testing.T) {
	cc := &fakeCommandCreator{}
	d := NewCommandDispatcher(cc, logger.NewNop())

	simRun := shared.NewID()
	job := ValidationJob{
		JobID:           shared.NewID(),
		TenantID:        shared.NewID(),
		SimulationRunID: simRun,
		ExecutorKind:    KindSafeCheck,
		Technique:       "T1046",
		Target:          Target{AssetID: shared.NewID(), Type: "domain", Address: "example.com"},
	}
	if _, err := d.Dispatch(context.Background(), job); err != nil {
		t.Fatalf("Dispatch(simulation job): %v", err)
	}

	var p ValidateCommandPayload
	if err := json.Unmarshal(cc.created.Payload, &p); err != nil {
		t.Fatalf("unmarshal payload: %v", err)
	}
	if p.SimulationRunID != simRun.String() {
		t.Errorf("payload simulation_run_id = %q, want %q", p.SimulationRunID, simRun.String())
	}
	if p.FindingID != "" {
		t.Errorf("payload finding_id = %q, want empty for a simulation job", p.FindingID)
	}
}

func TestCommandDispatcher_Dispatch_PropagatesRepoError(t *testing.T) {
	cc := &fakeCommandCreator{err: errors.New("db down")}
	d := NewCommandDispatcher(cc, logger.NewNop())
	_, err := d.Dispatch(context.Background(), ValidationJob{
		JobID:     shared.NewID(),
		TenantID:  shared.NewID(),
		FindingID: shared.NewID(),
	})
	if err == nil {
		t.Fatal("expected error when command repo fails")
	}
}

package scancoverage

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/openctemio/api/pkg/domain/command"
	"github.com/openctemio/api/pkg/domain/shared"
)

type fakeCommandCreator struct {
	created *command.Command
	err     error
}

func (f *fakeCommandCreator) Create(_ context.Context, cmd *command.Command) error {
	if f.err != nil {
		return f.err
	}
	f.created = cmd
	return nil
}

func TestDispatchTenableScan_BuildsRoutableCommand(t *testing.T) {
	fc := &fakeCommandCreator{}
	d := NewDispatcher(fc)
	tenant := shared.NewID()

	id, session, err := d.DispatchTenableScan(context.Background(), DispatchTenableInput{
		TenantID:  tenant,
		Targets:   []string{"10.0.0.0/24", "10.0.1.5"},
		SessionID: "batch-7",
		Engine:    "tenable_sc",
	})
	if err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	if id.IsZero() || session != "batch-7" {
		t.Fatalf("bad return: id=%v session=%q", id, session)
	}
	if fc.created == nil {
		t.Fatal("no command created")
	}
	if fc.created.Type != command.CommandTypeScan {
		t.Fatalf("command type should be scan, got %q", fc.created.Type)
	}
	if fc.created.TenantID != tenant {
		t.Fatal("tenant not set on command")
	}
	if fc.created.AgentID != nil {
		t.Fatal("agent should be unpinned (capability-routed) by default")
	}

	var p map[string]any
	if err := json.Unmarshal(fc.created.Payload, &p); err != nil {
		t.Fatalf("payload not JSON: %v", err)
	}
	// scanner=tenable is what the agent routes on (must reach the tenable executor).
	if p["scanner"] != "tenable" {
		t.Fatalf("scanner must be tenable, got %v", p["scanner"])
	}
	if p["session_id"] != "batch-7" {
		t.Fatalf("session_id wrong: %v", p["session_id"])
	}
	caps, _ := p["required_capabilities"].([]any)
	if len(caps) != 1 || caps[0] != "infra" {
		t.Fatalf("required_capabilities should be [infra], got %v", p["required_capabilities"])
	}
	tgts, _ := p["targets"].([]any)
	if len(tgts) != 2 {
		t.Fatalf("expected 2 targets, got %v", p["targets"])
	}
}

func TestDispatchTenableScan_GeneratesSessionAndPinsAgent(t *testing.T) {
	fc := &fakeCommandCreator{}
	d := NewDispatcher(fc)
	agent := shared.NewID()

	_, session, err := d.DispatchTenableScan(context.Background(), DispatchTenableInput{
		TenantID: shared.NewID(),
		Targets:  []string{"10.0.0.1"},
		AgentID:  &agent,
	})
	if err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	if session == "" {
		t.Fatal("session id should be generated when empty")
	}
	if fc.created.AgentID == nil || *fc.created.AgentID != agent {
		t.Fatal("agent id should be pinned when provided (C3)")
	}
}

func TestDispatchTenableScan_Validation(t *testing.T) {
	d := NewDispatcher(&fakeCommandCreator{})
	if _, _, err := d.DispatchTenableScan(context.Background(), DispatchTenableInput{Targets: []string{"x"}}); err == nil {
		t.Fatal("missing tenant must error")
	}
	if _, _, err := d.DispatchTenableScan(context.Background(), DispatchTenableInput{TenantID: shared.NewID()}); err == nil {
		t.Fatal("missing targets must error")
	}
}

func TestDispatchTenableScan_PropagatesCreateError(t *testing.T) {
	fc := &fakeCommandCreator{err: errors.New("db down")}
	d := NewDispatcher(fc)
	if _, _, err := d.DispatchTenableScan(context.Background(), DispatchTenableInput{
		TenantID: shared.NewID(), Targets: []string{"10.0.0.1"},
	}); err == nil {
		t.Fatal("create error must propagate")
	}
}

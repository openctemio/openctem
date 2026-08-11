package validation

import (
	"context"
	"errors"
	"testing"

	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/logger"
)

// fakeAvailability stubs the per-tenant capability gate.
type fakeAvailability struct {
	has    bool
	err    error
	called bool
}

func (f *fakeAvailability) HasValidationAgent(_ context.Context, _ shared.ID) (bool, error) {
	f.called = true
	return f.has, f.err
}

func newGatedRunService(disp *fakeJobDispatcher, avail AgentAvailability, f *fakeFindingLookup, a *fakeAssetLookup) *RunService {
	svc := NewRunService(f, a, disp, DefaultSelector{}, []ExecutorKind{KindSafeCheck}, logger.NewNop())
	svc.SetAgentAvailability(avail)
	return svc
}

// When a validation-capable agent is online, ValidateFinding dispatches.
func TestRunService_ValidateFinding_GateOpen_Dispatches(t *testing.T) {
	assetID := shared.NewID()
	f := newTestFinding(t, assetID)
	a := newTestAsset(t, "example.com")
	disp := &fakeJobDispatcher{id: shared.NewID()}
	avail := &fakeAvailability{has: true}

	svc := newGatedRunService(disp, avail, &fakeFindingLookup{f: f}, &fakeAssetLookup{a: a})

	cmdID, err := svc.ValidateFinding(context.Background(), shared.NewID(), f.ID())
	if err != nil {
		t.Fatalf("ValidateFinding: %v", err)
	}
	if !avail.called {
		t.Fatal("expected availability gate to be consulted")
	}
	if cmdID != disp.id {
		t.Errorf("command id = %s, want %s", cmdID, disp.id)
	}
	if disp.got.FindingID != f.ID() {
		t.Errorf("dispatcher not invoked with finding: got %s", disp.got.FindingID)
	}
}

// When no validation-capable agent is online, ValidateFinding skips with
// ErrNoValidationAgent and NEVER enqueues a command (non-inert: nothing is left
// for an absent consumer).
func TestRunService_ValidateFinding_GateClosed_SkipsAndDoesNotDispatch(t *testing.T) {
	assetID := shared.NewID()
	f := newTestFinding(t, assetID)
	a := newTestAsset(t, "example.com")
	disp := &fakeJobDispatcher{id: shared.NewID()}
	avail := &fakeAvailability{has: false}

	svc := newGatedRunService(disp, avail, &fakeFindingLookup{f: f}, &fakeAssetLookup{a: a})

	_, err := svc.ValidateFinding(context.Background(), shared.NewID(), f.ID())
	if !errors.Is(err, ErrNoValidationAgent) {
		t.Fatalf("error = %v, want ErrNoValidationAgent", err)
	}
	// Wraps ErrValidation so the HTTP layer returns 400, not 500.
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("ErrNoValidationAgent should wrap ErrValidation")
	}
	if !disp.got.JobID.IsZero() {
		t.Error("dispatcher must NOT be called when no agent is available")
	}
}

// A gate lookup failure propagates rather than silently dispatching.
func TestRunService_ValidateFinding_GateError_Propagates(t *testing.T) {
	assetID := shared.NewID()
	f := newTestFinding(t, assetID)
	a := newTestAsset(t, "example.com")
	disp := &fakeJobDispatcher{id: shared.NewID()}
	sentinel := errors.New("registry down")
	avail := &fakeAvailability{err: sentinel}

	svc := newGatedRunService(disp, avail, &fakeFindingLookup{f: f}, &fakeAssetLookup{a: a})

	_, err := svc.ValidateFinding(context.Background(), shared.NewID(), f.ID())
	if !errors.Is(err, sentinel) {
		t.Fatalf("error = %v, want wrapped %v", err, sentinel)
	}
	if !disp.got.JobID.IsZero() {
		t.Error("dispatcher must NOT be called when the gate errors")
	}
}

// With no gate installed (nil), behavior is unchanged — dispatch is
// unconditional (backward compatibility with the pre-gate wiring).
func TestRunService_ValidateFinding_NilGate_DispatchesUnconditionally(t *testing.T) {
	assetID := shared.NewID()
	f := newTestFinding(t, assetID)
	a := newTestAsset(t, "example.com")
	disp := &fakeJobDispatcher{id: shared.NewID()}

	svc := NewRunService(&fakeFindingLookup{f: f}, &fakeAssetLookup{a: a}, disp,
		DefaultSelector{}, []ExecutorKind{KindSafeCheck}, logger.NewNop())

	if _, err := svc.ValidateFinding(context.Background(), shared.NewID(), f.ID()); err != nil {
		t.Fatalf("ValidateFinding: %v", err)
	}
	if disp.got.JobID.IsZero() {
		t.Error("dispatcher should be called when no gate is installed")
	}
}

// The simulation-run path is gated identically: no agent → ErrNoValidationAgent
// and no dispatch, so the caller (tryDispatchLive) falls back to the synthetic
// path instead of stranding the run in "running".
func TestRunService_DispatchSimulationCheck_GateClosed_SkipsAndDoesNotDispatch(t *testing.T) {
	assetID := shared.NewID()
	a := newTestAsset(t, "example.com")
	disp := &fakeJobDispatcher{id: shared.NewID()}
	avail := &fakeAvailability{has: false}

	svc := newGatedRunService(disp, avail, &fakeFindingLookup{}, &fakeAssetLookup{a: a})

	_, err := svc.DispatchSimulationCheck(context.Background(), shared.NewID(), shared.NewID(), assetID, "T1046")
	if !errors.Is(err, ErrNoValidationAgent) {
		t.Fatalf("error = %v, want ErrNoValidationAgent", err)
	}
	if !disp.got.JobID.IsZero() {
		t.Error("dispatcher must NOT be called when no agent is available")
	}
}

func TestRunService_DispatchSimulationCheck_GateOpen_Dispatches(t *testing.T) {
	assetID := shared.NewID()
	a := newTestAsset(t, "example.com")
	disp := &fakeJobDispatcher{id: shared.NewID()}
	avail := &fakeAvailability{has: true}

	svc := newGatedRunService(disp, avail, &fakeFindingLookup{}, &fakeAssetLookup{a: a})

	cmdID, err := svc.DispatchSimulationCheck(context.Background(), shared.NewID(), shared.NewID(), assetID, "T1046")
	if err != nil {
		t.Fatalf("DispatchSimulationCheck: %v", err)
	}
	if cmdID != disp.id {
		t.Errorf("command id = %s, want %s", cmdID, disp.id)
	}
	if disp.got.SimulationRunID.IsZero() {
		t.Error("dispatcher should be invoked with the simulation run id")
	}
}

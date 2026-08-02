package validation

import (
	"context"
	"errors"
	"testing"

	"github.com/openctemio/api/pkg/domain/asset"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/domain/vulnerability"
	"github.com/openctemio/api/pkg/logger"
)

type fakeFindingLookup struct {
	f   *vulnerability.Finding
	err error
}

func (l fakeFindingLookup) GetByID(_ context.Context, _, _ shared.ID) (*vulnerability.Finding, error) {
	return l.f, l.err
}

type fakeAssetLookup struct {
	a   *asset.Asset
	err error
}

func (l fakeAssetLookup) GetByID(_ context.Context, _, _ shared.ID) (*asset.Asset, error) {
	return l.a, l.err
}

type fakeJobDispatcher struct {
	got ValidationJob
	id  shared.ID
	err error
}

func (d *fakeJobDispatcher) Dispatch(_ context.Context, job ValidationJob) (shared.ID, error) {
	d.got = job
	return d.id, d.err
}

func newTestFinding(t *testing.T, assetID shared.ID) *vulnerability.Finding {
	t.Helper()
	f, err := vulnerability.NewFinding(
		shared.NewID(), assetID,
		vulnerability.FindingSourceManual, "tool",
		vulnerability.SeverityHigh, "test finding",
	)
	if err != nil {
		t.Fatalf("new finding: %v", err)
	}
	return f
}

func newTestAsset(t *testing.T, name string) *asset.Asset {
	t.Helper()
	a, err := asset.NewAsset(name, asset.AssetTypeDomain, asset.CriticalityHigh)
	if err != nil {
		t.Fatalf("new asset: %v", err)
	}
	return a
}

func TestRunService_ValidateFinding_SelectsSafeCheckAndDispatches(t *testing.T) {
	assetID := shared.NewID()
	f := newTestFinding(t, assetID)
	a := newTestAsset(t, "example.com")
	disp := &fakeJobDispatcher{id: shared.NewID()}

	svc := NewRunService(
		fakeFindingLookup{f: f},
		fakeAssetLookup{a: a},
		disp,
		DefaultSelector{},
		[]ExecutorKind{KindSafeCheck},
		logger.NewNop(),
	)

	cmdID, err := svc.ValidateFinding(context.Background(), shared.NewID(), f.ID())
	if err != nil {
		t.Fatalf("ValidateFinding: %v", err)
	}
	if cmdID != disp.id {
		t.Errorf("returned command id %s != dispatched %s", cmdID, disp.id)
	}
	if disp.got.ExecutorKind != KindSafeCheck {
		t.Errorf("executor kind = %q, want safe-check", disp.got.ExecutorKind)
	}
	if disp.got.Target.Address != "example.com" {
		t.Errorf("target address = %q, want example.com", disp.got.Target.Address)
	}
	if disp.got.Technique != safeCheckTechnique {
		t.Errorf("technique = %q, want %q", disp.got.Technique, safeCheckTechnique)
	}
	if disp.got.FindingID != f.ID() {
		t.Errorf("finding id = %s, want %s", disp.got.FindingID, f.ID())
	}
}

func TestRunService_ValidateFinding_NoExecutorAvailable(t *testing.T) {
	assetID := shared.NewID()
	f := newTestFinding(t, assetID)
	a := newTestAsset(t, "example.com")
	disp := &fakeJobDispatcher{id: shared.NewID()}

	// Fleet advertises no executor kinds → selector returns ErrNoExecutor.
	svc := NewRunService(
		fakeFindingLookup{f: f},
		fakeAssetLookup{a: a},
		disp,
		DefaultSelector{},
		nil,
		logger.NewNop(),
	)

	_, err := svc.ValidateFinding(context.Background(), shared.NewID(), f.ID())
	if err == nil {
		t.Fatal("expected error when no executor kind is available")
	}
	if !errors.Is(err, ErrNoExecutor) {
		t.Errorf("error = %v, want ErrNoExecutor", err)
	}
}

func TestRunService_ValidateFinding_RejectsNonNetworkAsset(t *testing.T) {
	assetID := shared.NewID()
	f := newTestFinding(t, assetID)
	// A code repository has no host/IP a safe-check probe can dial.
	repo, err := asset.NewAsset("github.com/acme/app", asset.AssetTypeRepository, asset.CriticalityHigh)
	if err != nil {
		t.Fatalf("new asset: %v", err)
	}
	disp := &fakeJobDispatcher{id: shared.NewID()}

	svc := NewRunService(
		fakeFindingLookup{f: f},
		fakeAssetLookup{a: repo},
		disp,
		DefaultSelector{},
		[]ExecutorKind{KindSafeCheck},
		logger.NewNop(),
	)

	_, err = svc.ValidateFinding(context.Background(), shared.NewID(), f.ID())
	if !errors.Is(err, ErrNotNetworkAddressable) {
		t.Fatalf("error = %v, want ErrNotNetworkAddressable", err)
	}
	if disp.got.FindingID != (shared.ID{}) {
		t.Error("dispatcher should not be called for a non-network asset")
	}
}

func TestRunService_DispatchSimulationCheck_BuildsJobWithSimRunID(t *testing.T) {
	a := newTestAsset(t, "example.com")
	disp := &fakeJobDispatcher{id: shared.NewID()}
	svc := NewRunService(
		fakeFindingLookup{}, fakeAssetLookup{a: a}, disp,
		DefaultSelector{}, []ExecutorKind{KindSafeCheck}, logger.NewNop(),
	)

	simRunID := shared.NewID()
	cmdID, err := svc.DispatchSimulationCheck(context.Background(), shared.NewID(), simRunID, shared.NewID(), string(safeCheckTechnique))
	if err != nil {
		t.Fatalf("DispatchSimulationCheck: %v", err)
	}
	if cmdID != disp.id {
		t.Errorf("returned cmd id %s != dispatched %s", cmdID, disp.id)
	}
	if disp.got.SimulationRunID != simRunID {
		t.Errorf("job simulation run id = %s, want %s", disp.got.SimulationRunID, simRunID)
	}
	if !disp.got.FindingID.IsZero() {
		t.Errorf("simulation job must not carry a finding id, got %s", disp.got.FindingID)
	}
	if disp.got.Target.Address != "example.com" {
		t.Errorf("target address = %q, want example.com", disp.got.Target.Address)
	}
}

func TestRunService_DispatchSimulationCheck_RejectsNonNetworkAsset(t *testing.T) {
	repo, _ := asset.NewAsset("github.com/acme/app", asset.AssetTypeRepository, asset.CriticalityHigh)
	disp := &fakeJobDispatcher{id: shared.NewID()}
	svc := NewRunService(
		fakeFindingLookup{}, fakeAssetLookup{a: repo}, disp,
		DefaultSelector{}, []ExecutorKind{KindSafeCheck}, logger.NewNop(),
	)
	_, err := svc.DispatchSimulationCheck(context.Background(), shared.NewID(), shared.NewID(), shared.NewID(), string(safeCheckTechnique))
	if !errors.Is(err, ErrNotNetworkAddressable) {
		t.Fatalf("error = %v, want ErrNotNetworkAddressable", err)
	}
}

func TestRunService_DispatchSimulationCheck_RejectsUnsupportedTechnique(t *testing.T) {
	a := newTestAsset(t, "example.com")
	disp := &fakeJobDispatcher{id: shared.NewID()}
	svc := NewRunService(
		fakeFindingLookup{}, fakeAssetLookup{a: a}, disp,
		DefaultSelector{}, []ExecutorKind{KindSafeCheck}, logger.NewNop(),
	)
	// A technique the safe-check kind does not support → selector rejects → the
	// caller falls back to the synthetic path.
	if _, err := svc.DispatchSimulationCheck(context.Background(), shared.NewID(), shared.NewID(), shared.NewID(), "T1055"); err == nil {
		t.Fatal("expected an error for an unsupported technique")
	}
}

func TestRunService_ValidateFinding_PropagatesFindingLookupError(t *testing.T) {
	disp := &fakeJobDispatcher{}
	svc := NewRunService(
		fakeFindingLookup{err: errors.New("not found")},
		fakeAssetLookup{},
		disp,
		DefaultSelector{},
		[]ExecutorKind{KindSafeCheck},
		logger.NewNop(),
	)
	if _, err := svc.ValidateFinding(context.Background(), shared.NewID(), shared.NewID()); err == nil {
		t.Fatal("expected finding lookup error to propagate")
	}
}

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

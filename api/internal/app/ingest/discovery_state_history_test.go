package ingest

import (
	"context"
	"errors"
	"testing"

	"github.com/openctemio/api/pkg/domain/asset"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/logger"
	"github.com/openctemio/ctis"
)

// fakeStateHistory captures CreateBatch calls (embeds the interface so the
// unused methods need not be implemented).
type fakeStateHistory struct {
	asset.StateHistoryRepository
	batches [][]*asset.AssetStateChange
	err     error
}

func (f *fakeStateHistory) CreateBatch(_ context.Context, changes []*asset.AssetStateChange) error {
	f.batches = append(f.batches, changes)
	return f.err
}

func newProcessorWithHistory(repo asset.StateHistoryRepository) *AssetProcessor {
	p := NewAssetProcessor(nil, logger.NewNop())
	if repo != nil {
		p.SetStateHistoryRepository(repo)
	}
	return p
}

func newTestAsset(t *testing.T, tenantID shared.ID, name string) *asset.Asset {
	t.Helper()
	a, err := asset.NewAssetWithTenant(tenantID, name, asset.AssetTypeHost, asset.CriticalityMedium)
	if err != nil {
		t.Fatalf("NewAssetWithTenant: %v", err)
	}
	return a
}

func TestRecordDiscoveryHistory_AppearedAndRecovered(t *testing.T) {
	fake := &fakeStateHistory{}
	p := newProcessorWithHistory(fake)
	tenantID := shared.NewID()

	appeared := []*asset.Asset{newTestAsset(t, tenantID, "a.example.com"), newTestAsset(t, tenantID, "b.example.com")}
	recovered := []shared.ID{shared.NewID()}

	p.recordDiscoveryHistory(context.Background(), tenantID, appeared, recovered)

	if len(fake.batches) != 1 {
		t.Fatalf("expected 1 CreateBatch, got %d", len(fake.batches))
	}
	changes := fake.batches[0]
	if len(changes) != 3 {
		t.Fatalf("expected 3 records (2 appeared + 1 recovered), got %d", len(changes))
	}
	appearedCount, recoveredCount := 0, 0
	for _, c := range changes {
		if c.Source() != asset.ChangeSourceScan {
			t.Errorf("source = %q, want scan", c.Source())
		}
		switch c.ChangeType() {
		case asset.StateChangeAppeared:
			appearedCount++
		case asset.StateChangeRecovered:
			recoveredCount++
		default:
			t.Errorf("unexpected change type %q", c.ChangeType())
		}
	}
	if appearedCount != 2 || recoveredCount != 1 {
		t.Fatalf("appeared=%d recovered=%d, want 2/1", appearedCount, recoveredCount)
	}
}

func TestRecordDiscoveryHistory_NilRepoIsNoOp(t *testing.T) {
	p := newProcessorWithHistory(nil)
	p.recordDiscoveryHistory(context.Background(), shared.NewID(), []*asset.Asset{newTestAsset(t, shared.NewID(), "x")}, nil)
}

func TestRecordDiscoveryHistory_EmptySkips(t *testing.T) {
	fake := &fakeStateHistory{}
	p := newProcessorWithHistory(fake)
	p.recordDiscoveryHistory(context.Background(), shared.NewID(), nil, nil)
	if len(fake.batches) != 0 {
		t.Fatalf("expected no CreateBatch, got %d", len(fake.batches))
	}
}

func TestRecordDiscoveryHistory_ErrorSwallowed(t *testing.T) {
	fake := &fakeStateHistory{err: errors.New("db down")}
	p := newProcessorWithHistory(fake)
	// Best-effort: must not panic or propagate.
	p.recordDiscoveryHistory(context.Background(), shared.NewID(), []*asset.Asset{newTestAsset(t, shared.NewID(), "x")}, nil)
}

// mergeCTISIntoAsset must flag a reactivation (stale → active via MarkSeen) so
// the caller records a `recovered` event.
func TestMergeCTISIntoAsset_DetectsReactivation(t *testing.T) {
	p := newProcessorWithHistory(nil)
	tenantID := shared.NewID()
	a := newTestAsset(t, tenantID, "host.example.com")
	if !a.MarkStale() {
		t.Fatalf("expected fresh asset to transition to stale")
	}
	if a.Status() != asset.StatusStale {
		t.Fatalf("status = %q, want stale", a.Status())
	}

	var recovered []shared.ID
	p.mergeCTISIntoAsset(a, &ctis.Asset{}, nil, &recovered)

	if a.Status() != asset.StatusActive {
		t.Fatalf("MarkSeen should have reactivated to active, got %q", a.Status())
	}
	if len(recovered) != 1 || recovered[0] != a.ID() {
		t.Fatalf("expected reactivation recorded for the asset, got %v", recovered)
	}
}

func TestMergeCTISIntoAsset_ActiveAssetNotFlaggedRecovered(t *testing.T) {
	p := newProcessorWithHistory(nil)
	a := newTestAsset(t, shared.NewID(), "host.example.com") // active by default

	var recovered []shared.ID
	p.mergeCTISIntoAsset(a, &ctis.Asset{}, nil, &recovered)

	if len(recovered) != 0 {
		t.Fatalf("an already-active asset must not be flagged recovered, got %v", recovered)
	}
}

package asset

import (
	"context"
	"errors"
	"testing"

	assetdom "github.com/openctemio/api/pkg/domain/asset"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/logger"
)

// fakeStateHistory captures CreateBatch calls. It embeds the interface so the
// other (unused) methods need not be implemented.
type fakeStateHistory struct {
	assetdom.StateHistoryRepository
	batches [][]*assetdom.AssetStateChange
	err     error
}

func (f *fakeStateHistory) CreateBatch(_ context.Context, changes []*assetdom.AssetStateChange) error {
	f.batches = append(f.batches, changes)
	return f.err
}

func newWorkerWithHistory(repo assetdom.StateHistoryRepository) *AssetLifecycleWorker {
	w := NewAssetLifecycleWorker(nil, nil, logger.NewNop())
	if repo != nil {
		w.SetStateHistoryRepository(repo)
	}
	return w
}

func TestRecordStaleHistory_WritesStatusChangedPerAsset(t *testing.T) {
	fake := &fakeStateHistory{}
	w := newWorkerWithHistory(fake)
	tenantID := shared.NewID()
	a1, a2 := shared.NewID(), shared.NewID()

	w.recordStaleHistory(context.Background(), tenantID, []string{a1.String(), a2.String()})

	if len(fake.batches) != 1 {
		t.Fatalf("expected 1 CreateBatch call, got %d", len(fake.batches))
	}
	changes := fake.batches[0]
	if len(changes) != 2 {
		t.Fatalf("expected 2 state-change records, got %d", len(changes))
	}
	for _, c := range changes {
		if c.ChangeType() != assetdom.StateChangeStatusChanged {
			t.Errorf("change type = %q, want status_changed", c.ChangeType())
		}
		if c.Field() != "status" || c.OldValue() != "active" || c.NewValue() != "stale" {
			t.Errorf("unexpected field/old/new: %q/%q/%q", c.Field(), c.OldValue(), c.NewValue())
		}
		if c.Source() != assetdom.ChangeSourceSystem {
			t.Errorf("source = %q, want system", c.Source())
		}
	}
}

func TestRecordStaleHistory_NilRepoIsNoOp(t *testing.T) {
	w := newWorkerWithHistory(nil)
	// Must not panic with no repo wired.
	w.recordStaleHistory(context.Background(), shared.NewID(), []string{shared.NewID().String()})
}

func TestRecordStaleHistory_EmptyIDsSkipsCreateBatch(t *testing.T) {
	fake := &fakeStateHistory{}
	w := newWorkerWithHistory(fake)
	w.recordStaleHistory(context.Background(), shared.NewID(), nil)
	if len(fake.batches) != 0 {
		t.Fatalf("expected no CreateBatch for empty ids, got %d", len(fake.batches))
	}
}

func TestRecordStaleHistory_SkipsInvalidIDs(t *testing.T) {
	fake := &fakeStateHistory{}
	w := newWorkerWithHistory(fake)
	valid := shared.NewID()
	w.recordStaleHistory(context.Background(), shared.NewID(), []string{"not-a-uuid", valid.String()})
	if len(fake.batches) != 1 || len(fake.batches[0]) != 1 {
		t.Fatalf("expected 1 valid record, got batches=%d", len(fake.batches))
	}
	if fake.batches[0][0].AssetID() != valid {
		t.Errorf("recorded wrong asset id")
	}
}

func TestRecordStaleHistory_CreateBatchErrorIsSwallowed(t *testing.T) {
	fake := &fakeStateHistory{err: errors.New("db down")}
	w := newWorkerWithHistory(fake)
	// Best-effort: a repo error must not panic or propagate.
	w.recordStaleHistory(context.Background(), shared.NewID(), []string{shared.NewID().String()})
}

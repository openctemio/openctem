package controller

import (
	"context"
	"testing"
	"time"

	assetdom "github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

type fakeTimelineStore struct {
	ensured  int
	cutoffs  []time.Time
	tenants  []shared.ID
	assets   map[shared.ID][]shared.ID
	pageSize []int
}

func (f *fakeTimelineStore) EnsurePartitions(context.Context, time.Time, int) (int, error) {
	f.ensured++
	return 0, nil
}

func (f *fakeTimelineStore) DropBefore(_ context.Context, cutoff time.Time) (int, int64, error) {
	f.cutoffs = append(f.cutoffs, cutoff)
	return 0, 0, nil
}

func (f *fakeTimelineStore) TenantsWithAttributeSources(context.Context) ([]shared.ID, error) {
	return f.tenants, nil
}

func (f *fakeTimelineStore) AssetsWithAttributeSources(_ context.Context, tid shared.ID, after *shared.ID, limit int) ([]shared.ID, error) {
	f.pageSize = append(f.pageSize, limit)
	all := f.assets[tid]
	start := 0
	if after != nil {
		for i, id := range all {
			if id == *after {
				start = i + 1
			}
		}
	}
	end := start + limit
	if end > len(all) {
		end = len(all)
	}
	return all[start:end], nil
}

type fakeResolver struct {
	calls map[shared.ID]int // tenant -> assets resolved
}

func (f *fakeResolver) ResolveAttributes(_ context.Context, tid shared.ID, ids []shared.ID, _ assetdom.ChangeReason) (int, error) {
	f.calls[tid] += len(ids)
	return 0, nil
}

func TestAssetChangeTimelineController(t *testing.T) {
	t1, t2 := shared.NewID(), shared.NewID()
	many := make([]shared.ID, assetResolveBatch+5)
	for i := range many {
		many[i] = shared.NewID()
	}
	store := &fakeTimelineStore{tenants: []shared.ID{t1, t2}, assets: map[shared.ID][]shared.ID{t1: many, t2: {shared.NewID()}}}
	res := &fakeResolver{calls: map[shared.ID]int{}}
	c := NewAssetChangeTimelineController(store, res, 10, nil) // below the floor
	now := time.Date(2026, 10, 10, 0, 0, 0, 0, time.UTC)
	c.now = func() time.Time { return now }

	if _, err := c.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if store.ensured != 1 {
		t.Fatalf("partitions ensured %d times", store.ensured)
	}
	if want := now.AddDate(0, 0, -minAssetChangeRetentionDays); !store.cutoffs[0].Equal(want) {
		t.Fatalf("retention cutoff %s, want %s (floor)", store.cutoffs[0], want)
	}
	if res.calls[t1] != len(many) || res.calls[t2] != 1 {
		t.Fatalf("sweep resolved %v, want every asset of each tenant once", res.calls)
	}

	// Within the day: partitions and retention again, no second sweep.
	now = now.Add(time.Hour)
	if _, err := c.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if store.ensured != 2 || res.calls[t1] != len(many) {
		t.Fatalf("second run: ensured %d, resolved %d", store.ensured, res.calls[t1])
	}
	now = now.Add(24 * time.Hour)
	if _, err := c.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if res.calls[t1] != 2*len(many) {
		t.Fatalf("next day: resolved %d, want a second sweep", res.calls[t1])
	}
}

func TestAssetChangeTimelineControllerDefaultRetention(t *testing.T) {
	c := NewAssetChangeTimelineController(&fakeTimelineStore{}, nil, 0, nil)
	if c.retentionDays != assetdom.DefaultChangeRetentionDays {
		t.Fatalf("retention %d", c.retentionDays)
	}
}

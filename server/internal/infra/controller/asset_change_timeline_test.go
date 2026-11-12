package controller

import (
	"context"
	"testing"
	"time"

	assetdom "github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

type fakeTimelineStore struct {
	runs    int
	cutoffs []time.Time
	tenants []shared.ID
}

func (f *fakeTimelineStore) DeleteBefore(_ context.Context, cutoff time.Time) (int64, error) {
	f.runs++
	f.cutoffs = append(f.cutoffs, cutoff)
	return 0, nil
}

func (f *fakeTimelineStore) TenantsWithAttributeSources(context.Context) ([]shared.ID, error) {
	return f.tenants, nil
}

type fakeResolver struct {
	calls map[shared.ID]int
}

func (f *fakeResolver) ReResolveTenant(_ context.Context, tid shared.ID, reason assetdom.ChangeReason) (int, error) {
	if reason != "" {
		panic("the sweep leaves the reason to the resolver")
	}
	f.calls[tid]++
	return 0, nil
}

func TestAssetChangeTimelineController(t *testing.T) {
	t1, t2 := shared.NewID(), shared.NewID()
	store := &fakeTimelineStore{tenants: []shared.ID{t1, t2}}
	res := &fakeResolver{calls: map[shared.ID]int{}}
	c := NewAssetChangeTimelineController(store, res, 10, nil) // below the floor
	now := time.Date(2026, 10, 10, 0, 0, 0, 0, time.UTC)
	c.now = func() time.Time { return now }

	if _, err := c.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if store.runs != 1 {
		t.Fatalf("retention ran %d times", store.runs)
	}
	if want := now.AddDate(0, 0, -minAssetChangeRetentionDays); !store.cutoffs[0].Equal(want) {
		t.Fatalf("retention cutoff %s, want %s (floor)", store.cutoffs[0], want)
	}
	if res.calls[t1] != 1 || res.calls[t2] != 1 {
		t.Fatalf("sweep resolved %v, want each tenant once", res.calls)
	}

	// Within the day: retention again, no second sweep.
	now = now.Add(time.Hour)
	if _, err := c.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if store.runs != 2 || res.calls[t1] != 1 {
		t.Fatalf("second run: retention %d, swept %d", store.runs, res.calls[t1])
	}
	now = now.Add(24 * time.Hour)
	if _, err := c.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if res.calls[t1] != 2 {
		t.Fatalf("next day: swept %d, want a second sweep", res.calls[t1])
	}
}

func TestAssetChangeTimelineControllerDefaultRetention(t *testing.T) {
	c := NewAssetChangeTimelineController(&fakeTimelineStore{}, nil, 0, nil)
	if c.retentionDays != assetdom.DefaultChangeRetentionDays {
		t.Fatalf("retention %d", c.retentionDays)
	}
}

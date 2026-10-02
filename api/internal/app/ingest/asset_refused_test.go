package ingest

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// refusingAssetRepo stores like memAssetRepo but refuses the named rows the
// way the Postgres per-row fallback does: no error, the row is just absent
// from persistedIDs. With failAll it fails the whole batch instead.
type refusingAssetRepo struct {
	*memAssetRepo
	refuse  map[string]bool
	failAll bool
}

func (r *refusingAssetRepo) UpsertBatch(ctx context.Context, assets []*asset.Asset) (int, int, map[string]shared.ID, error) {
	if r.failAll {
		return 0, 0, nil, errors.New("connection reset")
	}
	keep := make([]*asset.Asset, 0, len(assets))
	for _, a := range assets {
		if !r.refuse[a.Name()] {
			keep = append(keep, a)
		}
	}
	return r.memAssetRepo.UpsertBatch(ctx, keep)
}

func TestProcessBatch_OverlongNameRefusedAlone(t *testing.T) {
	p := NewAssetProcessor(newMemAssetRepo(), logger.NewNop())
	long := strings.Repeat("a", 300) + ".example.com"
	out := &Output{}
	m, err := p.ProcessBatch(context.Background(), shared.NewID(), reconReport("a.example.com", long, "c.example.com"), out, nil)
	if err != nil {
		t.Fatalf("ProcessBatch: %v", err)
	}
	if out.AssetsCreated != 2 || len(m) != 2 {
		t.Fatalf("created=%d mapped=%d, want 2/2 (errors %v)", out.AssetsCreated, len(m), out.Errors)
	}
	if _, ok := m["a1"]; ok {
		t.Fatalf("over-long asset was mapped")
	}
	if len(out.Errors) != 1 || !strings.Contains(out.Errors[0], "asset a1") || !strings.Contains(out.Errors[0], "maximum is 255") {
		t.Fatalf("errors = %v, want one item error for a1", out.Errors)
	}
	if strings.Contains(out.Errors[0], long) {
		t.Fatalf("error carries the whole name")
	}
}

func TestProcessBatch_RowRefusedByDatabaseUnmapped(t *testing.T) {
	repo := &refusingAssetRepo{memAssetRepo: newMemAssetRepo(), refuse: map[string]bool{"b.example.com": true}}
	p, calls := newDiscoveryProcessor(repo)
	out := &Output{}
	m, err := p.ProcessBatch(context.Background(), shared.NewID(), reconReport("a.example.com", "b.example.com", "c.example.com"), out, nil)
	if err != nil {
		t.Fatalf("ProcessBatch: %v", err)
	}
	if _, ok := m["a1"]; ok || len(m) != 2 {
		t.Fatalf("asset map %v: the refused asset must not be mapped", m)
	}
	if len(out.Errors) != 1 || !strings.Contains(out.Errors[0], "asset a1 (b.example.com): refused by the database") {
		t.Fatalf("errors = %v", out.Errors)
	}
	if len(*calls) != 1 || len((*calls)[0].assets) != 2 {
		t.Fatalf("discovered callback should announce the 2 stored assets, got %+v", *calls)
	}
}

func TestProcessBatch_FailedUpsertMapsNoNewAsset(t *testing.T) {
	repo := &refusingAssetRepo{memAssetRepo: newMemAssetRepo(), failAll: true}
	p := NewAssetProcessor(repo, logger.NewNop())
	m, err := p.ProcessBatch(context.Background(), shared.NewID(), reconReport("a.example.com", "b.example.com"), &Output{}, nil)
	if err == nil {
		t.Fatalf("want the upsert error")
	}
	if len(m) != 0 {
		t.Fatalf("asset map %v: assets that were never stored must not be mapped", m)
	}
}

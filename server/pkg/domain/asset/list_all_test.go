package asset

import (
	"context"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/pagination"
)

type keysetFake struct {
	assets []*Asset
	calls  int
	lists  int
}

func (f *keysetFake) List(_ context.Context, _ Filter, _ ListOptions, p pagination.Pagination) (pagination.Result[*Asset], error) {
	f.lists++
	lo := min(p.Offset(), len(f.assets))
	hi := min(lo+p.Limit(), len(f.assets))
	return pagination.NewResult(f.assets[lo:hi], int64(len(f.assets)), p), nil
}

func (f *keysetFake) ListAfterID(_ context.Context, _ Filter, after string, limit int) ([]*Asset, error) {
	f.calls++
	start := 0
	if after != "" {
		for i, a := range f.assets {
			if a.ID().String() == after {
				start = i + 1
			}
		}
	}
	return f.assets[start:min(start+limit, len(f.assets))], nil
}

type pageOnly struct{ f *keysetFake }

func (p pageOnly) List(ctx context.Context, fl Filter, o ListOptions, pg pagination.Pagination) (pagination.Result[*Asset], error) {
	return p.f.List(ctx, fl, o, pg)
}

func manyAssets(t *testing.T, n int) []*Asset {
	t.Helper()
	tenant := shared.NewID()
	out := make([]*Asset, n)
	for i := range out {
		a, err := NewAssetWithTenant(tenant, "a"+shared.NewID().String(), AssetTypeDomain, CriticalityLow)
		if err != nil {
			t.Fatal(err)
		}
		out[i] = a
	}
	return out
}

// ListAll pages by id when the repository can (no List, one call per batch)
// and still reads everything through List otherwise.
func TestListAll_KeysetAndFallback(t *testing.T) {
	all := manyAssets(t, 250)
	tenant := "t"
	k := &keysetFake{assets: all}
	got, err := ListAll(context.Background(), k, Filter{TenantID: &tenant}, 100)
	if err != nil || len(got) != 250 {
		t.Fatalf("keyset: got %d, err %v", len(got), err)
	}
	if k.calls != 3 || k.lists != 0 {
		t.Fatalf("keyset calls = %d, List calls = %d; want 3 and 0", k.calls, k.lists)
	}
	p := &keysetFake{assets: all}
	got, err = ListAll(context.Background(), pageOnly{p}, Filter{TenantID: &tenant}, 100)
	if err != nil || len(got) != 250 || p.lists == 0 {
		t.Fatalf("fallback: got %d, lists %d, err %v", len(got), p.lists, err)
	}
}

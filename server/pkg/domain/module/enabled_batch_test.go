package module

import (
	"context"
	"testing"

	"github.com/openctemio/openctem/server/pkg/domain/shared"
)

type row struct{ tenant shared.ID }

func TestCollectEnabled_DoesNotStarveOnDisabledTenantRows(t *testing.T) {
	off, on := shared.NewID(), shared.NewID()
	all := []row{{off}, {off}, {off}, {on}}
	const limit = 3
	fetch := func(skip []shared.ID) ([]row, error) {
		var out []row
		for _, r := range all {
			ex := false
			for _, s := range skip {
				ex = ex || s == r.tenant
			}
			if !ex && len(out) < limit {
				out = append(out, r)
			}
		}
		return out, nil
	}
	got, err := CollectEnabled(context.Background(), limit, fetch,
		func(r row) shared.ID { return r.tenant },
		func(_ context.Context, id shared.ID) bool { return id == off })
	if err != nil || len(got) != 1 || got[0].tenant != on {
		t.Fatalf("want the enabled tenant's row after skipping the disabled tenant, got %v err=%v", got, err)
	}
}

func TestCollectEnabled_NilOffKeepsEverything(t *testing.T) {
	a := shared.NewID()
	got, _ := CollectEnabled(context.Background(), 5,
		func([]shared.ID) ([]row, error) { return []row{{a}}, nil },
		func(r row) shared.ID { return r.tenant }, nil)
	if len(got) != 1 {
		t.Fatalf("got %d", len(got))
	}
}

func TestCollectEnabled_StopsWhenDrained(t *testing.T) {
	off := shared.NewID()
	calls := 0
	got, _ := CollectEnabled(context.Background(), 10,
		func([]shared.ID) ([]row, error) { calls++; return []row{{off}}, nil },
		func(r row) shared.ID { return r.tenant },
		func(context.Context, shared.ID) bool { return true })
	if len(got) != 0 || calls != 1 {
		t.Fatalf("got=%d calls=%d", len(got), calls)
	}
}

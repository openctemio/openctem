package postgres

import (
	"context"
	"errors"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/supportaccess"
)

// A support session never sees the assets of a private program (support is
// no program member) or their findings, nor another organization's rows.
// Requires DATABASE_URL.
func TestSupportReadHidesPrivateProgramAndOtherTenants_DB(t *testing.T) {
	fx := seedPrivateProgram(t)
	ctx := context.Background()
	r := NewSupportReadRepository(fx.pdb)

	assets, total, err := r.ListAssets(ctx, fx.tenant, supportaccess.ListQuery{Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, a := range assets {
		seen[a.ID] = true
	}
	if seen[fx.hidden.String()] || seen[fx.foreign.String()] || !seen[fx.own.String()] || !seen[fx.shared1.String()] || total != int64(len(assets)) {
		t.Fatalf("assets: %v (total %d)", seen, total)
	}
	if _, err := r.GetAsset(ctx, fx.tenant, fx.hidden); !errors.Is(err, supportaccess.ErrNotFound) {
		t.Fatalf("hidden asset by id: %v", err)
	}
	if _, err := r.GetAsset(ctx, fx.tenant, fx.foreign); !errors.Is(err, supportaccess.ErrNotFound) {
		t.Fatalf("foreign asset by id: %v", err)
	}

	findings, _, err := r.ListFindings(ctx, fx.tenant, supportaccess.ListQuery{Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range findings {
		if f.ID == fx.hiddenFinding.String() {
			t.Fatal("the hidden program finding is listed")
		}
	}
	if _, err := r.GetFinding(ctx, fx.tenant, fx.hiddenFinding); !errors.Is(err, supportaccess.ErrNotFound) {
		t.Fatalf("hidden finding by id: %v", err)
	}
	if f, err := r.GetFinding(ctx, fx.tenant, fx.ownFinding); err != nil || f.ID != fx.ownFinding.String() {
		t.Fatalf("own finding: %v", err)
	}
	o, err := r.Overview(ctx, fx.tenant)
	if err != nil || o.OpenFindingCount != 1 || o.AssetCount != int64(len(assets)) {
		t.Fatalf("overview: %+v %v", o, err)
	}
}

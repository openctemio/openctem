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
	if _, err := r.GetFinding(ctx, fx.tenant, fx.hiddenFinding, true); !errors.Is(err, supportaccess.ErrNotFound) {
		t.Fatalf("hidden finding by id: %v", err)
	}
	if f, err := r.GetFinding(ctx, fx.tenant, fx.ownFinding, true); err != nil || f.ID != fx.ownFinding.String() {
		t.Fatalf("own finding: %v", err)
	}
	both := supportaccess.ReadScope{Assets: true, Findings: true}
	o, err := r.Overview(ctx, fx.tenant, both)
	if err != nil || o.OpenFindingCount == nil || *o.OpenFindingCount != 1 || o.AssetCount == nil || *o.AssetCount != int64(len(assets)) {
		t.Fatalf("overview: %+v %v", o, err)
	}

	// The overview carries only the granted scopes' parts.
	o, err = r.Overview(ctx, fx.tenant, supportaccess.ReadScope{Findings: true})
	if err != nil || o.AssetCount != nil || o.OpenFindingCount == nil || len(o.OpenFindingsBySeverity) == 0 {
		t.Fatalf("findings-only overview: %+v %v", o, err)
	}
	o, err = r.Overview(ctx, fx.tenant, supportaccess.ReadScope{Assets: true})
	if err != nil || o.AssetCount == nil || o.OpenFindingCount != nil || o.OpenFindingsBySeverity != nil {
		t.Fatalf("assets-only overview: %+v %v", o, err)
	}

	// Asset columns of a finding row need the assets scope.
	with, _, err := r.ListFindings(ctx, fx.tenant, supportaccess.ListQuery{Limit: 100, WithAssets: true})
	if err != nil {
		t.Fatal(err)
	}
	without, _, err := r.ListFindings(ctx, fx.tenant, supportaccess.ListQuery{Limit: 100})
	if err != nil || len(without) != len(with) || len(with) == 0 {
		t.Fatalf("lists: %d vs %d %v", len(without), len(with), err)
	}
	named := false
	for _, f := range with {
		named = named || f.AssetName != ""
	}
	if !named {
		t.Fatal("with the assets scope a finding names its asset")
	}
	for _, f := range without {
		if f.AssetID != "" || f.AssetName != "" || f.AssetType != "" {
			t.Fatalf("finding row leaked asset columns without the assets scope: %+v", f)
		}
	}
	if f, err := r.GetFinding(ctx, fx.tenant, fx.ownFinding, false); err != nil || f.AssetID != "" || f.AssetName != "" || f.AssetType != "" {
		t.Fatalf("finding by id without the assets scope: %+v %v", f, err)
	}
}

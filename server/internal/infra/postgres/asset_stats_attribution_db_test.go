package postgres

// "All assets" in the sidebar counts GET /assets/stats with the inventory's
// attribution; the page heading counts GET /assets with the same values.
// Both must apply the list's own attribution field, so for every value the
// two numbers are the same, and another tenant's assets never count.

import (
	"context"
	"net/url"
	"testing"

	"github.com/openctemio/openctem/server/pkg/domain/asset"
	"github.com/openctemio/openctem/server/pkg/domain/assetlist"
	"github.com/openctemio/openctem/server/pkg/domain/attribution"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
	"github.com/openctemio/openctem/server/pkg/filterspec"
)

func TestAssetStats_AttributionCountsWhatTheListShows(t *testing.T) {
	ctx := context.Background()
	db := openGroupsDB(t)
	repo := NewAssetRepository(&DB{DB: db})
	tenant := seedTestTenant(ctx, t, db)
	other := seedTestTenant(ctx, t, db)

	seed := func(tid shared.ID, state, reason string) {
		t.Helper()
		id := seedOwnedAsset(ctx, t, db, tid, nil)
		if state == "" {
			return // no record: a legacy asset, counted as confirmed
		}
		if _, err := db.ExecContext(ctx, `INSERT INTO asset_attributions (asset_id, tenant_id, state, confidence, reason)
			VALUES ($1, $2, $3, 50, $4)`, id.String(), tid.String(), state, reason); err != nil {
			t.Fatalf("seed attribution %s: %v", state, err)
		}
	}
	// Every stored state, an unrecorded asset and a provider address.
	for _, st := range []string{"", "confirmed", "discovered", "needs_review", "candidate", "dependency", "monitor_only", "rejected"} {
		seed(tenant, st, "")
		seed(other, st, "") // the other tenant holds the same mix: it must never count
	}
	seed(tenant, "dependency", string(attribution.RuleProviderSharedFrontEnd))
	// A deleted asset counts nowhere.
	gone := seedOwnedAsset(ctx, t, db, tenant, nil)
	if _, err := db.ExecContext(ctx, `UPDATE assets SET deleted_at = NOW() WHERE id = $1`, gone.String()); err != nil {
		t.Fatal(err)
	}

	listTotal := func(values string) int64 {
		t.Helper()
		q := url.Values{"per_page": {"1"}}
		if values != "" {
			q.Set("attribution", values)
		}
		spec, err := filterspec.ParseValues(q, assetlist.Fields, filterspec.Options{Unknown: filterspec.UnknownStrict})
		if err != nil {
			t.Fatalf("parse %q: %v", values, err)
		}
		w, err := filterspec.Compile(spec, assetlist.Fields, filterspec.SystemActor(tenant, "stats parity test"))
		if err != nil {
			t.Fatalf("compile %q: %v", values, err)
		}
		res, err := repo.ListWhere(ctx, asset.WhereQuery{Where: w, PerPage: 1})
		if err != nil {
			t.Fatalf("list %q: %v", values, err)
		}
		return res.Total
	}

	values := []string{"", "all", "approved", "attributed", "unconfirmed", "unknown", "provider_address",
		"confirmed", "discovered", "needs_review", "candidate", "dependency", "monitor_only", "rejected",
		"approved,provider_address"}
	for _, v := range values {
		var attr []string
		if v != "" {
			attr = []string{v}
			if v == "approved,provider_address" {
				attr = []string{"approved", "provider_address"}
			}
		}
		stats, err := repo.GetAggregateStats(ctx, tenant, asset.AccessScope{}, nil, nil, nil, "", attr)
		if err != nil {
			t.Fatalf("stats %q: %v", v, err)
		}
		if want := listTotal(v); int64(stats.Total) != want {
			t.Errorf("attribution=%q: stats total %d, list total %d", v, stats.Total, want)
		}
	}

	// The inventory default: unrecorded, confirmed, discovered, dependency
	// and monitor_only; no review queue, no rejected, no provider address.
	approved, err := repo.GetAggregateStats(ctx, tenant, asset.AccessScope{}, nil, nil, nil, "", []string{"approved"})
	if err != nil {
		t.Fatal(err)
	}
	if approved.Total != 5 {
		t.Errorf("approved total %d, want 5", approved.Total)
	}
	all, err := repo.GetAggregateStats(ctx, tenant, asset.AccessScope{}, nil, nil, nil, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	if all.Total != 9 {
		t.Errorf("unfiltered total %d, want 9 (one tenant, no deleted asset)", all.Total)
	}

	if _, err := repo.GetAggregateStats(ctx, tenant, asset.AccessScope{}, nil, nil, nil, "", []string{"nope"}); err == nil {
		t.Error("an unknown attribution value was accepted")
	}
}

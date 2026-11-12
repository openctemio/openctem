package postgres

// GetPropertyFacets is bounded (RFC-042 F10): values per key are cut in SQL,
// array properties are expanded only up to facetMaxArrayElems per asset, and
// a key's count still sums every value, not only the returned ones.

import (
	"context"
	"fmt"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/asset"
)

func TestGetPropertyFacets_Bounded_DB(t *testing.T) {
	db := openStatsTestDB(t)
	ctx := context.Background()
	tenantID := seedTestTenant(ctx, t, db)

	// 25 assets, each with a distinct "owner_team" value, and one wide array.
	const assets = 25
	wide := "["
	for i := 0; i < 3*facetMaxArrayElems; i++ {
		if i > 0 {
			wide += ","
		}
		wide += fmt.Sprintf(`"elem-%03d"`, i)
	}
	wide += "]"
	for i := 0; i < assets; i++ {
		props := fmt.Sprintf(`{"owner_team":"team-%02d","labels":%s}`, i, wide)
		if _, err := db.ExecContext(ctx,
			`INSERT INTO assets (tenant_id, name, asset_type, properties) VALUES ($1, $2, 'domain', $3::jsonb)`,
			tenantID.String(), fmt.Sprintf("facet-bound-%02d.example.com", i), props); err != nil {
			t.Fatalf("seed asset: %v", err)
		}
	}

	repo := NewAssetRepository(&DB{DB: db})
	facets, err := repo.GetPropertyFacets(ctx, tenantID, asset.AccessScope{}, nil, "")
	if err != nil {
		t.Fatalf("GetPropertyFacets: %v", err)
	}
	byKey := map[string]asset.PropertyFacet{}
	for _, f := range facets {
		byKey[f.Key] = f
	}

	team, ok := byKey["owner_team"]
	if !ok {
		t.Fatalf("owner_team facet missing: %+v", facets)
	}
	if len(team.Values) != facetMaxValuesPerKey {
		t.Errorf("owner_team values = %d, want the %d-value cut", len(team.Values), facetMaxValuesPerKey)
	}
	if team.Count != assets {
		t.Errorf("owner_team count = %d, want %d (every value counted, not only the returned ones)", team.Count, assets)
	}

	labels, ok := byKey["labels"]
	if !ok {
		t.Fatalf("labels facet missing: %+v", facets)
	}
	if want := assets * facetMaxArrayElems; labels.Count != want {
		t.Errorf("labels count = %d, want %d (array expanded to %d elements per asset)", labels.Count, want, facetMaxArrayElems)
	}
}

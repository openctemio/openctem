package postgres

import (
	"context"
	"database/sql"
	"testing"

	_ "github.com/lib/pq"

	"github.com/openctemio/openctem/api/internal/testdb"
	"github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/pagination"
)

// Rows that tie on every sort key must page deterministically: each row once,
// none skipped, whatever the planner does between page queries.
func TestAssetList_StableOrderAcrossTies_DB(t *testing.T) {
	dbURL := testdb.URL()
	if dbURL == "" {
		t.Skip("DATABASE_URL not set; skipping DB execution check")
	}
	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer func() { _ = db.Close() }()
	ctx := context.Background()
	if err := db.PingContext(ctx); err != nil {
		t.Skipf("cannot reach DATABASE_URL: %v", err)
	}
	tenant := seedTestTenant(ctx, t, db)
	const n = 11
	for i := 0; i < n; i++ {
		seedPublicAsset(ctx, t, db, tenant)
	}
	// Every row ties on created_at and criticality.
	if _, err := db.ExecContext(ctx,
		`UPDATE assets SET created_at = '2026-01-01T00:00:00Z' WHERE tenant_id = $1`, tenant.String()); err != nil {
		t.Fatalf("tie rows: %v", err)
	}

	repo := NewAssetRepository(&DB{DB: db})
	tid := tenant.String()
	filter := asset.Filter{TenantID: &tid}
	sortBy := func(s string) asset.ListOptions {
		return asset.ListOptions{Sort: pagination.NewSortOption(map[string]string{"criticality": "criticality", "created_at": "created_at"}).Parse(s)}
	}
	// The tie-breaker follows the direction of the last sort key, so tied
	// rows come back in id order (descending for a descending sort). Heap
	// order alone happens to be insertion order on a small table, which is
	// why the pages are also checked for that id order.
	for name, c := range map[string]struct {
		opts asset.ListOptions
		desc bool
	}{
		"default":     {asset.NewListOptions(), true},
		"criticality": {sortBy("criticality"), false},
		"-created_at": {sortBy("-created_at"), true},
	} {
		opts := c.opts
		t.Run(name, func(t *testing.T) {
			seen := map[string]bool{}
			var order []string
			for p := 1; p <= 5; p++ {
				res, err := repo.List(ctx, filter, opts, pagination.New(p, 3))
				if err != nil {
					t.Fatalf("list page %d: %v", p, err)
				}
				for _, a := range res.Data {
					id := a.ID().String()
					if seen[id] {
						t.Fatalf("asset %s repeated across pages", id)
					}
					seen[id] = true
					order = append(order, id)
				}
			}
			if len(seen) != n {
				t.Fatalf("paged %d assets, want %d", len(seen), n)
			}
			for i := 1; i < len(order); i++ {
				if (order[i-1] < order[i]) == c.desc {
					t.Fatalf("tied rows not in id %s order at %d: %v", map[bool]string{true: "descending", false: "ascending"}[c.desc], i, order)
				}
			}
		})
	}
}

package postgres

import (
	"context"
	"database/sql"
	"testing"
	"time"

	_ "github.com/lib/pq"

	"github.com/openctemio/openctem/api/internal/testdb"
	"github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/pagination"
)

// TestAsset_TrendFilters runs the attack-surface trend filters (CreatedAfter,
// ExposureChangedOrCreatedAfter) against Postgres. Skipped unless DATABASE_URL
// is set.
//
// Fixture (one tenant, window = last 7 days):
//
//	fresh:    created 1 day ago, public           -> new, newly exposed
//	flipped:  created 30 days ago, public, exposure changed 2 days ago -> newly exposed only
//	steady:   created 30 days ago, public, exposure unchanged          -> neither
//	internal: created 1 day ago, private          -> new, not exposed
func TestAsset_TrendFilters(t *testing.T) {
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

	repo := NewAssetRepository(&DB{DB: db})
	tenant := seedTestTenant(ctx, t, db).String()
	now := time.Now().UTC()
	day := 24 * time.Hour

	insert := func(name, exposure string, created time.Time, exposureChanged *time.Time) {
		t.Helper()
		mustExec(t, db,
			`INSERT INTO assets (id, tenant_id, name, asset_type, exposure, created_at, updated_at, exposure_changed_at)
			 VALUES ($1,$2,$3,'domain',$4,$5,$5,$6)`,
			shared.NewID().String(), tenant, name+".trend.example", exposure, created, exposureChanged)
	}
	twoDaysAgo := now.Add(-2 * day)
	insert("fresh", "public", now.Add(-day), nil)
	insert("flipped", "public", now.Add(-30*day), &twoDaysAgo)
	insert("steady", "public", now.Add(-30*day), nil)
	insert("internal", "private", now.Add(-day), nil)

	since := now.Add(-7 * day)
	count := func(f asset.Filter) int64 {
		t.Helper()
		n, err := repo.Count(ctx, f.WithTenantID(tenant))
		if err != nil {
			t.Fatalf("count: %v", err)
		}
		return n
	}

	if got := count(asset.NewFilter().WithCreatedAfter(since)); got != 2 {
		t.Errorf("new assets = %d, want 2 (fresh, internal)", got)
	}
	newlyExposed := asset.NewFilter().WithExposures(asset.ExposurePublic).WithExposureChangedOrCreatedAfter(since)
	if got := count(newlyExposed); got != 2 {
		t.Errorf("newly exposed = %d, want 2 (fresh, flipped)", got)
	}
	if got := count(asset.NewFilter().WithExposures(asset.ExposurePublic)); got != 3 {
		t.Errorf("exposed = %d, want 3", got)
	}

	// The overview's exposed list sorts by risk then freshness; the ORDER BY
	// must be valid against the real List query (joins included).
	opts := asset.NewListOptions().WithSort(pagination.NewSortOption(asset.AllowedSortFields()).Parse("-risk_score,-last_seen"))
	res, err := repo.List(ctx, asset.NewFilter().WithTenantID(tenant).WithExposures(asset.ExposurePublic), opts, pagination.New(1, 5))
	if err != nil {
		t.Fatalf("list sorted by risk: %v", err)
	}
	if len(res.Data) != 3 {
		t.Errorf("sorted list = %d rows, want 3", len(res.Data))
	}
}

// TestAsset_SortByLevel runs the criticality and exposure sorts against the
// real List query: by level, not alphabetically. Skipped unless DATABASE_URL
// is set.
func TestAsset_SortByLevel(t *testing.T) {
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

	repo := NewAssetRepository(&DB{DB: db})
	tenant := seedTestTenant(ctx, t, db).String()
	other := seedTestTenant(ctx, t, db).String()
	insert := func(tenantID, name, criticality, exposure string) {
		t.Helper()
		mustExec(t, db,
			`INSERT INTO assets (id, tenant_id, name, asset_type, criticality, exposure, created_at, updated_at)
			 VALUES ($1,$2,$3,'domain',$4,$5,now(),now())`,
			shared.NewID().String(), tenantID, name+".sort.example", criticality, exposure)
	}
	insert(tenant, "m", "medium", "private")
	insert(tenant, "l", "low", "isolated")
	insert(tenant, "c", "critical", "public")
	insert(tenant, "h", "high", "restricted")
	// Another organisation's asset never appears, whatever the sort.
	insert(other, "x", "critical", "public")

	names := func(sort string) []string {
		t.Helper()
		opts := asset.NewListOptions().WithSort(pagination.NewSortOption(asset.AllowedSortFields()).Parse(sort))
		res, err := repo.List(ctx, asset.NewFilter().WithTenantID(tenant), opts, pagination.New(1, 10))
		if err != nil {
			t.Fatalf("list sorted by %s: %v", sort, err)
		}
		out := make([]string, 0, len(res.Data))
		for _, a := range res.Data {
			out = append(out, a.Name()[:1])
		}
		return out
	}
	want := []string{"c", "h", "m", "l"}
	for _, sort := range []string{"-criticality", "-exposure"} {
		got := names(sort)
		if len(got) != len(want) {
			t.Fatalf("%s: %v, want %v (own tenant only)", sort, got, want)
		}
		for i := range want {
			if got[i] != want[i] {
				t.Errorf("%s: %v, want %v", sort, got, want)
				break
			}
		}
	}
}

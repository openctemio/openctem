package postgres

import (
	"context"
	"database/sql"
	"os"
	"testing"
	"time"

	_ "github.com/lib/pq"

	"github.com/openctemio/api/pkg/domain/asset"
	"github.com/openctemio/api/pkg/domain/shared"
)

// Executes the "What changed" list filters against a real schema: the single
// change-type filter (previously ignored), new_value, the asset-scope and
// internet-facing EXISTS filters, and the tenant-scoped asset ref lookup.
func TestStateHistoryList_ChangeViewFilters(t *testing.T) {
	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		t.Skip("DATABASE_URL not set; skipping DB execution check")
	}
	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		t.Skipf("open db: %v", err)
	}
	defer func() { _ = db.Close() }()
	ctx := context.Background()
	if err := db.PingContext(ctx); err != nil {
		t.Skipf("cannot reach DATABASE_URL: %v", err)
	}

	repo := NewAssetStateHistoryRepository(&DB{DB: db})
	tenant := seedTestTenant(ctx, t, db)
	other := seedTestTenant(ctx, t, db)

	insertAsset := func(tenantID shared.ID, name, scope, exposure string, internet bool) shared.ID {
		t.Helper()
		id := shared.NewID()
		if _, err := db.ExecContext(ctx,
			`INSERT INTO assets (id, tenant_id, name, asset_type, scope, exposure, is_internet_accessible)
			 VALUES ($1,$2,$3,'domain',$4,$5,$6)`,
			id.String(), tenantID.String(), name, scope, exposure, internet); err != nil {
			t.Fatalf("seed asset %s: %v", name, err)
		}
		return id
	}
	public := insertAsset(tenant, "public.example.com", "external", "public", true)
	shadow := insertAsset(tenant, "shadow.example.com", "shadow", "unknown", false)
	internal := insertAsset(tenant, "internal.corp", "internal", "private", false)
	foreign := insertAsset(other, "foreign.example.com", "shadow", "public", true)

	changes := []*asset.AssetStateChange{
		asset.RecordAssetAppeared(tenant, public, asset.ChangeSourceScan, "discovered by scan"),
		asset.RecordAssetAppeared(tenant, shadow, asset.ChangeSourceScan, "discovered by scan"),
		asset.RecordAssetAppeared(tenant, internal, asset.ChangeSourceScan, "discovered by scan"),
		asset.RecordFieldChange(tenant, public, asset.StateChangeInternetExposureChanged, "is_internet_accessible", "false", "true", asset.ChangeSourceScan, nil),
		asset.RecordFieldChange(tenant, internal, asset.StateChangeInternetExposureChanged, "is_internet_accessible", "true", "false", asset.ChangeSourceScan, nil),
		asset.RecordFieldChange(tenant, public, asset.StateChangeExposureChanged, "exposure", "unknown", "public", asset.ChangeSourceScan, nil),
		asset.RecordAssetAppeared(other, foreign, asset.ChangeSourceScan, "discovered by scan"),
	}
	if err := repo.CreateBatch(ctx, changes); err != nil {
		t.Fatalf("seed history: %v", err)
	}
	from := time.Now().Add(-time.Hour)

	list := func(opts asset.ListStateHistoryOptions) int {
		t.Helper()
		opts.From = &from
		opts.Limit = 50
		rows, total, err := repo.List(ctx, tenant, opts)
		if err != nil {
			t.Fatalf("List: %v", err)
		}
		if len(rows) != total {
			t.Fatalf("page %d != total %d", len(rows), total)
		}
		for _, r := range rows {
			if r.TenantID() != tenant {
				t.Fatalf("row of tenant %s leaked", r.TenantID())
			}
		}
		return total
	}

	appeared := asset.StateChangeAppeared
	if n := list(asset.ListStateHistoryOptions{ChangeType: &appeared}); n != 3 {
		t.Fatalf("single ChangeType appeared = %d, want 3 (filter was ignored before)", n)
	}
	shadowScope := asset.ScopeShadow
	if n := list(asset.ListStateHistoryOptions{ChangeType: &appeared, AssetScope: &shadowScope}); n != 1 {
		t.Fatalf("shadow appearances = %d, want 1 (other tenant's shadow asset must not count)", n)
	}
	yes := true
	if n := list(asset.ListStateHistoryOptions{ChangeType: &appeared, AssetInternetFacing: &yes}); n != 1 {
		t.Fatalf("internet-facing appearances = %d, want 1", n)
	}
	no := false
	if n := list(asset.ListStateHistoryOptions{ChangeType: &appeared, AssetInternetFacing: &no}); n != 2 {
		t.Fatalf("non-internet-facing appearances = %d, want 2", n)
	}
	newlyExposed := asset.ListStateHistoryOptions{
		ChangeTypes: []asset.StateChangeType{asset.StateChangeExposureChanged, asset.StateChangeInternetExposureChanged},
		NewValues:   []string{"public", "true"},
	}
	if n := list(newlyExposed); n != 2 {
		t.Fatalf("newly exposed = %d, want 2 (the true->false transition is excluded)", n)
	}

	refs, err := repo.GetAssetRefs(ctx, tenant, []shared.ID{public, shadow, foreign})
	if err != nil {
		t.Fatalf("GetAssetRefs: %v", err)
	}
	if _, leaked := refs[foreign]; leaked {
		t.Fatal("GetAssetRefs returned another tenant's asset")
	}
	if r := refs[public]; r.Name != "public.example.com" || !r.InternetAccessible || r.Exposure != "public" || r.Type != "domain" {
		t.Fatalf("public ref = %+v", r)
	}
	if r := refs[shadow]; r.Scope != "shadow" {
		t.Fatalf("shadow ref = %+v", r)
	}
}

// Ingest infers an exposure for a re-scanned asset still at 'unknown' and
// records the transition; the upsert used to drop it (exposure was not in the
// ON CONFLICT set), so the history said "public" while the asset stayed
// "unknown". It must now fill the gap, and never override a known value.
func TestUpsertBatch_ExposureFillsGapOnly(t *testing.T) {
	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		t.Skip("DATABASE_URL not set; skipping DB execution check")
	}
	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		t.Skipf("open db: %v", err)
	}
	defer func() { _ = db.Close() }()
	ctx := context.Background()
	if err := db.PingContext(ctx); err != nil {
		t.Skipf("cannot reach DATABASE_URL: %v", err)
	}
	repo := NewAssetRepository(&DB{DB: db})
	tenant := seedTestTenant(ctx, t, db)

	upsert := func(name string, exp asset.Exposure) {
		t.Helper()
		a, err := asset.NewAssetWithTenant(tenant, name, asset.AssetTypeHost, asset.CriticalityMedium)
		if err != nil {
			t.Fatal(err)
		}
		a.SetExposure(exp)
		if _, _, _, err := repo.UpsertBatch(ctx, []*asset.Asset{a}); err != nil {
			t.Fatalf("upsert: %v", err)
		}
	}
	exposureOf := func(name string) string {
		t.Helper()
		var e string
		if err := db.QueryRowContext(ctx, `SELECT exposure FROM assets WHERE tenant_id=$1 AND name=$2`, tenant.String(), name).Scan(&e); err != nil {
			t.Fatal(err)
		}
		return e
	}

	upsert("gap-fill-host", asset.ExposureUnknown)
	upsert("gap-fill-host", asset.ExposurePublic)
	if got := exposureOf("gap-fill-host"); got != "public" {
		t.Fatalf("unknown -> public not persisted: %s", got)
	}

	upsert("operator-host", asset.ExposurePrivate)
	upsert("operator-host", asset.ExposurePublic)
	if got := exposureOf("operator-host"); got != "private" {
		t.Fatalf("a scan overrode a known exposure: %s", got)
	}
}

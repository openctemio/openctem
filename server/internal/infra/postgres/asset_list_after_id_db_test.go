package postgres

import (
	"context"
	"database/sql"
	"testing"

	_ "github.com/lib/pq"

	"github.com/openctemio/openctem/api/internal/testdb"
	"github.com/openctemio/openctem/api/pkg/domain/asset"
)

// ListAfterID pages a tenant's assets by id: every matching asset exactly
// once, in id order, never another tenant's, and never without a tenant.
func TestAssetListAfterID_DB(t *testing.T) {
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
	tenant, other := seedTestTenant(ctx, t, db), seedTestTenant(ctx, t, db)
	want := map[string]bool{}
	for i := 0; i < 7; i++ {
		want[seedPublicAsset(ctx, t, db, tenant).String()] = true
	}
	foreign := seedPublicAsset(ctx, t, db, other)

	repo := NewAssetRepository(&DB{DB: db})
	tid := tenant.String()
	filter := asset.Filter{TenantID: &tid}
	got := map[string]bool{}
	after, prev := "", ""
	for pages := 0; pages < 10; pages++ {
		page, err := repo.ListAfterID(ctx, filter, after, 3)
		if err != nil {
			t.Fatalf("ListAfterID: %v", err)
		}
		for _, a := range page {
			id := a.ID().String()
			if got[id] {
				t.Fatalf("asset %s returned twice", id)
			}
			if prev != "" && id <= prev {
				t.Fatalf("ids out of order: %s after %s", id, prev)
			}
			got[id], prev = true, id
		}
		if len(page) < 3 {
			break
		}
		after = page[len(page)-1].ID().String()
	}
	if len(got) != len(want) {
		t.Fatalf("read %d assets, want %d", len(got), len(want))
	}
	if got[foreign.String()] {
		t.Fatal("another tenant's asset was returned")
	}
	if _, err := repo.ListAfterID(ctx, asset.Filter{}, "", 3); err == nil {
		t.Fatal("a read without a tenant was not refused")
	}
}

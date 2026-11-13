package postgres

// A tag change written from a stale copy of an asset keeps every tag stored
// since that copy was loaded (asset.ChangeTags + AssetRepository.Update).
// Skipped unless DATABASE_URL names a migrated test database.

import (
	"context"
	"database/sql"
	"slices"
	"testing"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/server/internal/testdb"
)

func TestAssetUpdate_TagChangeAppliesToStoredTags(t *testing.T) {
	url := testdb.URL()
	if url == "" {
		t.Skip("DATABASE_URL not set; skipping DB execution check")
	}
	db, err := sql.Open("postgres", url)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	ctx := context.Background()
	if err := db.PingContext(ctx); err != nil {
		t.Skipf("cannot reach DATABASE_URL: %v", err)
	}
	tenant := seedTestTenant(ctx, t, db)
	id := seedPublicAsset(ctx, t, db, tenant)
	repo := NewAssetRepository(&DB{DB: db})
	stored := func() []string {
		var tags []string
		if err := db.QueryRowContext(ctx, `SELECT tags FROM assets WHERE id = $1`, id.String()).Scan(pq.Array(&tags)); err != nil {
			t.Fatal(err)
		}
		return tags
	}
	if _, err := db.ExecContext(ctx, `UPDATE assets SET tags = '{shared,old}' WHERE id = $1`, id.String()); err != nil {
		t.Fatal(err)
	}

	// Two people load the asset, then a sensor stores a tag.
	first, err := repo.GetByID(ctx, tenant, id)
	if err != nil {
		t.Fatal(err)
	}
	second, err := repo.GetByID(ctx, tenant, id)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `UPDATE assets SET tags = tags || '{scanner:nuclei}' WHERE id = $1`, id.String()); err != nil {
		t.Fatal(err)
	}

	first.ChangeTags(nil, []string{"old"})
	if err := repo.Update(ctx, first); err != nil {
		t.Fatal(err)
	}
	second.ChangeTags([]string{"new"}, nil)
	if err := repo.Update(ctx, second); err != nil {
		t.Fatal(err)
	}

	want := []string{"shared", "scanner:nuclei", "new"}
	if got := stored(); !slices.Equal(got, want) {
		t.Fatalf("stored tags = %v, want %v (nobody's tag lost)", got, want)
	}
	// The written copy now holds the stored list, and no pending change.
	if got := second.Tags(); !slices.Equal(got, want) {
		t.Errorf("entity tags after write = %v, want %v", got, want)
	}
	if _, ok := second.PendingTagChange(); ok {
		t.Error("pending tag change kept after the write")
	}
}

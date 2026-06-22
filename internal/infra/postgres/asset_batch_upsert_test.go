package postgres

import (
	"context"
	"database/sql"
	"os"
	"strconv"
	"strings"
	"testing"

	_ "github.com/lib/pq"

	"github.com/openctemio/api/pkg/domain/asset"
)

// These no-DB tests pin the assets upsert column header, the assetUpsertArgs
// order, and assetUpsertColumnCount together so a future column add/remove
// fails at build time rather than in production discovery ingest (which can
// carry tens of thousands of assets through the multi-row path).

func newTestAsset(t *testing.T) *asset.Asset {
	t.Helper()
	a, err := asset.NewAsset("example.com", asset.AssetTypeDomain, asset.CriticalityMedium)
	if err != nil {
		t.Fatalf("NewAsset: %v", err)
	}
	return a
}

func TestAssetUpsertArgs_MatchesColumnCount(t *testing.T) {
	args, err := assetUpsertArgs(newTestAsset(t))
	if err != nil {
		t.Fatalf("assetUpsertArgs: %v", err)
	}
	if len(args) != assetUpsertColumnCount {
		t.Fatalf("arg count %d != assetUpsertColumnCount %d", len(args), assetUpsertColumnCount)
	}
}

func TestAssetUpsertColumnsSQL_MatchesColumnCount(t *testing.T) {
	sql := assetUpsertColumnsSQL()
	open := strings.Index(sql, "(")
	closeIdx := strings.LastIndex(sql, ")")
	if open < 0 || closeIdx < 0 || closeIdx < open {
		t.Fatalf("could not locate column list parens in: %q", sql)
	}
	cols := strings.Split(sql[open+1:closeIdx], ",")
	count := 0
	for _, c := range cols {
		if strings.TrimSpace(c) != "" {
			count++
		}
	}
	if count != assetUpsertColumnCount {
		t.Fatalf("column header lists %d columns, assetUpsertColumnCount is %d", count, assetUpsertColumnCount)
	}
}

func TestAssetValuesPlaceholders(t *testing.T) {
	const rows = 3
	out := assetValuesPlaceholders(rows)

	last := "$" + strconv.Itoa(rows*assetUpsertColumnCount)
	if !strings.HasSuffix(out, last+")") {
		t.Fatalf("expected placeholders to end with %s), got tail %q", last, out[len(out)-12:])
	}
	if got := strings.Count(out, "("); got != rows {
		t.Fatalf("expected %d value groups, got %d", rows, got)
	}
	if got := strings.Count(out, "$"); got != rows*assetUpsertColumnCount {
		t.Fatalf("expected %d placeholders, got %d", rows*assetUpsertColumnCount, got)
	}
}

// TestAssetUpsertSQL_PreparesAgainstSchema validates the generated multi-row
// assets upsert against the real schema via PREPARE (parses/plans without
// executing). Skipped unless DATABASE_URL is set.
func TestAssetUpsertSQL_PreparesAgainstSchema(t *testing.T) {
	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		t.Skip("DATABASE_URL not set; skipping schema-level PREPARE check")
	}

	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer db.Close()

	ctx := context.Background()
	if err := db.PingContext(ctx); err != nil {
		t.Skipf("cannot reach DATABASE_URL: %v", err)
	}

	query := assetUpsertColumnsSQL() + "\nVALUES " + assetValuesPlaceholders(3) + "\n" + assetUpsertConflictSQL()
	if _, err := db.ExecContext(ctx, "PREPARE _asset_batch_test AS "+query); err != nil {
		t.Fatalf("multi-row asset upsert failed to prepare against schema: %v", err)
	}
	if _, err := db.ExecContext(ctx, "DEALLOCATE _asset_batch_test"); err != nil {
		t.Logf("deallocate failed (non-fatal): %v", err)
	}
}

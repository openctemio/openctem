package postgres

import (
	"context"
	"database/sql"
	"os"
	"testing"

	_ "github.com/lib/pq"

	"github.com/openctemio/api/pkg/domain/shared"
)

// TestSourceBreakdown_ExecutesAgainstSchema runs the GROUP BY source/tool query
// with the FILTER clause against the real findings schema using a random
// (empty) tenant — it mutates nothing but parses/plans/executes the actual SQL,
// so a column or status-enum mismatch surfaces here instead of in production.
// Skipped unless DATABASE_URL is set.
func TestSourceBreakdown_ExecutesAgainstSchema(t *testing.T) {
	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		t.Skip("DATABASE_URL not set; skipping schema-level check")
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

	repo := NewFindingRepository(&DB{DB: db})
	stats, err := repo.SourceBreakdown(ctx, shared.NewID())
	if err != nil {
		t.Fatalf("SourceBreakdown: %v", err)
	}
	if len(stats) != 0 {
		t.Fatalf("expected empty breakdown for a random tenant, got %d rows", len(stats))
	}
}

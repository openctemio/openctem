package postgres

import (
	"context"
	"database/sql"
	"os"
	"testing"

	_ "github.com/lib/pq"
)

// TestInsertChunkSQL_PreparesAgainstSchema validates the generated multi-row
// finding INSERT against the real findings schema. PREPARE parses and plans
// the statement (checking column names, the column/placeholder count, and the
// ON CONFLICT clause) WITHOUT executing it, so no FK/tenant seeding is needed.
//
// This is the regression guard for the multi-row batch insert: if a column is
// added to findingInsertColumnsSQL without bumping findingInsertColumnCount
// (or vice-versa), PREPARE fails here with a clear error instead of blowing up
// in production ingest.
//
// Skipped unless DATABASE_URL is set (e.g. when running against the docker DB).
func TestInsertChunkSQL_PreparesAgainstSchema(t *testing.T) {
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

	// Build the exact statement insertChunk would run for a 3-row batch.
	query := findingInsertColumnsSQL() + "\nVALUES " + findingValuesPlaceholders(3) + "\n" + findingUpsertConflictSQL()

	if _, err := db.ExecContext(ctx, "PREPARE _ic_batch_test AS "+query); err != nil {
		t.Fatalf("multi-row finding INSERT failed to prepare against schema: %v", err)
	}
	if _, err := db.ExecContext(ctx, "DEALLOCATE _ic_batch_test"); err != nil {
		t.Logf("deallocate failed (non-fatal): %v", err)
	}
}

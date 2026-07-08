package postgres

import (
	"context"
	"database/sql"
	"os"
	"testing"
	"time"

	_ "github.com/lib/pq"

	"github.com/openctemio/api/pkg/domain/integration"
)

// TestListDueForSync_ExecutesAgainstSchema exercises the scheduler's due-query
// (with the provider/status/next_sync_at filter) against the real integrations
// schema. It mutates nothing but parses/plans/binds the real SQL, so a column
// or type mismatch surfaces here rather than in the scheduler at runtime.
// Skipped unless DATABASE_URL is set.
func TestListDueForSync_ExecutesAgainstSchema(t *testing.T) {
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

	repo := NewIntegrationRepository(&DB{DB: db})
	// No DefectDojo integrations seeded → empty, but the query runs for real.
	got, err := repo.ListDueForSync(ctx, integration.ProviderDefectDojo, time.Now(), 20)
	if err != nil {
		t.Fatalf("ListDueForSync: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("expected no due integrations in a clean DB, got %d", len(got))
	}
}

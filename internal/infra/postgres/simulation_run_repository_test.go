package postgres

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"testing"

	_ "github.com/lib/pq"

	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/domain/simulation"
	"github.com/openctemio/api/pkg/pagination"
)

// TestSimulationRunRepository_ReadPathsAgainstSchema exercises the hand-written
// column list + scanRun against the real attack_simulation_runs schema with a
// random (empty) tenant. It mutates nothing but parses/plans/binds the real SQL,
// so a column-name or scan-type mismatch (the main risk of a hand-written repo)
// surfaces here rather than in production. Skipped unless DATABASE_URL is set.
func TestSimulationRunRepository_ReadPathsAgainstSchema(t *testing.T) {
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

	repo := NewSimulationRunRepository(&DB{DB: db})
	tenantID := shared.NewID()

	// GetByID for a random id → NotFound (exercises SELECT + scanRun columns).
	if _, err := repo.GetByID(ctx, tenantID, shared.NewID()); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("GetByID(random) error = %v, want ErrNotFound", err)
	}

	// List for a random tenant → empty page (exercises COUNT + SELECT + filters).
	status := simulation.RunStatusRunning
	res, err := repo.List(ctx, simulation.RunFilter{TenantID: &tenantID, Status: &status}, pagination.New(1, 20))
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(res.Data) != 0 || res.Total != 0 {
		t.Fatalf("expected empty result for random tenant, got %d/%d", len(res.Data), res.Total)
	}
}

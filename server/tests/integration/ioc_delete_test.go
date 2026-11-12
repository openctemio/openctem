package integration

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"testing"

	"github.com/google/uuid"
	_ "github.com/lib/pq"

	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/internal/testdb"
	"github.com/openctemio/openctem/api/pkg/domain/ioc"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Deleting an IOC only deactivated it, and GET /iocs/{id} and the list still
// returned it. A deleted indicator is now gone for every read; a second
// delete is not found; re-creating the value brings it back.
func TestIOCDelete_HiddenFromReads(t *testing.T) {
	dsn := testdb.URL()
	if dsn == "" {
		t.Skip("DATABASE_URL not set; skipping IOC DB test")
	}
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := db.Ping(); err != nil {
		testdb.Skipf(t, "database not available: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	ctx := context.Background()

	tid := shared.NewID()
	if _, err := db.ExecContext(ctx, `INSERT INTO tenants (id, name, slug) VALUES ($1, 'IOC IT', $2)`,
		tid.String(), "ioc-it-"+strings.ReplaceAll(uuid.NewString()[:13], "-", "")); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = db.ExecContext(context.Background(), `DELETE FROM iocs WHERE tenant_id = $1`, tid.String())
		_, _ = db.ExecContext(context.Background(), `DELETE FROM tenants WHERE id = $1`, tid.String())
	})

	repo := postgres.NewIOCRepository(&postgres.DB{DB: db})
	ind, err := ioc.NewIndicator(tid, ioc.TypeIP, "198.51.100.23", ioc.SourceManual)
	if err != nil {
		t.Fatal(err)
	}
	if err := repo.Create(ctx, ind); err != nil {
		t.Fatal(err)
	}
	if err := repo.Deactivate(ctx, tid, ind.ID); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := repo.GetByID(ctx, tid, ind.ID); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("get after delete: want not found, got %v", err)
	}
	list, err := repo.ListByTenant(ctx, tid, 50, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 0 {
		t.Fatalf("list after delete: %d indicators", len(list))
	}
	if err := repo.Deactivate(ctx, tid, ind.ID); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("second delete: want not found, got %v", err)
	}

	again, _ := ioc.NewIndicator(tid, ioc.TypeIP, "198.51.100.23", ioc.SourceManual)
	if err := repo.Create(ctx, again); err != nil {
		t.Fatal(err)
	}
	if list, _ := repo.ListByTenant(ctx, tid, 50, 0); len(list) != 1 {
		t.Fatalf("re-created indicator not listed: %d", len(list))
	}
}

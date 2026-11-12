package postgres

import (
	"context"
	"database/sql"
	"errors"
	"testing"

	_ "github.com/lib/pq"

	"github.com/openctemio/openctem/api/internal/testdb"
	sensordom "github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// TestTenantToolSettings_TenantIsolation: an organization reads, replaces
// and deletes only its own tool defaults; the same tool of two
// organizations are two rows; deleting the organization deletes them.
func TestTenantToolSettings_TenantIsolation(t *testing.T) {
	dbURL := testdb.URL()
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
	seedTenant := func(name string) shared.ID {
		id := shared.NewID()
		if _, err := db.ExecContext(ctx, `INSERT INTO tenants (id, name, slug) VALUES ($1, $2, $3)`,
			id.String(), name, name+"-"+id.String()[28:]); err != nil {
			t.Fatalf("seed tenant: %v", err)
		}
		t.Cleanup(func() { _, _ = db.ExecContext(ctx, `DELETE FROM tenants WHERE id = $1`, id.String()) })
		return id
	}
	a, b := seedTenant("ttd-a"), seedTenant("ttd-b")
	repo := NewSensorRepository(&DB{DB: db})

	save := func(tenant shared.ID, rate int) {
		t.Helper()
		if err := repo.SaveTenantToolSettings(ctx, sensordom.TenantToolSettings{TenantID: tenant, Tool: "nuclei",
			Values: map[string]any{"rate_limit": rate}, SchemaDigest: testSettingsDigest}); err != nil {
			t.Fatalf("save: %v", err)
		}
	}
	save(a, 100)
	save(b, 200)
	save(a, 150) // replaces A's row, never B's

	got, err := repo.GetTenantToolSettings(ctx, a, "nuclei")
	if err != nil || got.Values["rate_limit"].(interface{ String() string }).String() != "150" {
		t.Fatalf("A = %+v, %v", got, err)
	}
	if rows, err := repo.ListTenantToolSettings(ctx, b); err != nil || len(rows) != 1 ||
		rows[0].Values["rate_limit"].(interface{ String() string }).String() != "200" {
		t.Fatalf("B list = %+v, %v", rows, err)
	}
	if _, err := repo.GetTenantToolSettings(ctx, a, "httpx"); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("missing tool: %v", err)
	}

	// A delete is scoped: B's row survives A's delete.
	if ok, err := repo.DeleteTenantToolSettings(ctx, a, "nuclei"); err != nil || !ok {
		t.Fatalf("delete A: %v %v", ok, err)
	}
	if ok, err := repo.DeleteTenantToolSettings(ctx, a, "nuclei"); err != nil || ok {
		t.Fatalf("second delete: %v %v", ok, err)
	}
	if _, err := repo.GetTenantToolSettings(ctx, b, "nuclei"); err != nil {
		t.Fatalf("B lost its row: %v", err)
	}

	// Deleting the organization deletes its defaults.
	if _, err := db.ExecContext(ctx, `DELETE FROM tenants WHERE id = $1`, b.String()); err != nil {
		t.Fatal(err)
	}
	var n int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM tenant_tool_settings WHERE tenant_id = $1`, b.String()).Scan(&n); err != nil || n != 0 {
		t.Fatalf("rows after tenant delete = %d, %v", n, err)
	}
}

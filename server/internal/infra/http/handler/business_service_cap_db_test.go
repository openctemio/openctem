package handler

import (
	"context"
	"database/sql"
	"testing"

	_ "github.com/lib/pq"

	"github.com/openctemio/openctem/api/internal/testdb"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// One business service lists at most the cap of asset links, only its own
// tenant's, newest first.
func TestListBusinessServiceAssets_Capped_DB(t *testing.T) {
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
	tenant, svc := shared.NewID(), shared.NewID()
	if _, err := db.ExecContext(ctx, `INSERT INTO tenants (id, name, slug) VALUES ($1, 'cap', $2)`, tenant.String(), "cap-"+tenant.String()); err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	t.Cleanup(func() {
		_, _ = db.ExecContext(context.Background(), `DELETE FROM tenants WHERE id = $1`, tenant.String())
	})
	if _, err := db.ExecContext(ctx, `INSERT INTO business_services (id, tenant_id, name) VALUES ($1, $2, 'svc')`, svc.String(), tenant.String()); err != nil {
		t.Fatalf("seed service: %v", err)
	}
	for i := 0; i < 5; i++ {
		a := shared.NewID()
		if _, err := db.ExecContext(ctx, `INSERT INTO assets (id, tenant_id, name, asset_type) VALUES ($1, $2, $3, 'host')`, a.String(), tenant.String(), "a-"+a.String()); err != nil {
			t.Fatalf("seed asset: %v", err)
		}
		if _, err := db.ExecContext(ctx, `INSERT INTO business_service_assets (tenant_id, service_id, asset_id) VALUES ($1, $2, $3)`, tenant.String(), svc.String(), a.String()); err != nil {
			t.Fatalf("seed link: %v", err)
		}
	}
	got, err := listBusinessServiceAssets(ctx, db, tenant.String(), svc.String(), 3)
	if err != nil || len(got) != 3 {
		t.Fatalf("listed %d links (err %v), want the cap of 3", len(got), err)
	}
	// Another tenant's id as the scope yields nothing.
	if other, err := listBusinessServiceAssets(ctx, db, shared.NewID().String(), svc.String(), 3); err != nil || len(other) != 0 {
		t.Fatalf("foreign tenant read %d links (err %v)", len(other), err)
	}
}

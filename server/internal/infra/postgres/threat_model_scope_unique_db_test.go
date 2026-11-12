package postgres

import (
	"context"
	"database/sql"
	"sync"
	"testing"

	_ "github.com/lib/pq"

	"github.com/openctemio/openctem/api/internal/testdb"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/threatmodel"
)

// The tenant-wide threat model has scope_ref_id NULL. The UNIQUE from 000189
// treated NULLs as distinct and Save selected before it inserted, so a tenant
// could hold two tenant-wide models (RFC-043 P0, probe P18). Migration 000295
// makes the key NULLS NOT DISTINCT and Save upserts on it.

func openThreatModelScopeDB(t *testing.T) *sql.DB {
	t.Helper()
	dbURL := testdb.URL()
	if dbURL == "" {
		t.Skip("DATABASE_URL not set; skipping threat model scope test")
	}
	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		t.Skipf("open db: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := db.PingContext(context.Background()); err != nil {
		t.Skipf("cannot reach DATABASE_URL: %v", err)
	}
	return db
}

func seedThreatModelTenant(t *testing.T, db *sql.DB) shared.ID {
	t.Helper()
	id := shared.NewID()
	if _, err := db.Exec(`INSERT INTO tenants (id, name, slug) VALUES ($1, $2, $2)`, id.String(), "tm-scope-"+id.String()); err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	t.Cleanup(func() { _, _ = db.Exec(`DELETE FROM tenants WHERE id = $1`, id.String()) })
	return id
}

func TestThreatModels_TenantWideScopeIsUnique(t *testing.T) {
	db := openThreatModelScopeDB(t)
	tenant := seedThreatModelTenant(t, db)

	insert := `INSERT INTO threat_models (tenant_id, scope_type, name) VALUES ($1, 'tenant', 'tenant-wide')`
	if _, err := db.Exec(insert, tenant.String()); err != nil {
		t.Fatalf("first tenant-wide model: %v", err)
	}
	if _, err := db.Exec(insert, tenant.String()); err == nil {
		t.Fatal("a second tenant-wide model for one tenant was accepted")
	}
}

func TestThreatModelRepository_ConcurrentTenantWideSaves(t *testing.T) {
	db := openThreatModelScopeDB(t)
	tenant := seedThreatModelTenant(t, db)
	repo := NewThreatModelRepository(&DB{DB: db})

	const n = 8
	var wg sync.WaitGroup
	errs := make(chan error, n)
	start := make(chan struct{})
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			m, err := threatmodel.NewThreatModel(tenant, threatmodel.ScopeTenant, nil, "tenant-wide")
			if err != nil {
				errs <- err
				return
			}
			<-start
			errs <- repo.Save(context.Background(), m, nil)
		}()
	}
	close(start)
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Errorf("Save: %v", err)
		}
	}
	var rows int
	if err := db.QueryRow(`SELECT count(*) FROM threat_models WHERE tenant_id = $1 AND scope_type = 'tenant'`, tenant.String()).Scan(&rows); err != nil {
		t.Fatal(err)
	}
	if rows != 1 {
		t.Fatalf("tenant-wide models = %d after %d concurrent saves, want 1", rows, n)
	}
}

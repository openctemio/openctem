package postgres

import (
	"context"
	"database/sql"
	"errors"
	"testing"

	_ "github.com/lib/pq"

	"github.com/openctemio/openctem/api/internal/testdb"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Tool lookup by name is how scans and pipeline steps resolve their tool. It
// ignored the tenant, so a name shared by two tenants' custom tools resolved
// to either one, and another tenant's custom tool could be dispatched
// (settings audit SC-M5). A name now resolves to the platform tool first,
// then the caller's own custom tool, never another tenant's.
func TestToolGetByName_IsTenantScoped(t *testing.T) {
	dbURL := testdb.URL()
	if dbURL == "" {
		t.Skip("DATABASE_URL not set; skipping DB-backed test")
	}
	raw, err := sql.Open("postgres", dbURL)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer raw.Close()
	if err := raw.Ping(); err != nil {
		t.Skipf("cannot reach test DB: %v", err)
	}
	ctx := context.Background()
	repo := NewToolRepository(&DB{DB: raw})

	tenantA, tenantB := shared.NewID(), shared.NewID()
	for _, id := range []shared.ID{tenantA, tenantB} {
		if _, err := raw.ExecContext(ctx, `INSERT INTO tenants (id, name, slug) VALUES ($1, $2, $2)`, id.String(), "tool-"+id.String()); err != nil {
			t.Fatalf("seed tenant: %v", err)
		}
	}
	name := "custom-" + tenantB.String()[:8]
	platformName := "platform-" + tenantB.String()[:8]
	t.Cleanup(func() {
		bg := context.Background()
		_, _ = raw.ExecContext(bg, `DELETE FROM tools WHERE name IN ($1, $2)`, name, platformName)
		_, _ = raw.ExecContext(bg, `DELETE FROM tenants WHERE id IN ($1, $2)`, tenantA.String(), tenantB.String())
	})
	// Tenant B's custom tool, and a platform tool that tenant A also shadows
	// with a custom tool of the same name.
	if _, err := raw.ExecContext(ctx, `INSERT INTO tools (name, display_name, tenant_id, install_method) VALUES ($1, 'B tool', $2, 'binary')`, name, tenantB.String()); err != nil {
		t.Fatalf("seed B tool: %v", err)
	}
	if _, err := raw.ExecContext(ctx, `INSERT INTO tools (name, display_name, tenant_id, install_method) VALUES ($1, 'platform', NULL, 'binary'), ($1, 'A shadow', $2, 'binary')`, platformName, tenantA.String()); err != nil {
		t.Fatalf("seed platform tool: %v", err)
	}

	if _, err := repo.GetByName(ctx, tenantA, name); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("tenant A resolved tenant B's custom tool: err = %v, want ErrNotFound", err)
	}
	got, err := repo.GetByName(ctx, tenantB, name)
	if err != nil || got.TenantID == nil || *got.TenantID != tenantB {
		t.Fatalf("tenant B's own tool: %+v, %v", got, err)
	}
	got, err = repo.GetByName(ctx, tenantA, platformName)
	if err != nil || got.TenantID != nil {
		t.Fatalf("platform tool must win over a tenant tool of the same name: %+v, %v", got, err)
	}
	if _, err := repo.GetByName(ctx, shared.ID{}, name); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("no tenant resolved a custom tool: err = %v", err)
	}
}

package postgres

import (
	"context"
	"database/sql"
	"testing"

	_ "github.com/lib/pq"

	"github.com/openctemio/openctem/api/internal/testdb"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// ListByCategoryID backs the "category is in use" check. It ignored the
// tenant, so it returned every tenant's custom tools in a category. It now
// lists platform tools plus the caller's own, never another tenant's.
func TestToolListByCategoryID_IsTenantScoped(t *testing.T) {
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
		if _, err := raw.ExecContext(ctx, `INSERT INTO tenants (id, name, slug) VALUES ($1, $2, $2)`, id.String(), "toolcat-"+id.String()); err != nil {
			t.Fatalf("seed tenant: %v", err)
		}
	}
	suffix := tenantB.String()[28:]
	catName := "cat-" + suffix
	var catID string
	if err := raw.QueryRowContext(ctx, `INSERT INTO tool_categories (name, display_name, tenant_id) VALUES ($1, $1, NULL) RETURNING id`, catName).Scan(&catID); err != nil {
		t.Fatalf("seed category: %v", err)
	}
	names := []string{"pl-" + suffix, "a-" + suffix, "b-" + suffix}
	t.Cleanup(func() {
		bg := context.Background()
		_, _ = raw.ExecContext(bg, `DELETE FROM tools WHERE category_id = $1`, catID)
		_, _ = raw.ExecContext(bg, `DELETE FROM tool_categories WHERE id = $1`, catID)
		_, _ = raw.ExecContext(bg, `DELETE FROM tenants WHERE id IN ($1, $2)`, tenantA.String(), tenantB.String())
	})
	for i, tenant := range []any{nil, tenantA.String(), tenantB.String()} {
		if _, err := raw.ExecContext(ctx, `INSERT INTO tools (name, display_name, tenant_id, category_id, install_method) VALUES ($1, $1, $2, $3, 'binary')`, names[i], tenant, catID); err != nil {
			t.Fatalf("seed tool %s: %v", names[i], err)
		}
	}
	cid, _ := shared.IDFromString(catID)

	got := func(tenant shared.ID) map[string]bool {
		tools, err := repo.ListByCategoryID(ctx, tenant, cid)
		if err != nil {
			t.Fatalf("ListByCategoryID: %v", err)
		}
		m := map[string]bool{}
		for _, tl := range tools {
			m[tl.Name] = true
		}
		return m
	}
	a := got(tenantA)
	if !a[names[0]] || !a[names[1]] || a[names[2]] || len(a) != 2 {
		t.Fatalf("tenant A must see the platform tool and its own only: %v", a)
	}
	b := got(tenantB)
	if !b[names[0]] || !b[names[2]] || b[names[1]] || len(b) != 2 {
		t.Fatalf("tenant B must see the platform tool and its own only: %v", b)
	}
	none := got(shared.ID{})
	if !none[names[0]] || len(none) != 1 {
		t.Fatalf("no tenant sees platform tools only: %v", none)
	}
}

package handler

import (
	"context"
	"database/sql"
	"testing"

	_ "github.com/lib/pq"

	"github.com/openctemio/openctem/server/internal/testdb"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
)

// The list total and the visibility checks run for every scope the reader
// can have. An administrator from whom private program assets are hidden
// gets an Unrestricted scope (not nil): its predicate is TRUE and the
// statement takes no scope argument. Passing the asset_count arguments
// anyway made GET /business-services a 500 ("got 3 parameters but the
// statement requires 1") in every organization with a private program, and
// the write and asset-list checks answered 404 for every service.
func TestBusinessServiceVisibility_EveryScope_DB(t *testing.T) {
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
	tenant, other := shared.NewID(), shared.NewID()
	linked, empty, foreign := shared.NewID(), shared.NewID(), shared.NewID()
	for _, tid := range []shared.ID{tenant, other} {
		if _, err := db.ExecContext(ctx, `INSERT INTO tenants (id, name, slug) VALUES ($1, 'bs-scope', $2)`, tid.String(), "bs-scope-"+tid.String()); err != nil {
			t.Fatalf("seed tenant: %v", err)
		}
	}
	t.Cleanup(func() {
		_, _ = db.ExecContext(context.Background(), `DELETE FROM tenants WHERE id = ANY($1::uuid[])`, "{"+tenant.String()+","+other.String()+"}")
	})
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := db.ExecContext(ctx, q, args...); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	exec(`INSERT INTO business_services (id, tenant_id, name) VALUES ($1, $2, 'linked'), ($3, $2, 'empty')`, linked.String(), tenant.String(), empty.String())
	exec(`INSERT INTO business_services (id, tenant_id, name) VALUES ($1, $2, 'foreign')`, foreign.String(), other.String())
	asset := shared.NewID()
	exec(`INSERT INTO assets (id, tenant_id, name, asset_type) VALUES ($1, $2, $3, 'host')`, asset.String(), tenant.String(), "a-"+asset.String())
	exec(`INSERT INTO business_service_assets (tenant_id, service_id, asset_id) VALUES ($1, $2, $3)`, tenant.String(), linked.String(), asset.String())

	user := shared.NewID()
	cases := []struct {
		name  string
		scope *shared.DataScope
		total int64
		// what the reader sees, and what they may write (a service with no
		// linked asset stays writable to a restricted reader).
		seesLinked, writesEmpty bool
	}{
		{"no scope (owner)", nil, 2, true, true},
		{"unrestricted with hidden program assets", &shared.DataScope{TenantID: tenant, UserID: user, Unrestricted: true}, 2, true, true},
		{"restricted, no scope rows", &shared.DataScope{TenantID: tenant, UserID: user}, 0, false, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			total, err := countVisibleServices(ctx, db, tenant.String(), c.scope)
			if err != nil || total != c.total {
				t.Fatalf("total = %d (err %v), want %d", total, err, c.total)
			}
			ok, err := serviceVisibleExists(ctx, db, tenant.String(), linked.String(), c.scope, false)
			if err != nil || ok != c.seesLinked {
				t.Fatalf("sees linked = %v (err %v), want %v", ok, err, c.seesLinked)
			}
			ok, err = serviceVisibleExists(ctx, db, tenant.String(), empty.String(), c.scope, true)
			if err != nil || ok != c.writesEmpty {
				t.Fatalf("writes empty = %v (err %v), want %v", ok, err, c.writesEmpty)
			}
			// Another tenant's service is never visible nor writable, and
			// it never counts.
			for _, orUnlinked := range []bool{false, true} {
				if ok, err := serviceVisibleExists(ctx, db, tenant.String(), foreign.String(), c.scope, orUnlinked); err != nil || ok {
					t.Fatalf("foreign service visible=%v (err %v, orUnlinked %v)", ok, err, orUnlinked)
				}
			}
			if ok, err := serviceVisibleExists(ctx, db, tenant.String(), "not-a-uuid", c.scope, true); err != nil || ok {
				t.Fatalf("malformed id visible=%v (err %v)", ok, err)
			}
		})
	}
	if total, err := countVisibleServices(ctx, db, shared.NewID().String(), nil); err != nil || total != 0 {
		t.Fatalf("unknown tenant counted %d (err %v)", total, err)
	}
}

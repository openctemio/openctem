package controller

import (
	"context"
	"database/sql"
	"testing"

	_ "github.com/lib/pq"

	"github.com/openctemio/openctem/api/internal/testdb"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// The owner-resolution controller writes the one owner model: the member whose
// email is an asset's owner_ref becomes a primary owner_ref row in
// asset_owners. It never overrides an owner set by a person, never adds a
// non-member, and never grants data access.
func TestOwnerResolution_WritesAssetOwners_DB(t *testing.T) {
	url := testdb.URL()
	if url == "" {
		t.Skip("DATABASE_URL not set; skipping owner resolution DB test")
	}
	db, err := sql.Open("postgres", url)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer db.Close()
	ctx := context.Background()
	if err := db.PingContext(ctx); err != nil {
		t.Skipf("cannot reach DATABASE_URL: %v", err)
	}
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := db.ExecContext(ctx, q, args...); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}

	tenant, other := shared.NewID(), shared.NewID()
	member, manual, outsider := shared.NewID(), shared.NewID(), shared.NewID()
	for _, id := range []shared.ID{tenant, other} {
		exec(`INSERT INTO tenants (id, name, slug) VALUES ($1, 'owner resolution test', $2)`, id.String(), "or-"+id.String())
	}
	for _, id := range []shared.ID{member, manual, outsider} {
		exec(`INSERT INTO users (id, email, name) VALUES ($1, $2, 'u')`, id.String(), id.String()+"@Owner-Res.test")
	}
	t.Cleanup(func() {
		bg := context.Background()
		for _, id := range []shared.ID{tenant, other} {
			_, _ = db.ExecContext(bg, `DELETE FROM tenants WHERE id = $1`, id.String())
		}
		for _, id := range []shared.ID{member, manual, outsider} {
			_, _ = db.ExecContext(bg, `DELETE FROM users WHERE id = $1`, id.String())
		}
	})
	exec(`INSERT INTO tenant_members (user_id, tenant_id, role) VALUES ($1, $2, 'member')`, member.String(), tenant.String())
	exec(`INSERT INTO tenant_members (user_id, tenant_id, role) VALUES ($1, $2, 'member')`, manual.String(), tenant.String())

	asset := func(tenantID shared.ID, ownerRef string) shared.ID {
		id := shared.NewID()
		exec(`INSERT INTO assets (id, tenant_id, name, asset_type, owner_ref) VALUES ($1, $2, $3, 'host', $4)`,
			id.String(), tenantID.String(), "or-"+id.String(), ownerRef)
		return id
	}
	matched := asset(tenant, member.String()+"@owner-res.TEST") // case-insensitive match
	manualOwned := asset(tenant, manual.String()+"@owner-res.test")
	notMember := asset(tenant, outsider.String()+"@owner-res.test")
	wrongTenant := asset(other, member.String()+"@owner-res.test")
	exec(`INSERT INTO asset_owners (asset_id, user_id, ownership_type, assignment_source) VALUES ($1, $2, 'stakeholder', 'manual')`,
		manualOwned.String(), manual.String())

	c := NewOwnerResolutionController(db, logger.NewNop())
	for range 2 { // idempotent
		if _, err := c.Reconcile(ctx); err != nil {
			t.Fatalf("reconcile: %v", err)
		}
	}

	owners := func(assetID shared.ID) []string {
		t.Helper()
		rows, err := db.QueryContext(ctx,
			`SELECT user_id::text || ':' || ownership_type || ':' || assignment_source FROM asset_owners WHERE asset_id = $1`, assetID.String())
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		var out []string
		for rows.Next() {
			var s string
			if err := rows.Scan(&s); err != nil {
				t.Fatal(err)
			}
			out = append(out, s)
		}
		if err := rows.Err(); err != nil {
			t.Fatal(err)
		}
		return out
	}
	if got := owners(matched); len(got) != 1 || got[0] != member.String()+":primary:owner_ref" {
		t.Errorf("matched asset owners = %v, want the member as primary owner_ref", got)
	}
	if got := owners(manualOwned); len(got) != 1 || got[0] != manual.String()+":stakeholder:manual" {
		t.Errorf("manually owned asset owners = %v, want the manual row unchanged", got)
	}
	if got := owners(notMember); len(got) != 0 {
		t.Errorf("non-member became an owner: %v", got)
	}
	if got := owners(wrongTenant); len(got) != 0 {
		t.Errorf("member of another tenant became an owner: %v", got)
	}

	var access int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM user_accessible_assets WHERE user_id = $1`, member.String()).Scan(&access); err != nil {
		t.Fatal(err)
	}
	if access != 0 {
		t.Errorf("owner resolution granted %d data-scope rows, want 0", access)
	}
}

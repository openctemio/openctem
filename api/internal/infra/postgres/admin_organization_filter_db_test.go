package postgres

import (
	"context"
	"database/sql"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	_ "github.com/lib/pq"

	"github.com/openctemio/openctem/api/internal/testdb"
	"github.com/openctemio/openctem/api/pkg/domain/admin"
	"github.com/openctemio/openctem/api/pkg/domain/tenant"
)

// The console's organization list filters by owner (none / present) and by
// plan, and reports each organization's plan (enterprise when none is
// stored: organizations created before plans). Requires DATABASE_URL.
func TestAdminOrganizationListFilters_DB(t *testing.T) {
	dbURL := testdb.URL()
	if dbURL == "" {
		t.Skip("DATABASE_URL not set")
	}
	raw, err := sql.Open("postgres", dbURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = raw.Close() })
	if err := raw.Ping(); err != nil {
		testdb.Skipf(t, "cannot reach DATABASE_URL: %v", err)
	}
	ctx := context.Background()
	repo := NewAdminOrganizationRepository(&DB{DB: raw})
	marker := "orgfilter" + strings.ReplaceAll(uuid.NewString()[:8], "-", "")

	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := raw.ExecContext(ctx, q, args...); err != nil {
			t.Fatalf("%v\n%s", err, q)
		}
	}
	org := func(suffix string) string {
		id := uuid.NewString()
		exec(`INSERT INTO tenants (id, name, slug) VALUES ($1, $2, $2)`, id, marker+"-"+suffix)
		t.Cleanup(func() {
			for _, q := range []string{
				`DELETE FROM tenant_plans WHERE tenant_id = $1`,
				`DELETE FROM users WHERE id IN (SELECT user_id FROM tenant_members WHERE tenant_id = $1)`,
				`DELETE FROM tenant_members WHERE tenant_id = $1`,
				`DELETE FROM tenants WHERE id = $1`,
			} {
				_, _ = raw.ExecContext(ctx, q, id)
			}
		})
		return id
	}
	member := func(tenantID, role, status string) {
		uid := uuid.NewString()
		exec(`INSERT INTO users (id, email, name) VALUES ($1, $2, 'Filter IT')`, uid, uid+"@it.test")
		exec(`INSERT INTO tenant_members (id, user_id, tenant_id, role, status) VALUES ($1, $2, $3, $4, $5)`,
			uuid.NewString(), uid, tenantID, role, status)
	}

	owned := org("owned")
	member(owned, "owner", "active")
	exec(`INSERT INTO tenant_plans (tenant_id, plan) VALUES ($1, 'free')`, owned)
	suspended := org("suspended") // its only owner is suspended: no active owner
	member(suspended, "owner", "suspended")
	exec(`INSERT INTO tenant_plans (tenant_id, plan) VALUES ($1, 'pro')`, suspended)
	empty := org("empty") // no plan row: enterprise
	member(empty, "member", "active")

	list := func(f admin.OrganizationFilter) map[string]string {
		t.Helper()
		f.Search, f.Limit = marker, 50
		orgs, total, err := repo.ListOrganizations(ctx, f)
		if err != nil {
			t.Fatal(err)
		}
		if total != len(orgs) {
			t.Fatalf("total %d, page %d", total, len(orgs))
		}
		out := map[string]string{}
		for _, o := range orgs {
			out[o.ID.String()] = o.Plan
		}
		return out
	}

	all := list(admin.OrganizationFilter{})
	if len(all) != 3 || all[owned] != "free" || all[suspended] != "pro" || all[empty] != "enterprise" {
		t.Fatalf("plans = %v", all)
	}
	none := list(admin.OrganizationFilter{Owner: admin.OrganizationOwnerNone})
	if len(none) != 2 || none[owned] != "" {
		t.Fatalf("owner=none = %v, want the suspended-owner and member-only organizations", none)
	}
	present := list(admin.OrganizationFilter{Owner: admin.OrganizationOwnerPresent})
	if len(present) != 1 || present[owned] == "" {
		t.Fatalf("owner=present = %v", present)
	}
	ent := list(admin.OrganizationFilter{Plan: "enterprise"})
	if len(ent) != 1 || ent[empty] == "" {
		t.Fatalf("plan=enterprise = %v, want only the organization without a stored plan", ent)
	}
	both := list(admin.OrganizationFilter{Owner: admin.OrganizationOwnerNone, Plan: "pro"})
	if len(both) != 1 || both[suspended] == "" {
		t.Fatalf("owner=none&plan=pro = %v", both)
	}
}

// The platform system tenant is internal: the console list and its total
// leave it out unless IncludeSystem asks for it, and the overview neither
// counts it nor names it as an organization without an owner.
func TestAdminOrganizationListHidesSystemTenant_DB(t *testing.T) {
	dbURL := testdb.URL()
	if dbURL == "" {
		t.Skip("DATABASE_URL not set")
	}
	raw, err := sql.Open("postgres", dbURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = raw.Close() })
	if err := raw.Ping(); err != nil {
		testdb.Skipf(t, "cannot reach DATABASE_URL: %v", err)
	}
	ctx := context.Background()
	if _, err := raw.ExecContext(ctx, `INSERT INTO tenants (id, name, slug) VALUES ($1, 'System', 'system') ON CONFLICT (id) DO NOTHING`, tenant.SystemTenantID); err != nil {
		t.Fatal(err)
	}
	repo := NewAdminOrganizationRepository(&DB{DB: raw})

	listed := func(f admin.OrganizationFilter) (bool, int) {
		t.Helper()
		f.Search, f.Limit = "system", 200
		orgs, total, err := repo.ListOrganizations(ctx, f)
		if err != nil {
			t.Fatal(err)
		}
		for _, o := range orgs {
			if o.ID.String() == tenant.SystemTenantID {
				return true, total
			}
		}
		return false, total
	}
	hidden, totalHidden := listed(admin.OrganizationFilter{})
	if hidden {
		t.Fatal("the system tenant is listed by default")
	}
	shown, totalShown := listed(admin.OrganizationFilter{IncludeSystem: true})
	if !shown || totalShown != totalHidden+1 {
		t.Fatalf("include_system: listed=%v total %d, want listed and %d", shown, totalShown, totalHidden+1)
	}

	// One snapshot, so organizations other tests add meanwhile do not count.
	tx, err := raw.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback() }()
	var orgs, withoutOwner int64
	if err := tx.QueryRowContext(ctx, `SELECT count(*), count(*) FILTER (WHERE NOT EXISTS (
		SELECT 1 FROM tenant_members m WHERE m.tenant_id = t.id AND m.role = 'owner' AND m.status = 'active'))
		FROM tenants t`).Scan(&orgs, &withoutOwner); err != nil {
		t.Fatal(err)
	}
	c, err := ReadAdminOverview(ctx, tx, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if c.Organizations != orgs-1 || c.OrganizationsWithoutOwner != withoutOwner-1 {
		t.Fatalf("overview counts %d organizations, %d without owner; want %d and %d (all but the system tenant)",
			c.Organizations, c.OrganizationsWithoutOwner, orgs-1, withoutOwner-1)
	}
	for _, o := range c.OrganizationsWithoutOwnerSample {
		if o.ID == tenant.SystemTenantID {
			t.Fatal("overview names the system tenant as an organization without an owner")
		}
	}
}

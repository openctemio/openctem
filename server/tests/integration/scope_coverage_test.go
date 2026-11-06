package integration

// Scope coverage of the inventory on a real database (research/53 S-3, SC8):
// counted in SQL, over the internet-facing inventory only, inside the
// caller's data scope, and never across tenants.

import (
	"context"
	"testing"

	"github.com/openctemio/openctem/api/internal/infra/postgres"
	scopedom "github.com/openctemio/openctem/api/pkg/domain/scope"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

func TestScopeCoverageRepository(t *testing.T) {
	db := openLifecycleDB(t)
	ctx := context.Background()
	tenantA := seedLifecycleTenant(ctx, t, db)
	tenantB := seedLifecycleTenant(ctx, t, db)
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := db.ExecContext(ctx, q, args...); err != nil {
			t.Fatal(err)
		}
	}
	asset := func(tenant shared.ID, typ, name, state string) shared.ID {
		t.Helper()
		id := shared.NewID()
		exec(`INSERT INTO assets (id, tenant_id, name, asset_type, status) VALUES ($1, $2, $3, $4, 'active')`,
			id.String(), tenant.String(), name, typ)
		if state != "" {
			exec(`INSERT INTO asset_attributions (asset_id, tenant_id, state, confidence) VALUES ($1, $2, $3, 85)`,
				id.String(), tenant.String(), state)
		}
		return id
	}
	exclusion := func(tenant shared.ID, typ, pattern string, approved bool) {
		t.Helper()
		status, approvedAt := "pending", "NULL"
		if approved {
			status, approvedAt = "active", "now()"
		}
		exec(`INSERT INTO scope_exclusions (tenant_id, exclusion_type, pattern, reason, status, approved_at)
			VALUES ($1, $2, $3, 'test', $4, `+approvedAt+`)`, tenant.String(), typ, pattern, status)
	}

	seedScopeTarget(t, db, tenantA, "domain", "*.acme.com")
	seedScopeTarget(t, db, tenantA, "cidr", "203.0.113.0/24")
	seedScopeTarget(t, db, tenantA, "domain", "*.inactive.example")
	exec(`UPDATE scope_targets SET status = 'inactive' WHERE tenant_id = $1 AND pattern = '*.inactive.example'`, tenantA.String())
	exclusion(tenantA, "domain", "secret.acme.com", true)
	exclusion(tenantA, "domain", "app.acme.com", false) // pending: excludes nothing
	exclusion(tenantA, "finding_type", "*", true)       // describes findings, not assets

	app := asset(tenantA, "domain", "app.acme.com", "")                       // covered (no record: legacy inventory)
	asset(tenantA, "subdomain", "ACME.com.", "confirmed")                     // covered: *.x covers x
	asset(tenantA, "application", "https://shop.acme.com/cart", "dependency") // covered through its host
	asset(tenantA, "service", "203.0.113.5:443", "monitor_only")              // covered by the CIDR
	other := asset(tenantA, "ip_address", "198.51.100.7", "confirmed")        // not covered
	asset(tenantA, "domain", "secret.acme.com", "confirmed")                  // excluded
	asset(tenantA, "domain", "old.inactive.example", "confirmed")             // its target is inactive
	asset(tenantA, "service", "mail.acme.com:25:tcp", "")                     // covered: a stored service name
	asset(tenantA, "service", "10.0.0.6:22:tcp", "")                          // internal service
	asset(tenantA, "ip_address", "10.0.0.5", "")                              // internal
	asset(tenantA, "domain", "build.corp.internal", "")                       // internal
	asset(tenantA, "domain", "review.acme.com", "needs_review")               // not in the inventory
	asset(tenantA, "domain", "gone.acme.com", "rejected")                     // not in the inventory
	asset(tenantA, "repository", "github.com/acme/app", "")                   // not internet-facing
	// Tenant B has the same target and more assets: none counts for A.
	seedScopeTarget(t, db, tenantB, "domain", "*.acme.com")
	asset(tenantB, "domain", "b1.acme.com", "")
	asset(tenantB, "domain", "b2.acme.com", "")

	repo := postgres.NewScopeCoverageRepository(&postgres.DB{DB: db})
	got, err := repo.CountCoverage(ctx, tenantA, nil)
	if err != nil {
		t.Fatal(err)
	}
	want := scopedom.InventoryCoverage{InternetFacing: 8, InScope: 5, Internal: 3}
	if got != want {
		t.Fatalf("tenant-wide = %+v, want %+v", got, want)
	}
	if p := got.Percent(); p != 62.5 {
		t.Fatalf("percent = %v", p)
	}

	// A restricted member counts only the assets they may see.
	member := seedActUser(t, db)
	grantScope(t, db, tenantA, member, app)
	grantScope(t, db, tenantA, member, other)
	got, err = repo.CountCoverage(ctx, tenantA, &shared.DataScope{TenantID: tenantA, UserID: member})
	if err != nil {
		t.Fatal(err)
	}
	if want := (scopedom.InventoryCoverage{InternetFacing: 2, InScope: 1}); got != want {
		t.Fatalf("restricted member = %+v, want %+v", got, want)
	}

	// A member with no scope rows sees nothing; a scope of another tenant
	// admits nothing.
	nobody := seedActUser(t, db)
	if got, err := repo.CountCoverage(ctx, tenantA, &shared.DataScope{TenantID: tenantA, UserID: nobody}); err != nil || got != (scopedom.InventoryCoverage{}) {
		t.Fatalf("member without scope rows = %+v %v", got, err)
	}
	if got, err := repo.CountCoverage(ctx, tenantA, &shared.DataScope{TenantID: tenantB, UserID: member}); err != nil || got != (scopedom.InventoryCoverage{}) {
		t.Fatalf("foreign scope = %+v %v", got, err)
	}

	// Tenant B: its own two assets only.
	if got, err := repo.CountCoverage(ctx, tenantB, nil); err != nil || got != (scopedom.InventoryCoverage{InternetFacing: 2, InScope: 2}) {
		t.Fatalf("tenant B = %+v %v", got, err)
	}
}

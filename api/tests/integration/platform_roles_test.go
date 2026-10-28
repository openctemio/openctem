package integration

// Platform roles (RFC-134) in the database: the built-in roles mirror the code
// catalog, the base role follows admin_users.role, the platform and tenant
// authorization tables never reference each other, and neither namespace
// accepts the other's permission keys.

import (
	"context"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/admin"
	"github.com/openctemio/openctem/api/pkg/domain/permission"
	"github.com/openctemio/openctem/api/pkg/domain/platformauthz"
)

func TestPlatformRolesMirrorCode(t *testing.T) {
	db := openConsoleDB(t)
	rows, err := db.QueryContext(t.Context(), `
		SELECT r.key, r.base, r.tier, r.builtin, COALESCE(string_agg(p.permission, ',' ORDER BY p.permission), '')
		FROM platform_roles r LEFT JOIN platform_role_permissions p ON p.role_id = r.id
		WHERE r.builtin GROUP BY r.key, r.base, r.tier, r.builtin`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	inDB := map[string]string{}
	for rows.Next() {
		var key, tier, perms string
		var base, builtin bool
		if err := rows.Scan(&key, &base, &tier, &builtin, &perms); err != nil {
			t.Fatal(err)
		}
		inDB[key] = strings.Join([]string{tier, map[bool]string{true: "base", false: "extra"}[base], perms}, "|")
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	inCode := map[string]string{}
	for _, r := range platformauthz.BuiltinRoles() {
		ps := make([]string, 0, len(r.Permissions))
		for _, p := range r.Permissions {
			ps = append(ps, string(p))
		}
		sort.Strings(ps)
		inCode[string(r.Key)] = strings.Join([]string{string(r.Tier), map[bool]string{true: "base", false: "extra"}[r.Base], strings.Join(ps, ",")}, "|")
	}
	for k, want := range inCode {
		if inDB[k] != want {
			t.Errorf("built-in role %s: database %q, code %q (add a migration that updates the rows)", k, inDB[k], want)
		}
	}
	for k := range inDB {
		if _, ok := inCode[k]; !ok {
			t.Errorf("built-in role %s is in the database but not in code", k)
		}
	}
}

func TestPlatformBaseRoleFollowsTier(t *testing.T) {
	db := openConsoleDB(t)
	admins := postgres.NewAdminRepository(db)
	roles := postgres.NewPlatformRoleRepository(db)
	a, err := admin.NewAdminUser("roles-it-"+time.Now().Format("150405.000000")+"@example.test", "IT", admin.AdminRoleOpsAdmin, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := admins.Create(t.Context(), a); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = admins.Delete(context.Background(), a.ID()) })
	held := func() []platformauthz.RoleKey {
		t.Helper()
		got, err := roles.HeldRoles(t.Context(), a.ID().String())
		if err != nil {
			t.Fatal(err)
		}
		return got
	}
	if got := held(); len(got) != 1 || got[0] != platformauthz.RoleAdmin {
		t.Fatalf("a new ops_admin holds %v, want [platform_admin]", got)
	}
	// An additional role stays when the tier changes; the base role moves.
	if _, err := db.ExecContext(t.Context(), `INSERT INTO platform_role_assignments (admin_id, role_id)
		SELECT $1, id FROM platform_roles WHERE key = 'support'`, a.ID().String()); err != nil {
		t.Fatal(err)
	}
	if err := a.UpdateRole(admin.AdminRoleSuperAdmin); err != nil {
		t.Fatal(err)
	}
	if err := admins.GuardedUpdate(t.Context(), a); err != nil {
		t.Fatal(err)
	}
	got := held()
	if len(got) != 2 || got[0] != platformauthz.RoleOwner || got[1] != platformauthz.RoleSupport {
		t.Fatalf("after promotion: %v, want [platform_owner support]", got)
	}
	// Deleting the administrator removes its assignments, nothing else.
	if err := admins.Delete(t.Context(), a.ID()); err != nil {
		t.Fatal(err)
	}
	if got := held(); len(got) != 0 {
		t.Fatalf("assignments left after delete: %v", got)
	}
}

func TestPlatformAndTenantAuthorizationNeverMeet(t *testing.T) {
	db := openConsoleDB(t)
	// No foreign key in either direction between the two sets of tables.
	var n int
	if err := db.QueryRowContext(t.Context(), `
		SELECT count(*) FROM pg_constraint c
		WHERE c.contype = 'f' AND (
		  (c.conrelid::regclass::text LIKE 'platform_role%' AND c.confrelid::regclass::text IN ('roles', 'role_permissions', 'permissions', 'user_roles', 'tenant_members', 'tenants'))
		  OR (c.confrelid::regclass::text LIKE 'platform_role%' AND c.conrelid::regclass::text NOT LIKE 'platform_role%'))`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("%d foreign keys link platform roles and tenant authorization (or point at platform roles)", n)
	}
	// Neither table set takes the other's keys.
	if _, err := db.ExecContext(t.Context(), `INSERT INTO permissions (id, name) VALUES ('platform.admins.manage', 'x')`); err == nil {
		_, _ = db.ExecContext(context.Background(), `DELETE FROM permissions WHERE id = 'platform.admins.manage'`)
		t.Fatal("the tenant permission catalog accepted a platform key")
	}
	if _, err := db.ExecContext(t.Context(), `INSERT INTO platform_role_permissions (role_id, permission)
		SELECT id, 'findings:read' FROM platform_roles WHERE key = 'billing'`); err == nil {
		t.Fatal("a platform role accepted a tenant permission")
	}
	// And the tenant catalog in code never uses the platform namespace.
	for _, p := range permission.AllPermissions() {
		if platformauthz.IsPlatformKey(string(p)) {
			t.Errorf("tenant permission %s uses the platform namespace", p)
		}
	}
}

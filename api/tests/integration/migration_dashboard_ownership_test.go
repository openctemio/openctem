package integration

// Migration dashboard_ownership: dashboard:aggregate becomes
// dashboards:org:view for every holder (system roles, template roles, custom
// roles, API key scopes); owners and admins get dashboards:org:manage; each
// migrated custom role is audited with its members and the organization's
// owners and admins get one notice naming them; existing dashboards become
// personal. The down migration restores the old grant.
//
// Runs on a private database: everything up to the migration before, seed,
// up, down, up.

import (
	"strings"
	"testing"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/api/internal/testdb"
)

func TestMigrationDashboardOwnership(t *testing.T) {
	const dir = "../../migrations"
	v := testdb.MigrationVersion(t, dir, "dashboard_ownership")
	db := testdb.PrivateDatabase(t, "migdash", dir)
	testdb.Migrate(t, db, dir, v, v, true)

	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := db.Exec(q, args...); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	count := func(q string, args ...any) int {
		t.Helper()
		var n int
		if err := db.QueryRow(q, args...).Scan(&n); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
		return n
	}
	const (
		owner    = "00000000-0000-0000-0000-000000000001"
		admin    = "00000000-0000-0000-0000-000000000002"
		tenantA  = "a1111111-1111-4111-8111-111111111111" // a custom role holds it
		tenantB  = "b2222222-2222-4222-8222-222222222222" // nobody beyond owners
		userLead = "d1111111-1111-4111-8111-111111111111"
		userOwn  = "d2222222-2222-4222-8222-222222222222"
		userOwnB = "d3333333-3333-4333-8333-333333333333"
		roleExec = "e1111111-1111-4111-8111-111111111111" // custom role with the grant
		roleTpl  = "e2222222-2222-4222-8222-222222222222" // program-lead template v1
		keyID    = "f1111111-1111-4111-8111-111111111111"
		dashID   = "c1111111-1111-4111-8111-111111111111"
	)
	exec(`INSERT INTO tenants (id, name, slug) VALUES ($1, 'a', 'mig-dash-a'), ($2, 'b', 'mig-dash-b')`, tenantA, tenantB)
	exec(`INSERT INTO users (id, email, name) VALUES ($1, 'lead@migdash.test', 'Lead Person'), ($2, 'own@migdash.test', 'Owner A'), ($3, 'ownb@migdash.test', 'Owner B')`,
		userLead, userOwn, userOwnB)
	exec(`INSERT INTO tenant_members (user_id, tenant_id, role) VALUES ($1, $3, 'member'), ($2, $3, 'owner'), ($4, $5, 'owner')`,
		userLead, userOwn, tenantA, userOwnB, tenantB)
	exec(`INSERT INTO roles (id, tenant_id, slug, name, hierarchy_level) VALUES ($1, $2, 'exec', 'Executive view', 20)`, roleExec, tenantA)
	exec(`INSERT INTO roles (id, tenant_id, slug, name, hierarchy_level, has_full_data_access, template_id, template_version, template_permissions)
		VALUES ($1, $2, 'lead', 'Program lead', 40, true, 'program-lead', 1, ARRAY['dashboard:read', 'dashboard:aggregate'])`, roleTpl, tenantA)
	exec(`INSERT INTO role_permissions (role_id, permission_id) VALUES ($1, 'dashboard:aggregate'), ($2, 'dashboard:aggregate')`, roleExec, roleTpl)
	exec(`INSERT INTO user_roles (user_id, tenant_id, role_id) VALUES ($1, $2, $3)`, userLead, tenantA, roleExec)
	exec(`INSERT INTO api_keys (id, tenant_id, user_id, name, key_hash, key_prefix, scopes)
		VALUES ($1, $2, $3, 'k', 'hash-migdash', 'oc_mig', ARRAY['dashboard:read', 'dashboard:aggregate'])`, keyID, tenantA, userOwn)
	exec(`INSERT INTO user_dashboards (id, tenant_id, user_id, name) VALUES ($1, $2, $3, 'Mine')`, dashID, tenantA, userLead)

	up := func() { testdb.Migrate(t, db, dir, v, v, false) }
	down := func() { testdb.Migrate(t, db, dir, v, v, true) }

	check := func(round int) {
		t.Helper()
		if n := count(`SELECT count(*) FROM permissions WHERE id = 'dashboard:aggregate'`); n != 0 {
			t.Fatalf("round %d: dashboard:aggregate still exists", round)
		}
		if n := count(`SELECT count(*) FROM role_permissions WHERE permission_id = 'dashboard:aggregate'`); n != 0 {
			t.Fatalf("round %d: grants of dashboard:aggregate left", round)
		}
		for _, r := range []string{owner, admin, roleExec, roleTpl} {
			if count(`SELECT count(*) FROM role_permissions WHERE role_id = $1 AND permission_id = 'dashboards:org:view'`, r) != 1 {
				t.Errorf("round %d: role %s lost organization view", round, r)
			}
		}
		for _, r := range []string{owner, admin} {
			if count(`SELECT count(*) FROM role_permissions WHERE role_id = $1 AND permission_id = 'dashboards:org:manage'`, r) != 1 {
				t.Errorf("round %d: role %s has no dashboards:org:manage", round, r)
			}
		}
		if count(`SELECT count(*) FROM role_permissions WHERE permission_id = 'dashboards:org:manage' AND role_id NOT IN ($1, $2)`, owner, admin) != 0 {
			t.Errorf("round %d: dashboards:org:manage granted beyond owner and admin", round)
		}
		var tpl pq.StringArray
		var tplVersion int
		if err := db.QueryRow(`SELECT template_permissions, template_version FROM roles WHERE id = $1`, roleTpl).Scan(&tpl, &tplVersion); err != nil {
			t.Fatal(err)
		}
		if strings.Join(tpl, ",") != "dashboard:read,dashboards:org:view" || tplVersion != 2 {
			t.Errorf("round %d: template role = %v v%d", round, tpl, tplVersion)
		}
		var scopes pq.StringArray
		if err := db.QueryRow(`SELECT scopes FROM api_keys WHERE id = $1`, keyID).Scan(&scopes); err != nil {
			t.Fatal(err)
		}
		if strings.Join(scopes, ",") != "dashboard:read,dashboards:org:view" {
			t.Errorf("round %d: api key scopes = %v", round, scopes)
		}
		var kind string
		if err := db.QueryRow(`SELECT kind FROM user_dashboards WHERE id = $1`, dashID).Scan(&kind); err != nil || kind != "personal" {
			t.Errorf("round %d: existing dashboard kind = %q %v", round, kind, err)
		}
	}

	up()
	check(1)
	// Audit: one row per migrated custom role, naming its members.
	var members string
	if err := db.QueryRow(`SELECT metadata->>'members' FROM audit_logs
		WHERE tenant_id = $1 AND action = 'role.permission_migrated' AND resource_id = $2`, tenantA, roleExec).Scan(&members); err != nil {
		t.Fatalf("audit row of the custom role: %v", err)
	}
	if !strings.Contains(members, userLead) {
		t.Errorf("audit members = %s, want %s", members, userLead)
	}
	if n := count(`SELECT count(*) FROM audit_logs WHERE action = 'role.permission_migrated' AND tenant_id = $1`, tenantA); n != 2 {
		t.Errorf("audit rows in tenant A = %d, want 2 (custom and template role)", n)
	}
	if n := count(`SELECT count(*) FROM audit_logs WHERE action = 'role.permission_migrated' AND tenant_id = $1`, tenantB); n != 0 {
		t.Errorf("audit rows in tenant B = %d, want 0", n)
	}
	// Notice: the owner of tenant A, naming the member; nothing in tenant B.
	var body string
	if err := db.QueryRow(`SELECT body FROM notifications WHERE tenant_id = $1 AND audience = 'user' AND audience_id = $2 AND notification_type = 'access_changed'`,
		tenantA, userOwn).Scan(&body); err != nil {
		t.Fatalf("owner notice: %v", err)
	}
	if !strings.Contains(body, "Lead Person") {
		t.Errorf("notice = %q, want the member's name", body)
	}
	if n := count(`SELECT count(*) FROM notifications WHERE notification_type = 'access_changed' AND tenant_id = $1`, tenantB); n != 0 {
		t.Errorf("tenant B notices = %d, want 0", n)
	}
	if n := count(`SELECT count(*) FROM notifications WHERE notification_type = 'access_changed' AND audience_id = $1`, userLead); n != 0 {
		t.Errorf("the member got the admin notice")
	}

	// An organization dashboard cannot have an owner, a personal one must.
	if _, err := db.Exec(`INSERT INTO user_dashboards (tenant_id, user_id, name, kind) VALUES ($1, $2, 'x', 'organization')`, tenantA, userLead); err == nil {
		t.Error("organization dashboard with an owner was accepted")
	}
	if _, err := db.Exec(`INSERT INTO user_dashboards (tenant_id, name, kind) VALUES ($1, 'x', 'personal')`, tenantA); err == nil {
		t.Error("personal dashboard without an owner was accepted")
	}
	exec(`INSERT INTO user_dashboards (tenant_id, name, kind) VALUES ($1, 'Org one', 'organization')`, tenantA)

	down()
	if count(`SELECT count(*) FROM role_permissions WHERE role_id = $1 AND permission_id = 'dashboard:aggregate'`, roleExec) != 1 {
		t.Error("down: custom role lost dashboard:aggregate")
	}
	if count(`SELECT count(*) FROM permissions WHERE id LIKE 'dashboards:org:%'`) != 0 {
		t.Error("down: new permissions left")
	}
	if count(`SELECT count(*) FROM user_dashboards WHERE tenant_id = $1`, tenantA) != 1 {
		t.Error("down: personal dashboard lost or organization dashboard left")
	}
	var scopes pq.StringArray
	_ = db.QueryRow(`SELECT scopes FROM api_keys WHERE id = $1`, keyID).Scan(&scopes)
	if strings.Join(scopes, ",") != "dashboard:read,dashboard:aggregate" {
		t.Errorf("down: api key scopes = %v", scopes)
	}

	up()
	check(2)
}

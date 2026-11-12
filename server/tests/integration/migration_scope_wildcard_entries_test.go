package integration

// Migration scope_wildcard_entries: takes scope entries that could authorize
// every host or address out of effect (active becomes inactive, pending
// becomes rejected), writes one audit event per entry in the entry's own
// tenant, leaves proper entries and other tenants' rows alone, is reversible
// from its audit events, and can run again.
//
// Runs on a private database: everything up, this migration down, seed, up.

import (
	"testing"

	"github.com/openctemio/openctem/api/internal/testdb"
)

func TestMigrationScopeWildcardEntries(t *testing.T) {
	const dir = "../../migrations"
	db := testdb.PrivateDatabase(t, "migscopewild", dir)
	v := testdb.MigrationVersion(t, dir, "scope_wildcard_entries")
	testdb.Migrate(t, db, dir, v, v, true)

	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := db.Exec(q, args...); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	const (
		tenantA = "a1111111-1111-4111-8111-111111111111"
		tenantB = "b2222222-2222-4222-8222-222222222222"
	)
	exec(`INSERT INTO tenants (id, name, slug) VALUES ($1, 'a', 'mig-wild-a'), ($2, 'b', 'mig-wild-b')`, tenantA, tenantB)
	type row struct {
		id, tenant, typ, pattern, status string
		hit                              bool
	}
	rows := []row{
		{"01000000-0000-4000-8000-000000000001", tenantA, "certificate", "*", "active", true},
		{"01000000-0000-4000-8000-000000000002", tenantA, "network", "*", "active", true},
		{"01000000-0000-4000-8000-000000000003", tenantA, "container", "reg*", "active", true},
		{"01000000-0000-4000-8000-000000000004", tenantA, "url", "*", "active", true},
		{"01000000-0000-4000-8000-000000000005", tenantA, "website", "https://*.example.com", "active", true},
		{"01000000-0000-4000-8000-000000000006", tenantA, "api", "app.example.com", "active", false},
		{"01000000-0000-4000-8000-000000000007", tenantA, "host", "*", "active", true},
		{"01000000-0000-4000-8000-000000000008", tenantA, "mobile_app", "*", "pending", true},
		{"01000000-0000-4000-8000-000000000009", tenantB, "database", "*", "active", true},
		// Kept: proper entries, an exact value of a type without a matcher
		// (it never matches anyway), an already inactive row.
		{"01000000-0000-4000-8000-00000000000a", tenantA, "domain", "*.example.com", "active", false},
		{"01000000-0000-4000-8000-00000000000b", tenantA, "cidr", "203.0.113.0/24", "active", false},
		{"01000000-0000-4000-8000-00000000000c", tenantA, "url", "https://app.example.com/api/*", "active", false},
		{"01000000-0000-4000-8000-00000000000d", tenantA, "host", "*.example.com", "active", false},
		{"01000000-0000-4000-8000-00000000000e", tenantA, "certificate", "abcdef", "active", false},
		{"01000000-0000-4000-8000-00000000000f", tenantA, "project", "github.com/org/*", "active", false},
		{"01000000-0000-4000-8000-000000000010", tenantA, "database", "*", "inactive", false},
		{"01000000-0000-4000-8000-000000000011", tenantB, "repository", "github.com/org/*", "active", false},
		{"01000000-0000-4000-8000-000000000012", tenantA, "website", "*://shop.example.com", "active", false},
		{"01000000-0000-4000-8000-000000000013", tenantA, "url", "*.example.com", "active", true},
		{"01000000-0000-4000-8000-000000000014", tenantA, "host", "0.0.0.0/0", "active", true},
		{"01000000-0000-4000-8000-000000000015", tenantA, "host", "1.0.0.0-223.255.255.255", "active", true},
		{"01000000-0000-4000-8000-000000000016", tenantA, "host", "*.com", "active", true},
		{"01000000-0000-4000-8000-000000000017", tenantA, "host", "203.0.113.5", "active", false},
		{"01000000-0000-4000-8000-000000000018", tenantA, "api", "*.api.example.com", "active", true},
		{"01000000-0000-4000-8000-000000000019", tenantA, "website", "shop.example.com", "active", false},
	}
	for _, r := range rows {
		exec(`INSERT INTO scope_targets (id, tenant_id, target_type, pattern, status) VALUES ($1, $2, $3, $4, $5)`,
			r.id, r.tenant, r.typ, r.pattern, r.status)
	}

	status := func(id string) string {
		t.Helper()
		var s string
		if err := db.QueryRow(`SELECT status FROM scope_targets WHERE id = $1`, id).Scan(&s); err != nil {
			t.Fatal(err)
		}
		return s
	}
	check := func() {
		t.Helper()
		hits := 0
		for _, r := range rows {
			want := r.status
			if r.hit {
				hits++
				want = "inactive"
				if r.status == "pending" {
					want = "rejected"
				}
			}
			if got := status(r.id); got != want {
				t.Errorf("%s %q (%s): status %s, want %s", r.typ, r.pattern, r.tenant[:2], got, want)
			}
			var n int
			var tenant string
			err := db.QueryRow(`SELECT count(*), coalesce(max(tenant_id::text), '') FROM audit_logs
				WHERE resource_type = 'scope_target' AND resource_id = $1 AND metadata ->> 'trigger' = 'scope_wildcard_entries'`, r.id).Scan(&n, &tenant)
			if err != nil {
				t.Fatal(err)
			}
			switch {
			case r.hit && (n != 1 || tenant != r.tenant):
				t.Errorf("%s %q: %d audit events in tenant %q, want 1 in %s", r.typ, r.pattern, n, tenant, r.tenant)
			case !r.hit && n != 0:
				t.Errorf("%s %q: unexpected audit event", r.typ, r.pattern)
			}
		}
		var total int
		_ = db.QueryRow(`SELECT count(*) FROM audit_logs WHERE metadata ->> 'trigger' = 'scope_wildcard_entries'`).Scan(&total)
		if total != hits {
			t.Errorf("%d audit events, want %d", total, hits)
		}
	}
	testdb.Migrate(t, db, dir, v, v, false)
	check()

	// Down puts the statuses back; the audit events stay as history.
	testdb.Migrate(t, db, dir, v, v, true)
	for _, r := range rows {
		if got := status(r.id); got != r.status {
			t.Errorf("after down: %s %q status %s, want %s", r.typ, r.pattern, got, r.status)
		}
	}
	// Up again takes the same rows out of effect (a second event each).
	testdb.Migrate(t, db, dir, v, v, false)
	for _, r := range rows {
		if r.hit && status(r.id) == r.status {
			t.Errorf("after second up: %s %q still %s", r.typ, r.pattern, r.status)
		}
	}
}

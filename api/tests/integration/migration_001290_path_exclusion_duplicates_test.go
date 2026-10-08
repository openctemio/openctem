package integration

// Migration 001290 (RFC-056 §5) rewrites legacy `path` exclusions into host +
// path prefix and keeps one row per rule. A database upgraded from v0.8.0 can
// hold two legacy rows of one rule where the row to drop already carries the
// new pattern ("/api/*" next to "*/api", "https://x/admin/*" next to
// "https://x/admin"). The duplicates must be deleted before the kept row is
// rewritten, or the unique (tenant_id, exclusion_type, pattern) check fails
// the whole migration. Runs as the schema owner in a rolled-back transaction.

import (
	"context"
	"database/sql"
	"os"
	"testing"

	"github.com/openctemio/openctem/api/internal/testdb"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

func TestMigration001290KeepsOneRowPerPathRule(t *testing.T) {
	appDB := openLifecycleDB(t)
	ctx := context.Background()
	tenantA := seedLifecycleTenant(ctx, t, appDB)
	tenantB := seedLifecycleTenant(ctx, t, appDB)

	up, err := os.ReadFile("../../migrations/001290_web_path_exclusions.up.sql")
	if err != nil {
		t.Fatal(err)
	}

	db, err := sql.Open("postgres", testdb.MigratorURL())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback() }()
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := tx.ExecContext(ctx, q, args...); err != nil {
			t.Fatalf("%v\n%s", err, q)
		}
	}

	// The database is migrated: lift the constraints 001290 adds so legacy
	// rows (no path_prefix) can be stored, as on a database before 001290.
	exec(`ALTER TABLE scope_exclusions
		DROP CONSTRAINT IF EXISTS chk_scope_exclusion_testing,
		DROP CONSTRAINT IF EXISTS chk_scope_exclusion_path_rule,
		DROP CONSTRAINT IF EXISTS chk_scope_exclusion_methods`)

	type legacy struct {
		tenant  shared.ID
		pattern string
		status  string
		age     string // created this long ago
	}
	rows := []legacy{
		// "/api/*" (active, older) is kept; "*/api" (inactive) already holds
		// the rewritten pattern and is dropped.
		{tenantA, "/api/*", "active", "3 days"},
		{tenantA, "*/api", "inactive", "1 day"},
		// The older wildcard is kept; the exact URL already holds the
		// rewritten pattern and is dropped.
		{tenantA, "https://www.example.test/admin/*", "active", "2 days"},
		{tenantA, "https://www.example.test/admin", "active", "1 day"},
		// One row of its rule: rewritten only.
		{tenantA, "/debug/*", "active", "1 day"},
		// Another tenant's rows of the same rules are its own.
		{tenantB, "*/api", "active", "1 day"},
		{tenantB, "/api/*", "inactive", "2 days"},
	}
	for _, r := range rows {
		exec(`INSERT INTO scope_exclusions (tenant_id, exclusion_type, pattern, reason, status, created_at, path_prefix)
			VALUES ($1, 'path', $2, 'legacy', $3, now() - $4::interval, NULL)`,
			r.tenant.String(), r.pattern, r.status, r.age)
	}

	runSQL(ctx, t, tx, string(up))

	type kept struct{ pattern, prefix, status string }
	read := func(tenant shared.ID) map[string]kept {
		t.Helper()
		q, err := tx.QueryContext(ctx, `SELECT pattern, path_prefix, status
			FROM scope_exclusions WHERE tenant_id = $1 AND exclusion_type = 'path' ORDER BY pattern`, tenant.String())
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = q.Close() }()
		out := map[string]kept{}
		for q.Next() {
			var k kept
			if err := q.Scan(&k.pattern, &k.prefix, &k.status); err != nil {
				t.Fatal(err)
			}
			out[k.pattern] = k
		}
		if err := q.Err(); err != nil {
			t.Fatal(err)
		}
		return out
	}

	a := read(tenantA)
	if len(a) != 3 {
		t.Fatalf("tenant A: want 3 path rules, got %d: %v", len(a), a)
	}
	for pattern, want := range map[string]kept{
		"*/api":                          {prefix: "/api", status: "active"},
		"https://www.example.test/admin": {prefix: "/admin", status: "active"},
		"*/debug":                        {prefix: "/debug", status: "active"},
	} {
		got, ok := a[pattern]
		if !ok {
			t.Errorf("tenant A: rule %s missing", pattern)
			continue
		}
		if got.prefix != want.prefix || got.status != want.status {
			t.Errorf("tenant A %s: prefix %q status %q, want %q %q", pattern, got.prefix, got.status, want.prefix, want.status)
		}
	}

	// The kept row is the one in effect first: tenant A's "*/api" rule is the
	// active "/api/*" row (status checked above), not the inactive row that
	// held "*/api" before the rewrite.

	b := read(tenantB)
	if len(b) != 1 {
		t.Fatalf("tenant B: want 1 path rule, got %d: %v", len(b), b)
	}
	if got := b["*/api"]; got.status != "active" || got.prefix != "/api" {
		t.Errorf("tenant B */api: %+v, want the active row with prefix /api", got)
	}
}

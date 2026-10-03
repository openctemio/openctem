package postgres

// Migration 000292: "*.x" exclusions no longer cover the apex "x" in the
// matcher (RFC-042 §6.13), so the migration adds an apex sibling for every
// existing wildcard exclusion. A name excluded before the change stays
// excluded after it.

import (
	"context"
	"os"
	"testing"

	scopedom "github.com/openctemio/openctem/api/pkg/domain/scope"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

func TestScopeExclusionWildcardApexMigration_DB(t *testing.T) {
	ctx := context.Background()
	db := openScanDB(t)
	up, err := os.ReadFile("../../../migrations/000292_scope_exclusion_wildcard_apex.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback() }()

	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := tx.ExecContext(ctx, q, args...); err != nil {
			t.Fatalf("%.80s: %v", q, err)
		}
	}
	tenantID := shared.NewID()
	exec(`INSERT INTO tenants (id, name, slug) VALUES ($1, 'wildcard apex', $2)`, tenantID.String(), "wcapex-"+tenantID.String())
	add := func(typ, pattern, status string) {
		t.Helper()
		approvedBy := any(nil)
		if status == "active" {
			approvedBy = "owner@example.test"
		}
		exec(`INSERT INTO scope_exclusions (tenant_id, exclusion_type, pattern, reason, status, approved_by, approved_at, expires_at, created_by)
		      VALUES ($1, $2, $3, 'r', $4, $5::varchar, CASE WHEN $5::varchar IS NULL THEN NULL ELSE NOW() END, '2099-01-01', 'u')`,
			tenantID.String(), typ, pattern, status, approvedBy)
	}
	add("domain", "*.Corp.Example.", "active")
	add("subdomain", "**.pending.example", "pending")
	add("domain", "*.rejected.example", "rejected")
	add("domain", "*.decided.example", "active")
	add("domain", "decided.example", "inactive")
	add("url", "*.url.example", "active")

	exec(string(up))
	exec(string(up)) // a second run adds nothing

	// query returns each row's columns as strings.
	query := func(q string, args ...any) [][]string {
		t.Helper()
		rows, err := tx.QueryContext(ctx, q, args...)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = rows.Close() }()
		cols, err := rows.Columns()
		if err != nil {
			t.Fatal(err)
		}
		var out [][]string
		for rows.Next() {
			vals := make([]string, len(cols))
			ptrs := make([]any, len(cols))
			for i := range vals {
				ptrs[i] = &vals[i]
			}
			if err := rows.Scan(ptrs...); err != nil {
				t.Fatal(err)
			}
			out = append(out, vals)
		}
		if err := rows.Err(); err != nil {
			t.Fatal(err)
		}
		return out
	}

	type row struct{ typ, status, approvedBy string }
	got := map[string]row{}
	for _, r := range query(`
		SELECT pattern, exclusion_type, status, COALESCE(approved_by, '')
		FROM scope_exclusions WHERE tenant_id = $1 AND created_by = 'system:migration-000292'`, tenantID.String()) {
		got[r[0]] = row{r[1], r[2], r[3]}
	}
	want := map[string]row{
		"corp.example":    {"domain", "active", "owner@example.test"},
		"pending.example": {"subdomain", "pending", ""},
	}
	if len(got) != len(want) {
		t.Fatalf("siblings = %v, want %v", got, want)
	}
	for p, w := range want {
		if got[p] != w {
			t.Errorf("sibling %s = %+v, want %+v", p, got[p], w)
		}
	}

	// With the new matcher, the tenant's active exclusions still exclude the
	// apex that "*.corp.example" used to cover, and its subdomains.
	active := query(`
		SELECT exclusion_type, pattern FROM scope_exclusions
		WHERE tenant_id = $1 AND status = 'active'`, tenantID.String())
	excluded := func(v string) bool {
		for _, e := range active {
			if scopedom.MatchesExclusionPattern(scopedom.ExclusionType(e[0]), e[1], v) {
				return true
			}
		}
		return false
	}
	for _, v := range []string{"corp.example", "CORP.example.", "www.corp.example"} {
		if !excluded(v) {
			t.Errorf("%s is no longer excluded after the migration", v)
		}
	}
	if excluded("decided.example") {
		t.Error("an apex the tenant already decided on (inactive row) was overridden")
	}
}

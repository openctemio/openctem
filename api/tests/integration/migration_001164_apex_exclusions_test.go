package integration

// Migration 001164 (research/53 §6.1, SC6): the apex exclusions 000292 split
// from wildcard exclusions are deleted while their wildcard parent is in
// effect at least as long; the rest keep a rewritten reason; the down
// migration restores both. Run inside a transaction that is rolled back.

import (
	"context"
	"database/sql"
	"os"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

const splitBy = "system:migration-000292"

func TestMigration001164DropsRedundantApexExclusions(t *testing.T) {
	db := openLifecycleDB(t)
	ctx := context.Background()
	tenantA := seedLifecycleTenant(ctx, t, db)
	tenantB := seedLifecycleTenant(ctx, t, db)

	up, err := os.ReadFile("../../migrations/001164_drop_redundant_apex_exclusions.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	down, err := os.ReadFile("../../migrations/001164_drop_redundant_apex_exclusions.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	for name, b := range map[string][]byte{"up": up, "down": down} {
		var code []string
		for _, l := range strings.Split(string(b), "\n") {
			if !strings.HasPrefix(strings.TrimSpace(l), "--") {
				code = append(code, l)
			}
		}
		if strings.Contains(strings.ToLower(strings.Join(code, "\n")), "audit_log") {
			t.Fatalf("%s writes audit rows from SQL", name)
		}
	}

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
	// parent inserts a wildcard exclusion; expires is an interval or "".
	parent := func(tenant shared.ID, pattern, status string, approved bool, expires string) string {
		t.Helper()
		id := shared.NewID().String()
		approvedAt := "NULL"
		if approved {
			approvedAt = "now()"
		}
		exp := "NULL"
		if expires != "" {
			exp = "now() + interval '" + expires + "'"
		}
		exec(`INSERT INTO scope_exclusions (id, tenant_id, exclusion_type, pattern, reason, status, approved_at, expires_at, created_by)
			VALUES ($1, $2, 'domain', $3, 'vendor host', $4, `+approvedAt+`, `+exp+`, 'admin')`,
			id, tenant.String(), pattern, status)
		return id
	}
	// sibling inserts a 000292 apex row split from parentPattern/parentID.
	sibling := func(tenant shared.ID, apex, parentPattern, parentID, expires string, edited bool) {
		t.Helper()
		exp := "NULL"
		if expires != "" {
			exp = "now() + interval '" + expires + "'"
		}
		// 000292 rows are a day old; an edited one changed an hour ago.
		updated := "now() - interval '1 day'"
		if edited {
			updated = "now() - interval '1 hour'"
		}
		reason := "Split from wildcard exclusion " + parentPattern + " (" + parentID +
			`): "*.x" no longer covers "x" itself, so the apex keeps its exclusion. Original reason: vendor host`
		exec(`INSERT INTO scope_exclusions (tenant_id, exclusion_type, pattern, reason, status, approved_at, expires_at,
				created_by, created_at, updated_at)
			VALUES ($1, 'domain', $2, $3, 'active', now(), `+exp+`, $4, now() - interval '1 day', `+updated+`)`,
			tenant.String(), apex, reason, splitBy)
	}

	pa := parent(tenantA, "*.a-apex.example", "active", true, "")
	sibling(tenantA, "a-apex.example", "*.a-apex.example", pa, "", false) // deleted
	pb := parent(tenantA, "*.b-apex.example", "inactive", true, "")
	sibling(tenantA, "b-apex.example", "*.b-apex.example", pb, "", false) // kept: parent inactive
	pc := parent(tenantA, "**.c-apex.example", "active", true, "5 days")
	sibling(tenantA, "c-apex.example", "**.c-apex.example", pc, "10 days", false) // kept: parent shorter
	pd := parent(tenantA, "*.d-apex.example", "active", true, "10 days")
	sibling(tenantA, "d-apex.example", "*.d-apex.example", pd, "5 days", false) // deleted
	pe := parent(tenantA, "*.e-apex.example", "pending", false, "")
	sibling(tenantA, "e-apex.example", "*.e-apex.example", pe, "", false) // kept: parent pending
	pf := parent(tenantA, "*.f-apex.example", "active", true, "")
	sibling(tenantA, "f-apex.example", "*.f-apex.example", pf, "", true) // kept: a person changed it
	pp := parent(tenantA, "*.p-apex.example", "active", true, "")
	sibling(tenantA, "p-apex.example", "*.p-apex.example", pp, "10 days", false) // deleted: permanent parent
	parent(tenantA, "*.g-apex.example", "active", true, "")
	exec(`INSERT INTO scope_exclusions (tenant_id, exclusion_type, pattern, reason, status, approved_at, created_by)
		VALUES ($1, 'domain', 'g-apex.example', 'a person excluded it', 'active', now(), 'admin')`, tenantA.String()) // untouched
	ph := parent(tenantB, "*.h-apex.example", "active", true, "")
	sibling(tenantA, "h-apex.example", "*.h-apex.example", ph, "", false) // kept: the parent is another tenant's

	state := func() map[string]string {
		t.Helper()
		rows, err := tx.QueryContext(ctx, `SELECT pattern, reason FROM scope_exclusions
			WHERE tenant_id = $1 AND pattern NOT LIKE '*%' ORDER BY pattern`, tenantA.String())
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = rows.Close() }()
		out := map[string]string{}
		for rows.Next() {
			var p, r string
			if err := rows.Scan(&p, &r); err != nil {
				t.Fatal(err)
			}
			out[p] = r
		}
		return out
	}
	before := state()

	runSQL(ctx, t, tx, string(up))
	after := state()
	for _, gone := range []string{"a-apex.example", "d-apex.example", "p-apex.example"} {
		if _, ok := after[gone]; ok {
			t.Errorf("%s kept; its wildcard parent covers it at least as long", gone)
		}
	}
	for _, kept := range []string{"b-apex.example", "c-apex.example", "e-apex.example", "f-apex.example", "h-apex.example"} {
		r, ok := after[kept]
		if !ok {
			t.Errorf("%s deleted", kept)
			continue
		}
		if !strings.HasPrefix(r, "Apex of the former wildcard exclusion ") || !strings.HasSuffix(r, "Original reason: vendor host") {
			t.Errorf("%s reason = %q", kept, r)
		}
	}
	if after["g-apex.example"] != "a person excluded it" {
		t.Errorf("a person's exclusion changed: %q", after["g-apex.example"])
	}

	// Down restores the 000292 state exactly (patterns and reasons).
	runSQL(ctx, t, tx, string(down))
	restored := state()
	if len(restored) != len(before) {
		t.Fatalf("down: %d rows, want %d: %v", len(restored), len(before), restored)
	}
	for p, r := range before {
		if restored[p] != r {
			t.Errorf("down: %s reason %q, want %q", p, restored[p], r)
		}
	}
	// Up again converges.
	runSQL(ctx, t, tx, string(up))
	if again := state(); len(again) != len(after) {
		t.Fatalf("up after down: %v, want %v", again, after)
	}
}

func runSQL(ctx context.Context, t *testing.T, tx *sql.Tx, stmts string) {
	t.Helper()
	if _, err := tx.ExecContext(ctx, stmts); err != nil {
		t.Fatalf("migration: %v", err)
	}
}

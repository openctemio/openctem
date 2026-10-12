package integration

// Migration 001262 (research/53 A1, SC1, SC2): seeds and easm verified
// domains fold into scope entries with today's authority kept, SSO domains
// get no entry, one-off entries stop discovering, and the down migration
// brings the seeds back. Replayed in a rolled-back transaction as the
// migrator (it runs DDL).

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/internal/testdb"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

func TestMigration001262FoldsSeedsIntoEntries(t *testing.T) {
	db := openLifecycleDB(t)
	mig := testdb.OpenMigrator(t)
	ctx := context.Background()
	tenantA := seedLifecycleTenant(ctx, t, db)
	tenantB := seedLifecycleTenant(ctx, t, db)

	read := func(name string) string {
		t.Helper()
		b, err := os.ReadFile("../../migrations/" + name)
		if err != nil {
			t.Fatal(err)
		}
		var code []string
		for _, l := range strings.Split(string(b), "\n") {
			if !strings.HasPrefix(strings.TrimSpace(l), "--") {
				code = append(code, l)
			}
		}
		if strings.Contains(strings.ToLower(strings.Join(code, "\n")), "audit_log") {
			t.Fatalf("%s writes audit rows from SQL", name)
		}
		return string(b)
	}
	up, down := read("001262_scope_fold_seeds.up.sql"), read("001262_scope_fold_seeds.down.sql")

	tx, err := mig.BeginTx(ctx, nil)
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
	// Back to the state before 001262 (the scratch database is migrated):
	// later migrations that change what 001262 relies on (the unique key it
	// upserts on) are rolled back first, inside this transaction.
	later, err := filepath.Glob("../../migrations/*_scope_entry_constraints.down.sql")
	if err != nil || len(later) != 1 {
		t.Fatalf("scope_entry_constraints down migration: %v %v", later, err)
	}
	exec(read(filepath.Base(later[0])))
	exec(down)

	seed := func(tenant shared.ID, v string, discovery bool) {
		exec(`INSERT INTO easm_seeds (id, tenant_id, kind, value, discovery_enabled) VALUES ($1, $2, 'root_domain', $3, $4)`,
			shared.NewID().String(), tenant.String(), v, discovery)
	}
	entry := func(tenant shared.ID, pattern, status string, tier int, expiring bool) {
		exp := "NULL"
		if expiring {
			exp = "now() + interval '3 days'"
		}
		exec(`INSERT INTO scope_targets (tenant_id, target_type, pattern, status, max_tier, reason, expires_at)
			VALUES ($1, 'domain', $2, $3, $4, 'r', `+exp+`)`, tenant.String(), pattern, status, tier)
	}
	vd := func(tenant shared.ID, d, status, purpose string) {
		exec(`INSERT INTO verified_domains (id, tenant_id, domain, verification_token, status, purpose) VALUES ($1, $2, $3, 'tok', $4, $5)`,
			shared.NewID().String(), tenant.String(), d, status, purpose)
	}
	seed(tenantA, "s1.example", true)  // becomes *.s1.example
	seed(tenantA, "s2.example", false) // merges into an active t0 entry
	entry(tenantA, "*.s2.example", "active", 0, false)
	seed(tenantA, "s3.example", true) // puts an inactive entry back into effect
	entry(tenantA, "*.s3.example", "inactive", 1, false)
	seed(tenantA, "x.s4.example", true) // already covered by *.s4.example
	entry(tenantA, "*.s4.example", "active", 1, false)
	entry(tenantA, "promo.example", "active", 1, true) // one-off: no discovery
	vd(tenantA, "v1.example", "verified", "easm")      // becomes *.v1.example
	vd(tenantA, "sso.example", "verified", "sso")      // never an entry
	vd(tenantA, "p.example", "pending", "easm")        // not verified: nothing
	seed(tenantB, "s1.example", true)                  // tenant B's own

	exec(up)

	type row struct {
		status, origin string
		tier           int
		discovery      bool
		expires        sql.NullTime
	}
	get := func(tenant shared.ID, pattern string) (row, bool) {
		t.Helper()
		var r row
		err := tx.QueryRowContext(ctx, `SELECT status, origin, max_tier, discovery, expires_at FROM scope_targets WHERE tenant_id = $1 AND pattern = $2`,
			tenant.String(), pattern).Scan(&r.status, &r.origin, &r.tier, &r.discovery, &r.expires)
		if err == sql.ErrNoRows {
			return r, false
		}
		if err != nil {
			t.Fatal(err)
		}
		return r, true
	}
	if r, ok := get(tenantA, "*.s1.example"); !ok || r.status != "active" || r.origin != "seed_migration" || r.tier != 1 || !r.discovery || r.expires.Valid {
		t.Fatalf("*.s1.example = %+v %v", r, ok)
	}
	if r, ok := get(tenantA, "*.s2.example"); !ok || r.status != "active" || r.tier != 1 || r.origin != "manual" {
		t.Fatalf("*.s2.example = %+v %v (merged: at least t1, still manual)", r, ok)
	}
	if r, ok := get(tenantA, "*.s3.example"); !ok || r.status != "active" || r.expires.Valid {
		t.Fatalf("*.s3.example = %+v %v (the seed authorized it: back in effect)", r, ok)
	}
	if _, ok := get(tenantA, "*.x.s4.example"); ok {
		t.Fatal("a seed already covered by an entry got an entry of its own")
	}
	if r, ok := get(tenantA, "promo.example"); !ok || r.discovery {
		t.Fatalf("a one-off entry discovers: %+v", r)
	}
	if r, ok := get(tenantA, "*.v1.example"); !ok || r.status != "active" || r.origin != "seed_migration" || r.tier != 1 {
		t.Fatalf("*.v1.example = %+v %v", r, ok)
	}
	for _, p := range []string{"*.sso.example", "*.p.example"} {
		if _, ok := get(tenantA, p); ok {
			t.Fatalf("%s got an entry (SSO or unverified domains never authorize)", p)
		}
	}
	if r, ok := get(tenantB, "*.s1.example"); !ok || r.status != "active" {
		t.Fatalf("tenant B's seed: %+v %v", r, ok)
	}
	var tables int
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM information_schema.tables WHERE table_name = 'easm_seeds'`).Scan(&tables); err != nil || tables != 0 {
		t.Fatalf("easm_seeds still exists: %d %v", tables, err)
	}

	// Down brings the folded seeds back and removes their entries.
	exec(down)
	var n int
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM easm_seeds WHERE tenant_id = $1 AND value = 's1.example'`, tenantA.String()).Scan(&n); err != nil || n != 1 {
		t.Fatalf("down: seed s1 = %d %v", n, err)
	}
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM scope_targets WHERE tenant_id = $1 AND origin = 'seed_migration'`, tenantA.String()).Scan(&n); err != nil || n != 0 {
		t.Fatalf("down: folded entries left = %d %v", n, err)
	}
	// Up again converges.
	exec(up)
	if _, ok := get(tenantA, "*.s1.example"); !ok {
		t.Fatal("up after down lost the folded seed")
	}
}

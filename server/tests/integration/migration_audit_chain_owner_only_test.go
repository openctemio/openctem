package integration

// Migration audit_chain_owner_only: a role that appends audit rows (the API
// role) loses every write that could remove or rewrite audit history and gets
// EXECUTE on the two owner functions; the setting openctem.audit_rebaseline no
// longer opens the chain to UPDATE. Down gives the role back exactly what it
// held and re-opens the setting; up again closes both.
//
// Runs on a private database (owned by the admin connection) with a scratch
// role standing in for the API role.

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"testing"

	"github.com/openctemio/openctem/server/internal/testdb"
)

func TestMigrationAuditChainOwnerOnly(t *testing.T) {
	const dir = "../../migrations"
	v := testdb.MigrationVersion(t, dir, "audit_chain_owner_only")
	db := testdb.PrivateDatabase(t, "migauditowner", dir)
	ctx := context.Background()

	sfx := make([]byte, 4)
	if _, err := rand.Read(sfx); err != nil {
		t.Fatal(err)
	}
	role := "aco_app_" + hex.EncodeToString(sfx)
	if _, err := db.ExecContext(ctx, `CREATE ROLE `+role+` NOLOGIN`); err != nil {
		testdb.Skipf(t, "cannot create a scratch role (needs DATABASE_ADMIN_URL as a superuser): %v", err)
	}
	t.Cleanup(func() {
		_, _ = db.ExecContext(context.Background(), `DROP OWNED BY `+role)
		_, _ = db.ExecContext(context.Background(), `DROP ROLE IF EXISTS `+role)
	})

	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := db.ExecContext(ctx, q, args...); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	tables := []string{"audit_logs", "audit_log_chain", "audit_chain_anchors", "audit_chain_rebaselines", "audit_chain_rebaseline_entries"}
	has := func(table, priv string) bool {
		t.Helper()
		var ok bool
		if err := db.QueryRowContext(ctx, `SELECT has_table_privilege($1, $2, $3)`, role, "public."+table, priv).Scan(&ok); err != nil {
			t.Fatal(err)
		}
		return ok
	}
	canRun := func(fn string) bool {
		t.Helper()
		var ok bool
		if err := db.QueryRowContext(ctx, `SELECT has_function_privilege($1, $2, 'EXECUTE')`, role, fn).Scan(&ok); err != nil {
			t.Fatal(err)
		}
		return ok
	}
	const pruneFn = "audit_chain_prune_prefix(uuid, bigint, text, uuid[], text, text)"
	const rebaselineFn = "audit_chain_rebaseline_apply(uuid, uuid, uuid, integer, bigint, uuid[], bigint[], text[], text[], text[], text[])"

	// The old setting re-hashes a chain row (as the owner) iff it is open.
	const tenant = "a1111111-1111-4111-8111-111111111112"
	exec(`INSERT INTO tenants (id, name, slug) VALUES ($1, 'a', 'mig-audit-owner-a')`, tenant)
	exec(`INSERT INTO audit_logs (tenant_id, action, resource_type, resource_id) VALUES ($1, 'settings.updated', 'settings', 's-1')`, tenant)
	oldSettingRewrites := func() bool {
		t.Helper()
		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback() }()
		if _, err := tx.ExecContext(ctx, `SET LOCAL openctem.audit_rebaseline = 'on'`); err != nil {
			t.Fatal(err)
		}
		_, err = tx.ExecContext(ctx, `UPDATE audit_log_chain SET hash = repeat('ab', 32) WHERE tenant_id = $1`, tenant)
		return err == nil
	}

	// Before: what the least-privilege bootstrap granted the API role.
	testdb.Migrate(t, db, dir, v, v, true)
	for _, tb := range tables {
		exec(`GRANT SELECT, INSERT, UPDATE, DELETE ON public.` + tb + ` TO ` + role)
	}
	exec(`REVOKE UPDATE ON audit_logs, audit_chain_anchors, audit_chain_rebaselines, audit_chain_rebaseline_entries FROM ` + role)
	if !oldSettingRewrites() {
		t.Fatal("before: the old rebaseline setting did not open the chain")
	}

	up := func(round int) {
		t.Helper()
		testdb.Migrate(t, db, dir, v, v, false)
		for _, tb := range tables {
			if !has(tb, "SELECT") {
				t.Fatalf("round %d: %s lost SELECT", round, tb)
			}
			for _, p := range []string{"UPDATE", "DELETE", "TRUNCATE"} {
				if has(tb, p) {
					t.Fatalf("round %d: role keeps %s on %s", round, p, tb)
				}
			}
		}
		if !has("audit_logs", "INSERT") || !has("audit_log_chain", "INSERT") {
			t.Fatalf("round %d: role lost INSERT on audit_logs/audit_log_chain (appends)", round)
		}
		for _, tb := range []string{"audit_chain_anchors", "audit_chain_rebaselines", "audit_chain_rebaseline_entries"} {
			if has(tb, "INSERT") {
				t.Fatalf("round %d: role keeps INSERT on %s", round, tb)
			}
		}
		if !canRun(pruneFn) || !canRun(rebaselineFn) {
			t.Fatalf("round %d: role cannot run the owner functions", round)
		}
		var public bool
		if err := db.QueryRowContext(ctx, `SELECT has_function_privilege('public', $1, 'EXECUTE')`, pruneFn).Scan(&public); err != nil {
			t.Fatal(err)
		}
		if public {
			t.Fatalf("round %d: PUBLIC may run %s", round, pruneFn)
		}
		if oldSettingRewrites() {
			t.Fatalf("round %d: the old rebaseline setting still opens the chain", round)
		}
	}
	down := func() {
		t.Helper()
		testdb.Migrate(t, db, dir, v, v, true)
		if !has("audit_logs", "DELETE") || !has("audit_log_chain", "UPDATE") || !has("audit_chain_anchors", "INSERT") {
			t.Fatal("down: the role's previous grants are not back")
		}
		if !oldSettingRewrites() {
			t.Fatal("down: the old rebaseline setting is not back")
		}
	}

	up(1)
	down()
	up(2)
}

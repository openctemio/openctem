package integration

// Migration audit_log_db_chain on a database that already holds audit rows of
// a deleted organization (tenant_id nulled by the old foreign key, the chain
// row still naming the organization): up gives the rows their organization
// back although it no longer exists, down and up again keep them.
//
// Runs on a private database: everything up to the migration before, seed,
// up, down, up.

import (
	"context"
	"testing"

	"github.com/openctemio/openctem/server/internal/testdb"
)

func TestMigrationAuditLogDBChain_DeletedOrganizationRows(t *testing.T) {
	const dir = "../../migrations"
	v := testdb.MigrationVersion(t, dir, "audit_log_db_chain")
	db := testdb.PrivateDatabase(t, "migauditchain", dir)
	ctx := context.Background()
	testdb.Migrate(t, db, dir, v, v, true)

	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := db.ExecContext(ctx, q, args...); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	const (
		tenant = "a1111111-1111-4111-8111-111111111111"
		row    = "c1111111-1111-4111-8111-111111111111"
	)
	exec(`INSERT INTO tenants (id, name, slug) VALUES ($1, 'gone', 'mig-audit-chain-gone')`, tenant)
	exec(`INSERT INTO audit_logs (id, tenant_id, action, resource_type, resource_id) VALUES ($1, $2, 'settings.updated', 'settings', 's-1')`, row, tenant)
	exec(`INSERT INTO audit_log_chain (audit_log_id, tenant_id, prev_hash, hash) VALUES ($1, $2, '', repeat('ab', 32))`, row, tenant)
	// The old foreign key nulls tenant_id when the organization is deleted.
	exec(`DELETE FROM tenants WHERE id = $1`, tenant)

	check := func(round int) {
		t.Helper()
		var got string
		if err := db.QueryRowContext(ctx, `SELECT COALESCE(tenant_id::text, '') FROM audit_logs WHERE id = $1`, row).Scan(&got); err != nil {
			t.Fatal(err)
		}
		if got != tenant {
			t.Fatalf("round %d: audit row tenant_id = %q, want %s", round, got, tenant)
		}
	}
	testdb.Migrate(t, db, dir, v, v, false)
	check(1)
	testdb.Migrate(t, db, dir, v, v, true)
	testdb.Migrate(t, db, dir, v, v, false)
	check(2)
}

package integration

// Migration 001362: pending and rejected scope entries lose the approval
// time they were wrongly stored with; active and inactive entries keep
// theirs. Runs as the schema owner in a rolled-back transaction.

import (
	"context"
	"database/sql"
	"os"
	"testing"

	"github.com/openctemio/openctem/api/internal/testdb"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

func TestMigration001362ClearsApprovedAtOnPendingEntries(t *testing.T) {
	appDB := openLifecycleDB(t)
	ctx := context.Background()
	tenant := seedLifecycleTenant(ctx, t, appDB)

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

	entry := func(status string) string {
		t.Helper()
		id := shared.NewID().String()
		if _, err := tx.ExecContext(ctx, `INSERT INTO scope_targets (id, tenant_id, target_type, pattern, status, approved_at)
			VALUES ($1, $2, 'domain', $3, $4, now())`, id, tenant.String(), status+"-"+id+".example.com", status); err != nil {
			t.Fatalf("seed %s entry: %v", status, err)
		}
		return id
	}
	want := map[string]bool{ // id -> keeps approved_at
		entry("pending"):  false,
		entry("rejected"): false,
		entry("active"):   true,
		entry("inactive"): true,
	}

	for _, f := range []string{"001362_scope_pending_not_approved.up.sql", "001362_scope_pending_not_approved.down.sql", "001362_scope_pending_not_approved.up.sql"} {
		sqlText, err := os.ReadFile("../../migrations/" + f)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := tx.ExecContext(ctx, string(sqlText)); err != nil {
			t.Fatalf("%s: %v", f, err)
		}
	}

	for id, keeps := range want {
		var has bool
		if err := tx.QueryRowContext(ctx, `SELECT approved_at IS NOT NULL FROM scope_targets WHERE id = $1`, id).Scan(&has); err != nil {
			t.Fatal(err)
		}
		if has != keeps {
			t.Errorf("entry %s: has approved_at = %v, want %v", id, has, keeps)
		}
	}
}

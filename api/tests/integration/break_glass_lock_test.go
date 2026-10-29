package integration

import (
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"

	"github.com/openctemio/openctem/api/internal/testdb"
)

// Migration 20261029050639: the two break-glass triggers share one lock per account,
// so a membership insert and a break-glass flag change on the same account
// cannot both commit. Runs up, down, up on a private database, then holds an
// uncommitted membership insert open and shows the flag change waits for it
// and then fails (without the lock it would commit at once).
func TestBreakGlassTriggers_SerialiseOnOneAccount(t *testing.T) {
	const migrations = "../../migrations"
	db := testdb.PrivateDatabase(t, "bgl", migrations)
	v := testdb.MigrationVersion(t, migrations, "platform_admin_membership_allowed")
	testdb.Migrate(t, db, migrations, v, v, true)
	testdb.Migrate(t, db, migrations, v, v, false)

	userID, tenantID, adminID := uuid.NewString(), uuid.NewString(), uuid.NewString()
	for _, q := range []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO users (id, email, name) VALUES ($1, 'bg@example.test', 'IT')`, []any{userID}},
		{`INSERT INTO tenants (id, name, slug) VALUES ($1, 'org', 'bg-lock-org')`, []any{tenantID}},
		{`INSERT INTO admin_users (id, email, name, role, user_id) VALUES ($1, 'bg@example.test', 'bg', 'super_admin', $2)`, []any{adminID, userID}},
	} {
		if _, err := db.Exec(q.sql, q.args...); err != nil {
			t.Fatal(err)
		}
	}

	tx1, err := db.BeginTx(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx1.Rollback() }()
	if _, err := tx1.Exec(`INSERT INTO tenant_members (user_id, tenant_id) VALUES ($1, $2)`, userID, tenantID); err != nil {
		t.Fatal(err)
	}

	done := make(chan error, 1)
	go func() {
		_, err := db.Exec(`UPDATE admin_users SET is_break_glass = TRUE WHERE id = $1`, adminID)
		done <- err
	}()
	select {
	case err := <-done:
		t.Fatalf("the flag change must wait for the open membership insert, finished with %v", err)
	case <-time.After(500 * time.Millisecond):
	}
	if err := tx1.Commit(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		var pqErr *pq.Error
		if !errors.As(err, &pqErr) || pqErr.Constraint != "break_glass_console_only" {
			t.Fatalf("after the membership committed the flag change must fail, got %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the flag change never finished")
	}
}

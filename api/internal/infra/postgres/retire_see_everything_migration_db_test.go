package postgres

import (
	"context"
	"os"
	"testing"

	"github.com/openctemio/openctem/api/internal/testdb"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Migration 000910 retires "members without an access group see everything"
// (research doc 15 L-04, owner decision D2): every organization is stored as
// "nothing", "everything" can no longer be stored, and the down migration
// relaxes the CHECK without flipping any organization back. Replayed on
// populated rows in a rolled-back transaction, up -> down -> up.
func TestRetireSeeEverythingMigration_UpDownUp(t *testing.T) {
	ctx := context.Background()
	up, err := os.ReadFile("../../../migrations/000910_retire_see_everything_data_scope.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	down, err := os.ReadFile("../../../migrations/000910_retire_see_everything_data_scope.down.sql")
	if err != nil {
		t.Fatal(err)
	}

	tx, err := testdb.OpenMigrator(t).BeginTx(ctx, nil) // DDL: schema owner
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback() }()
	testdb.LockForDDL(t, ctx, tx, "tenants")
	exec := func(q string, args ...any) error {
		t.Helper()
		_, err := tx.ExecContext(ctx, q, args...)
		return err
	}
	must := func(q string, args ...any) {
		t.Helper()
		if err := exec(q, args...); err != nil {
			t.Fatalf("%.80s: %v", q, err)
		}
	}
	policy := func(id shared.ID) string {
		t.Helper()
		var v string
		if err := tx.QueryRowContext(ctx, `SELECT members_without_group_see FROM tenants WHERE id = $1`, id.String()).Scan(&v); err != nil {
			t.Fatal(err)
		}
		return v
	}
	insert := func(value string) error {
		id := shared.NewID()
		if err := exec(`SAVEPOINT ins`); err != nil {
			return err
		}
		err := exec(`INSERT INTO tenants (id, name, slug, members_without_group_see) VALUES ($1, 'm', $2, $3)`,
			id.String(), "mig800-"+id.String(), value)
		if err != nil {
			_ = exec(`ROLLBACK TO SAVEPOINT ins`)
			return err
		}
		return exec(`RELEASE SAVEPOINT ins`)
	}

	// The state before 000910: the 000247 CHECK, organizations on both values.
	must(string(down))
	legacy, closed := shared.NewID(), shared.NewID()
	must(`INSERT INTO tenants (id, name, slug, members_without_group_see) VALUES ($1, 'legacy', $2, 'everything')`, legacy.String(), "mig800-l-"+legacy.String())
	must(`INSERT INTO tenants (id, name, slug, members_without_group_see) VALUES ($1, 'closed', $2, 'nothing')`, closed.String(), "mig800-c-"+closed.String())

	must(string(up))
	if v := policy(legacy); v != "nothing" {
		t.Errorf("legacy organization after up: %q, want nothing", v)
	}
	if v := policy(closed); v != "nothing" {
		t.Errorf("fail-closed organization after up: %q, want nothing", v)
	}
	if err := insert("everything"); err == nil {
		t.Error("after up, 'everything' must be refused by the CHECK")
	}
	fresh := shared.NewID()
	must(`INSERT INTO tenants (id, name, slug) VALUES ($1, 'fresh', $2)`, fresh.String(), "mig800-f-"+fresh.String())
	if v := policy(fresh); v != "nothing" {
		t.Errorf("new organization default: %q, want nothing", v)
	}
	// Idempotent.
	must(string(up))

	// Down relaxes the CHECK but does not flip data back.
	must(string(down))
	if v := policy(legacy); v != "nothing" {
		t.Errorf("legacy organization after down: %q, want nothing (no flip back)", v)
	}
	if err := insert("everything"); err != nil {
		t.Errorf("after down the 000247 CHECK allows 'everything' again: %v", err)
	}
	if err := insert("garbage"); err == nil {
		t.Error("after down the 000247 CHECK must still refuse unknown values")
	}

	// And up again, over a row written while down was applied.
	must(string(up))
	var everything int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM tenants WHERE members_without_group_see <> 'nothing'`).Scan(&everything); err != nil {
		t.Fatal(err)
	}
	if everything != 0 {
		t.Errorf("after up -> down -> up, %d organizations are not 'nothing'", everything)
	}
}

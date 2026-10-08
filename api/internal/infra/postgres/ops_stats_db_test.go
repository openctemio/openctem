package postgres

import (
	"context"
	"database/sql"
	"testing"
)

// The operator snapshot reads on the migrated schema and moves with the
// rows it counts. The counts are platform-wide and other tests share the
// database, so the test reads before and after its own writes inside one
// REPEATABLE READ transaction (rolled back): what other tests commit in
// between is not seen, and the deltas are exactly this test's rows.
// Requires DATABASE_URL.
func TestReadOpsSnapshot(t *testing.T) {
	sqlDB := openSensorDB(t)
	ctx := context.Background()

	// Committed before the transaction starts: the tenant and two active,
	// online sensors the transaction then takes offline.
	tenant := seedTestTenant(ctx, t, sqlDB)
	offlineID := seedZoneSensor(ctx, t, sqlDB, &tenant, "ops-offline", zoneSensorOpts{})
	disabledID := seedZoneSensor(ctx, t, sqlDB, &tenant, "ops-disabled", zoneSensorOpts{})

	tx, err := sqlDB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
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

	before, err := ReadOpsSnapshot(ctx, tx)
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	if !before.SchemaKnown || before.SchemaVersion == 0 {
		t.Fatalf("schema version not read: %+v", before)
	}

	exec(`UPDATE sensors SET health = 'offline' WHERE id = $1`, offlineID.String())
	exec(`UPDATE sensors SET health = 'offline', status = 'disabled' WHERE id = $1`, disabledID.String())
	// A pending command due an hour ago, and one scheduled in the future
	// (not due: neither counted nor aged).
	exec(`INSERT INTO commands (tenant_id, type, status, created_at)
		VALUES ($1, 'scan', 'pending', now() - interval '1 hour')`, tenant.String())
	exec(`INSERT INTO commands (tenant_id, type, status, scheduled_at)
		VALUES ($1, 'scan', 'pending', now() + interval '1 day')`, tenant.String())
	exec(`INSERT INTO notification_outbox (tenant_id, event_type, title, status)
		VALUES ($1, 'test', 'ops snapshot test', 'dead')`, tenant.String())

	after, err := ReadOpsSnapshot(ctx, tx)
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	if got := after.CommandsPending - before.CommandsPending; got != 1 {
		t.Errorf("due pending commands +%d, want +1 (the future one is not due)", got)
	}
	if after.CommandOldestPendingSecs < 3500 {
		t.Errorf("oldest pending = %.0fs, want about an hour", after.CommandOldestPendingSecs)
	}
	if got := after.OutboxDead - before.OutboxDead; got != 1 {
		t.Errorf("dead outbox entries +%d, want +1", got)
	}
	offline := func(s OpsSnapshot) (n int64) {
		for _, c := range s.Sensors {
			if !c.Platform && c.Health == "offline" {
				n += c.Count
			}
		}
		return n
	}
	if got := offline(after) - offline(before); got != 1 {
		t.Errorf("offline tenant sensors +%d, want +1 (a disabled sensor is not counted)", got)
	}
}

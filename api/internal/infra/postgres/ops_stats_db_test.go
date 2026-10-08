package postgres

import (
	"context"
	"testing"
)

// The operator snapshot reads on the migrated schema and moves with the
// rows it counts. Other tests share the database, so it checks deltas.
// Requires DATABASE_URL.
func TestReadOpsSnapshot(t *testing.T) {
	sqlDB := openSensorDB(t)
	ctx := context.Background()

	before, err := ReadOpsSnapshot(ctx, sqlDB)
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	if !before.SchemaKnown || before.SchemaVersion == 0 {
		t.Fatalf("schema version not read: %+v", before)
	}

	tenant := seedTestTenant(ctx, t, sqlDB)
	seedZoneSensor(ctx, t, sqlDB, &tenant, "ops-offline", zoneSensorOpts{health: "offline"})
	seedZoneSensor(ctx, t, sqlDB, &tenant, "ops-disabled", zoneSensorOpts{health: "offline", status: "disabled"})

	// A pending command due an hour ago, and one scheduled in the future
	// (not due: neither counted nor aged).
	if _, err := sqlDB.ExecContext(ctx, `
		INSERT INTO commands (tenant_id, type, status, created_at)
		VALUES ($1, 'scan', 'pending', now() - interval '1 hour')`, tenant.String()); err != nil {
		t.Fatal(err)
	}
	if _, err := sqlDB.ExecContext(ctx, `
		INSERT INTO commands (tenant_id, type, status, scheduled_at)
		VALUES ($1, 'scan', 'pending', now() + interval '1 day')`, tenant.String()); err != nil {
		t.Fatal(err)
	}
	if _, err := sqlDB.ExecContext(ctx, `
		INSERT INTO notification_outbox (tenant_id, event_type, title, status)
		VALUES ($1, 'test', 'ops snapshot test', 'dead')`, tenant.String()); err != nil {
		t.Fatal(err)
	}

	after, err := ReadOpsSnapshot(ctx, sqlDB)
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

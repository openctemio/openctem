package postgres

import (
	"context"
	"database/sql"
	"strings"
	"testing"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/api/pkg/domain/sensor"
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

// openctem_sensors_unhardened counts active tenant sensors by reason, from
// the stored local policy, the current manifest posture and the auth kind:
// a weak sensor counts under every reason, a hardened one under none, a
// platform sensor and a manifest version that is not current are never read.
// Requires DATABASE_URL.
func TestReadOpsSnapshot_Unhardened(t *testing.T) {
	sqlDB := openSensorDB(t)
	ctx := context.Background()
	tenant := seedTestTenant(ctx, t, sqlDB)
	// Seeded disabled (not counted), activated inside the transaction.
	weak := seedZoneSensor(ctx, t, sqlDB, &tenant, "ops-weak", zoneSensorOpts{status: "disabled"})
	strong := seedZoneSensor(ctx, t, sqlDB, &tenant, "ops-strong", zoneSensorOpts{status: "disabled"})
	platform := seedZoneSensor(ctx, t, sqlDB, &tenant, "ops-platform", zoneSensorOpts{status: "disabled", platform: true})

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
		t.Fatal(err)
	}

	weakPosture := `{"platform_tls":{"pin":"none"},"sandbox":{"mode":"auto","sandboxed":true,"network_enforced":false}}`
	strongPosture := `{"platform_tls":{"pin":"fingerprint"},"sandbox":{"mode":"required","sandboxed":true,"network_enforced":true}}`
	manifest := func(id, digit, posture string, current bool) {
		digest := "sha256:" + strings.Repeat(digit, 64)
		exec(`INSERT INTO sensor_manifests (sensor_id, tenant_id, digest, source, manifest)
			VALUES ($1, $2, $3, 'sensor', jsonb_build_object('schema', 1, 'posture', $4::jsonb))`, id, tenant.String(), digest, posture)
		if current {
			exec(`UPDATE sensors SET manifest_digest = $2 WHERE id = $1`, id, digest)
		}
	}
	all := []string{weak.String(), strong.String(), platform.String()}
	exec(`UPDATE sensors SET status = 'active' WHERE id = ANY($1)`, pq.Array(all))
	exec(`UPDATE sensors SET reported_local_policy = '{"state":"absent","required":false}' WHERE id = ANY($1)`,
		pq.Array([]string{weak.String(), platform.String()}))
	manifest(weak.String(), "1", weakPosture, true)
	manifest(platform.String(), "2", weakPosture, true)
	// The strong sensor's older, weak version is not the current one.
	manifest(strong.String(), "3", weakPosture, false)
	manifest(strong.String(), "4", strongPosture, true)
	exec(`UPDATE sensors SET auth_kind = 'key_bound',
		reported_local_policy = '{"state":"enforced","required":true}' WHERE id = $1`, strong.String())

	after, err := ReadOpsSnapshot(ctx, tx)
	if err != nil {
		t.Fatal(err)
	}
	for _, kind := range sensor.UnhardenedKinds() {
		if got := after.SensorsUnhardened[kind] - before.SensorsUnhardened[kind]; got != 1 {
			t.Errorf("%s +%d, want +1 (the weak tenant sensor only)", kind, got)
		}
	}
	if len(after.SensorsUnhardened) != len(sensor.UnhardenedKinds()) {
		t.Errorf("kinds %v", after.SensorsUnhardened)
	}
}

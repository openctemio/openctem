package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"strings"
	"testing"

	"github.com/openctemio/openctem/server/pkg/domain/command"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
)

// A routed scan task whose only sensor drops offline (a DNS or network
// outage) waits for it instead of using up its dispatch attempts: the
// incident's 64 chunks each burned three attempts on infra.sensor_offline in
// minutes and the step failed after four hours. A task that takes its
// sensor offline every time still ends: past command.MaxOfflineWaits the
// losses count again. Requires DATABASE_URL.

// newRoutedScanCommand creates a scan command of a run (routed work).
func newRoutedScanCommand(ctx context.Context, t *testing.T, cmds *CommandRepository, tenant shared.ID) *command.Command {
	t.Helper()
	raw, _ := json.Marshal(map[string]any{"scanner": "nuclei", "targets": []string{uniqueTestHost()}, "scan_run_id": shared.NewID().String()})
	cmd, err := command.NewCommand(tenant, command.CommandTypeScan, command.CommandPriorityNormal, raw)
	if err != nil {
		t.Fatal(err)
	}
	if err := cmds.Create(ctx, cmd); err != nil {
		t.Fatal(err)
	}
	return cmd
}

// loseLease claims cmd for sensor, sets the sensor's health and expires the
// lease, then runs the reaper.
func loseLease(ctx context.Context, t *testing.T, db *sql.DB, cmds *CommandRepository, tenant shared.ID, cmd *command.Command, sensor shared.ID, health string) {
	t.Helper()
	if _, err := db.ExecContext(ctx, `UPDATE commands SET scheduled_at = NULL WHERE id = $1`, cmd.ID.String()); err != nil {
		t.Fatal(err)
	}
	if ok, err := cmds.ClaimForSensor(ctx, tenant, cmd.ID, sensor.String()); err != nil || !ok {
		t.Fatalf("claim: %v %v", ok, err)
	}
	if _, err := db.ExecContext(ctx, `UPDATE sensors SET health = $2 WHERE id = $1`, sensor.String(), health); err != nil {
		t.Fatal(err)
	}
	if _, err := cmds.ExpireLeasesHeldBy(ctx, sensor); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `UPDATE commands SET lease_expires_at = NOW() - interval '1 second' WHERE id = $1`, cmd.ID.String()); err != nil {
		t.Fatal(err)
	}
	if _, err := cmds.RequeueExpiredLeases(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `UPDATE sensors SET health = 'online' WHERE id = $1`, sensor.String()); err != nil {
		t.Fatal(err)
	}
}

func TestOfflineSensorDoesNotUseUpAttempts(t *testing.T) {
	sqlDB := openSensorDB(t)
	ctx := context.Background()
	defer lockGlobalSweep(ctx, t, sqlDB)()
	cmds := NewCommandRepository(&DB{DB: sqlDB})
	tenant := seedTestTenant(ctx, t, sqlDB)
	a := seedZoneSensor(ctx, t, sqlDB, &tenant, "a", zoneSensorOpts{tools: []string{"nuclei"}})
	cmd := newRoutedScanCommand(ctx, t, cmds, tenant)

	for i := range command.MaxOfflineWaits {
		loseLease(ctx, t, sqlDB, cmds, tenant, cmd, a, "offline")
		if failsExhausted(ctx, t, cmds, cmd.ID) {
			t.Fatalf("offline loss %d failed the command as exhausted", i+1)
		}
		c := readAttempts(ctx, t, cmds, tenant, cmd.ID)
		if c.DispatchAttempts != 0 || c.Status != command.CommandStatusPending {
			t.Fatalf("offline loss %d: attempts %d status %s, want 0 and pending", i+1, c.DispatchAttempts, c.Status)
		}
		if !strings.Contains(c.ErrorMessage, "waiting for sensor") {
			t.Fatalf("offline loss %d: message %q, want the visible wait", i+1, c.ErrorMessage)
		}
	}
	// Past MaxOfflineWaits every loss counts: the anti-loop still ends it.
	for i := range exhaustLimit {
		loseLease(ctx, t, sqlDB, cmds, tenant, cmd, a, "offline")
		if got := readAttempts(ctx, t, cmds, tenant, cmd.ID).DispatchAttempts; got != i+1 {
			t.Fatalf("loss %d past the waits: attempts %d, want %d", i+1, got, i+1)
		}
	}
	if !failsExhausted(ctx, t, cmds, cmd.ID) {
		t.Fatal("a command that keeps taking its sensor offline was never failed")
	}
	c := readAttempts(ctx, t, cmds, tenant, cmd.ID)
	if !strings.Contains(c.ErrorMessage, "Failed on 3 sensor attempt(s)") {
		t.Fatalf("failure message %q, want only the counted attempts", c.ErrorMessage)
	}
}

// A lost lease of a sensor that is still online (it crashed on the task and
// came back, or it stopped renewing) counts as before.
func TestOnlineSensorLostLeaseStillCounts(t *testing.T) {
	sqlDB := openSensorDB(t)
	ctx := context.Background()
	defer lockGlobalSweep(ctx, t, sqlDB)()
	cmds := NewCommandRepository(&DB{DB: sqlDB})
	tenant := seedTestTenant(ctx, t, sqlDB)
	a := seedZoneSensor(ctx, t, sqlDB, &tenant, "a", zoneSensorOpts{tools: []string{"nuclei"}})
	cmd := newRoutedScanCommand(ctx, t, cmds, tenant)

	loseLease(ctx, t, sqlDB, cmds, tenant, cmd, a, "online")
	c := readAttempts(ctx, t, cmds, tenant, cmd.ID)
	if c.DispatchAttempts != 1 || c.ErrorMessage != command.LeaseExpiredMessage {
		t.Fatalf("online loss: attempts %d message %q, want 1 and the lease message", c.DispatchAttempts, c.ErrorMessage)
	}
}

// Another tenant's offline sensor with the same name never decides: the
// holder is looked up in the command's own tenant.
func TestOfflineWaitIsTenantScoped(t *testing.T) {
	sqlDB := openSensorDB(t)
	ctx := context.Background()
	defer lockGlobalSweep(ctx, t, sqlDB)()
	cmds := NewCommandRepository(&DB{DB: sqlDB})
	tenant := seedTestTenant(ctx, t, sqlDB)
	other := seedTestTenant(ctx, t, sqlDB)
	a := seedZoneSensor(ctx, t, sqlDB, &tenant, "a", zoneSensorOpts{tools: []string{"nuclei"}})
	b := seedZoneSensor(ctx, t, sqlDB, &other, "a", zoneSensorOpts{tools: []string{"nuclei"}})
	cmd := newRoutedScanCommand(ctx, t, cmds, tenant)

	// The other tenant's sensor is offline; the holder is online.
	if _, err := sqlDB.ExecContext(ctx, `UPDATE sensors SET health = 'offline' WHERE id = $1`, b.String()); err != nil {
		t.Fatal(err)
	}
	loseLease(ctx, t, sqlDB, cmds, tenant, cmd, a, "online")
	if c := readAttempts(ctx, t, cmds, tenant, cmd.ID); c.DispatchAttempts != 1 {
		t.Fatalf("attempts %d, want 1: another tenant's offline sensor must not make it wait", c.DispatchAttempts)
	}
}

// A task pinned to a sensor that is offline makes no dispatch while it
// waits: ten minutes of sweeps (every 30 s) leave it pending, pinned and at
// zero attempts.
func TestPinnedTaskOfflineSensorMakesNoDispatch(t *testing.T) {
	sqlDB := openSensorDB(t)
	ctx := context.Background()
	defer lockGlobalSweep(ctx, t, sqlDB)()
	cmds := NewCommandRepository(&DB{DB: sqlDB})
	tenant := seedTestTenant(ctx, t, sqlDB)
	a := seedZoneSensor(ctx, t, sqlDB, &tenant, "a", zoneSensorOpts{tools: []string{"nuclei"}})
	cmd := newRoutedScanCommand(ctx, t, cmds, tenant)
	if _, err := sqlDB.ExecContext(ctx, `UPDATE commands SET pinned_sensor_id = $2 WHERE id = $1`, cmd.ID.String(), a.String()); err != nil {
		t.Fatal(err)
	}
	loseLease(ctx, t, sqlDB, cmds, tenant, cmd, a, "offline")
	if _, err := sqlDB.ExecContext(ctx, `UPDATE sensors SET health = 'offline' WHERE id = $1`, a.String()); err != nil {
		t.Fatal(err)
	}
	for round := range 20 {
		if _, err := cmds.RequeueExpiredLeases(ctx); err != nil {
			t.Fatal(err)
		}
		if _, err := cmds.RequeueStalledCommands(ctx); err != nil {
			t.Fatal(err)
		}
		if failsExhausted(ctx, t, cmds, cmd.ID) {
			t.Fatalf("round %d: the waiting task was failed", round)
		}
	}
	c := readAttempts(ctx, t, cmds, tenant, cmd.ID)
	if c.DispatchAttempts != 0 || c.Status != command.CommandStatusPending || c.SensorID == nil || *c.SensorID != a {
		t.Fatalf("after ten minutes offline: attempts %d status %s sensor %v, want 0, pending, pinned to the sensor", c.DispatchAttempts, c.Status, c.SensorID)
	}
}

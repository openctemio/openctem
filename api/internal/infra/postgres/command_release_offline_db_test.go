package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/command"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// RFC-030 B7: pending scan work pinned to a sensor that went offline (or was
// disabled) is released to the pool, keeping its zone; work an operator
// addressed to one sensor is not. Requires DATABASE_URL (CI applies every
// migration first).
func TestReleasePendingFromUnavailableSensors(t *testing.T) {
	sqlDB := openSensorDB(t)
	ctx := context.Background()
	defer lockGlobalSweep(ctx, t, sqlDB)()
	db := &DB{DB: sqlDB}
	zones := NewScanZoneRepository(db)
	cmds := NewCommandRepository(db)
	tenant := seedTestTenant(ctx, t, sqlDB)

	zone := newTestZone(t, tenant, "a", false, "10.1.0.0/16")
	if err := zones.Create(ctx, zone); err != nil {
		t.Fatal(err)
	}
	dead := seedZoneSensor(ctx, t, sqlDB, &tenant, "dead", zoneSensorOpts{tools: []string{"nuclei"}})
	alive := seedZoneSensor(ctx, t, sqlDB, &tenant, "alive", zoneSensorOpts{tools: []string{"nuclei"}})
	disabled := seedZoneSensor(ctx, t, sqlDB, &tenant, "disabled", zoneSensorOpts{tools: []string{"nuclei"}, status: "disabled"})
	for _, s := range []shared.ID{dead, alive} {
		if err := zones.AssignSensor(ctx, tenant, zone.ID, s, nil); err != nil {
			t.Fatal(err)
		}
	}

	routed := func(sensor shared.ID, zoned bool, mutate func(*command.Command)) shared.ID {
		t.Helper()
		raw, _ := json.Marshal(map[string]any{
			"scanner": "nuclei", "targets": []string{"10.1.0.1"},
			"scan_run_id": shared.NewID().String(), "step_key": "scan",
		})
		cmd, err := command.NewCommand(tenant, command.CommandTypeScan, command.CommandPriorityNormal, raw)
		if err != nil {
			t.Fatal(err)
		}
		cmd.SetSensorID(sensor)
		if zoned {
			cmd.SetScanZone(zone.ID)
		}
		if mutate != nil {
			mutate(cmd)
		}
		if err := cmds.Create(ctx, cmd); err != nil {
			t.Fatal(err)
		}
		return cmd.ID
	}
	zoneBatch := routed(dead, true, nil)
	unzonedStep := routed(dead, false, nil)
	onDisabled := routed(disabled, false, nil)
	onAlive := routed(alive, true, nil)
	running := routed(dead, true, func(c *command.Command) { c.Status = command.CommandStatusRunning })
	// An operator's command for that one sensor (no scan run) keeps it.
	addressedRaw, _ := json.Marshal(map[string]any{"scanner": "tenable", "session_id": "s"})
	addressed, err := command.NewCommand(tenant, command.CommandTypeScan, command.CommandPriorityNormal, addressedRaw)
	if err != nil {
		t.Fatal(err)
	}
	addressed.SetSensorID(dead)
	if err := cmds.Create(ctx, addressed); err != nil {
		t.Fatal(err)
	}

	// Nothing to release while every sensor is online and active.
	if _, err := sqlDB.ExecContext(ctx, `UPDATE sensors SET health = 'online' WHERE id = $1`, dead.String()); err != nil {
		t.Fatal(err)
	}
	n, err := cmds.ReleasePendingFromUnavailableSensors(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if got := pinnedTo(ctx, t, sqlDB, onDisabled); got.Valid {
		t.Error("a pending command on a disabled sensor kept its pin")
	}
	if n != 1 {
		t.Errorf("released %d with only the disabled sensor unavailable, want 1", n)
	}

	// The sensor dies: the health controller marks it offline.
	if _, err := sqlDB.ExecContext(ctx, `UPDATE sensors SET health = 'offline' WHERE id = $1`, dead.String()); err != nil {
		t.Fatal(err)
	}
	n, err = cmds.ReleasePendingFromUnavailableSensors(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Errorf("released %d commands of the dead sensor, want 2 (zone batch + step)", n)
	}
	for name, id := range map[string]shared.ID{"zone batch": zoneBatch, "unzoned step": unzonedStep} {
		if got := pinnedTo(ctx, t, sqlDB, id); got.Valid {
			t.Errorf("%s still pinned to the dead sensor", name)
		}
	}
	for name, id := range map[string]shared.ID{"running": running, "addressed": addressed.ID} {
		if got := pinnedTo(ctx, t, sqlDB, id); !got.Valid || got.String != dead.String() {
			t.Errorf("%s command lost its sensor (%v); only pending routed work is released", name, got)
		}
	}
	if got := pinnedTo(ctx, t, sqlDB, onAlive); !got.Valid || got.String != alive.String() {
		t.Error("a command pinned to a live sensor was released")
	}

	// The released zone batch keeps its zone: the live zone sensor gets it,
	// a sensor outside the zone does not.
	var zoneID sql.NullString
	if err := sqlDB.QueryRowContext(ctx, `SELECT scan_zone_id FROM commands WHERE id = $1`, zoneBatch.String()).Scan(&zoneID); err != nil {
		t.Fatal(err)
	}
	if !zoneID.Valid || zoneID.String != zone.ID.String() {
		t.Errorf("released zone batch lost its zone stamp: %v", zoneID)
	}
	outsider := seedZoneSensor(ctx, t, sqlDB, &tenant, "outsider", zoneSensorOpts{tools: []string{"nuclei"}})
	if polledIDs(ctx, t, cmds, tenant, outsider)[zoneBatch] {
		t.Error("released zone batch leaked to a sensor outside the zone")
	}
	if !polledIDs(ctx, t, cmds, tenant, alive)[zoneBatch] {
		t.Error("the zone's live sensor was not offered the released batch")
	}

	// Idempotent.
	if n, err = cmds.ReleasePendingFromUnavailableSensors(ctx); err != nil || n != 0 {
		t.Errorf("second sweep released %d (err %v), want 0", n, err)
	}
}

func pinnedTo(ctx context.Context, t *testing.T, db *sql.DB, id shared.ID) sql.NullString {
	t.Helper()
	var s sql.NullString
	if err := db.QueryRowContext(ctx, `SELECT sensor_id FROM commands WHERE id = $1`, id.String()).Scan(&s); err != nil {
		t.Fatal(err)
	}
	return s
}

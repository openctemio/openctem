package postgres

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/command"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Every path that returns a command to pending counts the return, delays the
// next offer, and ends the command at command.MaxRequeues. Requires DATABASE_URL.

type requeueState struct {
	count     int
	scheduled bool
	delaySecs float64
}

func readRequeue(ctx context.Context, t *testing.T, cmds *CommandRepository, id shared.ID) requeueState {
	t.Helper()
	var s requeueState
	err := cmds.db.QueryRowContext(ctx, `
		SELECT requeue_count, scheduled_at IS NOT NULL,
		       COALESCE(EXTRACT(EPOCH FROM scheduled_at - NOW()), 0)
		FROM commands WHERE id = $1`, id.String()).Scan(&s.count, &s.scheduled, &s.delaySecs)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestRequeue_EveryPathCountsAndBacksOff(t *testing.T) {
	sqlDB := openSensorDB(t)
	ctx := context.Background()
	defer lockGlobalSweep(ctx, t, sqlDB)()
	cmds := NewCommandRepository(&DB{DB: sqlDB})
	tenant := seedTestTenant(ctx, t, sqlDB)
	a := seedZoneSensor(ctx, t, sqlDB, &tenant, "a", zoneSensorOpts{tools: []string{"nuclei"}})

	routed := false
	newCmd := func() shared.ID {
		t.Helper()
		pl := map[string]any{"scanner": "nuclei", "targets": []string{uniqueTestHost()}}
		if routed {
			pl["scan_run_id"] = shared.NewID().String()
		}
		raw, _ := json.Marshal(pl)
		c, err := command.NewCommand(tenant, command.CommandTypeScan, command.CommandPriorityNormal, raw)
		if err != nil {
			t.Fatal(err)
		}
		if err := cmds.Create(ctx, c); err != nil {
			t.Fatal(err)
		}
		return c.ID
	}
	claim := func(id shared.ID) {
		t.Helper()
		if ok, err := cmds.ClaimForSensor(ctx, tenant, id, a.String()); err != nil || !ok {
			t.Fatalf("claim: %v %v", ok, err)
		}
	}
	// open lets the back-off pass so the next claim is possible.
	open := func(id shared.ID) {
		t.Helper()
		if _, err := sqlDB.ExecContext(ctx, `UPDATE commands SET scheduled_at = NULL WHERE id = $1`, id.String()); err != nil {
			t.Fatal(err)
		}
	}

	paths := map[string]func(id shared.ID){
		"unclaim (signer down)": func(id shared.ID) {
			claim(id)
			if ok, err := cmds.UnclaimForSensor(ctx, tenant, id, a.String(), false); err != nil || !ok {
				t.Fatalf("unclaim: %v %v", ok, err)
			}
		},
		"voluntary release": func(id shared.ID) {
			claim(id)
			if ok, err := cmds.ReleaseForSensor(ctx, tenant, id, a.String(), command.ReleasedBySensorPrefix+"no free slot"); err != nil || !ok {
				t.Fatalf("release: %v %v", ok, err)
			}
		},
		"lease expiry": func(id shared.ID) {
			claim(id)
			if _, err := sqlDB.ExecContext(ctx, `UPDATE commands SET lease_expires_at = NOW() - interval '1 minute' WHERE id = $1`, id.String()); err != nil {
				t.Fatal(err)
			}
			if _, err := cmds.RequeueExpiredLeases(ctx); err != nil {
				t.Fatal(err)
			}
		},
		"sensor withdrawn": func(id shared.ID) {
			claim(id)
			if _, err := cmds.ReleaseHeldBySensor(ctx, tenant, a, "requeued", "failed"); err != nil {
				t.Fatal(err)
			}
		},
	}
	for name, run := range paths {
		routed = name == "sensor withdrawn" // only routed scan work goes back to pending
		id := newCmd()
		run(id)
		if s := readRequeue(ctx, t, cmds, id); s.count != 1 {
			t.Errorf("%s: requeue_count %d after one return, want 1", name, s.count)
		}
		for i := 2; i <= 4; i++ {
			open(id)
			run(id)
			s := readRequeue(ctx, t, cmds, id)
			if s.count != i {
				t.Fatalf("%s: requeue_count %d after %d returns", name, s.count, i)
			}
			if want := float64(int(5) << (i - 2)); !s.scheduled || s.delaySecs < want-5 || s.delaySecs > want+1 {
				t.Errorf("%s: return %d waits %.1fs, want about %.0fs", name, i, s.delaySecs, want)
			}
		}
		// While it backs off it cannot be claimed again.
		if ok, _ := cmds.ClaimForSensor(ctx, tenant, id, a.String()); ok {
			t.Errorf("%s: a command inside its back-off was claimed", name)
		}
	}
}

func TestRequeue_CapFailsTheCommandWithAReason(t *testing.T) {
	sqlDB := openSensorDB(t)
	ctx := context.Background()
	defer lockGlobalSweep(ctx, t, sqlDB)()
	cmds := NewCommandRepository(&DB{DB: sqlDB})
	tenant := seedTestTenant(ctx, t, sqlDB)
	a := seedZoneSensor(ctx, t, sqlDB, &tenant, "a", zoneSensorOpts{tools: []string{"nuclei"}})

	raw, _ := json.Marshal(map[string]any{"scanner": "nuclei", "targets": []string{uniqueTestHost()}})
	cmd, err := command.NewCommand(tenant, command.CommandTypeScan, command.CommandPriorityNormal, raw)
	if err != nil {
		t.Fatal(err)
	}
	if err := cmds.Create(ctx, cmd); err != nil {
		t.Fatal(err)
	}
	for i := 1; i <= command.MaxRequeues; i++ {
		if _, err := sqlDB.ExecContext(ctx, `UPDATE commands SET scheduled_at = NULL WHERE id = $1`, cmd.ID.String()); err != nil {
			t.Fatal(err)
		}
		if ok, err := cmds.ClaimForSensor(ctx, tenant, cmd.ID, a.String()); err != nil || !ok {
			t.Fatalf("claim %d: %v %v", i, ok, err)
		}
		if ok, err := cmds.UnclaimForSensor(ctx, tenant, cmd.ID, a.String(), false); err != nil || !ok {
			t.Fatalf("unclaim %d: %v %v", i, ok, err)
		}
		if i < command.MaxRequeues && failsExhausted(ctx, t, cmds, cmd.ID) {
			t.Fatalf("failed after only %d returns", i)
		}
	}
	if !failsExhausted(ctx, t, cmds, cmd.ID) {
		t.Fatalf("a command returned %d times was not failed", command.MaxRequeues)
	}
	c := readAttempts(ctx, t, cmds, tenant, cmd.ID)
	if c.Status != command.CommandStatusFailed || c.ErrorMessage != command.RequeueExhaustedMessage {
		t.Fatalf("status %s message %q", c.Status, c.ErrorMessage)
	}
	// Dispatch attempts were not charged by an unclaim.
	if c.DispatchAttempts != 0 {
		t.Fatalf("dispatch attempts %d", c.DispatchAttempts)
	}
}

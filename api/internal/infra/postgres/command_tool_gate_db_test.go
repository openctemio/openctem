package postgres

import (
	"context"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/command"
)

// The tool gate (RFC-030 B5) against a real schema: outside zones too, a
// command that names a tool is offered to, and claimable by, only a sensor
// that has the tool; tool-less commands are unaffected; the doorbell counts
// the same. Requires DATABASE_URL (CI applies every migration first).
func TestCommandToolGate_UnzonedCommands(t *testing.T) {
	sqlDB := openSensorDB(t)
	ctx := context.Background()
	db := &DB{DB: sqlDB}
	cmds := NewCommandRepository(db)
	tenant := seedTestTenant(ctx, t, sqlDB)
	other := seedTestTenant(ctx, t, sqlDB)

	withNuclei := seedZoneSensor(ctx, t, sqlDB, &tenant, "nuclei", zoneSensorOpts{tools: []string{"nuclei", "trivy"}})
	withLeaks := seedZoneSensor(ctx, t, sqlDB, &tenant, "leaks", zoneSensorOpts{tools: []string{"betterleaks"}})
	noTools := seedZoneSensor(ctx, t, sqlDB, &tenant, "none", zoneSensorOpts{})
	// Same tool, other tenant: its tools must not satisfy this tenant's gate.
	otherNuclei := seedZoneSensor(ctx, t, sqlDB, &other, "other", zoneSensorOpts{tools: []string{"nuclei"}})

	nucleiScan := createZoneCommand(ctx, t, cmds, tenant, nil, nil, "nuclei")
	leaksScan := createZoneCommand(ctx, t, cmds, tenant, nil, nil, "betterleaks")
	// A workflow step names its tool in preferred_tool.
	seedRawCommand(ctx, t, cmds, tenant, map[string]any{"preferred_tool": "trivy", "step_key": "s"}, nil)
	// A tool-less command (collect, validate) goes to any sensor.
	seedRawCommand(ctx, t, cmds, tenant, map[string]any{"kind": "collect"}, func(c *command.Command) { c.Type = command.CommandTypeCollect })
	// A command pinned to a sensor that lacks the tool is not offered either.
	pinned := createZoneCommand(ctx, t, cmds, tenant, nil, &withLeaks, "nuclei")

	got := polledIDs(ctx, t, cmds, tenant, withNuclei)
	if !got[nucleiScan] || got[leaksScan] || got[pinned] || len(got) != 3 {
		t.Errorf("nuclei+trivy sensor polled %d commands %v; want the nuclei scan, the trivy step and the collect", len(got), got)
	}
	assertPollParity(ctx, t, cmds, tenant, withNuclei, nil, 3)

	got = polledIDs(ctx, t, cmds, tenant, withLeaks)
	if got[nucleiScan] || !got[leaksScan] || got[pinned] || len(got) != 2 {
		t.Errorf("betterleaks sensor polled %d commands %v; want the betterleaks scan and the collect", len(got), got)
	}
	assertPollParity(ctx, t, cmds, tenant, withLeaks, nil, 2)

	got = polledIDs(ctx, t, cmds, tenant, noTools)
	if len(got) != 1 {
		t.Errorf("sensor with no tools polled %d commands; want only the tool-less collect", len(got))
	}
	assertPollParity(ctx, t, cmds, tenant, noTools, nil, 1)

	// The claim by id refuses what the poll would not offer.
	if ok, err := cmds.ClaimForSensor(ctx, tenant, nucleiScan, withLeaks.String()); err != nil || ok {
		t.Errorf("sensor without nuclei claimed a nuclei scan: ok=%v err=%v", ok, err)
	}
	if ok, err := cmds.ClaimForSensor(ctx, tenant, nucleiScan, noTools.String()); err != nil || ok {
		t.Errorf("sensor with no tools claimed a nuclei scan: ok=%v err=%v", ok, err)
	}
	if ok, err := cmds.ClaimForSensor(ctx, tenant, nucleiScan, otherNuclei.String()); err != nil || ok {
		t.Errorf("another tenant's nuclei sensor claimed this tenant's scan: ok=%v err=%v", ok, err)
	}
	if ok, err := cmds.ClaimForSensor(ctx, tenant, pinned, withLeaks.String()); err != nil || ok {
		t.Errorf("pinned sensor without the tool claimed the command: ok=%v err=%v", ok, err)
	}
	if ok, err := cmds.ClaimForSensor(ctx, tenant, nucleiScan, withNuclei.String()); err != nil || !ok {
		t.Errorf("nuclei sensor could not claim the nuclei scan: ok=%v err=%v", ok, err)
	}

	// No sensor identity: only tool-less, unpinned, unzoned commands.
	anon, err := cmds.GetPendingForSensor(ctx, tenant, nil, nil, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(anon) != 1 {
		t.Errorf("anonymous poll returned %d commands; want only the tool-less collect", len(anon))
	}
}

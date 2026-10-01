package postgres

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/openctemio/api/pkg/domain/command"
	"github.com/openctemio/api/pkg/domain/scanzone"
	"github.com/openctemio/api/pkg/domain/shared"
)

// The heartbeat doorbell (RFC-023 §9.2a) must count exactly what the poll
// would offer: the same tenant, pinning, readiness, zone claim predicate and
// capability gate. Requires DATABASE_URL (CI applies every migration first).

func pendingWork(ctx context.Context, t *testing.T, repo *CommandRepository, tenant, sensor shared.ID, caps []string, limit int) (int, string) {
	t.Helper()
	w, err := repo.PendingWorkForSensor(ctx, tenant, sensor, caps, limit)
	if err != nil {
		t.Fatalf("PendingWorkForSensor: %v", err)
	}
	return w.Count, w.ZoneFingerprint
}

// assertPollParity fails unless the doorbell count equals what the poll
// returns for the same sensor and capabilities.
func assertPollParity(ctx context.Context, t *testing.T, repo *CommandRepository, tenant, sensor shared.ID, caps []string, want int) {
	t.Helper()
	polled, err := repo.GetPendingForSensor(ctx, tenant, &sensor, caps, 100)
	if err != nil {
		t.Fatalf("poll: %v", err)
	}
	got, _ := pendingWork(ctx, t, repo, tenant, sensor, caps, 100)
	if got != len(polled) {
		t.Errorf("doorbell counted %d but the poll offers %d (caps %v)", got, len(polled), caps)
	}
	if got != want {
		t.Errorf("doorbell counted %d, want %d (caps %v)", got, want, caps)
	}
}

func seedRawCommand(ctx context.Context, t *testing.T, repo *CommandRepository, tenant shared.ID, payload map[string]any, mutate func(*command.Command)) {
	t.Helper()
	raw, _ := json.Marshal(payload)
	cmd, err := command.NewCommand(tenant, command.CommandTypeScan, command.CommandPriorityNormal, raw)
	if err != nil {
		t.Fatal(err)
	}
	if mutate != nil {
		mutate(cmd)
	}
	if err := repo.Create(ctx, cmd); err != nil {
		t.Fatalf("create command: %v", err)
	}
}

func TestPendingWorkForSensor_MatchesThePoll(t *testing.T) {
	sqlDB := openSensorDB(t)
	ctx := context.Background()
	db := &DB{DB: sqlDB}
	zones := NewScanZoneRepository(db)
	cmds := NewCommandRepository(db)
	tenant := seedTestTenant(ctx, t, sqlDB)
	other := seedTestTenant(ctx, t, sqlDB)

	zoneA := newTestZone(t, tenant, "a", false, "10.1.0.0/16")
	zoneB := newTestZone(t, tenant, "b", false, "10.2.0.0/16")
	for _, z := range []*scanzone.Zone{zoneA, zoneB} {
		if err := zones.Create(ctx, z); err != nil {
			t.Fatal(err)
		}
	}
	s1 := seedZoneSensor(ctx, t, sqlDB, &tenant, "s1", zoneSensorOpts{tools: []string{"nuclei"}})
	s2 := seedZoneSensor(ctx, t, sqlDB, &tenant, "s2", zoneSensorOpts{tools: []string{"nuclei"}})
	s1noTool := seedZoneSensor(ctx, t, sqlDB, &tenant, "s1-no-nuclei", zoneSensorOpts{tools: []string{"betterleaks"}})
	outsider := seedZoneSensor(ctx, t, sqlDB, &tenant, "no-zone", zoneSensorOpts{tools: []string{"nuclei"}})
	for _, a := range []struct{ z, s shared.ID }{{zoneA.ID, s1}, {zoneA.ID, s1noTool}, {zoneB.ID, s2}} {
		if err := zones.AssignSensor(ctx, tenant, a.z, a.s, nil); err != nil {
			t.Fatal(err)
		}
	}

	// Nothing waiting yet.
	assertPollParity(ctx, t, cmds, tenant, s1, nil, 0)

	createZoneCommand(ctx, t, cmds, tenant, &zoneA.ID, &s1, "nuclei") // pinned to s1, zone a
	createZoneCommand(ctx, t, cmds, tenant, &zoneA.ID, nil, "nuclei") // zone-a pool
	createZoneCommand(ctx, t, cmds, tenant, &zoneB.ID, &s2, "nuclei") // pinned to s2, zone b
	createZoneCommand(ctx, t, cmds, tenant, &zoneB.ID, nil, "nuclei") // zone-b pool
	createZoneCommand(ctx, t, cmds, tenant, nil, nil, "nuclei")       // unzoned pool
	// Not claimable by anyone right now.
	seedRawCommand(ctx, t, cmds, tenant, map[string]any{}, func(c *command.Command) {
		past := time.Now().Add(-time.Minute)
		c.ExpiresAt = &past
	})
	seedRawCommand(ctx, t, cmds, tenant, map[string]any{}, func(c *command.Command) {
		later := time.Now().Add(time.Hour)
		c.ScheduledAt = &later
	})
	seedRawCommand(ctx, t, cmds, tenant, map[string]any{}, func(c *command.Command) { c.Status = command.CommandStatusCompleted })
	// Capability-gated.
	seedRawCommand(ctx, t, cmds, tenant, map[string]any{"required_capabilities": []string{"validate", "validate:nuclei"}}, nil)
	// Another tenant's pool must never count.
	createZoneCommand(ctx, t, cmds, other, nil, nil, "nuclei")

	// s1: its pinned command, the zone-a pool, the unzoned pool.
	assertPollParity(ctx, t, cmds, tenant, s1, nil, 3)
	// ...plus the capability-gated command once it has both capabilities.
	assertPollParity(ctx, t, cmds, tenant, s1, []string{"validate"}, 3)
	assertPollParity(ctx, t, cmds, tenant, s1, []string{"validate", "validate:nuclei"}, 4)
	// s2: its pinned command, the zone-b pool, the unzoned pool.
	assertPollParity(ctx, t, cmds, tenant, s2, nil, 3)
	// A zone member without the command's tool gets only the unzoned pool.
	assertPollParity(ctx, t, cmds, tenant, s1noTool, nil, 1)
	// A sensor in no zone: only the unzoned pool.
	assertPollParity(ctx, t, cmds, tenant, outsider, nil, 1)

	// The cap bounds the count.
	if n, _ := pendingWork(ctx, t, cmds, tenant, s1, nil, 2); n != 2 {
		t.Errorf("count with limit 2 = %d, want 2", n)
	}

	// Removing s1 from zone a takes the zone's commands away from it.
	if _, err := zones.UnassignSensor(ctx, tenant, zoneA.ID, s1); err != nil {
		t.Fatal(err)
	}
	assertPollParity(ctx, t, cmds, tenant, s1, nil, 1)
}

func TestPendingWorkForSensor_ZoneFingerprint(t *testing.T) {
	sqlDB := openSensorDB(t)
	ctx := context.Background()
	db := &DB{DB: sqlDB}
	zones := NewScanZoneRepository(db)
	cmds := NewCommandRepository(db)
	tenant := seedTestTenant(ctx, t, sqlDB)
	s := seedZoneSensor(ctx, t, sqlDB, &tenant, "s", zoneSensorOpts{tools: []string{"nuclei"}})

	_, none := pendingWork(ctx, t, cmds, tenant, s, nil, 100)
	if none != "" {
		t.Fatalf("fingerprint with no zones = %q, want empty", none)
	}

	z := newTestZone(t, tenant, "a", false, "10.1.0.0/16")
	if err := zones.Create(ctx, z); err != nil {
		t.Fatal(err)
	}
	if err := zones.AssignSensor(ctx, tenant, z.ID, s, nil); err != nil {
		t.Fatal(err)
	}
	_, assigned := pendingWork(ctx, t, cmds, tenant, s, nil, 100)
	if assigned == "" {
		t.Fatal("assigning a zone did not change the fingerprint")
	}
	if _, again := pendingWork(ctx, t, cmds, tenant, s, nil, 100); again != assigned {
		t.Fatalf("fingerprint not stable: %q then %q", assigned, again)
	}

	ranges := []string{"10.1.0.0/16", "10.3.0.0/16"}
	if err := z.Update(nil, nil, nil, &ranges); err != nil {
		t.Fatal(err)
	}
	if err := zones.Update(ctx, z); err != nil {
		t.Fatal(err)
	}
	_, edited := pendingWork(ctx, t, cmds, tenant, s, nil, 100)
	if edited == assigned {
		t.Fatal("editing the zone's ranges did not change the fingerprint")
	}

	if _, err := zones.UnassignSensor(ctx, tenant, z.ID, s); err != nil {
		t.Fatal(err)
	}
	if _, after := pendingWork(ctx, t, cmds, tenant, s, nil, 100); after != "" {
		t.Fatalf("fingerprint after unassignment = %q, want empty", after)
	}
}

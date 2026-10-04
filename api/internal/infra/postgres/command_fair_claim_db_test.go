package postgres

import (
	"context"
	"encoding/json"
	"reflect"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/command"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// The dispatch order (RFC-046 §11, RFC-030 §5.3): priority class with aging,
// then round-robin across runs, then age; and claim-N, which claims a set of
// commands for one sensor in one statement. Against the real SQL.

type fairFixture struct {
	ctx    context.Context
	cmds   *CommandRepository
	tenant shared.ID
	sensor shared.ID
	t      *testing.T
	n      int
}

func newFairFixture(t *testing.T) *fairFixture {
	t.Helper()
	sqlDB := openSensorDB(t)
	ctx := context.Background()
	tenant := seedTestTenant(ctx, t, sqlDB)
	s := seedZoneSensor(ctx, t, sqlDB, &tenant, "fair", zoneSensorOpts{tools: []string{"nuclei"}})
	return &fairFixture{ctx: ctx, cmds: NewCommandRepository(&DB{DB: sqlDB}), tenant: tenant, sensor: s, t: t}
}

// add creates a pending nuclei command of run (any string; "" for none) at
// priority p, created age ago. Creation times are spread a millisecond apart
// so the order within one age is the creation order.
func (f *fairFixture) add(run string, p command.CommandPriority, age time.Duration) shared.ID {
	f.t.Helper()
	payload := map[string]any{"scanner": "nuclei", "targets": []string{"10.0.0.1"}}
	if run != "" {
		payload["pipeline_run_id"] = run
	}
	raw, _ := json.Marshal(payload)
	cmd, err := command.NewCommand(f.tenant, command.CommandTypeScan, p, raw)
	if err != nil {
		f.t.Fatal(err)
	}
	f.n++
	cmd.CreatedAt = time.Now().Add(-age).Add(time.Duration(f.n) * time.Millisecond)
	if err := f.cmds.Create(f.ctx, cmd); err != nil {
		f.t.Fatalf("create command: %v", err)
	}
	return cmd.ID
}

func (f *fairFixture) poll(limit int) []shared.ID {
	f.t.Helper()
	got, err := f.cmds.GetPendingForSensor(f.ctx, f.tenant, &f.sensor, nil, limit)
	if err != nil {
		f.t.Fatalf("poll: %v", err)
	}
	ids := make([]shared.ID, len(got))
	for i, c := range got {
		ids[i] = c.ID
	}
	return ids
}

func TestFairPoll_RoundRobinAcrossRuns(t *testing.T) {
	f := newFairFixture(t)
	runA, runB := shared.NewID().String(), shared.NewID().String()
	// A big run queued first, then a small one.
	a1 := f.add(runA, command.CommandPriorityNormal, time.Minute)
	a2 := f.add(runA, command.CommandPriorityNormal, time.Minute)
	a3 := f.add(runA, command.CommandPriorityNormal, time.Minute)
	b1 := f.add(runB, command.CommandPriorityNormal, 0)
	b2 := f.add(runB, command.CommandPriorityNormal, 0)

	if got, want := f.poll(4), []shared.ID{a1, b1, a2, b2}; !reflect.DeepEqual(got, want) {
		t.Fatalf("order = %v, want %v (one of each run before the second of any)", got, want)
	}
	if got := f.poll(10); len(got) != 5 || got[4] != a3 {
		t.Fatalf("full order = %v, want a3 last", got)
	}
}

func TestFairPoll_PriorityClassesAndAging(t *testing.T) {
	f := newFairFixture(t)
	low := f.add("", command.CommandPriorityLow, time.Minute)
	normal := f.add("", command.CommandPriorityNormal, time.Minute)
	high := f.add("", command.CommandPriorityHigh, 0)
	critical := f.add("", command.CommandPriorityCritical, 0)
	// A normal command that waited 40 minutes ages into the high class and,
	// being older, goes before the fresh high one; a low one that waited 2 h
	// ages at most to high too, never to critical.
	agedNormal := f.add("", command.CommandPriorityNormal, 40*time.Minute)
	agedLow := f.add("", command.CommandPriorityLow, 2*time.Hour)

	want := []shared.ID{critical, agedLow, agedNormal, high, normal, low}
	if got := f.poll(10); !reflect.DeepEqual(got, want) {
		t.Fatalf("order = %v, want %v", got, want)
	}
}

func TestClaimManyForSensor_GatesAndTenant(t *testing.T) {
	sqlDB := openSensorDB(t)
	ctx := context.Background()
	db := &DB{DB: sqlDB}
	cmds := NewCommandRepository(db)
	zones := NewScanZoneRepository(db)
	tenant := seedTestTenant(ctx, t, sqlDB)
	other := seedTestTenant(ctx, t, sqlDB)

	zone := newTestZone(t, tenant, "z", false, "10.9.0.0/16")
	if err := zones.Create(ctx, zone); err != nil {
		t.Fatal(err)
	}
	s := seedZoneSensor(ctx, t, sqlDB, &tenant, "claimer", zoneSensorOpts{tools: []string{"nuclei"}})
	peer := seedZoneSensor(ctx, t, sqlDB, &tenant, "peer", zoneSensorOpts{tools: []string{"nuclei"}})
	foreignSensor := seedZoneSensor(ctx, t, sqlDB, &other, "foreign", zoneSensorOpts{tools: []string{"nuclei"}})

	open := createZoneCommand(ctx, t, cmds, tenant, nil, nil, "nuclei")
	pinnedToPeer := createZoneCommand(ctx, t, cmds, tenant, nil, &peer, "nuclei")
	otherZone := createZoneCommand(ctx, t, cmds, tenant, &zone.ID, nil, "nuclei") // s is not in the zone
	wrongTool := createZoneCommand(ctx, t, cmds, tenant, nil, nil, "naabu")
	foreign := createZoneCommand(ctx, t, cmds, other, nil, nil, "nuclei")

	ids := []shared.ID{open, pinnedToPeer, otherZone, wrongTool, foreign}
	got, err := cmds.ClaimManyForSensor(ctx, tenant, s, nil, ids)
	if err != nil {
		t.Fatalf("ClaimManyForSensor: %v", err)
	}
	if !reflect.DeepEqual(got, []shared.ID{open}) {
		t.Fatalf("claimed %v, want only the open command (pinned, zoned, tool and tenant gates)", got)
	}
	c, _ := cmds.GetByTenantAndID(ctx, tenant, open)
	if c.Status != command.CommandStatusAcknowledged || c.SensorID == nil || *c.SensorID != s ||
		c.LeaseExpiresAt == nil || c.LeaseEpoch != 1 {
		t.Fatalf("claimed command = status %s sensor %v lease %v epoch %d", c.Status, c.SensorID, c.LeaseExpiresAt, c.LeaseEpoch)
	}
	// Claimed once: a second claim of the same id by another sensor gets nothing.
	if again, _ := cmds.ClaimManyForSensor(ctx, tenant, peer, nil, []shared.ID{open}); len(again) != 0 {
		t.Fatalf("second claim got %v", again)
	}
	// A sensor of another tenant, asking with its own tenant, cannot take
	// this tenant's commands by id; and asking with this tenant's id, the
	// tool gate (sensor tenant = command tenant) still refuses.
	if g, _ := cmds.ClaimManyForSensor(ctx, other, foreignSensor, nil, []shared.ID{pinnedToPeer, otherZone}); len(g) != 0 {
		t.Fatalf("foreign sensor claimed %v", g)
	}
	if g, _ := cmds.ClaimManyForSensor(ctx, tenant, foreignSensor, nil, []shared.ID{wrongTool, otherZone}); len(g) != 0 {
		t.Fatalf("foreign sensor claimed %v under the victim tenant", g)
	}
	if n, err := cmds.CountHeldScans(ctx, tenant, s); err != nil || n != 1 {
		t.Fatalf("CountHeldScans = %d, %v; want 1", n, err)
	}
	if n, _ := cmds.CountHeldScans(ctx, other, s); n != 0 {
		t.Fatalf("CountHeldScans under another tenant = %d", n)
	}
}

package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/api/pkg/domain/command"
	"github.com/openctemio/openctem/api/pkg/domain/scan"
	"github.com/openctemio/openctem/api/pkg/domain/scanzone"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Scan zones (RFC-023 Phase 1) against a real schema: tenant isolation in SQL,
// the claim predicate (layer 2), routable-sensor selection, coverage and the
// step-batch gate. Requires DATABASE_URL (CI applies every migration first).

type zoneSensorOpts struct {
	health   string
	tools    []string
	lastSeen *time.Time
	status   string
	platform bool
	// declaredOnly: the sensor never reported (verified) the tools; dispatch
	// must not use them.
	declaredOnly bool
}

func seedZoneSensor(ctx context.Context, t *testing.T, db *sql.DB, tenantID *shared.ID, name string, o zoneSensorOpts) shared.ID {
	t.Helper()
	if o.health == "" {
		o.health = "online"
	}
	if o.status == "" {
		o.status = "active"
	}
	if o.lastSeen == nil {
		now := time.Now()
		o.lastSeen = &now
	}
	id := shared.NewID()
	tenant := tenantID.String()
	// By default the sensor also reported (verified) its tools, as a sensor
	// on a current SDK does on every heartbeat.
	var reported any
	if !o.declaredOnly && o.tools != nil {
		reported = pq.Array(o.tools)
	}
	_, err := db.ExecContext(ctx,
		`INSERT INTO sensors (id, tenant_id, name, type, status, health, api_key_hash, api_key_prefix,
		                      execution_mode, max_concurrent_jobs, current_jobs, last_seen_at, is_platform_sensor,
		                      reported_tool_names)
		 VALUES ($1, $2, $3, 'worker', $4, $5, $6, $7, 'daemon', 5, 0, $8, $9, $10)`,
		id.String(), tenant, name+" "+id.String()[:8], o.status, o.health,
		"hash-"+id.String(), id.String()[:8], *o.lastSeen, o.platform, reported)
	if err != nil {
		t.Fatalf("seed sensor %s: %v", name, err)
	}
	t.Cleanup(func() {
		_, _ = db.ExecContext(context.Background(), `DELETE FROM sensors WHERE id = $1`, id.String())
	})
	return id
}

func newTestZone(t *testing.T, tenantID shared.ID, name string, isDefault bool, ranges ...string) *scanzone.Zone {
	t.Helper()
	z, err := scanzone.NewZone(tenantID, name, "", isDefault, ranges, nil)
	if err != nil {
		t.Fatalf("NewZone: %v", err)
	}
	return z
}

func createZoneCommand(ctx context.Context, t *testing.T, repo *CommandRepository, tenantID shared.ID,
	zoneID, sensorID *shared.ID, scanner string) shared.ID {
	t.Helper()
	payload, _ := json.Marshal(map[string]any{"scanner": scanner, "targets": []string{"10.0.0.1"}})
	cmd, err := command.NewCommand(tenantID, command.CommandTypeScan, command.CommandPriorityNormal, payload)
	if err != nil {
		t.Fatal(err)
	}
	if zoneID != nil {
		cmd.SetScanZone(*zoneID)
	}
	if sensorID != nil {
		cmd.SetSensorID(*sensorID)
	}
	if err := repo.Create(ctx, cmd); err != nil {
		t.Fatalf("create command: %v", err)
	}
	return cmd.ID
}

func polledIDs(ctx context.Context, t *testing.T, repo *CommandRepository, tenantID, sensorID shared.ID) map[shared.ID]bool {
	t.Helper()
	cmds, err := repo.GetPendingForSensor(ctx, tenantID, &sensorID, nil, 100)
	if err != nil {
		t.Fatalf("poll: %v", err)
	}
	out := map[shared.ID]bool{}
	for _, c := range cmds {
		out[c.ID] = true
	}
	return out
}

func TestScanZoneRepository_CRUDAndTenantIsolation(t *testing.T) {
	sqlDB := openSensorDB(t)
	ctx := context.Background()
	repo := NewScanZoneRepository(&DB{DB: sqlDB})
	tenantA := seedTestTenant(ctx, t, sqlDB)
	tenantB := seedTestTenant(ctx, t, sqlDB)

	dc := newTestZone(t, tenantA, "DC-230", false, "10.230.0.0/16", "fd00:230::/48")
	if err := repo.Create(ctx, dc); err != nil {
		t.Fatalf("create: %v", err)
	}
	got, err := repo.GetByID(ctx, tenantA, dc.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if len(got.Ranges) != 2 || got.Ranges[0].String() != "10.230.0.0/16" || got.Ranges[1].String() != "fd00:230::/48" {
		t.Errorf("ranges round-trip = %v", got.Ranges)
	}

	// Names are unique per tenant, case-insensitively; another tenant may reuse one.
	if err := repo.Create(ctx, newTestZone(t, tenantA, "dc-230", false, "10.1.0.0/16")); !errors.Is(err, scanzone.ErrZoneNameTaken) {
		t.Errorf("duplicate name: err = %v, want ErrZoneNameTaken", err)
	}
	if err := repo.Create(ctx, newTestZone(t, tenantB, "DC-230", false, "10.230.0.0/16")); err != nil {
		t.Errorf("same name in another tenant: %v", err)
	}

	// One default zone per tenant.
	if err := repo.Create(ctx, newTestZone(t, tenantA, "internet", true)); err != nil {
		t.Fatalf("default zone: %v", err)
	}
	if err := repo.Create(ctx, newTestZone(t, tenantA, "internet-2", true)); !errors.Is(err, scanzone.ErrDefaultZoneTaken) {
		t.Errorf("second default zone: err = %v, want ErrDefaultZoneTaken", err)
	}

	// Another tenant cannot read, change or delete the zone.
	if _, err := repo.GetByID(ctx, tenantB, dc.ID); !errors.Is(err, scanzone.ErrZoneNotFound) {
		t.Errorf("cross-tenant get: %v", err)
	}
	foreign := *dc
	foreign.TenantID = tenantB
	foreign.Name = "hijacked"
	if err := repo.Update(ctx, &foreign); !errors.Is(err, scanzone.ErrZoneNotFound) {
		t.Errorf("cross-tenant update: %v", err)
	}
	if err := repo.Delete(ctx, tenantB, dc.ID); !errors.Is(err, scanzone.ErrZoneNotFound) {
		t.Errorf("cross-tenant delete: %v", err)
	}
	if got, _ := repo.GetByID(ctx, tenantA, dc.ID); got == nil || got.Name != "DC-230" {
		t.Errorf("zone changed by another tenant: %+v", got)
	}

	zones, err := repo.List(ctx, tenantA)
	if err != nil || len(zones) != 2 {
		t.Fatalf("list = %d zones, err %v", len(zones), err)
	}
	if n, _ := repo.Count(ctx, tenantA); n != 2 {
		t.Errorf("count = %d", n)
	}
}

func TestScanZoneRepository_AssignmentIsSameTenantInSQL(t *testing.T) {
	sqlDB := openSensorDB(t)
	ctx := context.Background()
	repo := NewScanZoneRepository(&DB{DB: sqlDB})
	tenantA := seedTestTenant(ctx, t, sqlDB)
	tenantB := seedTestTenant(ctx, t, sqlDB)

	zoneA := newTestZone(t, tenantA, "a", false, "10.1.0.0/16")
	zoneB := newTestZone(t, tenantB, "b", false, "10.2.0.0/16")
	for _, z := range []*scanzone.Zone{zoneA, zoneB} {
		if err := repo.Create(ctx, z); err != nil {
			t.Fatal(err)
		}
	}
	sensorA := seedZoneSensor(ctx, t, sqlDB, &tenantA, "a", zoneSensorOpts{tools: []string{"nuclei"}})
	sensorB := seedZoneSensor(ctx, t, sqlDB, &tenantB, "b", zoneSensorOpts{tools: []string{"nuclei"}})
	platform := seedZoneSensor(ctx, t, sqlDB, &tenantA, "platform", zoneSensorOpts{tools: []string{"nuclei"}, platform: true})

	if err := repo.AssignSensor(ctx, tenantA, zoneA.ID, sensorA, nil); err != nil {
		t.Fatalf("assign own sensor: %v", err)
	}
	if err := repo.AssignSensor(ctx, tenantA, zoneA.ID, sensorA, nil); err != nil {
		t.Errorf("assign is not idempotent: %v", err)
	}
	if err := repo.AssignSensor(ctx, tenantA, zoneA.ID, sensorB, nil); !errors.Is(err, scanzone.ErrSensorNotFound) {
		t.Errorf("other tenant's sensor: err = %v, want ErrSensorNotFound", err)
	}
	if err := repo.AssignSensor(ctx, tenantA, zoneB.ID, sensorA, nil); !errors.Is(err, scanzone.ErrZoneNotFound) {
		t.Errorf("other tenant's zone: err = %v, want ErrZoneNotFound", err)
	}
	if err := repo.AssignSensor(ctx, tenantA, zoneA.ID, platform, nil); !errors.Is(err, scanzone.ErrSensorNotFound) {
		t.Errorf("platform sensor: err = %v, want ErrSensorNotFound", err)
	}
	// The schema itself refuses a mixed-tenant row, whatever the caller does.
	_, err := sqlDB.ExecContext(ctx,
		`INSERT INTO scan_zone_sensors (tenant_id, zone_id, sensor_id) VALUES ($1, $2, $3)`,
		tenantB.String(), zoneA.ID.String(), sensorB.String())
	if !isForeignKeyViolation(err) {
		t.Errorf("raw cross-tenant insert: err = %v, want a foreign-key violation", err)
	}

	got, _ := repo.GetByID(ctx, tenantA, zoneA.ID)
	if len(got.SensorIDs) != 1 || got.SensorIDs[0] != sensorA {
		t.Errorf("zone sensors = %v", got.SensorIDs)
	}
	if removed, err := repo.UnassignSensor(ctx, tenantB, zoneA.ID, sensorA); err != nil || removed {
		t.Errorf("cross-tenant unassign removed=%v err=%v", removed, err)
	}
	if removed, err := repo.UnassignSensor(ctx, tenantA, zoneA.ID, sensorA); err != nil || !removed {
		t.Errorf("unassign removed=%v err=%v", removed, err)
	}
}

// Layer 2 (RFC-023 D7): the poll and the claim only hand a zone's command to
// a sensor assigned to that zone that has the command's tool.
func TestCommandClaim_ZonePredicate(t *testing.T) {
	sqlDB := openSensorDB(t)
	ctx := context.Background()
	db := &DB{DB: sqlDB}
	zones := NewScanZoneRepository(db)
	cmds := NewCommandRepository(db)
	tenant := seedTestTenant(ctx, t, sqlDB)

	zoneA := newTestZone(t, tenant, "a", false, "10.1.0.0/16")
	zoneB := newTestZone(t, tenant, "b", false, "10.2.0.0/16")
	for _, z := range []*scanzone.Zone{zoneA, zoneB} {
		if err := zones.Create(ctx, z); err != nil {
			t.Fatal(err)
		}
	}
	s1 := seedZoneSensor(ctx, t, sqlDB, &tenant, "s1", zoneSensorOpts{tools: []string{"nuclei"}})
	s1b := seedZoneSensor(ctx, t, sqlDB, &tenant, "s1b", zoneSensorOpts{tools: []string{"nuclei"}})
	s2 := seedZoneSensor(ctx, t, sqlDB, &tenant, "s2", zoneSensorOpts{tools: []string{"nuclei"}})
	s1noTool := seedZoneSensor(ctx, t, sqlDB, &tenant, "s1-no-nuclei", zoneSensorOpts{tools: []string{"betterleaks"}})
	outsider := seedZoneSensor(ctx, t, sqlDB, &tenant, "no-zone", zoneSensorOpts{tools: []string{"nuclei"}})
	for _, a := range []struct{ z, s shared.ID }{{zoneA.ID, s1}, {zoneA.ID, s1b}, {zoneA.ID, s1noTool}, {zoneB.ID, s2}} {
		if err := zones.AssignSensor(ctx, tenant, a.z, a.s, nil); err != nil {
			t.Fatal(err)
		}
	}

	pinnedA := createZoneCommand(ctx, t, cmds, tenant, &zoneA.ID, &s1, "nuclei")
	poolA := createZoneCommand(ctx, t, cmds, tenant, &zoneA.ID, nil, "nuclei")
	pinnedB := createZoneCommand(ctx, t, cmds, tenant, &zoneB.ID, &s2, "nuclei")
	unzoned := createZoneCommand(ctx, t, cmds, tenant, nil, nil, "nuclei")

	got := polledIDs(ctx, t, cmds, tenant, s1)
	if !got[pinnedA] || !got[poolA] || !got[unzoned] || got[pinnedB] {
		t.Errorf("s1 (zone a) polled %v; want pinnedA, poolA, unzoned and not pinnedB", got)
	}
	got = polledIDs(ctx, t, cmds, tenant, s2)
	if got[poolA] || got[pinnedA] || !got[pinnedB] || !got[unzoned] {
		t.Errorf("s2 (zone b) polled %v; want pinnedB and unzoned only", got)
	}
	got = polledIDs(ctx, t, cmds, tenant, outsider)
	if got[poolA] || got[pinnedA] || got[pinnedB] || !got[unzoned] {
		t.Errorf("sensor in no zone polled %v; want only the unzoned command", got)
	}
	got = polledIDs(ctx, t, cmds, tenant, s1noTool)
	if got[poolA] {
		t.Error("zone sensor without the command's tool was offered it")
	}

	// The claim refuses what the poll would not offer, by id.
	if ok, err := cmds.ClaimForSensor(ctx, tenant, poolA, s2.String()); err != nil || ok {
		t.Errorf("sensor of zone b claimed a zone-a command: ok=%v err=%v", ok, err)
	}
	if ok, err := cmds.ClaimForSensor(ctx, tenant, poolA, outsider.String()); err != nil || ok {
		t.Errorf("sensor in no zone claimed a zone command: ok=%v err=%v", ok, err)
	}
	if ok, err := cmds.ClaimForSensor(ctx, tenant, poolA, s1b.String()); err != nil || !ok {
		t.Errorf("zone-a sensor could not claim the zone-a pool command: ok=%v err=%v", ok, err)
	}

	// The reaper unpins a stuck command; it must stay inside its zone.
	if _, err := sqlDB.ExecContext(ctx, `UPDATE commands SET sensor_id = NULL WHERE id = $1`, pinnedB.String()); err != nil {
		t.Fatal(err)
	}
	if got := polledIDs(ctx, t, cmds, tenant, outsider); got[pinnedB] {
		t.Error("an unpinned zone-b command leaked to a sensor outside the zone")
	}
	if got := polledIDs(ctx, t, cmds, tenant, s2); !got[pinnedB] {
		t.Error("the zone-b sensor lost the unpinned zone-b command")
	}

	// Unassigning s1 returns its pending zone commands to the zone pool.
	if _, err := zones.UnassignSensor(ctx, tenant, zoneA.ID, s1); err != nil {
		t.Fatal(err)
	}
	if got := polledIDs(ctx, t, cmds, tenant, s1); got[pinnedA] {
		t.Error("a sensor removed from the zone still receives the zone's command")
	}
	if got := polledIDs(ctx, t, cmds, tenant, s1b); !got[pinnedA] {
		t.Error("the zone's remaining sensor did not inherit the unpinned command")
	}

	// A zone with active commands cannot be deleted; one without can.
	if err := zones.Delete(ctx, tenant, zoneA.ID); !errors.Is(err, scanzone.ErrZoneInUse) {
		t.Errorf("delete zone with active commands: err = %v, want ErrZoneInUse", err)
	}
	if _, err := sqlDB.ExecContext(ctx, `UPDATE commands SET status = 'completed' WHERE scan_zone_id = $1`, zoneA.ID.String()); err != nil {
		t.Fatal(err)
	}
	if err := zones.Delete(ctx, tenant, zoneA.ID); err != nil {
		t.Errorf("delete idle zone: %v", err)
	}
}

func TestScanZoneRepository_RoutableSensors(t *testing.T) {
	sqlDB := openSensorDB(t)
	ctx := context.Background()
	db := &DB{DB: sqlDB}
	zones := NewScanZoneRepository(db)
	cmds := NewCommandRepository(db)
	tenant := seedTestTenant(ctx, t, sqlDB)
	z := newTestZone(t, tenant, "dc", false, "10.0.0.0/8")
	if err := zones.Create(ctx, z); err != nil {
		t.Fatal(err)
	}
	stale := time.Now().Add(-time.Hour)
	busy := seedZoneSensor(ctx, t, sqlDB, &tenant, "busy", zoneSensorOpts{tools: []string{"nuclei"}})
	idle := seedZoneSensor(ctx, t, sqlDB, &tenant, "idle", zoneSensorOpts{tools: []string{"nuclei"}})
	offline := seedZoneSensor(ctx, t, sqlDB, &tenant, "offline", zoneSensorOpts{tools: []string{"nuclei"}, health: "offline", lastSeen: &stale})
	disabled := seedZoneSensor(ctx, t, sqlDB, &tenant, "disabled", zoneSensorOpts{tools: []string{"nuclei"}, status: "disabled"})
	noTool := seedZoneSensor(ctx, t, sqlDB, &tenant, "no-tool", zoneSensorOpts{tools: []string{"betterleaks"}})
	for _, s := range []shared.ID{busy, idle, offline, disabled, noTool} {
		if err := zones.AssignSensor(ctx, tenant, z.ID, s, nil); err != nil {
			t.Fatal(err)
		}
	}
	createZoneCommand(ctx, t, cmds, tenant, &z.ID, &busy, "nuclei")

	got, err := zones.RoutableSensors(ctx, tenant, []shared.ID{z.ID}, "nuclei")
	if err != nil {
		t.Fatal(err)
	}
	list := got[z.ID]
	if len(list) != 2 || list[0].ID != idle || list[1].ID != busy {
		t.Fatalf("routable = %+v; want idle then busy, nothing offline/disabled/without the tool", list)
	}
	if list[1].ActiveCommands != 1 {
		t.Errorf("busy sensor active commands = %d", list[1].ActiveCommands)
	}
	other := seedTestTenant(ctx, t, sqlDB)
	if got, _ := zones.RoutableSensors(ctx, other, []shared.ID{z.ID}, "nuclei"); len(got[z.ID]) != 0 {
		t.Error("another tenant listed the zone's sensors")
	}
}

func TestScanZoneRepository_Coverage(t *testing.T) {
	sqlDB := openSensorDB(t)
	ctx := context.Background()
	zones := NewScanZoneRepository(&DB{DB: sqlDB})
	tenant := seedTestTenant(ctx, t, sqlDB)
	for _, a := range []struct{ name, typ string }{
		{"10.1.0.5", "ip_address"}, {"10.1.0.6", "ip_address"}, // in zone
		{"192.168.9.9", "ip_address"}, // private, outside
		{"8.8.8.8", "ip_address"},     // public, outside
		{"10.1.0.7", "host"},          // a host named by its address
		{"db.corp.example", "host"},   // not an address: ignored
		{"10.1.0.0/24", "ip_address"}, // a range, not an address: ignored
		{"10.1.0.8", "domain"},        // not an address asset type: ignored
	} {
		if _, err := sqlDB.ExecContext(ctx, `INSERT INTO assets (tenant_id, name, asset_type) VALUES ($1, $2, $3)`,
			tenant.String(), a.name, a.typ); err != nil {
			t.Fatalf("seed asset %s: %v", a.name, err)
		}
	}
	z := newTestZone(t, tenant, "dc", false, "10.1.0.0/16")
	if err := zones.Create(ctx, z); err != nil {
		t.Fatal(err)
	}
	cov, err := zones.Coverage(ctx, tenant)
	if err != nil {
		t.Fatal(err)
	}
	if cov.InventoryAddresses != 5 || cov.InZones != 3 || cov.OutsidePrivate != 1 || cov.OutsidePublic != 1 || cov.HasDefaultZone {
		t.Errorf("coverage = %+v", cov)
	}
	if len(cov.Zones) != 1 || cov.Zones[0].Addresses != 3 || !cov.Zones[0].HasPrivateRange || cov.Zones[0].AssignedSensors != 0 {
		t.Errorf("zone coverage = %+v", cov.Zones)
	}
}

// A zoned run has several commands under one step run: the step's outcome is
// recorded once, after the last batch.
func TestCommandRepository_StepBatchGate(t *testing.T) {
	sqlDB := openSensorDB(t)
	ctx := context.Background()
	cmds := NewCommandRepository(&DB{DB: sqlDB})
	tenant := seedTestTenant(ctx, t, sqlDB)

	var runID, stepID, stepRunID string
	if err := sqlDB.QueryRowContext(ctx,
		`INSERT INTO pipeline_runs (pipeline_id, tenant_id, status, trigger_type)
		 VALUES ('00000000-0000-0000-0000-000000000001', $1, 'running', 'manual') RETURNING id`,
		tenant.String()).Scan(&runID); err != nil {
		t.Skipf("seed run (quick-scan template missing?): %v", err)
	}
	if err := sqlDB.QueryRowContext(ctx,
		`SELECT id FROM pipeline_steps WHERE pipeline_id = '00000000-0000-0000-0000-000000000001' LIMIT 1`).Scan(&stepID); err != nil {
		t.Skipf("quick-scan template has no step: %v", err)
	}
	if err := sqlDB.QueryRowContext(ctx,
		`INSERT INTO step_runs (pipeline_run_id, step_id, step_key, step_order) VALUES ($1, $2, 'scan', 1) RETURNING id`,
		runID, stepID).Scan(&stepRunID); err != nil {
		t.Fatal(err)
	}
	srID, _ := shared.IDFromString(stepRunID)

	mk := func(status, result, msg string) {
		cmd, _ := command.NewCommand(tenant, command.CommandTypeScan, command.CommandPriorityNormal, json.RawMessage(`{}`))
		cmd.SetStepRunID(srID)
		cmd.Status = command.CommandStatus(status)
		cmd.ErrorMessage = msg
		if result != "" {
			cmd.Result = json.RawMessage(result)
		}
		if err := cmds.Create(ctx, cmd); err != nil {
			t.Fatal(err)
		}
	}
	mk("completed", `{"findings_count": 3}`, "")
	mk("running", "", "")
	mk("failed", "", "nuclei crashed")

	b, err := cmds.StepBatchState(ctx, tenant, srID)
	if err != nil {
		t.Fatal(err)
	}
	if b.Total != 3 || b.Active != 1 || b.Failed != 1 || b.Findings != 3 || b.FirstError != "nuclei crashed" {
		t.Errorf("batch state = %+v", b)
	}
	if other, _ := cmds.StepBatchState(ctx, seedTestTenant(ctx, t, sqlDB), srID); other.Total != 0 {
		t.Error("another tenant saw the step's batches")
	}

	first, err := cmds.ClaimStepFinalization(ctx, srID)
	if err != nil || !first {
		t.Fatalf("first finalization claim = %v, %v", first, err)
	}
	if second, _ := cmds.ClaimStepFinalization(ctx, srID); second {
		t.Error("the step was finalized twice")
	}
}

// The zone picker: a scan stores the zone it pins its targets to, and a zone
// that scans still pin cannot be deleted.
func TestScanZoneRepository_ScanZonePicker(t *testing.T) {
	sqlDB := openSensorDB(t)
	ctx := context.Background()
	db := &DB{DB: sqlDB}
	zones := NewScanZoneRepository(db)
	scans := NewScanRepository(db)
	tenant := seedTestTenant(ctx, t, sqlDB)
	z := newTestZone(t, tenant, "picked", false, "10.40.0.0/16")
	if err := zones.Create(ctx, z); err != nil {
		t.Fatal(err)
	}

	sc, err := scan.NewScanWithTargets(tenant, "pinned-"+shared.NewID().String(), []string{"10.40.0.1"}, scan.ScanTypeSingle)
	if err != nil {
		t.Fatal(err)
	}
	if err := sc.SetSingleScanner("nuclei", nil, 1); err != nil {
		t.Fatal(err)
	}
	sc.SetScanZone(&z.ID)
	if err := scans.Create(ctx, sc); err != nil {
		t.Fatal(err)
	}
	got, err := scans.GetByTenantAndID(ctx, tenant, sc.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.ScanZoneID == nil || *got.ScanZoneID != z.ID {
		t.Fatalf("scan_zone_id = %v, want %s", got.ScanZoneID, z.ID)
	}

	err = zones.Delete(ctx, tenant, z.ID)
	var de *shared.DomainError
	if !errors.As(err, &de) || de.Code != "ZONE_IN_USE" || !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("delete a zone a scan pins: err = %v, want ZONE_IN_USE conflict", err)
	}

	got.SetScanZone(nil)
	if err := scans.Update(ctx, got); err != nil {
		t.Fatal(err)
	}
	again, err := scans.GetByTenantAndID(ctx, tenant, sc.ID)
	if err != nil {
		t.Fatal(err)
	}
	if again.ScanZoneID != nil {
		t.Errorf("scan_zone_id = %v after switching to Automatic", again.ScanZoneID)
	}
	if err := zones.Delete(ctx, tenant, z.ID); err != nil {
		t.Errorf("delete zone no scan pins: %v", err)
	}
}

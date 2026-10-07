package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/command"
	"github.com/openctemio/openctem/api/pkg/domain/scanfreeze"
	"github.com/openctemio/openctem/api/pkg/domain/scanzone"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Scan freeze windows against a real schema: tenant isolation, the active
// expression across time zones and DST changes, and the claim-time hold.
// Requires DATABASE_URL (CI applies every migration first).

func mustTime(t *testing.T, s string) time.Time {
	t.Helper()
	ts, err := time.Parse(time.RFC3339, s)
	if err != nil {
		t.Fatal(err)
	}
	return ts
}

func newFreezeWindow(t *testing.T, tenantID shared.ID, zoneID *shared.ID, spec scanfreeze.Spec) *scanfreeze.Window {
	t.Helper()
	if spec.Name == "" {
		spec.Name = "maintenance"
	}
	spec.Enabled = true
	// Creation refuses a one-off window that already ended; tests place
	// windows anywhere in time, so create "now" before the window.
	now := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	w, err := scanfreeze.NewWindow(tenantID, zoneID, spec, nil, now)
	if err != nil {
		t.Fatalf("NewWindow: %v", err)
	}
	return w
}

func weekly(tz string, days []int, start, end string) scanfreeze.Spec {
	return scanfreeze.Spec{Timezone: tz, Recurrence: scanfreeze.RecurrenceWeekly, Days: days, StartTime: start, EndTime: end}
}

func TestScanFreezeWindowRepository_CRUDAndTenantIsolation(t *testing.T) {
	sqlDB := openSensorDB(t)
	ctx := context.Background()
	repo := NewScanFreezeWindowRepository(&DB{DB: sqlDB})
	zones := NewScanZoneRepository(&DB{DB: sqlDB})
	tenantA := seedTestTenant(ctx, t, sqlDB)
	tenantB := seedTestTenant(ctx, t, sqlDB)

	zoneB := newTestZone(t, tenantB, "B-zone", false, "10.77.0.0/16")
	if err := zones.Create(ctx, zoneB); err != nil {
		t.Fatal(err)
	}

	w := newFreezeWindow(t, tenantA, nil, weekly("Europe/Berlin", []int{6, 7}, "22:00", "06:00"))
	if err := repo.Create(ctx, w); err != nil {
		t.Fatalf("create: %v", err)
	}
	got, err := repo.GetByID(ctx, tenantA, w.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Timezone != "Europe/Berlin" || got.StartMinute != 22*60 || got.EndMinute != 6*60 || len(got.Days) != 2 {
		t.Errorf("round trip = %+v", got)
	}

	// Another tenant cannot read, change, list or delete it.
	if _, err := repo.GetByID(ctx, tenantB, w.ID); !errors.Is(err, scanfreeze.ErrNotFound) {
		t.Errorf("cross-tenant get: %v, want not found", err)
	}
	other := *w
	other.TenantID = tenantB
	other.Name = "hijacked"
	if err := repo.Update(ctx, &other); !errors.Is(err, scanfreeze.ErrNotFound) {
		t.Errorf("cross-tenant update: %v, want not found", err)
	}
	if err := repo.Delete(ctx, tenantB, w.ID); !errors.Is(err, scanfreeze.ErrNotFound) {
		t.Errorf("cross-tenant delete: %v, want not found", err)
	}
	if ws, _ := repo.List(ctx, tenantB, scanfreeze.Filter{}); len(ws) != 0 {
		t.Errorf("tenant B lists %d windows of tenant A", len(ws))
	}

	// A window cannot name another tenant's zone (composite foreign key).
	foreign := newFreezeWindow(t, tenantA, &zoneB.ID, weekly("UTC", []int{1}, "00:00", "01:00"))
	if err := repo.Create(ctx, foreign); !errors.Is(err, scanfreeze.ErrZoneNotFound) {
		t.Errorf("window on another tenant's zone: %v, want zone not found", err)
	}

	// A time zone the database does not know is refused before it reaches
	// the claim predicate.
	bad := newFreezeWindow(t, tenantA, nil, weekly("UTC", []int{1}, "00:00", "01:00"))
	bad.Timezone = "Mars/Olympus"
	if err := repo.Create(ctx, bad); !errors.Is(err, shared.ErrValidation) {
		t.Errorf("unknown time zone: %v, want validation error", err)
	}

	if n, _ := repo.Count(ctx, tenantA); n != 1 {
		t.Errorf("count = %d, want 1", n)
	}
	if err := repo.Delete(ctx, tenantA, w.ID); err != nil {
		t.Fatalf("delete: %v", err)
	}
}

// The active expression, evaluated by the database at fixed instants: wall
// clock in the window's zone, overnight windows, and both DST changes.
func TestScanFreezeWindowRepository_ActiveAtTimeZonesAndDST(t *testing.T) {
	sqlDB := openSensorDB(t)
	ctx := context.Background()
	repo := NewScanFreezeWindowRepository(&DB{DB: sqlDB})

	type probe struct {
		at     string
		active bool
		until  string // RFC3339, when active
	}
	cases := []struct {
		name   string
		spec   scanfreeze.Spec
		probes []probe
	}{
		{
			name: "same-day weekly window in New York",
			spec: weekly("America/New_York", []int{3}, "01:00", "03:00"), // Wednesdays
			probes: []probe{
				{"2026-07-15T05:00:00Z", true, "2026-07-15T07:00:00Z"}, // Wed 01:00 EDT
				{"2026-07-15T06:59:59Z", true, "2026-07-15T07:00:00Z"},
				{"2026-07-15T07:00:00Z", false, ""}, // 03:00 EDT, end exclusive
				{"2026-07-15T04:59:00Z", false, ""}, // 00:59 EDT
				{"2026-07-16T05:30:00Z", false, ""}, // Thursday
			},
		},
		{
			name: "overnight window ends the next day",
			spec: weekly("Europe/Berlin", []int{5}, "22:00", "06:00"), // Friday night
			probes: []probe{
				{"2026-07-17T20:30:00Z", true, "2026-07-18T04:00:00Z"}, // Fri 22:30 CEST
				{"2026-07-18T03:59:00Z", true, "2026-07-18T04:00:00Z"}, // Sat 05:59 CEST
				{"2026-07-18T04:00:00Z", false, ""},                    // Sat 06:00
				{"2026-07-18T20:30:00Z", false, ""},                    // Saturday night is not listed
				{"2026-07-17T03:00:00Z", false, ""},                    // Fri 05:00: Thursday is not listed
			},
		},
		{
			name: "equal times freeze the whole day",
			spec: weekly("Asia/Ho_Chi_Minh", []int{7}, "00:00", "00:00"), // Sundays, UTC+7
			probes: []probe{
				{"2026-07-18T17:00:00Z", true, "2026-07-19T17:00:00Z"}, // Sun 00:00 local
				{"2026-07-19T16:59:00Z", true, "2026-07-19T17:00:00Z"},
				{"2026-07-19T17:00:00Z", false, ""}, // Mon 00:00 local
			},
		},
		{
			name: "spring forward: the skipped hour shortens the window",
			// 2026-03-29: Berlin goes from 02:00 CET to 03:00 CEST.
			spec: weekly("Europe/Berlin", []int{7}, "01:00", "04:00"),
			probes: []probe{
				{"2026-03-29T00:00:00Z", true, "2026-03-29T02:00:00Z"}, // 01:00 CET; ends 04:00 CEST
				{"2026-03-29T01:30:00Z", true, "2026-03-29T02:00:00Z"}, // 03:30 CEST
				{"2026-03-29T02:00:00Z", false, ""},                    // 04:00 CEST: two real hours
			},
		},
		{
			name: "fall back: the repeated hour is frozen on both passes",
			// 2026-10-25: Berlin goes from 03:00 CEST back to 02:00 CET.
			spec: weekly("Europe/Berlin", []int{7}, "02:00", "03:00"),
			probes: []probe{
				{"2026-10-25T00:30:00Z", true, "2026-10-25T02:00:00Z"}, // 02:30 CEST, first pass
				{"2026-10-25T01:30:00Z", true, "2026-10-25T02:00:00Z"}, // 02:30 CET, second pass
				{"2026-10-25T02:00:00Z", false, ""},                    // 03:00 CET
			},
		},
		{
			name: "one-off window uses instants",
			spec: scanfreeze.Spec{Timezone: "UTC", Recurrence: scanfreeze.RecurrenceOnce,
				StartsAt: ptrTime(mustTime(t, "2026-12-24T18:00:00Z")), EndsAt: ptrTime(mustTime(t, "2026-12-26T06:00:00Z"))},
			probes: []probe{
				{"2026-12-24T17:59:59Z", false, ""},
				{"2026-12-24T18:00:00Z", true, "2026-12-26T06:00:00Z"},
				{"2026-12-26T06:00:00Z", false, ""},
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tenant := seedTestTenant(ctx, t, sqlDB)
			w := newFreezeWindow(t, tenant, nil, tc.spec)
			if err := repo.Create(ctx, w); err != nil {
				t.Fatalf("create: %v", err)
			}
			for _, p := range tc.probes {
				at := mustTime(t, p.at)
				ws, err := repo.ActiveAt(ctx, tenant, nil, at)
				if err != nil {
					t.Fatalf("%s: %v", p.at, err)
				}
				if got := len(ws) == 1; got != p.active {
					t.Errorf("%s: active = %v, want %v", p.at, got, p.active)
					continue
				}
				if p.active {
					if want := mustTime(t, p.until); ws[0].ActiveUntil == nil || !ws[0].ActiveUntil.Equal(want) {
						t.Errorf("%s: until = %v, want %s", p.at, ws[0].ActiveUntil, p.until)
					}
				}
			}
		})
	}
}

func ptrTime(t time.Time) *time.Time { return &t }

func createTypedCommand(ctx context.Context, t *testing.T, repo *CommandRepository, tenantID shared.ID, zoneID *shared.ID,
	typ command.CommandType, payload map[string]any, override bool) shared.ID {
	t.Helper()
	raw, _ := json.Marshal(payload)
	cmd, err := command.NewCommand(tenantID, typ, command.CommandPriorityNormal, raw)
	if err != nil {
		t.Fatal(err)
	}
	if zoneID != nil {
		cmd.SetScanZone(*zoneID)
	}
	cmd.FreezeOverride = override
	if err := repo.Create(ctx, cmd); err != nil {
		t.Fatalf("create command: %v", err)
	}
	return cmd.ID
}

// The claim-time hold: whatever created a command (trigger, workflow step,
// direct POST /commands, validation, EASM), active work of a frozen tenant
// or zone is neither offered, counted for the doorbell, nor claimable by id.
func TestScanFreezeWindow_ClaimHold(t *testing.T) {
	sqlDB := openSensorDB(t)
	ctx := context.Background()
	db := &DB{DB: sqlDB}
	cmds := NewCommandRepository(db)
	windows := NewScanFreezeWindowRepository(db)
	zones := NewScanZoneRepository(db)
	tenant := seedTestTenant(ctx, t, sqlDB)
	otherTenant := seedTestTenant(ctx, t, sqlDB)
	tools := []string{"nuclei", "subfinder"}
	sensor := seedZoneSensor(ctx, t, sqlDB, &tenant, "s", zoneSensorOpts{tools: tools})

	frozenZone := newTestZone(t, tenant, "frozen", false, "10.81.0.0/16")
	openZone := newTestZone(t, tenant, "open", false, "10.82.0.0/16")
	for _, z := range []*scanzone.Zone{frozenZone, openZone} {
		if err := zones.Create(ctx, z); err != nil {
			t.Fatal(err)
		}
		if err := zones.AssignSensor(ctx, tenant, z.ID, sensor, nil); err != nil {
			t.Fatal(err)
		}
	}

	allWeek := weekly("UTC", []int{1, 2, 3, 4, 5, 6, 7}, "00:00", "00:00")
	zoneWindow := newFreezeWindow(t, tenant, &frozenZone.ID, allWeek)
	if err := windows.Create(ctx, zoneWindow); err != nil {
		t.Fatal(err)
	}
	// Another tenant's tenant-wide window must not touch this tenant.
	if err := windows.Create(ctx, newFreezeWindow(t, otherTenant, nil, allWeek)); err != nil {
		t.Fatal(err)
	}

	nuclei := map[string]any{"scanner": "nuclei", "targets": []string{"10.81.0.1"}}
	activeInFrozen := createTypedCommand(ctx, t, cmds, tenant, &frozenZone.ID, command.CommandTypeScan, nuclei, false)
	noToolInFrozen := createTypedCommand(ctx, t, cmds, tenant, &frozenZone.ID, command.CommandTypeScan, map[string]any{"targets": []string{"10.81.0.2"}}, false)
	validateInFrozen := createTypedCommand(ctx, t, cmds, tenant, &frozenZone.ID, command.CommandTypeValidate, map[string]any{"target": "10.81.0.3"}, false)
	passiveInFrozen := createTypedCommand(ctx, t, cmds, tenant, &frozenZone.ID, command.CommandTypeScan,
		map[string]any{"scanner": "subfinder", "targets": []string{"example.com"}}, false)
	collectInFrozen := createTypedCommand(ctx, t, cmds, tenant, &frozenZone.ID, command.CommandTypeCollect, map[string]any{}, false)
	overrideInFrozen := createTypedCommand(ctx, t, cmds, tenant, &frozenZone.ID, command.CommandTypeScan, nuclei, true)
	activeInOpen := createTypedCommand(ctx, t, cmds, tenant, &openZone.ID, command.CommandTypeScan, nuclei, false)
	activeUnzoned := createTypedCommand(ctx, t, cmds, tenant, nil, command.CommandTypeScan, nuclei, false)

	polled := polledIDs(ctx, t, cmds, tenant, sensor)
	for name, id := range map[string]shared.ID{"active scan": activeInFrozen, "scan without a tool": noToolInFrozen, "validation": validateInFrozen} {
		if polled[id] {
			t.Errorf("%s in the frozen zone was offered", name)
		}
	}
	for name, id := range map[string]shared.ID{
		"passive scan": passiveInFrozen, "collect": collectInFrozen, "overridden scan": overrideInFrozen,
		"scan in another zone": activeInOpen, "unzoned scan (zone window only)": activeUnzoned,
	} {
		if !polled[id] {
			t.Errorf("%s was held", name)
		}
	}
	work, err := cmds.PendingWorkForSensor(ctx, tenant, sensor, nil, 100)
	if err != nil {
		t.Fatal(err)
	}
	if work.Count != 5 {
		t.Errorf("doorbell counts %d claimable commands, want 5 (the held ones excluded)", work.Count)
	}
	if ok, err := cmds.ClaimForSensor(ctx, tenant, activeInFrozen, sensor.String()); err != nil || ok {
		t.Errorf("claim by id of held work = %v, %v; want refused", ok, err)
	}
	if got, err := cmds.ClaimManyForSensor(ctx, tenant, sensor, nil, []shared.ID{activeInFrozen, activeInOpen}); err != nil || len(got) != 1 || got[0] != activeInOpen {
		t.Errorf("batch claim = %v, %v; want only the command of the open zone", got, err)
	}

	// A tenant-wide window holds unzoned work too; disabling it releases.
	tenantWindow := newFreezeWindow(t, tenant, nil, allWeek)
	if err := windows.Create(ctx, tenantWindow); err != nil {
		t.Fatal(err)
	}
	if polledIDs(ctx, t, cmds, tenant, sensor)[activeUnzoned] {
		t.Error("unzoned active scan offered during a tenant-wide window")
	}
	tenantWindow.Enabled = false
	zoneWindow.Enabled = false
	for _, w := range []*scanfreeze.Window{tenantWindow, zoneWindow} {
		if err := windows.Update(ctx, w); err != nil {
			t.Fatal(err)
		}
	}
	if ok, err := cmds.ClaimForSensor(ctx, tenant, activeInFrozen, sensor.String()); err != nil || !ok {
		t.Errorf("claim after the windows were disabled = %v, %v; want claimed", ok, err)
	}
}

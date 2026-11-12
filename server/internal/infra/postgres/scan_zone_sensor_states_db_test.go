package postgres

import (
	"context"
	"testing"
	"time"

	"github.com/openctemio/openctem/server/pkg/domain/sensor"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
)

// ZoneSensorStates against the real SQL (research 466 g): every active
// sensor assigned to the zone, online or not, with its trust level and the
// allow_private it reported; never a disabled sensor, never another
// tenant's zone or sensor.
func TestScanZoneRepository_ZoneSensorStates(t *testing.T) {
	sqlDB := openSensorDB(t)
	ctx := context.Background()
	pg := &DB{DB: sqlDB}
	zones := NewScanZoneRepository(pg)
	sensors := NewSensorRepository(pg)
	tenant := seedTestTenant(ctx, t, sqlDB)
	other := seedTestTenant(ctx, t, sqlDB)

	zone := newTestZone(t, tenant, "dc", false, "10.60.0.0/16")
	if err := zones.Create(ctx, zone); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-48 * time.Hour)
	trusted := seedZoneSensor(ctx, t, sqlDB, &tenant, "core", zoneSensorOpts{})
	fresh := seedZoneSensor(ctx, t, sqlDB, &tenant, "edge", zoneSensorOpts{health: "offline", lastSeen: &old})
	disabled := seedZoneSensor(ctx, t, sqlDB, &tenant, "gone", zoneSensorOpts{status: "disabled"})
	for _, id := range []shared.ID{trusted, fresh, disabled} {
		if err := zones.AssignSensor(ctx, tenant, zone.ID, id, nil); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := sqlDB.ExecContext(ctx, `UPDATE sensors SET trust_level = CASE WHEN id = $2 THEN 'trusted' ELSE 'new' END WHERE tenant_id = $1`,
		tenant.String(), trusted.String()); err != nil {
		t.Fatal(err)
	}
	off := false
	setLocalPolicy(ctx, t, sensors, tenant, trusted, &sensor.LocalPolicyReport{State: sensor.LocalPolicyAbsent, AllowPrivate: &off})

	got, err := zones.ZoneSensorStates(ctx, tenant, []shared.ID{zone.ID})
	if err != nil {
		t.Fatal(err)
	}
	states := got[zone.ID]
	if len(states) != 2 {
		t.Fatalf("states = %+v, want the two active sensors", states)
	}
	byID := map[shared.ID]int{}
	for i, st := range states {
		byID[st.ID] = i
	}
	core, ok := byID[trusted]
	if !ok || !states[core].Trusted || !states[core].LocalPolicy.RefusesPrivate() {
		t.Errorf("core = %+v", states)
	}
	edge, ok := byID[fresh]
	if !ok || states[edge].Trusted || states[edge].LocalPolicy.RefusesPrivate() {
		t.Errorf("an offline New sensor is missing or wrong: %+v", states)
	}
	if _, ok := byID[disabled]; ok {
		t.Error("a disabled sensor counts")
	}

	// Another tenant asking for this zone gets nothing.
	if got, err := zones.ZoneSensorStates(ctx, other, []shared.ID{zone.ID}); err != nil || len(got[zone.ID]) != 0 {
		t.Fatalf("cross-tenant read: %+v %v", got, err)
	}
	if got, err := zones.ZoneSensorStates(ctx, tenant, nil); err != nil || len(got) != 0 {
		t.Fatalf("no zones: %+v %v", got, err)
	}
}

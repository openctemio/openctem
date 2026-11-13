package postgres

import (
	"context"
	"testing"

	"github.com/openctemio/openctem/server/pkg/domain/scanzone"
)

// Overlap ambiguity is per tenant (research 466 D9): another tenant's zone
// that holds the same range never makes a target ambiguous, because a
// tenant routes over its own zones only (List is tenant-scoped in SQL).
func TestScanZoneOverlap_OtherTenantsZoneNeverTies(t *testing.T) {
	sqlDB := openSensorDB(t)
	ctx := context.Background()
	zones := NewScanZoneRepository(&DB{DB: sqlDB})
	a := seedTestTenant(ctx, t, sqlDB)
	b := seedTestTenant(ctx, t, sqlDB)

	za := newTestZone(t, a, "office", false, "10.70.0.0/16")
	zb := newTestZone(t, b, "office", false, "10.70.0.0/16")
	for _, z := range []*scanzone.Zone{za, zb} {
		if err := zones.Create(ctx, z); err != nil {
			t.Fatal(err)
		}
	}
	sa := seedZoneSensor(ctx, t, sqlDB, &a, "a-edge", zoneSensorOpts{})
	sb := seedZoneSensor(ctx, t, sqlDB, &b, "b-edge", zoneSensorOpts{})
	if err := zones.AssignSensor(ctx, a, za.ID, sa, nil); err != nil {
		t.Fatal(err)
	}
	if err := zones.AssignSensor(ctx, b, zb.ID, sb, nil); err != nil {
		t.Fatal(err)
	}

	listA, err := zones.List(ctx, a)
	if err != nil {
		t.Fatal(err)
	}
	got := scanzone.NewRouter(listA, nil).Route(ctx, "10.70.1.1")
	if got.Zone == nil || got.Zone.ID != za.ID || got.Kind != "" {
		t.Fatalf("tenant A route = %+v, want its own zone", got)
	}
	if same := scanzone.SameRangeZones(za, listA); len(same) != 0 {
		t.Fatalf("another tenant's zone is reported as the same range: %+v", same)
	}

	// A second zone of tenant A with the same range and another sensor ties.
	za2 := newTestZone(t, a, "cloud", false, "10.70.0.0/16")
	if err := zones.Create(ctx, za2); err != nil {
		t.Fatal(err)
	}
	sa2 := seedZoneSensor(ctx, t, sqlDB, &a, "a-cloud", zoneSensorOpts{})
	if err := zones.AssignSensor(ctx, a, za2.ID, sa2, nil); err != nil {
		t.Fatal(err)
	}
	if listA, err = zones.List(ctx, a); err != nil {
		t.Fatal(err)
	}
	if got := scanzone.NewRouter(listA, nil).Route(ctx, "10.70.1.1"); got.Kind != scanzone.KindAmbiguousZone {
		t.Fatalf("tenant A with two sites on one range: %+v", got)
	}
	if same := scanzone.SameRangeZones(za, listA); len(same) != 1 || same[0].ID != za2.ID {
		t.Fatalf("same range zones = %+v", same)
	}
	// Tenant B still routes to its own zone.
	listB, err := zones.List(ctx, b)
	if err != nil {
		t.Fatal(err)
	}
	if got := scanzone.NewRouter(listB, nil).Route(ctx, "10.70.1.1"); got.Zone == nil || got.Zone.ID != zb.ID {
		t.Fatalf("tenant B route = %+v", got)
	}
}

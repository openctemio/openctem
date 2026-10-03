package scan

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/scanzone"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// listZones is a ZoneDirectory with fixed zones.
type listZones struct{ zones []*scanzone.Zone }

func (l listZones) List(context.Context, shared.ID) ([]*scanzone.Zone, error) { return l.zones, nil }
func (l listZones) RoutableSensors(context.Context, shared.ID, []shared.ID, string) (map[shared.ID][]scanzone.SensorCandidate, error) {
	return nil, nil
}

func mustGateZone(t *testing.T, tenant shared.ID, name string, sensors []shared.ID, ranges ...string) *scanzone.Zone {
	t.Helper()
	z, err := scanzone.NewZone(tenant, name, "", false, ranges, nil)
	if err != nil {
		t.Fatal(err)
	}
	z.SensorIDs = sensors
	return z
}

func refusedTargets(d *DispatchTargets) []string {
	out := make([]string, 0, len(d.Refused))
	for _, r := range d.Refused {
		out = append(out, r.Target)
	}
	return out
}

func TestResolveDispatchTargets_NoZones(t *testing.T) {
	svc := &Service{scopeExclusions: &stubExclusions{values: map[string]bool{"excluded.example.com": true}}, logger: logger.NewNop()}
	got, err := svc.ResolveDispatchTargets(context.Background(), DispatchTargetsInput{
		TenantID: shared.NewID(),
		Targets: []string{
			"app.example.com", " APP.example.com ", "excluded.example.com",
			"10.0.0.5", "127.0.0.1", "169.254.169.254", "203.0.113.9",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"app.example.com", "203.0.113.9"}; !reflect.DeepEqual(got.Allowed, want) {
		t.Fatalf("allowed = %v, want %v", got.Allowed, want)
	}
	if want := []string{"excluded.example.com"}; !reflect.DeepEqual(got.Excluded, want) {
		t.Fatalf("excluded = %v, want %v", got.Excluded, want)
	}
	refused := strings.Join(refusedTargets(got), ",")
	for _, ip := range []string{"10.0.0.5", "127.0.0.1", "169.254.169.254"} {
		if !strings.Contains(refused, ip) {
			t.Fatalf("%s must be refused without a zone covering it; refused = %v", ip, refused)
		}
	}
	if z, err := got.SingleZone(); err != nil || z != nil {
		t.Fatalf("SingleZone = %v, %v; want unzoned", z, err)
	}
}

func TestResolveDispatchTargets_FailsClosed(t *testing.T) {
	in := DispatchTargetsInput{TenantID: shared.NewID(), Targets: []string{"app.example.com"}}

	if _, err := (&Service{logger: logger.NewNop()}).ResolveDispatchTargets(context.Background(), in); !errors.Is(err, ErrDispatchGateUnavailable) {
		t.Fatalf("no exclusion filter: err = %v, want ErrDispatchGateUnavailable", err)
	}
	svc := &Service{scopeExclusions: &stubExclusions{err: errors.New("db down")}, logger: logger.NewNop()}
	if got, err := svc.ResolveDispatchTargets(context.Background(), in); err == nil {
		t.Fatalf("a failed exclusion lookup must refuse the dispatch, got %+v", got)
	}
}

func TestResolveDispatchTargets_Zones(t *testing.T) {
	tenant := shared.NewID()
	inZone, other := shared.NewID(), shared.NewID()
	dcA := mustGateZone(t, tenant, "dc-a", []shared.ID{inZone}, "10.1.0.0/16")
	dcB := mustGateZone(t, tenant, "dc-b", []shared.ID{other}, "10.2.0.0/16")
	empty := mustGateZone(t, tenant, "lab", nil, "10.3.0.0/16")
	svc := &Service{
		scopeExclusions: &stubExclusions{values: map[string]bool{"10.1.0.9": true}},
		zones:           listZones{zones: []*scanzone.Zone{dcA, dcB, empty}},
		logger:          logger.NewNop(),
	}

	got, err := svc.ResolveDispatchTargets(context.Background(), DispatchTargetsInput{
		TenantID: tenant,
		SensorID: &inZone,
		Targets:  []string{"10.1.0.5", "10.1.0.9", "10.2.0.5", "10.3.0.5", "10.4.0.5", "203.0.113.9"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"10.1.0.5", "203.0.113.9"}; !reflect.DeepEqual(got.Allowed, want) {
		t.Fatalf("allowed = %v, want %v", got.Allowed, want)
	}
	if want := []string{"10.1.0.9"}; !reflect.DeepEqual(got.Excluded, want) {
		t.Fatalf("excluded = %v, want %v", got.Excluded, want)
	}
	// 10.2.0.5: the pinned sensor is not in dc-b; 10.3.0.5: lab has no
	// sensor; 10.4.0.5: private, outside every zone.
	if want := []string{"10.4.0.5", "10.2.0.5", "10.3.0.5"}; !sameSet(refusedTargets(got), want) {
		t.Fatalf("refused = %v, want %v", got.Refused, want)
	}
	if z := got.Zone("10.1.0.5"); z == nil || !z.ID.Equals(dcA.ID) {
		t.Fatalf("zone of 10.1.0.5 = %v, want dc-a", z)
	}
	if _, err := got.SingleZone(); err == nil {
		t.Fatal("a zoned and an unzoned target in one job must need a split")
	}
}

func sameSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	seen := map[string]int{}
	for _, v := range a {
		seen[v]++
	}
	for _, v := range b {
		seen[v]--
	}
	for _, n := range seen {
		if n != 0 {
			return false
		}
	}
	return true
}

package scan

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/validator"
)

// fakePrivateSensors answers the own-sensor rule: unpinned work by any, a
// sensor by its id.
type fakePrivateSensors struct {
	any     bool
	sensors map[shared.ID]bool
	err     error
	asked   []*shared.ID
}

func (f *fakePrivateSensors) PrivateTargetAdmission(_ context.Context, _ shared.ID, sensorID *shared.ID) (bool, error) {
	f.asked = append(f.asked, sensorID)
	if f.err != nil {
		return false, f.err
	}
	if sensorID == nil {
		return f.any, nil
	}
	return f.sensors[*sensorID], nil
}

// Without zones, a private address goes to the organization's own sensors
// when their local policy allows private ranges; loopback, link-local and
// metadata addresses never do; at the claim the claiming sensor must qualify
// itself; a failed lookup stops the run.
func TestOwnSensorPrivateTargets_NoZones(t *testing.T) {
	own := &fakePrivateSensors{any: true, sensors: map[shared.ID]bool{}}
	svc := allowAllChecks(&Service{zones: &gateZones{}, logger: logger.NewNop()})
	svc.SetPrivateTargetSensors(own)
	sc := testScan("nuclei", "10.20.0.5", "192.168.1.0/24", "203.0.113.7", "169.254.169.254", "http://127.0.0.1:8080/")

	got, err := svc.resolveScanTargets(context.Background(), sc)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"10.20.0.5", "192.168.1.0/24", "203.0.113.7"}; !reflect.DeepEqual(got.Targets, want) {
		t.Fatalf("own sensors: targets = %v, want %v", got.Targets, want)
	}

	// Not every own sensor qualifies: the zone rule stands.
	own.any = false
	got, err = svc.resolveScanTargets(context.Background(), sc)
	if err != nil || !reflect.DeepEqual(got.Targets, []string{"203.0.113.7"}) {
		t.Fatalf("no qualifying sensors: %v %v", got.Targets, err)
	}

	// At the claim the claiming sensor decides, not the fleet.
	good, bad := shared.NewID(), shared.NewID()
	own.any, own.sensors[good] = true, true
	for sensor, want := range map[shared.ID][]string{good: {"10.20.0.5"}, bad: nil} {
		id := sensor
		d, err := svc.ResolveDispatchTargets(context.Background(), DispatchTargetsInput{
			TenantID: sc.TenantID, Targets: []string{"10.20.0.5"}, SensorID: &id,
			AllowNonNetworkTargets: true, SkipZoneRouting: true,
		})
		if err != nil {
			t.Fatal(err)
		}
		if len(d.Allowed) != len(want) || (len(want) > 0 && !reflect.DeepEqual(d.Allowed, want)) {
			t.Fatalf("claim by %s: allowed %v, want %v", id, d.Allowed, want)
		}
	}

	own.err = errors.New("db down")
	if _, err := svc.resolveScanTargets(context.Background(), sc); err == nil {
		t.Fatal("a failed admission lookup must stop the run")
	}
}

// Scan create: a private address is admitted for the organization's own
// sensors, never for a scan bound to platform sensors; the validator path
// of the gate (validated targets) asks about the claiming sensor.
func TestOwnSensorPrivateTargets_ValidatorPath(t *testing.T) {
	tenant := shared.NewID()
	own := &fakePrivateSensors{any: true}
	svc := &Service{zones: &gateZones{}, logger: logger.NewNop()}
	svc.SetPrivateTargetSensors(own)
	v := validator.NewTargetValidator(validator.WithAllowInternalIPs(false), validator.WithAllowLocalhost(false))

	res := v.ValidateTargets([]string{"10.1.2.3", "127.0.0.1"})
	admitted, err := svc.admitZonedPrivateTargets(context.Background(), tenant.String(), res, true, nil)
	if err != nil || !reflect.DeepEqual(admitted, []string{"10.1.2.3"}) || len(res.Invalid) != 1 {
		t.Fatalf("own sensors: admitted %v, invalid %v, err %v", admitted, res.Invalid, err)
	}

	res = v.ValidateTargets([]string{"10.1.2.3"})
	admitted, err = svc.admitZonedPrivateTargets(context.Background(), tenant.String(), res, false, nil)
	if err != nil || len(admitted) != 0 || len(res.Invalid) != 1 {
		t.Fatalf("platform-bound scan: admitted %v, err %v", admitted, err)
	}

	sensor := shared.NewID()
	own.asked = nil
	if _, _, err := svc.validateTargetsEach(context.Background(), tenant.String(), []string{"10.1.2.3"}, 10, &sensor); err != nil {
		t.Fatal(err)
	}
	if len(own.asked) != 1 || own.asked[0] == nil || *own.asked[0] != sensor {
		t.Fatalf("the claiming sensor was not asked: %v", own.asked)
	}
}

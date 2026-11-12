package unit

// research/191 W-1: under routing auto a run step goes to the shared fleet
// when no sensor of the organization has the tool and the organization may
// use shared sensors. The production adapter used to ask the selector in
// tenant-only mode and drop IsPlatform, so no step ever went shared.

import (
	"context"
	"testing"

	"github.com/openctemio/openctem/api/internal/app"
	"github.com/openctemio/openctem/api/internal/app/scanrun"
	"github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

func TestScanRunSelectorAdapter_AutoGoesSharedWhenNoTenantSensor(t *testing.T) {
	tenant := shared.NewID()
	allow := func(context.Context, shared.ID) (bool, string) { return true, "" }
	deny := func(context.Context, shared.ID) (bool, string) { return false, "shared_sensors_opted_out" }
	req := scanrun.SelectSensorRequest{TenantID: tenant, Capabilities: []string{"nuclei"}, Tool: "nuclei",
		Mode: scanrun.SelectTenantFirst, AllowQueue: true}

	for _, tc := range []struct {
		name    string
		sensors []*sensor.Sensor
		policy  app.SharedSensorsPolicy
		want    bool
	}{
		{"no tenant sensor, shared allowed", nil, allow, true},
		{"no tenant sensor, shared refused", nil, deny, false},
		{"no tenant sensor, no policy", nil, nil, false},
		{"tenant sensor free", []*sensor.Sensor{makeSensorSelSensor("own", 0, 5)}, allow, false},
		// A busy tenant fleet keeps its work: it is never moved to shared
		// sensors because the organization's own sensors are busy.
		{"tenant sensors busy", []*sensor.Sensor{makeSensorSelSensor("busy", 5, 5)}, allow, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			repo := newSensorSelMockSensorRepo()
			repo.availableSensors = tc.sensors
			a := app.NewScanRunSensorSelectorAdapter(newSensorSelSelector(repo), tc.policy)
			res, err := a.SelectSensor(context.Background(), req)
			if err != nil {
				t.Fatal(err)
			}
			if res.IsPlatform != tc.want {
				t.Fatalf("IsPlatform = %v, want %v", res.IsPlatform, tc.want)
			}
		})
	}
}

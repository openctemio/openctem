package sensor_test

import (
	"context"
	"slices"
	"testing"

	sensorapp "github.com/openctemio/openctem/api/internal/app/sensor"
	sensordom "github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

type fakeStopFinder struct {
	fakeCancelFinder
	stopTenant, stopSensor shared.ID
	stops                  []string
}

func (f *fakeStopFinder) CommandsToStop(_ context.Context, tenantID, sensorID shared.ID, _ []string) ([]string, error) {
	f.stopTenant, f.stopSensor = tenantID, sensorID
	return f.stops, nil
}

// The heartbeat answer lists the stalled commands the sensor holds, to stop
// and hand back, looked up for the sensor's own tenant and id only.
func TestCommandsToStop(t *testing.T) {
	ctx := context.Background()
	tenant := shared.NewID()
	a := &sensordom.Sensor{ID: shared.NewID(), TenantID: &tenant}
	running := []string{shared.NewID().String(), shared.NewID().String()}

	svc := sensorapp.NewSensorService(nil, nil, logger.NewNop())
	svc.SetCancelFinder(&fakeCancelFinder{})
	if got := svc.CommandsToStop(ctx, a, running); got != nil {
		t.Fatalf("a finder without stops answered %v", got)
	}
	f := &fakeStopFinder{stops: running[1:]}
	svc.SetCancelFinder(f)
	if got := svc.CommandsToStop(ctx, a, running); !slices.Equal(got, running[1:]) || f.stopTenant != tenant || f.stopSensor != a.ID {
		t.Fatalf("got %v for tenant %v sensor %v", got, f.stopTenant, f.stopSensor)
	}
	if got := svc.CommandsToStop(ctx, &sensordom.Sensor{ID: shared.NewID()}, running); got != nil {
		t.Fatalf("tenant-less sensor: %v", got)
	}
}

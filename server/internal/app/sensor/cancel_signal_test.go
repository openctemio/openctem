package sensor_test

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"testing"

	sensorapp "github.com/openctemio/openctem/api/internal/app/sensor"
	sensordom "github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

type fakeCancelFinder struct {
	gotTenant, gotSensor shared.ID
	gotIDs               []string
	out                  []string
	err                  error
}

func (f *fakeCancelFinder) CommandsToCancel(_ context.Context, tenantID, sensorID shared.ID, ids []string) ([]string, error) {
	f.gotTenant, f.gotSensor, f.gotIDs = tenantID, sensorID, ids
	return f.out, f.err
}

// The heartbeat answer carries the commands the sensor must stop. Before,
// the service had no way to say it, so a canceled or timed-out scan kept
// running on the sensor until it finished.
func TestCommandsToCancel(t *testing.T) {
	ctx := context.Background()
	tenant := shared.NewID()
	a := &sensordom.Sensor{ID: shared.NewID(), TenantID: &tenant}
	running := []string{shared.NewID().String(), shared.NewID().String()}

	svc := sensorapp.NewSensorService(nil, nil, logger.NewNop())
	if got := svc.CommandsToCancel(ctx, a, running); got != nil {
		t.Fatalf("without a finder: %v", got)
	}

	f := &fakeCancelFinder{out: running[:1]}
	svc.SetCancelFinder(f)
	got := svc.CommandsToCancel(ctx, a, running)
	if !slices.Equal(got, running[:1]) || f.gotTenant != tenant || f.gotSensor != a.ID || !slices.Equal(f.gotIDs, running) {
		t.Fatalf("got %v; finder saw tenant %v sensor %v ids %v", got, f.gotTenant, f.gotSensor, f.gotIDs)
	}

	// Nothing reported, no tenant: no query.
	f.gotIDs = nil
	if got := svc.CommandsToCancel(ctx, a, nil); got != nil || f.gotIDs != nil {
		t.Fatalf("empty running list: %v (queried %v)", got, f.gotIDs)
	}
	if got := svc.CommandsToCancel(ctx, &sensordom.Sensor{ID: shared.NewID()}, running); got != nil {
		t.Fatalf("tenant-less sensor: %v", got)
	}

	// A failing lookup never fails the heartbeat.
	f.err = errors.New("db down")
	if got := svc.CommandsToCancel(ctx, a, running); got != nil {
		t.Fatalf("on error: %v", got)
	}

	// Both lists are bounded: the running list it looks up, and the answer
	// (sdk-go reads at most 256 ids).
	f.err = nil
	many := make([]string, 2000)
	for i := range many {
		many[i] = fmt.Sprintf("%d", i)
	}
	f.out = many
	got = svc.CommandsToCancel(ctx, a, many)
	if len(f.gotIDs) != 1000 || len(got) != sensorapp.MaxCancelCommandIDs {
		t.Fatalf("bounds: looked up %d, answered %d", len(f.gotIDs), len(got))
	}
}

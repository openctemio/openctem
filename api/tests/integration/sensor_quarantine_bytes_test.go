package integration

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/internal/app/ingest"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/sensorresult"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Pending quarantine items are kept until someone reviews them, so the
// payload bytes a tenant's pending items hold are capped as well as their
// number (sensor → platform review, RE-11). The cap is per tenant: another
// tenant can still quarantine.
func TestSensorQuarantine_PendingBytesCappedPerTenant(t *testing.T) {
	r := newV2Rig(t, ingest.DefaultBlindingGuard())
	a, b := r.newTenant("quarantine-a"), r.newTenant("quarantine-b")
	repo := postgres.NewSensorResultRepository(&postgres.DB{DB: r.db})
	ctx := context.Background()
	limits := sensorresult.Limits{MaxPendingPerTenant: 100, MaxPendingPerSensor: 100, MaxPayloadBytes: 4096,
		MaxPendingBytesPerTenant: 1000}
	item := func(tenant, sensor shared.ID) *sensorresult.Item {
		return &sensorresult.Item{TenantID: tenant, SensorID: sensor, Protocol: sensorresult.ProtocolV2,
			Route: "test", ReportID: shared.NewID().String(), ToolName: "nuclei",
			Reason: sensorresult.ReasonNoCommand, Payload: []byte(`{"pad":"` + strings.Repeat("x", 590) + `"}`)}
	}

	if err := repo.Create(ctx, item(a.tenant, a.sensor), limits); err != nil {
		t.Fatalf("first item: %v", err)
	}
	if err := repo.Create(ctx, item(a.tenant, a.sensor), limits); !errors.Is(err, sensorresult.ErrFull) {
		t.Fatalf("an item over the tenant byte cap: %v, want ErrFull", err)
	}
	if err := repo.Create(ctx, item(b.tenant, b.sensor), limits); err != nil {
		t.Fatalf("another tenant must not be affected: %v", err)
	}
}

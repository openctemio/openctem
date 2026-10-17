package ingest

// Trusted collectors (docs/architecture/sensors.md, "Collector sensors"): a
// collector sensor an administrator promoted to trusted reports the
// tenant's own inventory systems (a hypervisor manager, a directory), so its
// reports are an integration source for attribute reconciliation (RFC-069):
// what it says about ownership is used like an integration's, under the
// tenant's reconciliation policy, and a person's decision still wins.

import (
	"context"
	"errors"

	"github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// trustedCollector reports whether the sensor that submitted a report is a
// collector of this tenant that an administrator trusted: its stored row is
// an active collector of the tenant (never a platform sensor), and its grant
// is at trust level trusted with push ingest in effect. It fails closed: no
// sensor store or grant reader, a read error, or no grant row is false.
func (s *Service) trustedCollector(ctx context.Context, agt *sensor.Sensor, tenantID shared.ID) bool {
	if agt == nil || agt.ID.IsZero() || s.sensorRepo == nil || s.grants == nil {
		return false
	}
	stored, err := s.sensorRepo.GetByID(ctx, agt.ID)
	if err != nil || stored == nil || stored.TenantID == nil || *stored.TenantID != tenantID ||
		stored.IsShared() || stored.Type != sensor.SensorTypeCollector || stored.Status != sensor.SensorStatusActive {
		return false
	}
	g, err := s.grants.Get(ctx, tenantID, agt.ID)
	if err != nil {
		if !errors.Is(err, shared.ErrNotFound) {
			s.logger.Warn("collector trust: grant read failed", "sensor_id", agt.ID.String(), "error", err)
		}
		return false
	}
	return g != nil && g.TenantID == tenantID && g.SensorID == agt.ID &&
		g.TrustLevel == sensor.TrustTrusted && g.Effective().AllowPushIngest
}

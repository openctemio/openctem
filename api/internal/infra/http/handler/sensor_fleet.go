package handler

import (
	"context"

	"github.com/openctemio/openctem/api/pkg/domain/sensor"
)

// FleetDaemons returns the tenant's sensors as fleet rows in daemon mode
// (the fleet read model, fleet_handler.go). The state is the one GET
// /sensors computes; a sensor can be offline, a CI pipeline cannot.
func (h *SensorHandler) FleetDaemons(ctx context.Context, tenantID string) ([]FleetItem, error) {
	sensors, err := h.service.ListAllSensors(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	policy, now := h.policyFor(ctx, tenantID), h.now()
	out := make([]FleetItem, 0, len(sensors))
	for _, s := range sensors {
		hl := s.AssessHealth(now, policy)
		role := fleetRoleScanner
		if s.Type == sensor.SensorTypeCollector {
			role = fleetRoleCollector
		}
		out = append(out, FleetItem{ID: s.ID.String(), Mode: FleetModeDaemon, Kind: FleetKindSensor, Role: role,
			Name: s.Name, Description: s.Hostname, Status: string(hl.State),
			Attention:  hl.State == sensor.StateOffline || hl.State == sensor.StateDegraded || hl.State == sensor.StateStale,
			Inactive:   hl.State == sensor.StateRevoked || hl.State == sensor.StateDisabled,
			LastSeenAt: s.LastSeenAt, Version: hl.Version, Links: FleetLinks{Self: "/api/v1/sensors/" + s.ID.String()}})
	}
	return out, nil
}

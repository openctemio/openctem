package routes

// Hostile sensor suite (see hostile_sensor_db_test.go): the control plane
// per tenant.

import (
	"net/http"
	"testing"

	protov2 "github.com/openctemio/openctem/api/pkg/sensorproto/v2"
)

// RE-8: the per-sensor control budgets used to be the only ones, so an
// organization with many sensors multiplied them without bound. The control
// plane now has a per-tenant budget on top: two sensors of one tenant share
// it, each within its own per-sensor budget.
func TestHostileSensor_ControlPlaneHasATenantBudget(t *testing.T) {
	oldRate, oldBurst := v2ControlRatePerTenant, v2ControlBurstPerTenant
	v2ControlRatePerTenant, v2ControlBurstPerTenant = 0.001, 4
	t.Cleanup(func() { v2ControlRatePerTenant, v2ControlBurstPerTenant = oldRate, oldBurst })
	h := newCtlHarness(t)
	a := h.newLimitedSensor(h.tenantID, "fleet-a", nil, nil, 5)
	b := h.newLimitedSensor(h.tenantID, "fleet-b", nil, nil, 5)

	beat := func(s ctlSensor) int {
		resp, _ := h.call(s.key, http.MethodPost, protov2.PathPrefix+protov2.HeartbeatPath, map[string]any{})
		return resp.StatusCode
	}
	ok := 0
	for range 3 {
		for _, s := range []ctlSensor{a, b} {
			if beat(s) == http.StatusOK {
				ok++
			}
		}
	}
	if ok != 4 {
		t.Fatalf("%d heartbeats accepted across two sensors, want the tenant burst of 4", ok)
	}
}

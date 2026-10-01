package handler

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/openctemio/api/pkg/domain/sensor"
	"github.com/openctemio/api/pkg/domain/shared"
)

// A platform sensor (tenant_id NULL) must be rejected with 403 on tenant-scoped
// sensor operations, not panic on agt.TenantID deref (recovered as a 500).
func TestRequireSensorTenant_RejectsNilTenant(t *testing.T) {
	rec := httptest.NewRecorder()
	agt := &sensor.Sensor{ID: shared.NewID()} // TenantID nil
	if requireSensorTenant(rec, agt) {
		t.Fatal("expected false for nil-tenant agent")
	}
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", rec.Code)
	}
}

func TestRequireSensorTenant_AllowsTenantSensor(t *testing.T) {
	rec := httptest.NewRecorder()
	tid := shared.NewID()
	agt := &sensor.Sensor{ID: shared.NewID(), TenantID: &tid}
	if !requireSensorTenant(rec, agt) {
		t.Fatal("expected true for tenant-bound agent")
	}
	if rec.Code != http.StatusOK { // nothing written
		t.Fatalf("expected no error response, got %d", rec.Code)
	}
}

func TestSensorTenantString_NilSafe(t *testing.T) {
	if got := sensorTenantString(nil); got != "" {
		t.Errorf("nil agent: expected empty, got %q", got)
	}
	if got := sensorTenantString(&sensor.Sensor{}); got != "" {
		t.Errorf("nil tenant: expected empty, got %q", got)
	}
	tid := shared.NewID()
	if got := sensorTenantString(&sensor.Sensor{TenantID: &tid}); got != tid.String() {
		t.Errorf("expected %q, got %q", tid.String(), got)
	}
}

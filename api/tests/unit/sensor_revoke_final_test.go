package unit

import (
	"context"
	"errors"
	"testing"

	sensorsvc "github.com/openctemio/openctem/api/internal/app/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Revoking a sensor is permanent: ActivateSensor refuses a revoked sensor. The
// generic update (PUT /api/v1/sensors/{id} with a "status" field) did not, so
// {"status":"active"} brought a revoked sensor back and its old key worked
// again — reproduced live against develop on 2026-10-01.

func revokedSensorFixture(t *testing.T) (*mockSensorRepo, *sensorsvc.SensorService, shared.ID, *sensor.Sensor) {
	t.Helper()
	repo := newMockSensorRepo()
	svc := newTestSensorService(repo)
	tenantID := shared.NewID()
	a := createTestSensor(t, tenantID, "Revoked Sensor")
	a.Revoke("compromised")
	repo.sensors[a.ID] = a
	return repo, svc, tenantID, a
}

func TestUpdateSensor_CannotReactivateRevokedSensor(t *testing.T) {
	for _, status := range []string{"active", "disabled"} {
		t.Run(status, func(t *testing.T) {
			repo, svc, tenantID, a := revokedSensorFixture(t)

			_, err := svc.UpdateSensor(context.Background(), sensorsvc.UpdateSensorInput{
				TenantID: tenantID.String(),
				SensorID: a.ID.String(),
				Status:   status,
			})
			if !errors.Is(err, shared.ErrForbidden) {
				t.Fatalf("UpdateSensor(status=%s) on a revoked sensor: err = %v, want ErrForbidden", status, err)
			}
			if got := repo.sensors[a.ID].Status; got != sensor.SensorStatusRevoked {
				t.Errorf("sensor status = %s, want revoked to stay", got)
			}
		})
	}
}

// Renaming or describing a revoked sensor (for the record) stays allowed.
func TestUpdateSensor_RevokedSensorKeepsEditableMetadata(t *testing.T) {
	repo, svc, tenantID, a := revokedSensorFixture(t)

	got, err := svc.UpdateSensor(context.Background(), sensorsvc.UpdateSensorInput{
		TenantID:    tenantID.String(),
		SensorID:    a.ID.String(),
		Description: "decommissioned after incident 42",
	})
	if err != nil {
		t.Fatalf("UpdateSensor(description) on a revoked sensor: %v", err)
	}
	if got.Status != sensor.SensorStatusRevoked || repo.sensors[a.ID].Status != sensor.SensorStatusRevoked {
		t.Errorf("status changed to %s by a metadata update", got.Status)
	}
}

// Re-sending the current status is a no-op, not an error.
func TestUpdateSensor_RevokedToRevokedIsAllowed(t *testing.T) {
	_, svc, tenantID, a := revokedSensorFixture(t)

	if _, err := svc.UpdateSensor(context.Background(), sensorsvc.UpdateSensorInput{
		TenantID: tenantID.String(),
		SensorID: a.ID.String(),
		Status:   "revoked",
	}); err != nil {
		t.Fatalf("UpdateSensor(status=revoked) on a revoked sensor: %v", err)
	}
}

// Revoking through the generic update skipped the revoke route: it was logged
// as a Low sensor.updated instead of the Critical sensor.revoked, with no
// reason (settings audit SC-H6). Revocation now goes through
// POST /sensors/{id}/revoke only.
func TestUpdateSensor_CannotRevokeThroughUpdate(t *testing.T) {
	repo := newMockSensorRepo()
	svc := newTestSensorService(repo)
	tenantID := shared.NewID()
	a := createTestSensor(t, tenantID, "Active Sensor")
	repo.sensors[a.ID] = a

	_, err := svc.UpdateSensor(context.Background(), sensorsvc.UpdateSensorInput{
		TenantID: tenantID.String(),
		SensorID: a.ID.String(),
		Status:   "revoked",
	})
	if !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("UpdateSensor(status=revoked) on an active sensor: err = %v, want ErrValidation", err)
	}
	if got := repo.sensors[a.ID].Status; got == sensor.SensorStatusRevoked {
		t.Fatal("the sensor was revoked through the generic update")
	}
}

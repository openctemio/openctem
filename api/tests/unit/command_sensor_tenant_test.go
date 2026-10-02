package unit

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/openctemio/api/internal/app/command"
	"github.com/openctemio/api/pkg/domain/sensor"
	"github.com/openctemio/api/pkg/domain/shared"
)

// POST /api/v1/commands took any sensor_id. Reproduced live on develop
// (2026-10-01): tenant B created a command pinned to tenant A's sensor (201),
// while a random id hit the foreign key and answered 500 — so the endpoint
// told tenant B which sensor ids exist in other tenants, and left a command
// that no sensor could ever claim.

type tenantSensorLookup struct {
	tenantID shared.ID
	sensorID shared.ID
}

func (l tenantSensorLookup) GetByTenantAndID(_ context.Context, tenantID, id shared.ID) (*sensor.Sensor, error) {
	if tenantID == l.tenantID && id == l.sensorID {
		return &sensor.Sensor{ID: id, TenantID: &tenantID}, nil
	}
	return nil, sensor.ErrSensorNotFound
}

func TestCreateCommand_RejectsSensorOfAnotherTenant(t *testing.T) {
	tenantA, tenantB, sensorA := shared.NewID(), shared.NewID(), shared.NewID()
	repo := newCmdMockRepo()
	svc := command.NewService(repo, newCmdTestLogger(),
		command.WithSensorLookup(tenantSensorLookup{tenantID: tenantA, sensorID: sensorA}))

	for name, sensorID := range map[string]string{
		"another tenant's sensor": sensorA.String(),
		"unknown sensor":          shared.NewID().String(),
	} {
		t.Run(name, func(t *testing.T) {
			_, err := svc.Create(context.Background(), command.CreateInput{
				TenantID: tenantB.String(),
				SensorID: sensorID,
				Type:     "health_check",
				Payload:  json.RawMessage(`{}`),
			})
			if !errors.Is(err, shared.ErrValidation) {
				t.Fatalf("err = %v, want ErrValidation (400)", err)
			}
		})
	}
	if len(repo.commands) != 0 {
		t.Errorf("%d command(s) stored, want none", len(repo.commands))
	}
}

func TestCreateCommand_AcceptsOwnSensor(t *testing.T) {
	tenantA, sensorA := shared.NewID(), shared.NewID()
	svc := command.NewService(newCmdMockRepo(), newCmdTestLogger(),
		command.WithSensorLookup(tenantSensorLookup{tenantID: tenantA, sensorID: sensorA}))

	cmd, err := svc.Create(context.Background(), command.CreateInput{
		TenantID: tenantA.String(),
		SensorID: sensorA.String(),
		Type:     "health_check",
		Payload:  json.RawMessage(`{}`),
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if cmd.SensorID == nil || *cmd.SensorID != sensorA {
		t.Errorf("command sensor = %v, want %s", cmd.SensorID, sensorA)
	}
}

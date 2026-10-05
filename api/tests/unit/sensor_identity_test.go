package unit

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/internal/app"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// AuthenticateIdentity backs the sensor-key middleware. It must refuse
// exactly what AuthenticateByAPIKey refuses, except that a disabled (not
// revoked) sensor comes back as Paused so the heartbeat can tell it to pause
// (RFC-023 §9.2a).

func newIdentitySensor(t *testing.T) (*sensorSvcMockRepo, *app.SensorService, *app.CreateSensorOutput) {
	t.Helper()
	repo := newSensorSvcMockRepo()
	svc := newSensorSvcTestService(repo)
	out, err := svc.CreateSensor(context.Background(), app.CreateSensorInput{
		TenantID: shared.NewID().String(), Name: "identity-sensor", Type: "worker",
	})
	if err != nil {
		t.Fatalf("create sensor: %v", err)
	}
	return repo, svc, out
}

func TestAuthenticateIdentity_ActiveSensor(t *testing.T) {
	_, svc, out := newIdentitySensor(t)
	id, err := svc.AuthenticateIdentity(context.Background(), out.APIKey)
	if err != nil {
		t.Fatalf("active sensor refused: %v", err)
	}
	if id.Paused || id.Sensor == nil || id.Sensor.ID != out.Sensor.ID || id.KeyExpiresAt != nil {
		t.Fatalf("got %+v; want the active sensor, not paused, key never expires", id)
	}
}

func TestAuthenticateIdentity_DisabledSensorIsPaused(t *testing.T) {
	repo, svc, out := newIdentitySensor(t)
	out.Sensor.Disable("maintenance")
	repo.sensors[out.Sensor.ID.String()] = out.Sensor

	id, err := svc.AuthenticateIdentity(context.Background(), out.APIKey)
	if err != nil || !id.Paused || id.Sensor == nil {
		t.Fatalf("disabled sensor: id=%+v err=%v; want Paused", id, err)
	}
	// The strict path still refuses it.
	if _, err := svc.AuthenticateByAPIKey(context.Background(), out.APIKey); !errors.Is(err, shared.ErrForbidden) {
		t.Fatalf("AuthenticateByAPIKey on a disabled sensor: %v, want ErrForbidden", err)
	}
}

func TestAuthenticateIdentity_RefusesRevokedExpiredAndUnknown(t *testing.T) {
	repo, svc, out := newIdentitySensor(t)
	if _, err := svc.AuthenticateIdentity(context.Background(), "rda_not_a_key"); !errors.Is(err, shared.ErrUnauthorized) {
		t.Errorf("unknown key: %v, want ErrUnauthorized", err)
	}

	past := time.Now().Add(-time.Minute)
	out.Sensor.Disable("maintenance")
	out.Sensor.InlineKeyExpiresAt = &past
	repo.sensors[out.Sensor.ID.String()] = out.Sensor
	if _, err := svc.AuthenticateIdentity(context.Background(), out.APIKey); !errors.Is(err, shared.ErrUnauthorized) {
		t.Errorf("disabled sensor with an expired key: %v, want ErrUnauthorized (an expired key learns nothing)", err)
	}

	out.Sensor.InlineKeyExpiresAt = nil
	out.Sensor.Revoke("compromised")
	repo.sensors[out.Sensor.ID.String()] = out.Sensor
	if _, err := svc.AuthenticateIdentity(context.Background(), out.APIKey); !errors.Is(err, shared.ErrForbidden) {
		t.Errorf("revoked sensor: %v, want ErrForbidden", err)
	}
}

// With rotation overlap the presented key is a sensor_api_keys row; its own
// expiry, not the inline key's, is what rotate_key is computed from.
func TestAuthenticateIdentity_RowKeyCarriesItsOwnExpiry(t *testing.T) {
	repo, svc, out := newIdentitySensor(t)
	svc.SetKeyTTL(2 * time.Hour)
	svc.SetAPIKeyRepository(newMockSensorAPIKeyRepo(repo))

	renewed, expiresAt, err := svc.RenewAPIKey(context.Background(), app.SensorIdentity{Sensor: out.Sensor})
	if err != nil || expiresAt == nil {
		t.Fatalf("renew: key expiry %v, err %v", expiresAt, err)
	}
	id, err := svc.AuthenticateIdentity(context.Background(), renewed)
	if err != nil {
		t.Fatalf("renewed key refused: %v", err)
	}
	if id.KeyExpiresAt == nil || !id.KeyExpiresAt.Equal(*expiresAt) {
		t.Fatalf("presented key expiry = %v, want the renewed key's %v", id.KeyExpiresAt, expiresAt)
	}

	s := repo.sensors[out.Sensor.ID.String()]
	s.Disable("maintenance")
	if id, err := svc.AuthenticateIdentity(context.Background(), renewed); err != nil || !id.Paused {
		t.Fatalf("disabled sensor via its renewed key: id=%+v err=%v; want Paused", id, err)
	}
	if _, err := svc.AuthenticateByAPIKey(context.Background(), renewed); err == nil {
		t.Fatal("strict auth accepted a disabled sensor's renewed key")
	}
}

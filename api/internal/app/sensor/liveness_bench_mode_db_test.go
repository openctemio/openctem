package sensor_test

import (
	"context"
	"testing"

	sensorapp "github.com/openctemio/openctem/api/internal/app/sensor"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/internal/infra/redis"
	sensordom "github.com/openctemio/openctem/api/pkg/domain/sensor"
)

// benchConfigure wires the liveness store for TestHeartbeatWriteCost.
func benchConfigure(t *testing.T, svc *sensorapp.SensorService, repo *postgres.SensorRepository, db *postgres.DB, mode string) {
	t.Helper()
	m, err := sensordom.ParseLivenessMode(mode)
	if err != nil {
		t.Fatal(err)
	}
	if mode == "" {
		m = sensordom.LivenessPostgres
	}
	if m == sensordom.LivenessPostgres {
		return
	}
	rc := livenessRedis(t)
	_ = rc.FlushDB(context.Background()).Err()
	store := redis.NewSensorLivenessStore(rc)
	if m == sensordom.LivenessRedis {
		repo.SetLivenessOverlay(store)
	}
	svc.SetLiveness(m, store, repo, postgres.NewSensorHeartbeatHistoryRepository(db))
}

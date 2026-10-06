package jobs

import (
	"context"
	"database/sql"
	"testing"

	"github.com/google/uuid"
	_ "github.com/lib/pq"

	sensorapp "github.com/openctemio/openctem/api/internal/app/sensor"
	"github.com/openctemio/openctem/api/internal/config"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/internal/testdb"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// TestLegacySensorHealthChecker_OffByDefault_KeepsStartupGrace: the sensor
// health controller (RFC-035 §5.6.4) holds every offline conviction for its
// startup grace after the API starts, so sensors are not convicted for the
// heartbeats they could not deliver while the API was down. The older
// jobs.SensorHealthChecker (WORKER_HEALTH_CHECK_ENABLED, default true) knows
// nothing about that grace and sweeps once the moment it starts, so after an
// API restart it convicted every sensor anyway.
//
// With the default configuration, an API that just came back from a 10-minute
// outage must leave a sensor last seen 10 minutes ago alone.
//
// DB-gated: needs DATABASE_URL pointing at app_test (never the live DB).
func TestLegacySensorHealthChecker_OffByDefault_KeepsStartupGrace(t *testing.T) {
	dbURL := testdb.URL()
	if dbURL == "" {
		t.Skip("DATABASE_URL not set; skipping DB-backed test")
	}
	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer func() { _ = db.Close() }()
	if err := db.Ping(); err != nil {
		t.Skipf("cannot reach test DB: %v", err)
	}
	ctx := context.Background()

	// The defaults an operator gets without setting anything.
	t.Setenv("APP_ENV", "development")
	t.Setenv("WORKER_HEALTH_CHECK_ENABLED", "")
	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("load config: %v", err)
	}

	tenantID := uuid.NewString()
	if _, err := db.ExecContext(ctx, `INSERT INTO tenants (id, name, slug) VALUES ($1,$2,$3)`,
		tenantID, "legacy-health-test", "leghealth-"+tenantID); err != nil {
		t.Fatalf("insert tenant: %v", err)
	}
	t.Cleanup(func() { _, _ = db.ExecContext(ctx, `DELETE FROM tenants WHERE id=$1`, tenantID) })

	sensorID := uuid.NewString()
	if _, err := db.ExecContext(ctx, `
		INSERT INTO sensors (id, tenant_id, name, type, status, health, execution_mode,
			api_key_hash, api_key_prefix, last_seen_at)
		VALUES ($1, $2, $3, 'worker', 'active', 'online', 'standalone', $4, 'rda_test', now() - interval '10 minutes')`,
		sensorID, tenantID, "leghealth-"+sensorID[:8], "hash-"+sensorID); err != nil {
		t.Fatalf("insert sensor: %v", err)
	}

	// The health controller's guard, as wired at startup: it holds convictions.
	guard := sensorapp.NewPlatformHealth(sensorapp.PlatformHealthConfig{StartupGrace: cfg.SensorConfig.HealthStartupGrace})
	if reason := guard.HoldConvictions(0); reason == "" {
		t.Fatal("precondition: the health controller should hold convictions right after startup")
	}

	// The legacy checker, as wired in cmd/server/workers.go.
	repo := postgres.NewSensorRepository(&postgres.DB{DB: db})
	legacy := NewSensorHealthChecker(repo, &cfg.Worker, logger.NewNop())
	legacy.Start()
	legacy.Stop()

	var health string
	if err := db.QueryRowContext(ctx, `SELECT health FROM sensors WHERE id=$1`, sensorID).Scan(&health); err != nil {
		t.Fatalf("read back: %v", err)
	}
	if health != "online" {
		t.Fatalf("sensor health = %q right after API startup, want it left %q: the legacy checker "+
			"convicted it inside the health controller's startup grace", health, "online")
	}
}

package main

import (
	"context"
	"database/sql"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"

	"github.com/openctemio/openctem/api/internal/config"
	"github.com/openctemio/openctem/api/internal/infra/opsmetrics"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// registerOpsMetrics registers the platform-wide gauges the operator's
// alerts read (docs/operations/monitoring.md) on the default registry that
// /metrics serves. Never fatal: monitoring must not stop the API.
func registerOpsMetrics(db *sql.DB, cfg *config.Config, log *logger.Logger) {
	shipped, err := latestMigrationVersion(migrationsDirPath())
	if err != nil {
		log.Warn("operator metrics: shipped schema version unknown", "error", err)
	}
	c := opsmetrics.New(func(ctx context.Context) (postgres.OpsSnapshot, error) {
		return postgres.ReadOpsSnapshot(ctx, db)
	}, opsmetrics.Config{
		ShippedSchemaVersion: shipped,
		SDKLatest:            cfg.SensorConfig.SDKLatestVersion,
		SDKMin:               cfg.SensorConfig.SDKMinVersion,
	}, log)
	// go_sql_* (db_name="openctem"): the API's connection pool, for the
	// pool-exhaustion alert.
	for _, col := range []prometheus.Collector{c, collectors.NewDBStatsCollector(db, "openctem")} {
		if err := prometheus.Register(col); err != nil {
			log.Warn("operator metrics: not registered", "error", err)
		}
	}
}

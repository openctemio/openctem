package main

import (
	"github.com/openctemio/openctem/api/internal/config"
	"github.com/openctemio/openctem/api/internal/infra/redis"
	"github.com/openctemio/openctem/api/internal/infra/telemetry"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// wireSharedSensorDefaults gives the platform scanning policy the
// deployment defaults of MANAGED_SERVICE and the anomaly signals of shared
// sensor use (docs/rfcs/RFC-100-shared-sensors.md §6, §9): the counters live
// in Redis (shared by every replica); without Redis the signals are off.
func wireSharedSensorDefaults(svc *Services, cfg *config.Config, redisClient *redis.Client, log *logger.Logger) {
	if svc.ScanPolicy == nil {
		return
	}
	svc.ScanPolicy.SetManagedService(cfg.App.ManagedService)
	if cfg.App.ManagedService {
		log.Info("MANAGED_SERVICE is set: shared sensors default to a verified domain and public targets only until an administrator stores a value")
	}
	if redisClient == nil {
		log.Warn("Redis not configured: shared sensor anomaly signals are off")
		return
	}
	svc.ScanPolicy.SetAnomalyCounter(redis.NewSharedAnomalyCounter(redisClient), telemetry.SharedSensorAnomalyMetrics{})
	if svc.Scan != nil {
		svc.Scan.SetSharedUseObserver(svc.ScanPolicy)
	}
	if svc.ScanRun != nil {
		svc.ScanRun.SetSharedUseObserver(svc.ScanPolicy)
	}
	if svc.Command != nil {
		svc.Command.SetSharedFailureObserver(svc.ScanPolicy)
	}
}

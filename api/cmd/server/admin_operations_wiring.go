package main

import (
	"context"

	"github.com/openctemio/openctem/api/internal/config"
	"github.com/openctemio/openctem/api/internal/infra/http/handler"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// newAdminOperationsHandler wires Console > Operations to the API's own
// database pool, Redis client and metrics registry.
func newAdminOperationsHandler(deps *HandlerDeps, cfg *config.Config, log *logger.Logger) *handler.AdminOperationsHandler {
	var pingRedis func(ctx context.Context) error
	if deps.RedisClient != nil {
		pingRedis = deps.RedisClient.Ping
	}
	return handler.NewAdminOperationsHandler(deps.DB.DB,
		func(ctx context.Context) (postgres.OpsSnapshot, error) {
			return postgres.ReadOpsSnapshot(ctx, deps.DB.DB)
		},
		pingRedis, nil, shippedSchemaVersion(log), cfg.SensorConfig.SDKMinVersion, log)
}

package routes

// The fleet read model (docs/rfcs/RFC-051-ci-runner-identity-and-gate.md,
// "Pipelines in the fleet"): GET /api/v1/fleet lists sensors in daemon mode
// and CI pipelines in runner mode. The route admits a caller with either
// read permission; the handler filters each mode by its own permission.

import (
	"github.com/openctemio/openctem/api/internal/infra/http/handler"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/domain/permission"
	"github.com/openctemio/openctem/api/pkg/logger"
)

func registerFleetRoutes(router Router, sensors *handler.SensorHandler, ci *handler.CIAdminHandler,
	gate *middleware.ModuleGate, authMiddleware, userSyncMiddleware Middleware, log *logger.Logger) {
	// Typed nils must not reach the interfaces: a missing source is a nil
	// interface (its mode is not offered).
	var daemons handler.FleetDaemonSource
	if sensors != nil {
		daemons = sensors
	}
	var runners handler.FleetRunnerSource
	if ci != nil {
		runners = ci
	}
	if daemons == nil && runners == nil {
		return
	}
	h := handler.NewFleetHandler(daemons, runners, gate.IsEnabled, log)
	router.Group("/api/v1/fleet", func(r Router) {
		r.GET("/", h.List, middleware.RequireAny(permission.SensorsRead, permission.CIRead))
	}, buildTokenTenantMiddlewares(authMiddleware, userSyncMiddleware)...)
}

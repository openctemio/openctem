package routes

import (
	"github.com/openctemio/api/internal/infra/http/handler"
	"github.com/openctemio/api/internal/infra/http/middleware"
	"github.com/openctemio/api/pkg/domain/permission"
)

// registerSimulationRoutes registers attack simulation and control testing routes.
func registerSimulationRoutes(
	router Router,
	h *handler.SimulationHandler,
	authMiddleware Middleware,
	userSyncMiddleware Middleware,
	moduleGate Middleware,
	controlTestGate Middleware,
) {
	tenantMiddlewares := append(buildTokenTenantMiddlewares(authMiddleware, userSyncMiddleware), moduleGate)
	// Control tests are a separate per-tenant toggle from attack simulations, so
	// they get their own module gate (control_testing) rather than sharing the
	// attack_simulation gate.
	controlTestMiddlewares := append(buildTokenTenantMiddlewares(authMiddleware, userSyncMiddleware), controlTestGate)

	// Attack Simulations
	router.Group("/api/v1/simulations", func(r Router) {
		r.GET("/", h.ListSimulations, middleware.Require(permission.PentestRead))
		r.POST("/", h.CreateSimulation, middleware.Require(permission.PentestWrite))
		r.GET("/{id}", h.GetSimulation, middleware.Require(permission.PentestRead))
		r.PUT("/{id}", h.UpdateSimulation, middleware.Require(permission.PentestWrite))
		r.DELETE("/{id}", h.DeleteSimulation, middleware.Require(permission.PentestWrite))
		r.POST("/{id}/run", h.RunSimulation, middleware.Require(permission.PentestWrite))
		r.GET("/{id}/runs", h.ListSimulationRuns, middleware.Require(permission.PentestRead))
	}, tenantMiddlewares...)

	// Control Tests
	router.Group("/api/v1/control-tests", func(r Router) {
		r.GET("/", h.ListControlTests, middleware.Require(permission.PentestRead))
		r.GET("/stats", h.GetControlTestStats, middleware.Require(permission.PentestRead))
		r.POST("/", h.CreateControlTest, middleware.Require(permission.PentestWrite))
		r.PATCH("/{id}/result", h.RecordControlTestResult, middleware.Require(permission.PentestWrite))
		r.DELETE("/{id}", h.DeleteControlTest, middleware.Require(permission.PentestWrite))
	}, controlTestMiddlewares...)
}

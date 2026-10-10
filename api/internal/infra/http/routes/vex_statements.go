package routes

import (
	"time"

	"github.com/openctemio/openctem/api/internal/config"
	"github.com/openctemio/openctem/api/internal/infra/http/handler"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/domain/permission"
)

// registerVEXStatementRoutes wires the organization's VEX statements
// (api/docs/rfcs/RFC-070-software-components-inventory.md). Reading needs
// components:read; writing closes findings, so it needs findings:approve
// (the false-positive permission). Data scope is applied in the service.
func registerVEXStatementRoutes(router Router, h *handler.VEXStatementHandler,
	authMiddleware, userSyncMiddleware, moduleGate Middleware) {
	if h == nil {
		return
	}
	middlewares := append(buildTokenTenantMiddlewares(authMiddleware, userSyncMiddleware), moduleGate)
	importRL := middleware.NewRateLimiter(&config.RateLimitConfig{
		Enabled:         true,
		RequestsPerSec:  10.0 / 60.0, // 10 documents per minute
		Burst:           3,
		CleanupInterval: 5 * time.Minute,
	}, nil)
	router.Group("/api/v1/vex-statements", func(r Router) {
		r.GET("/", h.List, middleware.Require(permission.ComponentsRead))
		r.POST("/", h.Create, middleware.Require(permission.FindingsApprove))
		r.POST("/import", h.Import, middleware.Require(permission.FindingsApprove), importRL.Middleware())
		r.GET("/{id}", h.Get, middleware.Require(permission.ComponentsRead))
		r.PATCH("/{id}", h.Update, middleware.Require(permission.FindingsApprove))
		r.DELETE("/{id}", h.Delete, middleware.Require(permission.FindingsApprove))
	}, middlewares...)
}

package routes

import (
	"github.com/openctemio/openctem/api/internal/infra/http/handler"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/domain/permission"
)

// registerProgramRoutes registers the bug-bounty program routes (RFC-065
// §6), gated by the scope_config module. Import, re-import and resume put a
// program's entries into effect on the caller's attestation: they need a
// recent re-authentication. Pause and end narrow and need none. Which
// program a caller may see or change is decided in the service (members of
// the program's group, or full-data callers; anything else is 404).
func registerProgramRoutes(router Router, h *handler.BountyProgramHandler, authMiddleware, userSyncMiddleware, moduleGate Middleware) {
	tenantMiddlewares := append(buildTokenTenantMiddlewares(authMiddleware, userSyncMiddleware), moduleGate)
	router.Group("/api/v1/programs", func(r Router) {
		r.GET("/", h.List, middleware.Require(permission.ProgramsRead))
		r.POST("/preview", h.Preview, middleware.Require(permission.ProgramsWrite))
		r.POST("/", h.Import, middleware.Require(permission.ProgramsWrite), requireStepUp())
		r.GET("/{id}", h.Get, middleware.Require(permission.ProgramsRead))
		r.PUT("/{id}/scope", h.Reimport, middleware.Require(permission.ProgramsWrite), requireStepUp())
		r.POST("/{id}/suspend", h.Pause, middleware.Require(permission.ProgramsWrite))
		r.POST("/{id}/end", h.End, middleware.Require(permission.ProgramsWrite))
		r.POST("/{id}/reactivate", h.Resume, middleware.Require(permission.ProgramsWrite), requireStepUp())
		// Scope source and sync (RFC-065 §14): setting the source stores a
		// credential (step-up); a sync narrows at once and keeps additions
		// pending; applying them is the attestation (step-up).
		r.PUT("/{id}/source", h.SetSource, middleware.Require(permission.ProgramsWrite), requireStepUp())
		r.POST("/{id}/sync", h.Sync, middleware.Require(permission.ProgramsWrite))
		r.GET("/{id}/pending", h.Pending, middleware.Require(permission.ProgramsRead))
		r.POST("/{id}/pending/apply", h.ApplyPending, middleware.Require(permission.ProgramsWrite), requireStepUp())
	}, tenantMiddlewares...)
}

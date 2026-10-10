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
		// The public program catalog (public data) and following one of its
		// programs: entries are created inactive, so no step-up until a
		// member accepts the terms with /reactivate (RFC-065 §16).
		r.GET("/catalog", h.Catalog, middleware.Require(permission.ProgramsRead))
		r.POST("/subscriptions", h.Subscribe, middleware.Require(permission.ProgramsWrite))
		r.POST("/preview", h.Preview, middleware.Require(permission.ProgramsWrite))
		r.POST("/", h.Import, middleware.Require(permission.ProgramsWrite), requireStepUp())
		r.GET("/{id}", h.Get, middleware.Require(permission.ProgramsRead))
		// Accepting a program's terms changes no authorization; it unlocks a
		// private program's details for the caller.
		r.POST("/{id}/attest", h.Attest, middleware.Require(permission.ProgramsRead))
		// Confirming targets the feed only suggested widens a followed
		// program; its entries then wait for a new acceptance (step-up there).
		r.POST("/{id}/targets/approve", h.ConfirmTargets, middleware.Require(permission.ProgramsWrite))
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
		// Delivery of events about the program's private assets (RFC-065
		// §15.4). Attaching a channel widens who receives them (step-up);
		// the organization-channel opt-in is owner-only in the service,
		// with a reason (step-up). Both are audited.
		r.GET("/{id}/delivery", h.Delivery, middleware.Require(permission.ProgramsRead))
		r.PUT("/{id}/notification-channels/{integration_id}", h.AttachChannel,
			middleware.RequireAll(permission.ProgramsWrite, permission.IntegrationsManage), requireStepUp())
		r.DELETE("/{id}/notification-channels/{integration_id}", h.DetachChannel,
			middleware.RequireAll(permission.ProgramsWrite, permission.IntegrationsManage))
		r.PUT("/{id}/org-channels", h.SetOrgChannels, middleware.Require(permission.ProgramsWrite), requireStepUp())
	}, tenantMiddlewares...)
}

package routes

import (
	"github.com/openctemio/openctem/api/internal/infra/http/handler"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/domain/permission"
)

// registerEmergingThreatRoutes wires the emerging-threat alerts
// (docs/rfcs/RFC-117-emerging-threat-alerts.md): read with
// findings:vulnerabilities:read, triage with findings:triage, behind the
// threat_intel module. The organization comes from the token; the handler
// narrows everything to the caller's data scope.
func registerEmergingThreatRoutes(router Router, h *handler.EmergingThreatHandler, authMiddleware, userSyncMiddleware, moduleGate Middleware) {
	if h == nil {
		return
	}
	mws := append(buildTokenTenantMiddlewares(authMiddleware, userSyncMiddleware), moduleGate)
	router.Group("/api/v1/emerging-threats", func(r Router) {
		r.GET("/", h.List, middleware.Require(permission.VulnerabilitiesRead))
		r.GET("/{id}", h.Get, middleware.Require(permission.VulnerabilitiesRead))
		r.POST("/{id}/state", h.SetState, middleware.Require(permission.FindingsTriage))
	}, mws...)
}

// registerEmergingThreatSettingsRoutes wires the organization's
// emerging-threat alert policy under the token singleton
// /api/v1/organization. Owner/admin only; changes are audited.
func registerEmergingThreatSettingsRoutes(router Router, h *handler.TenantHandler, authMiddleware, userSyncMiddleware Middleware) {
	if h == nil {
		return
	}
	router.Group("/api/v1/organization/settings/emerging-threats", func(r Router) {
		r.GET("/", h.GetEmergingThreatSettings, middleware.RequireAdmin())
		r.PUT("/", h.UpdateEmergingThreatSettings, middleware.RequireAdmin())
	}, buildTokenTenantMiddlewares(authMiddleware, userSyncMiddleware)...)
}

// registerAISettingsRoutes wires the organization's AI triage consent under
// the token singleton /api/v1/organization. Owner/admin only. Turning it on
// lets finding content go to the AI provider, so the write needs
// settings:write, a recent sign-in, and is audited.
func registerAISettingsRoutes(router Router, h *handler.TenantHandler, authMiddleware, userSyncMiddleware Middleware) {
	if h == nil {
		return
	}
	router.Group("/api/v1/organization/settings/ai", func(r Router) {
		r.GET("/", h.GetAISettings, middleware.RequireAdmin(), middleware.Require(permission.SettingsRead))
		r.PUT("/", h.UpdateAISettings, middleware.RequireAdmin(), middleware.Require(permission.SettingsWrite), requireStepUp())
	}, buildTokenTenantMiddlewares(authMiddleware, userSyncMiddleware)...)
}

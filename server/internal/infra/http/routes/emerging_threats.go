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

// registerAPIKeySettingsRoutes wires the organization's API key policy (the
// maximum lifetime of new keys) under the token singleton
// /api/v1/organization. Read: anyone who reads or creates API keys (the key
// dialog offers only allowed lifetimes). Write: owner or administrator with
// settings:write; a longer maximum asks a recent sign-in in the service.
func registerAPIKeySettingsRoutes(router Router, h *handler.TenantHandler, authMiddleware, userSyncMiddleware Middleware) {
	if h == nil {
		return
	}
	router.Group("/api/v1/organization/settings/api-keys", func(r Router) {
		r.GET("/", h.GetAPIKeySettings, middleware.RequireAny(permission.APIKeysRead, permission.APIKeysWrite, permission.SettingsRead))
		r.PUT("/", h.UpdateAPIKeySettings, middleware.RequireAdmin(), middleware.Require(permission.SettingsWrite))
	}, buildTokenTenantMiddlewares(authMiddleware, userSyncMiddleware)...)
}

// registerAISettingsRoutes wires the organization's AI settings (consent,
// source, own provider) under the token singleton /api/v1/organization.
// Owner/admin only. Turning AI on or changing the provider changes where
// finding content goes, so the write needs settings:write, a recent sign-in,
// and is audited; the connection test needs settings:write.
func registerAISettingsRoutes(router Router, h *handler.AISettingsHandler, masking *handler.AIMaskingHandler, authMiddleware, userSyncMiddleware Middleware) {
	if h == nil {
		return
	}
	router.Group("/api/v1/organization/settings/ai", func(r Router) {
		r.GET("/", h.Get, middleware.RequireAdmin(), middleware.Require(permission.SettingsRead))
		r.PUT("/", h.Update, middleware.RequireAdmin(), middleware.Require(permission.SettingsWrite), requireStepUp())
		r.POST("/test", h.Test, middleware.RequireAdmin(), middleware.Require(permission.SettingsWrite))
		// Automatic triage: a loosening (on, more severities) needs a recent
		// sign-in, asked by the service; tightening is one click.
		r.GET("/auto-triage", h.GetAutoTriage, middleware.RequireAdmin(), middleware.Require(permission.SettingsRead))
		r.PUT("/auto-triage", h.UpdateAutoTriage, middleware.RequireAdmin(), middleware.Require(permission.SettingsWrite))
		// Use cases (docs/architecture/ai-use-cases.md): per use case, whether
		// results wait for a person or apply on their own, and the data class
		// sent. Anyone with settings:read reads; a loosening (auto-apply on,
		// ceiling above internal, lower confidence while auto-applying) needs
		// a recent sign-in, asked by the service; tightening is one click.
		r.GET("/use-cases", h.ListUseCases, middleware.Require(permission.SettingsRead))
		r.PUT("/use-cases/{use_case}", h.UpdateUseCase, middleware.RequireAdmin(), middleware.Require(permission.SettingsWrite))

		// Masking of AI context (docs/architecture/ai-context-masking.md):
		// what is replaced by placeholders before finding data reaches a
		// model. A change can make less masked, so it needs a recent
		// sign-in; the preview reads a finding under the caller's own scope.
		if masking != nil {
			r.GET("/masking", masking.Get, middleware.RequireAdmin(), middleware.Require(permission.SettingsRead))
			r.PUT("/masking", masking.Update, middleware.RequireAdmin(), middleware.Require(permission.SettingsWrite), requireStepUp())
			r.POST("/masking/preview", masking.Preview, middleware.RequireAdmin(), middleware.Require(permission.SettingsRead))
		}
	}, buildTokenTenantMiddlewares(authMiddleware, userSyncMiddleware)...)
}

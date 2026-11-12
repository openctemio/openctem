package routes

import (
	"github.com/openctemio/openctem/api/internal/infra/http/handler"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
)

// registerCredentialSettingsRoutes wires the organization's leaked-credential
// policy (whether imported secret values are kept). Owners and
// administrators; the tenant is the token's
// (docs/architecture/credential-leaks.md).
func registerCredentialSettingsRoutes(router Router, h *handler.TenantHandler, authMiddleware, userSyncMiddleware Middleware) {
	if h == nil {
		return
	}
	router.Group("/api/v1/organization/settings/credentials", func(r Router) {
		r.GET("/", h.GetCredentialSettings, middleware.RequireAdmin())
		r.PUT("/", h.UpdateCredentialSettings, middleware.RequireAdmin())
	}, buildTokenTenantMiddlewares(authMiddleware, userSyncMiddleware)...)
}

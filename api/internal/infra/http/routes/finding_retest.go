package routes

import (
	"github.com/openctemio/openctem/api/internal/infra/http/handler"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/domain/permission"
)

// registerFindingRetestRoutes wires continuous retest (RFC-039) on its own
// /api/v1/findings/{id}/retests mount, on the token-tenant chain — which ends
// with DataScopeGuard, so a restricted member gets 404 for a finding outside
// their scope.
//
// "Retest now" needs findings:verify: a clean retest resolves the finding, the
// same segregation-of-duties permission a person needs to resolve it.
func registerFindingRetestRoutes(router Router, h *handler.FindingRetestHandler, authMiddleware, userSyncMiddleware Middleware) {
	if h == nil {
		return
	}
	router.Group("/api/v1/findings/{id}/retests", func(r Router) {
		r.GET("/", h.List, middleware.Require(permission.FindingsRead))
		r.POST("/", h.Request, middleware.Require(permission.FindingsVerify))
	}, buildTokenTenantMiddlewares(authMiddleware, userSyncMiddleware)...)
}

// registerRetestSettingsRoutes wires the organization's auto-retest settings
// (RFC-039) under the token singleton /api/v1/organization: the tenant comes
// from the credential, never from the path (docs/architecture/api-conventions.md
// §2). Owner/admin only; changes are audited.
func registerRetestSettingsRoutes(router Router, h *handler.TenantHandler, authMiddleware, userSyncMiddleware Middleware) {
	if h == nil {
		return
	}
	router.Group("/api/v1/organization/settings/retest", func(r Router) {
		r.GET("/", h.GetRetestSettings, middleware.RequireAdmin())
		r.PUT("/", h.UpdateRetestSettings, middleware.RequireAdmin())
	}, buildTokenTenantMiddlewares(authMiddleware, userSyncMiddleware)...)
}

// registerAssetReconciliationSettingsRoutes wires which sources decide asset
// attributes (RFC-069) under the token singleton /api/v1/organization.
// Owner/admin only; changes are audited.
func registerAssetReconciliationSettingsRoutes(router Router, h *handler.TenantHandler, authMiddleware, userSyncMiddleware Middleware) {
	if h == nil {
		return
	}
	router.Group("/api/v1/organization/settings/asset-reconciliation", func(r Router) {
		r.GET("/", h.GetAssetReconciliationSettings, middleware.RequireAdmin())
		r.PUT("/", h.UpdateAssetReconciliationSettings, middleware.RequireAdmin())
	}, buildTokenTenantMiddlewares(authMiddleware, userSyncMiddleware)...)
}

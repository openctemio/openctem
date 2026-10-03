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

package routes

import (
	"github.com/openctemio/openctem/api/internal/infra/http/handler"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/domain/permission"
)

// registerCTEMIDRoutes registers the CTEM-ID catalog endpoint. The catalog is
// global, tenant-agnostic reference data (like the EPSS/KEV threat-intel data),
// so it uses the base middleware chain and the vulnerabilities:read permission.
func registerCTEMIDRoutes(
	router Router,
	h *handler.CTEMIDHandler,
	authMiddleware Middleware,
	userSyncMiddleware Middleware,
) {
	baseMiddlewares := buildBaseMiddlewares(authMiddleware, userSyncMiddleware)

	router.Group("/api/v1/ctem-ids", func(r Router) {
		r.GET("/", h.List, middleware.Require(permission.VulnerabilitiesRead))
	}, baseMiddlewares...)
}

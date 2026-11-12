package routes

import (
	"github.com/openctemio/openctem/api/internal/infra/http/handler"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/domain/permission"
)

// registerSourceRetirementRoutes wires "stop using this source"
// (docs/architecture/source-retirement.md). Every route needs
// findings:sources:retire (owner and administrator), and the service
// refuses a caller whose data scope is narrowed (the source's findings are
// the whole organization's). Retiring and using a source again close or
// reopen findings in bulk: re-authentication as the organization's
// sensitive rule says, like a bulk close.
func registerSourceRetirementRoutes(router Router, h *handler.SourceRetirementHandler, authMiddleware, userSyncMiddleware Middleware) {
	if h == nil {
		return
	}
	tenant := buildTokenTenantMiddlewares(authMiddleware, userSyncMiddleware)
	retire := middleware.Require(permission.FindingsSourcesRetire)
	router.Group("/api/v1/findings/sources/retirements", func(r Router) {
		r.GET("/", h.List, retire)
		r.POST("/preview", h.Preview, retire)
		r.POST("/", h.Retire, retire, requireStepUpSensitive())
		r.GET("/{id}", h.Get, retire)
		r.POST("/{id}/reactivate", h.Restore, retire, requireStepUpSensitive())
	}, tenant...)
}

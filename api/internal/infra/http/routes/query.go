package routes

import (
	"time"

	"github.com/openctemio/openctem/api/internal/config"
	"github.com/openctemio/openctem/api/internal/infra/http/handler"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/domain/permission"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// Custom query request rate per user: a burst of 30, refilled at one per
// second. The service also caps concurrent queries per user and tenant.
const (
	queryBurst = 30
	queryRPS   = 1
)

// registerQueryRoutes mounts /api/v1/query (custom queries,
// docs/architecture/query-language.md) on the token-tenant chain. The
// route gate needs read access to at least one queryable entity; the
// service checks the entity's own permission and each field's.
func registerQueryRoutes(router Router, h *handler.QueryHandler, authMiddleware, userSyncMiddleware Middleware, log *logger.Logger) {
	if h == nil {
		return
	}
	limiter := middleware.NewRateLimiter(&config.RateLimitConfig{
		Enabled: true, RequestsPerSec: queryRPS, Burst: queryBurst, CleanupInterval: time.Minute,
	}, log)
	read := middleware.RequireAny(permission.FindingsRead, permission.AssetsRead)
	router.Group("/api/v1/query", func(r Router) {
		r.GET("/schema", h.Schema, read)
		r.POST("/explain", h.Explain, read, limiter.UserMiddleware())
		r.POST("/run", h.Run, read, limiter.UserMiddleware())
	}, buildTokenTenantMiddlewares(authMiddleware, userSyncMiddleware)...)
}

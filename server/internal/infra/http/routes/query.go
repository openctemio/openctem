package routes

import (
	"time"

	"github.com/openctemio/openctem/server/internal/config"
	"github.com/openctemio/openctem/server/internal/infra/http/handler"
	"github.com/openctemio/openctem/server/internal/infra/http/middleware"
	"github.com/openctemio/openctem/server/pkg/domain/permission"
	"github.com/openctemio/openctem/server/pkg/logger"
)

// Custom query request rate per user: a burst of 30, refilled at one per
// second. The service also caps concurrent queries per user and tenant.
const (
	queryBurst = 30
	queryRPS   = 1
	// Parsing reads no data: a burst of 30, 5 per second.
	parseBurst = 30
	parseRPS   = 5
	// Value completion reads data: a burst of 20, 2 per second.
	valuesBurst = 20
	valuesRPS   = 2
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
	parseLimiter := middleware.NewRateLimiter(&config.RateLimitConfig{
		Enabled: true, RequestsPerSec: parseRPS, Burst: parseBurst, CleanupInterval: time.Minute,
	}, log)
	valuesLimiter := middleware.NewRateLimiter(&config.RateLimitConfig{
		Enabled: true, RequestsPerSec: valuesRPS, Burst: valuesBurst, CleanupInterval: time.Minute,
	}, log)
	read := middleware.RequireAny(permission.FindingsRead, permission.AssetsRead, permission.ScansRead)
	router.Group("/api/v1/query", func(r Router) {
		r.GET("/schema", h.Schema, read)
		r.POST("/explain", h.Explain, read, limiter.UserMiddleware())
		// Search box filters: text, document or params to a checked document
		// (nothing runs; the entity's own permission is checked inside).
		r.POST("/parse", h.Parse, read, parseLimiter.UserMiddleware())
		// Value completion with counts in the caller's scope.
		r.GET("/values", h.Values, read, valuesLimiter.UserMiddleware())
		r.POST("/run", h.Run, read, limiter.UserMiddleware())
		// Pure text conversion of a findings list filter (nothing runs).
		r.POST("/from-filters", h.FromFilters, middleware.Require(permission.FindingsRead), limiter.UserMiddleware())
	}, buildTokenTenantMiddlewares(authMiddleware, userSyncMiddleware)...)
}

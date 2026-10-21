package routes

import (
	"time"

	"github.com/openctemio/openctem/api/internal/config"
	"github.com/openctemio/openctem/api/internal/infra/http/handler"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/domain/permission"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// Writes to subscriptions are personal and cheap, but a loop of them is
// noise: a per-user limit on top of the global one.
const (
	subscriptionRPS   = 2
	subscriptionBurst = 20
)

// registerParticipationRoutes registers the watchers of findings and
// remediation tasks (RFC-120, docs/architecture/participants-and-watchers.md).
//
// Reading the list and the bell need only read access to the item (a viewer
// may watch what they can read). Adding someone else needs the item's write
// permission; removing yourself needs only read, removing someone else the
// write permission (checked in the handler). The services check the data
// scope of the caller and of every person added; watching grants no access.
// They are separate groups under the item path, like the finding activities.
func registerParticipationRoutes(
	router Router,
	h *handler.ParticipationHandler,
	authMiddleware Middleware,
	userSyncMiddleware Middleware,
	moduleGate Middleware,
	log *logger.Logger,
) {
	limiter := middleware.NewRateLimiter(&config.RateLimitConfig{
		Enabled: true, RequestsPerSec: subscriptionRPS, Burst: subscriptionBurst, CleanupInterval: time.Minute,
	}, log)
	write := limiter.UserMiddleware()

	findingMW := buildTokenTenantMiddlewares(authMiddleware, userSyncMiddleware)
	router.Group("/api/v1/findings/{id}/participants", func(r Router) {
		r.GET("/", h.FindingParticipants, middleware.Require(permission.FindingsRead))
	}, findingMW...)
	router.Group("/api/v1/findings/{id}/subscription", func(r Router) {
		r.PUT("/", h.FindingSetSubscription, middleware.Require(permission.FindingsRead), write)
	}, findingMW...)
	router.Group("/api/v1/findings/{id}/watchers", func(r Router) {
		r.POST("/", h.FindingAddWatchers, middleware.Require(permission.FindingsAssign), write)
		r.DELETE("/{user_id}", h.FindingRemoveWatcher, middleware.Require(permission.FindingsRead), write)
	}, findingMW...)

	taskMW := append(buildTokenTenantMiddlewares(authMiddleware, userSyncMiddleware), moduleGate)
	router.Group("/api/v1/remediation/tasks/{task_id}/participants", func(r Router) {
		r.GET("/", h.TaskParticipants, middleware.Require(permission.RemediationRead))
	}, taskMW...)
	router.Group("/api/v1/remediation/tasks/{task_id}/subscription", func(r Router) {
		r.PUT("/", h.TaskSetSubscription, middleware.Require(permission.RemediationRead), write)
	}, taskMW...)
	router.Group("/api/v1/remediation/tasks/{task_id}/watchers", func(r Router) {
		r.POST("/", h.TaskAddWatchers, middleware.Require(permission.RemediationWrite), write)
		r.DELETE("/{user_id}", h.TaskRemoveWatcher, middleware.Require(permission.RemediationRead), write)
	}, taskMW...)
}

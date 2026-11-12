package routes

import (
	"github.com/openctemio/openctem/server/internal/infra/http/handler"
)

// registerInboxRoutes mounts /api/v1/me/inbox: the signed-in person's own
// Inbox counts in the current organization (docs/architecture/my-work.md).
// Any member: each queue needs its own list's permissions, checked by the
// service, which leaves out a queue the caller cannot use; every count runs
// as the caller. A user-less key or platform caller gets 400. Counting runs
// statements over findings, so the heavy-read limiter applies as on the
// quick views.
func registerInboxRoutes(router Router, h *handler.InboxHandler, authMiddleware, userSyncMiddleware Middleware) {
	tenantMiddlewares := buildTokenTenantMiddlewares(authMiddleware, userSyncMiddleware)
	router.Group("/api/v1/me/inbox", func(r Router) {
		r.GET("/summary", h.Summary, heavyReads.Middleware())
	}, tenantMiddlewares...)
}

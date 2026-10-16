package routes

import (
	"github.com/openctemio/openctem/api/internal/infra/http/handler"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/domain/permission"
)

// registerRemediationCampaignRoutes registers remediation campaign routes.
func registerRemediationCampaignRoutes(
	router Router,
	h *handler.RemediationCampaignHandler,
	authMiddleware Middleware,
	userSyncMiddleware Middleware,
	moduleGate Middleware,
) {
	tenantMiddlewares := append(buildTokenTenantMiddlewares(authMiddleware, userSyncMiddleware), moduleGate)

	router.Group("/api/v1/remediation/campaigns", func(r Router) {
		r.GET("/", h.List, middleware.Require(permission.RemediationRead))
		r.POST("/", h.Create, middleware.Require(permission.RemediationWrite))
		r.GET("/{id}", h.Get, middleware.Require(permission.RemediationRead))
		r.GET("/{id}/findings", h.ListFindings, middleware.RequireAll(permission.RemediationRead, permission.FindingsRead))
		r.PATCH("/{id}", h.Update, middleware.Require(permission.RemediationWrite))
		r.PATCH("/{id}/status", h.UpdateStatus, middleware.Require(permission.RemediationWrite))
		// Marking the campaign's findings fixed is a fix claim on each one:
		// the campaign write plus findings:fix_apply.
		r.POST("/{id}/resolve", h.Resolve, middleware.RequireAll(permission.RemediationWrite, permission.FindingsFixApply))
		r.POST("/{id}/refresh", h.Refresh, middleware.Require(permission.RemediationWrite))
		r.POST("/{id}/create-ticket", h.CreateTicket, middleware.Require(permission.RemediationWrite))
		r.DELETE("/{id}", h.Delete, middleware.Require(permission.RemediationWrite))
	}, tenantMiddlewares...)
}

// registerRemediationTaskRoutes registers remediation task routes
// (docs/rfcs/RFC-098-remediation-tasks.md). The service adds the data scope:
// a restricted member sees a task through its in-scope findings only and
// changes only a task whose findings are all in their scope.
func registerRemediationTaskRoutes(
	router Router,
	h *handler.RemediationTaskHandler,
	authMiddleware Middleware,
	userSyncMiddleware Middleware,
	moduleGate Middleware,
) {
	tenantMiddlewares := append(buildTokenTenantMiddlewares(authMiddleware, userSyncMiddleware), moduleGate)

	router.Group("/api/v1/remediation/tasks", func(r Router) {
		r.GET("/", h.List, middleware.Require(permission.RemediationRead))
		r.POST("/", h.Create, middleware.Require(permission.RemediationWrite))
		r.GET("/{task_id}", h.Get, middleware.Require(permission.RemediationRead))
		r.PATCH("/{task_id}", h.Update, middleware.Require(permission.RemediationWrite))
		r.GET("/{task_id}/members", h.ListMembers, middleware.RequireAll(permission.RemediationRead, permission.FindingsRead))
		r.POST("/{task_id}/members", h.AddMembers, middleware.Require(permission.RemediationWrite))
		r.GET("/{task_id}/timeline", h.Timeline, middleware.Require(permission.RemediationRead))
		r.POST("/{task_id}/splits", h.Split, middleware.Require(permission.RemediationWrite))
		r.POST("/{task_id}/merges", h.Merge, middleware.Require(permission.RemediationWrite))
	}, tenantMiddlewares...)

	// Moves of findings between tasks (or out of any task).
	router.Group("/api/v1/remediation/moves", func(r Router) {
		r.POST("/", h.Move, middleware.Require(permission.RemediationWrite))
		r.POST("/preview", h.PreviewMove, middleware.Require(permission.RemediationWrite))
	}, tenantMiddlewares...)
}

// registerRemediationSuggestionRoutes registers remediation suggestion
// routes (docs/rfcs/RFC-098-remediation-tasks.md §5). Suggestions only
// propose; the service hides findings outside the caller's data scope and
// refuses a decision on a suggestion with such findings.
func registerRemediationSuggestionRoutes(
	router Router,
	h *handler.RemediationSuggestionHandler,
	authMiddleware Middleware,
	userSyncMiddleware Middleware,
	moduleGate Middleware,
) {
	tenantMiddlewares := append(buildTokenTenantMiddlewares(authMiddleware, userSyncMiddleware), moduleGate)

	router.Group("/api/v1/remediation/suggestions", func(r Router) {
		r.GET("/", h.List, middleware.Require(permission.RemediationRead))
		r.GET("/stats", h.Summary, middleware.Require(permission.RemediationRead))
		r.POST("/run", h.Refresh, middleware.Require(permission.RemediationWrite))
		r.GET("/{id}", h.Get, middleware.Require(permission.RemediationRead))
		r.PATCH("/{id}", h.Snooze, middleware.Require(permission.RemediationWrite))
		r.GET("/{id}/members", h.Members, middleware.RequireAll(permission.RemediationRead, permission.FindingsRead))
		r.POST("/{id}/reject", h.Dismiss, middleware.Require(permission.RemediationWrite))
		r.POST("/{id}/reopen", h.Reopen, middleware.Require(permission.RemediationWrite))
		r.POST("/{id}/approve", h.Approve, middleware.Require(permission.RemediationWrite))
		r.POST("/approve", h.BulkApprove, middleware.Require(permission.RemediationWrite))
	}, tenantMiddlewares...)

	// Actions: what fixes a set of findings; their auto-join rule.
	router.Group("/api/v1/remediation/actions", func(r Router) {
		r.GET("/{id}", h.GetAction, middleware.Require(permission.RemediationRead))
		r.PATCH("/{id}", h.UpdateAction, middleware.Require(permission.RemediationWrite))
	}, tenantMiddlewares...)
}

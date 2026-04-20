package routes

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/openctemio/api/internal/infra/http/handler"
	"github.com/openctemio/api/internal/infra/http/middleware"
	"github.com/openctemio/api/internal/infra/websocket"
	"github.com/openctemio/api/pkg/domain/permission"
	"github.com/openctemio/api/pkg/logger"
)

// registerHealthRoutes registers health check endpoints.
func registerHealthRoutes(router Router, h *handler.HealthHandler) {
	router.GET("/health", h.Health)
	router.GET("/ready", h.Ready)
	router.GET("/metrics", func(w http.ResponseWriter, r *http.Request) {
		promhttp.Handler().ServeHTTP(w, r)
	})
}

// registerDocsRoutes registers API documentation endpoints (public).
func registerDocsRoutes(router Router, h *handler.DocsHandler) {
	// OpenAPI spec (YAML)
	router.GET("/openapi.yaml", h.ServeOpenAPISpec)

	// Scalar API documentation UI
	router.GET("/docs", h.ServeDocsUI)
}

// registerDashboardRoutes registers dashboard endpoints.
// Dashboard provides aggregated statistics for assets, findings, and repositories.
// Tenant stats use tenant from JWT token.
func registerDashboardRoutes(
	router Router,
	h *handler.DashboardHandler,
	authMiddleware Middleware,
	userSyncMiddleware Middleware,
) {
	// Build tenant middleware chain from JWT token
	tenantMiddlewares := buildTokenTenantMiddlewares(authMiddleware, userSyncMiddleware)

	// Dashboard routes
	router.Group("/api/v1/dashboard", func(r Router) {
		r.GET("/stats/global", h.GetGlobalStats, middleware.Require(permission.DashboardRead))
		r.GET("/stats", h.GetStats, middleware.Require(permission.DashboardRead))
		r.GET("/mttr", h.GetMTTR, middleware.Require(permission.DashboardRead))
		r.GET("/velocity", h.GetRiskVelocity, middleware.Require(permission.DashboardRead))
		r.GET("/data-quality", h.GetDataQuality, middleware.Require(permission.DashboardRead))
		r.GET("/risk-trend", h.GetRiskTrend, middleware.Require(permission.DashboardRead))
		r.GET("/executive-summary", h.GetExecutiveSummary, middleware.Require(permission.DashboardRead))
		r.GET("/executive-summary/export", h.ExportExecutiveSummary, middleware.Require(permission.DashboardRead))
		r.GET("/mttr-analytics", h.GetMTTRAnalytics, middleware.Require(permission.DashboardRead))
		r.GET("/process-metrics", h.GetProcessMetrics, middleware.Require(permission.DashboardRead))
	}, tenantMiddlewares...)
}

// registerAuditRoutes registers audit log endpoints.
// Audit logs are tenant-scoped (tenant from JWT token).
// Permission model:
// - Read (GET): audit:read permission
func registerAuditRoutes(
	router Router,
	h *handler.AuditHandler,
	authMiddleware Middleware,
	userSyncMiddleware Middleware,
) {
	// Build tenant middleware chain from JWT token
	tenantMiddlewares := buildTokenTenantMiddlewares(authMiddleware, userSyncMiddleware)

	// Audit log routes - tenant from JWT token
	router.Group("/api/v1/audit-logs", func(r Router) {
		// List and search audit logs
		r.GET("/", h.List, middleware.Require(permission.AuditRead))

		// Get audit log statistics
		r.GET("/stats", h.GetStats, middleware.Require(permission.AuditRead))

		// Get single audit log
		r.GET("/{id}", h.Get, middleware.Require(permission.AuditRead))

		// Get resource history
		r.GET("/resource/{type}/{id}", h.GetResourceHistory, middleware.Require(permission.AuditRead))

		// Get user activity
		r.GET("/user/{id}", h.GetUserActivity, middleware.Require(permission.AuditRead))

		// Verify the tamper-evident hash-chain for the tenant's audit
		// log. Returns 200 { ok: true, ... } when intact, 409 with a
		// breaks[] list when any entry fails. Admin-only: a compromised
		// operator should not be able to dismiss a chain break by
		// running verify with wider permissions than read.
		r.GET("/verify", h.VerifyChain, middleware.RequireAdmin())
	}, tenantMiddlewares...)
}

// registerSLARoutes registers SLA policy management endpoints.
// SLA policies are tenant-scoped with optional asset-specific overrides.
func registerSLARoutes(
	router Router,
	h *handler.SLAHandler,
	authMiddleware Middleware,
	userSyncMiddleware Middleware,
) {
	// Build tenant middleware chain from JWT token
	tenantMiddlewares := buildTokenTenantMiddlewares(authMiddleware, userSyncMiddleware)

	// SLA Policy routes - tenant from JWT token
	router.Group("/api/v1/sla-policies", func(r Router) {
		// List all SLA policies for tenant
		r.GET("/", h.List, middleware.Require(permission.SLARead))

		// Get default SLA policy
		r.GET("/default", h.GetDefault, middleware.Require(permission.SLARead))

		// Create new SLA policy
		r.POST("/", h.Create, middleware.Require(permission.SLAWrite))

		// Get, update, delete specific SLA policy
		r.GET("/{id}", h.Get, middleware.Require(permission.SLARead))
		r.PUT("/{id}", h.Update, middleware.Require(permission.SLAWrite))
		r.DELETE("/{id}", h.Delete, middleware.Require(permission.SLADelete))
	}, tenantMiddlewares...)

	// Asset-specific SLA policy
	router.Group("/api/v1/assets/{assetId}/sla-policy", func(r Router) {
		r.GET("/", h.GetByAsset, middleware.Require(permission.AssetsRead))
	}, tenantMiddlewares...)
}

// registerIntegrationRoutes registers integration management endpoints.
// Integrations are tenant-scoped (tenant from JWT token).
//
//nolint:dupl // Route registration functions naturally have similar structure
func registerIntegrationRoutes(
	router Router,
	h *handler.IntegrationHandler,
	authMiddleware Middleware,
	userSyncMiddleware Middleware,
) {
	// Build tenant middleware chain from JWT token
	tenantMiddlewares := buildTokenTenantMiddlewares(authMiddleware, userSyncMiddleware)

	// Integration routes - tenant from JWT token
	router.Group("/api/v1/integrations", func(r Router) {
		// List integrations
		r.GET("/", h.List, middleware.Require(permission.IntegrationsRead))

		// List SCM integrations specifically
		r.GET("/scm", h.ListSCM, middleware.Require(permission.IntegrationsRead))

		// List Notification integrations specifically
		r.GET("/notifications", h.ListNotifications, middleware.Require(permission.IntegrationsRead))

		// Create new integration
		r.POST("/", h.Create, middleware.Require(permission.IntegrationsManage))

		// Create notification integration
		r.POST("/notifications", h.CreateNotification, middleware.Require(permission.IntegrationsManage))

		// Test credentials without creating (must be before /{id} routes)
		r.POST("/test-credentials", h.TestCredentials, middleware.Require(permission.IntegrationsManage))

		// Get, update, delete specific integration
		r.GET("/{id}", h.Get, middleware.Require(permission.IntegrationsRead))
		r.PUT("/{id}", h.Update, middleware.Require(permission.IntegrationsManage))
		r.DELETE("/{id}", h.Delete, middleware.Require(permission.IntegrationsManage))

		// Integration actions
		r.POST("/{id}/test", h.Test, middleware.Require(permission.IntegrationsManage))
		r.POST("/{id}/sync", h.Sync, middleware.Require(permission.IntegrationsManage))
		r.POST("/{id}/enable", h.Enable, middleware.Require(permission.IntegrationsManage))
		r.POST("/{id}/disable", h.Disable, middleware.Require(permission.IntegrationsManage))

		// Notification actions
		r.PUT("/{id}/notification", h.UpdateNotification, middleware.Require(permission.IntegrationsManage))
		r.POST("/{id}/test-notification", h.TestNotification, middleware.Require(permission.IntegrationsManage))
		// NOTE: /send endpoint removed for security - notifications are triggered internally only
		// Use BroadcastNotification from FindingService/ScanService instead
		r.GET("/{id}/notification-events", h.GetNotificationEvents, middleware.Require(permission.IntegrationsRead))

		// List repositories from SCM integration
		r.GET("/{id}/repositories", h.ListRepositories, middleware.Require(permission.IntegrationsRead))
	}, tenantMiddlewares...)
}

// registerOutboxRoutes registers notification outbox endpoints for tenants.
// This allows tenants to monitor and manage their notification delivery queue.
// NOTE: Admin functionality will be developed in a separate admin backend later.
func registerOutboxRoutes(
	router Router,
	h *handler.OutboxHandler,
	authMiddleware Middleware,
	userSyncMiddleware Middleware,
) {
	// Build tenant middleware chain from JWT token
	tenantMiddlewares := buildTokenTenantMiddlewares(authMiddleware, userSyncMiddleware)

	// Tenant-scoped routes - tenant from JWT token
	router.Group("/api/v1/notification-outbox", func(r Router) {
		// Get outbox statistics for tenant
		r.GET("/stats", h.GetStats, middleware.Require(permission.NotificationsRead))

		// List outbox entries for tenant
		r.GET("/", h.List, middleware.Require(permission.NotificationsRead))

		// Get single outbox entry (must belong to tenant)
		r.GET("/{id}", h.Get, middleware.Require(permission.NotificationsRead))

		// Retry failed entry (must belong to tenant)
		r.POST("/{id}/retry", h.Retry, middleware.Require(permission.NotificationsWrite))

		// Delete entry (must belong to tenant)
		r.DELETE("/{id}", h.Delete, middleware.Require(permission.NotificationsDelete))
	}, tenantMiddlewares...)
}

// registerBootstrapRoutes registers the bootstrap endpoint.
// This endpoint returns all initial data needed after login in a single API call,
// reducing the number of requests from 4+ to 1.
func registerBootstrapRoutes(
	router Router,
	h *handler.BootstrapHandler,
	authMiddleware Middleware,
	userSyncMiddleware Middleware,
) {
	// Build tenant middleware chain from JWT token
	tenantMiddlewares := buildTokenTenantMiddlewares(authMiddleware, userSyncMiddleware)

	// Bootstrap endpoint - combines permissions, subscription, modules, and dashboard
	router.Group("/api/v1/me/bootstrap", func(r Router) {
		r.GET("/", h.Bootstrap)
	}, tenantMiddlewares...)

	// Tenant modules endpoint - returns enabled modules for current tenant
	router.Group("/api/v1/me/modules", func(r Router) {
		r.GET("/", h.GetTenantModules)
	}, tenantMiddlewares...)
}

// registerWebSocketRoutes registers WebSocket endpoints for real-time communication.
// WebSocket replaces SSE for real-time features (activities, scans, notifications).
// Authentication is handled by the UnifiedAuth middleware (JWT token in Authorization header).
//
// Channels follow the format: {type}:{id}
//   - finding:{id}       - Activity updates for a finding
//   - scan:{id}          - Scan progress updates
//   - tenant:{id}        - Tenant-wide notifications
//   - notification:{id}  - Notification delivery
//   - triage:{finding_id} - AI triage progress updates
func registerWebSocketRoutes(
	router Router,
	h *websocket.Handler,
	authMiddleware Middleware,
	userSyncMiddleware Middleware,
	wsTicketMiddleware Middleware, // F-8: non-nil when the single-use ticket path is enabled.
) {
	// F-8: When the single-use ticket middleware is wired (Redis available),
	// use it as the ONLY authenticator for /ws. This prevents replay-via-URL
	// because each ticket is atomically consumed on first redemption. We
	// intentionally skip the JWT auth chain here so that a leaked query-
	// string token is no longer an accepted credential for WS upgrades.
	if wsTicketMiddleware != nil {
		router.Group("/api/v1/ws", func(r Router) {
			r.GET("/", h.ServeWS)
		}, wsTicketMiddleware)
		return
	}

	// Fallback: build tenant middleware chain from JWT token. Only used
	// when Redis / WSTicketService is not configured — operators running
	// without Redis inherit the old short-lived-JWT-in-URL behaviour.
	tenantMiddlewares := buildTokenTenantMiddlewares(authMiddleware, userSyncMiddleware)
	router.Group("/api/v1/ws", func(r Router) {
		r.GET("/", h.ServeWS)
	}, tenantMiddlewares...)
}

// registerAPIKeyRoutes registers API key management routes.
func registerAPIKeyRoutes(
	router Router,
	h *handler.APIKeyHandler,
	authMiddleware Middleware,
	userSyncMiddleware Middleware,
) {
	tenantMiddlewares := buildTokenTenantMiddlewares(authMiddleware, userSyncMiddleware)

	router.Group("/api/v1/api-keys", func(r Router) {
		r.GET("/", h.List, middleware.Require(permission.APIKeysRead))
		r.POST("/", h.Create, middleware.Require(permission.APIKeysWrite))
		r.GET("/{id}", h.Get, middleware.Require(permission.APIKeysRead))
		r.DELETE("/{id}", h.Delete, middleware.Require(permission.APIKeysDelete))
		r.POST("/{id}/revoke", h.Revoke, middleware.Require(permission.APIKeysWrite))
	}, tenantMiddlewares...)
}

// registerNotificationRoutes registers user notification endpoints.
// Notifications are user-scoped within a tenant context.
// No specific permission middleware needed — users can only access their own notifications.
func registerNotificationRoutes(
	router Router,
	h *handler.NotificationHandler,
	authMiddleware Middleware,
	userSyncMiddleware Middleware,
) {
	tenantMiddlewares := buildTokenTenantMiddlewares(authMiddleware, userSyncMiddleware)

	router.Group("/api/v1/notifications", func(r Router) {
		r.GET("/", h.List)
		r.GET("/unread-count", h.GetUnreadCount)
		r.PATCH("/{id}/read", h.MarkAsRead)
		r.POST("/read-all", h.MarkAllAsRead)
		r.GET("/preferences", h.GetPreferences)
		r.PUT("/preferences", h.UpdatePreferences)
	}, tenantMiddlewares...)
}

// registerPlatformStatsRoutes registers platform stats endpoints.
// These are tenant-scoped routes for viewing platform agent statistics.
func registerPlatformStatsRoutes(
	router Router,
	h *handler.PlatformStatsHandler,
	authMiddleware Middleware,
	userSyncMiddleware Middleware,
) {
	tenantMiddlewares := buildTokenTenantMiddlewares(authMiddleware, userSyncMiddleware)

	router.Group("/api/v1/platform", func(r Router) {
		r.GET("/stats", h.GetStats)
	}, tenantMiddlewares...)
}

// registerWebhookRoutes registers webhook management routes.
func registerWebhookRoutes(
	router Router,
	h *handler.WebhookHandler,
	authMiddleware Middleware,
	userSyncMiddleware Middleware,
) {
	tenantMiddlewares := buildTokenTenantMiddlewares(authMiddleware, userSyncMiddleware)

	router.Group("/api/v1/webhooks", func(r Router) {
		r.GET("/", h.List, middleware.Require(permission.WebhooksRead))
		r.POST("/", h.Create, middleware.Require(permission.WebhooksWrite))
		r.GET("/{id}", h.Get, middleware.Require(permission.WebhooksRead))
		r.PUT("/{id}", h.Update, middleware.Require(permission.WebhooksWrite))
		r.DELETE("/{id}", h.Delete, middleware.Require(permission.WebhooksDelete))
		r.POST("/{id}/enable", h.Enable, middleware.Require(permission.WebhooksWrite))
		r.POST("/{id}/disable", h.Disable, middleware.Require(permission.WebhooksWrite))
		r.GET("/{id}/deliveries", h.ListDeliveries, middleware.Require(permission.WebhooksRead))
	}, tenantMiddlewares...)
}

// F-1: wire HMAC verification around the Jira webhook. The tenant query
// param remains for routing, but the middleware now requires a valid
// HMAC-SHA256 of the body signed with JIRA_WEBHOOK_SECRET before the
// handler runs — preventing cross-tenant spoofing by external callers.

// registerIncomingWebhookRoutes registers public incoming webhook endpoints.
// These endpoints are NOT protected by JWT — they are called by external services (e.g. Jira).
// Tenant routing is done via a ?tenant= query parameter that each external service configures.
//
// F-1: each endpoint is now wrapped in middleware.VerifyHMAC using a
// provider-specific shared secret. Requests without a valid
// X-OpenCTEM-Signature over the raw body are rejected before the handler
// runs, preventing cross-tenant spoofing.
func registerIncomingWebhookRoutes(
	router Router,
	jiraHandler *handler.JiraWebhookHandler,
	jiraSecret string,
	log *logger.Logger,
) {
	if jiraHandler == nil {
		return
	}
	// If the platform secret is empty the middleware fails closed (rejects
	// every request), so the endpoint is never reachable without explicit
	// configuration.
	hmacMW := middleware.VerifyHMAC(
		"X-OpenCTEM-Signature",
		func(*http.Request) (string, bool) {
			return jiraSecret, jiraSecret != ""
		},
		log,
	)
	router.POST("/api/v1/webhooks/incoming/jira", jiraHandler.IncomingJiraWebhook, hmacMW)
}

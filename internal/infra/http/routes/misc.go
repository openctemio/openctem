package routes

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/openctemio/api/internal/app"
	"github.com/openctemio/api/internal/infra/http/handler"
	"github.com/openctemio/api/internal/infra/http/middleware"
	"github.com/openctemio/api/internal/infra/websocket"
	"github.com/openctemio/api/pkg/domain/module"
	"github.com/openctemio/api/pkg/domain/permission"
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
	}, tenantMiddlewares...)
}

// registerAuditRoutes registers audit log endpoints.
// Audit logs are tenant-scoped (tenant from JWT token).
// Permission model:
// - Read (GET): audit:read permission
//
// Module check: Requires "audit" module to be enabled.
func registerAuditRoutes(
	router Router,
	h *handler.AuditHandler,
	authMiddleware Middleware,
	userSyncMiddleware Middleware,
	moduleService *app.ModuleService,
) {
	// Build tenant middleware chain from JWT token
	tenantMiddlewares := buildTokenTenantMiddlewares(authMiddleware, userSyncMiddleware)

	// Add module check middleware
	if moduleService != nil {
		tenantMiddlewares = append(tenantMiddlewares, middleware.RequireModule(moduleService, module.ModuleAudit))
	}

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
// Module check: Requires "integrations" module to be enabled.
//
//nolint:dupl // Route registration functions naturally have similar structure
func registerIntegrationRoutes(
	router Router,
	h *handler.IntegrationHandler,
	authMiddleware Middleware,
	userSyncMiddleware Middleware,
	moduleService *app.ModuleService,
) {
	// Build tenant middleware chain from JWT token
	tenantMiddlewares := buildTokenTenantMiddlewares(authMiddleware, userSyncMiddleware)

	// Add module check middleware
	if moduleService != nil {
		tenantMiddlewares = append(tenantMiddlewares, middleware.RequireModule(moduleService, module.ModuleIntegrations))
	}

	// Integration routes - tenant from JWT token
	router.Group("/api/v1/integrations", func(r Router) {
		// List integrations
		r.GET("/", h.List, middleware.Require(permission.IntegrationsRead))

		// List SCM integrations specifically
		// Sub-module check: requires integrations.scm to be enabled
		scmSubModuleCheck := middleware.RequireSubModule(moduleService, "integrations", "scm")
		r.GET("/scm", ChainFunc(h.ListSCM, scmSubModuleCheck).ServeHTTP, middleware.Require(permission.IntegrationsRead))

		// List Notification integrations specifically
		// Sub-module check: requires integrations.notifications to be enabled
		notificationsSubModuleCheck := middleware.RequireSubModule(moduleService, "integrations", "notifications")
		r.GET("/notifications", ChainFunc(h.ListNotifications, notificationsSubModuleCheck).ServeHTTP, middleware.Require(permission.IntegrationsRead))

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
		// Sub-module check: requires integrations.scm
		r.GET("/{id}/repositories", ChainFunc(h.ListRepositories, scmSubModuleCheck).ServeHTTP, middleware.Require(permission.IntegrationsRead))
	}, tenantMiddlewares...)
}

// registerNotificationOutboxRoutes registers notification outbox endpoints for tenants.
// This allows tenants to monitor and manage their notification delivery queue.
// NOTE: Admin functionality will be developed in a separate admin backend later.
func registerNotificationOutboxRoutes(
	router Router,
	h *handler.NotificationOutboxHandler,
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
) {
	// Build tenant middleware chain from JWT token
	tenantMiddlewares := buildTokenTenantMiddlewares(authMiddleware, userSyncMiddleware)

	// WebSocket endpoint - single connection for all real-time features
	// GET /api/v1/ws
	// Authentication: Bearer token in Authorization header
	router.Group("/api/v1/ws", func(r Router) {
		r.GET("/", h.ServeWS)
	}, tenantMiddlewares...)
}

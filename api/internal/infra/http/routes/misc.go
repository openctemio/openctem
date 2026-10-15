package routes

import (
	"context"
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/openctemio/openctem/api/internal/infra/http/handler"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/internal/infra/websocket"
	"github.com/openctemio/openctem/api/pkg/domain/permission"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// registerHealthRoutes registers health check endpoints.
//
// /health and /ready stay public (liveness/readiness probes must not require
// credentials). /metrics is gated by metricsAuth — non-nil and constructed
// from MetricsConfig by Register(). When metrics are non-public it requires a
// bearer token (see middleware.MetricsAuth); /health and /ready are unaffected.
func registerHealthRoutes(router Router, h *handler.HealthHandler, metricsAuth Middleware) {
	router.GET("/health", h.Health)
	router.GET("/ready", h.Ready)

	metricsHandler := func(w http.ResponseWriter, r *http.Request) {
		promhttp.Handler().ServeHTTP(w, r)
	}
	if metricsAuth != nil {
		router.GET("/metrics", metricsHandler, metricsAuth)
	} else {
		router.GET("/metrics", metricsHandler)
	}
}

// Rate limits of POST /api/v1/client-errors: per client address, and for
// all callers together, so an anonymous flood can neither grow memory nor
// push the error count far (labels are a fixed set either way).
const (
	clientErrorPerIPPerSecond = 0.2 // 12 a minute
	clientErrorPerIPBurst     = 10
	clientErrorPerSecond      = 5.0
	clientErrorBurst          = 50
)

// registerClientErrorRoute registers POST /api/v1/client-errors: the web
// console reports an error kind there for the operator's alerting. Public,
// because the worst web failures (a broken deploy) happen before sign-in;
// it accepts only a kind from a fixed set and stores nothing.
func registerClientErrorRoute(router Router, h *handler.ClientErrorHandler, log *logger.Logger) {
	if h == nil {
		return
	}
	perIP := middleware.NewTelemetryRateLimiter(clientErrorPerIPPerSecond, clientErrorPerIPBurst, time.Hour, log).
		MiddlewareKeyed(middleware.ClientIPKey, "Too many error reports")
	overall := middleware.NewTelemetryRateLimiter(clientErrorPerSecond, clientErrorBurst, time.Hour, log).
		MiddlewareKeyed(func(*http.Request) string { return "all" }, "Too many error reports")
	router.POST("/api/v1/client-errors", h.Report, perIP, overall)
}

// registerAnnouncementRoute registers GET /api/v1/announcements: the platform
// operator's active notices (maintenance, warnings) for the banner. Any
// signed-in user, like /version: plain text written by the operator, no
// tenant data. authMiddleware is the JWT/session chain (no oct_ keys).
func registerAnnouncementRoute(router Router, h *handler.AnnouncementHandler, authMiddleware Middleware) {
	router.GET("/api/v1/announcements", h.Active, authMiddleware)
}

// registerVersionRoute registers GET /api/v1/version: the running build, for
// Help > About. Any signed-in user, nothing more: it is not tenant data, and it
// stays off the public /health so an unauthenticated client cannot fingerprint
// the build. authMiddleware is the JWT/session chain, which takes no oct_ keys.
func registerVersionRoute(router Router, authMiddleware Middleware) {
	router.GET("/api/v1/version", handler.Version, authMiddleware)
}

// registerLegalRoute registers GET /api/v1/legal: the operator's legal
// information (links to the terms and privacy policy, the built-in legal
// pages' values, the security.txt contact), public on purpose because the web
// console shows it before sign-in. Nothing secret is stored there (RFC-079).
func registerLegalRoute(router Router, h *handler.AdminLegalHandler) {
	if h == nil {
		return
	}
	router.GET("/api/v1/legal", h.Public)
}

// registerDocsRoutes registers the API documentation (the OpenAPI spec and
// the API reference page). The public documentation lives on the docs site,
// so in production the API serves:
//   - /openapi.yaml to signed-in users only (authMiddleware);
//   - no public /docs page;
//   - /api/v1/admin/docs and /api/v1/admin/openapi.yaml to platform
//     administrators with a verified console session (consoleAuth).
//
// Outside production /docs and /openapi.yaml stay public for development.
func registerDocsRoutes(router Router, h *handler.DocsHandler, production bool, authMiddleware, consoleAuth Middleware) {
	if production {
		router.GET("/openapi.yaml", h.ServeOpenAPISpec, authMiddleware)
	} else {
		router.GET("/openapi.yaml", h.ServeOpenAPISpec)
		router.GET("/docs", h.ServeDocsUI)
	}
	if consoleAuth != nil {
		router.GET("/api/v1/admin/openapi.yaml", h.ServeOpenAPISpec, consoleAuth)
		router.GET("/api/v1/admin/docs", h.ServeConsoleDocsUI, consoleAuth)
	}
}

// registerDashboardRoutes registers dashboard endpoints.
// Dashboard provides aggregated statistics for assets, findings, and repositories.
// Tenant stats use tenant from JWT token.
func registerDashboardRoutes(
	router Router,
	h *handler.DashboardHandler,
	authMiddleware Middleware,
	userSyncMiddleware Middleware,
	log *logger.Logger,
) {
	// The dashboard's reads in one response (research/81). Each part is sent
	// through this router with the caller's credentials, so it passes its own
	// endpoint's gates; this route itself needs dashboard:read.
	overview := handler.NewDashboardOverviewHandler(router.Handler, log)
	// Build tenant middleware chain from JWT token. Program-only assets
	// (RFC-065 §16.5) are left out of every dashboard number unless the
	// request asks for them with include_program_assets=true.
	// Discovered assets nobody claimed are left out too unless the request
	// asks with include_discovered=true (research/124).
	tenantMiddlewares := append(buildTokenTenantMiddlewares(authMiddleware, userSyncMiddleware), includeProgramAssets, includeDiscoveredAssets)

	// Dashboard routes
	router.Group("/api/v1/dashboard", func(r Router) {
		r.GET("/stats", h.GetStats, middleware.Require(permission.DashboardRead), heavyReads.Middleware())
		r.GET("/mttr", h.GetMTTR, middleware.Require(permission.DashboardRead), heavyReads.Middleware())
		r.GET("/velocity", h.GetRiskVelocity, middleware.Require(permission.DashboardRead), heavyReads.Middleware())
		r.GET("/data-quality", h.GetDataQuality, middleware.Require(permission.DashboardRead), heavyReads.Middleware())
		r.GET("/risk-trend", h.GetRiskTrend, middleware.Require(permission.DashboardRead), heavyReads.Middleware())
		r.GET("/executive-summary", h.GetExecutiveSummary, middleware.Require(permission.DashboardRead), heavyReads.Middleware())
		r.GET("/executive-summary/export", h.ExportExecutiveSummary, middleware.Require(permission.DashboardRead))
		r.GET("/mttr-analytics", h.GetMTTRAnalytics, middleware.Require(permission.DashboardRead), heavyReads.Middleware())
		r.GET("/process-metrics", h.GetProcessMetrics, middleware.Require(permission.DashboardRead), heavyReads.Middleware())
		r.GET("/program-metrics", h.GetProgramMetrics, middleware.Require(permission.DashboardRead), heavyReads.Middleware())
		r.GET("/overview", overview.Overview, middleware.Require(permission.DashboardRead))
	}, tenantMiddlewares...)
}

// registerAuditRoutes registers audit log endpoints.
// Audit logs are tenant-scoped (tenant from JWT token).
// Permission model:
//   - Read (GET): audit:read, held by owners and administrators only
//     (the seed no longer grants it to member or viewer). Exception: anyone
//     may read their own activity (/user/{own id}).
//   - Verify: owner/admin. Rebaseline: owner.
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

		// Get user activity. audit:read (owner/admin), or the caller's own
		// activity: /account/activity shows everyone their own actions.
		r.GET("/user/{id}", h.GetUserActivity, middleware.RequirePermissionOrSelf(permission.AuditRead, "id"))

		// Verify the tamper-evident hash-chain for the tenant's audit
		// log. Returns 200 { ok: true, ... } when intact, 409 with a
		// breaks[] list when any entry fails. Admin-only: a compromised
		// operator should not be able to dismiss a chain break by
		// running verify with wider permissions than read.
		r.GET("/verify", h.VerifyChain, middleware.RequireAdmin())

		// There is no rebaseline here: re-signing the tamper-evident chain is
		// a platform-operator action, only in the admin console
		// (POST /api/v1/admin/tenants/{tenantId}/audit-chain/rebaseline). The
		// chain exists to make an insider's changes evident, and the
		// organization's owner is that insider.
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
	// SLA is a core module (every finding carries a deadline), so these
	// routes have no module gate; permissions still apply.
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
	jiraHandler *handler.JiraWebhookHandler,
	defectDojoHandler *handler.DefectDojoHandler,
	authMiddleware Middleware,
	userSyncMiddleware Middleware,
	moduleGate Middleware,
	scanNow *handler.ScanHandler,
	scansModule Middleware,
	ticketMapping *handler.TicketMappingHandler,
) {
	// Build tenant middleware chain from JWT token.
	// Append the module gate after tenant extraction so it can read the tenant.
	tenantMiddlewares := append(buildTokenTenantMiddlewares(authMiddleware, userSyncMiddleware), moduleGate)

	// Integration routes - tenant from JWT token
	router.Group("/api/v1/integrations", func(r Router) {
		// List integrations
		r.GET("/", h.List, middleware.Require(permission.IntegrationsRead))

		// List SCM integrations specifically
		r.GET("/scm", h.ListSCM, middleware.RequireAll(permission.IntegrationsRead, permission.SCMConnectionsRead))

		// List Notification integrations specifically
		r.GET("/notifications", h.ListNotifications, middleware.Require(permission.IntegrationsRead))

		// Create new integration
		r.POST("/", h.Create, middleware.Require(permission.IntegrationsManage))

		// Create notification integration
		r.POST("/notifications", h.CreateNotification, middleware.Require(permission.IntegrationsManage))

		// Test credentials without creating (must be before /{id} routes)
		r.POST("/test-credentials", h.TestCredentials, middleware.Require(permission.IntegrationsManage))

		// Per-tenant Jira inbound-webhook secret (static paths; must be before
		// /{id} routes). Gated by IntegrationsManage because the response
		// contains a secret, and by step-up: whoever holds the secret can
		// forge inbound webhook events for the organization.
		r.GET("/jira/webhook-secret", h.GetJiraWebhookSecret, middleware.Require(permission.IntegrationsManage), requireStepUp())
		r.POST("/jira/webhook-secret/rotate", h.RotateJiraWebhookSecret, middleware.Require(permission.IntegrationsManage), requireStepUp())
		r.GET("/github/webhook-secret", h.GetGitHubWebhookSecret, middleware.Require(permission.IntegrationsManage), requireStepUp())
		r.POST("/github/webhook-secret/rotate", h.RotateGitHubWebhookSecret, middleware.Require(permission.IntegrationsManage), requireStepUp())

		// List Jira projects for the destination-project picker (static path;
		// must be before /{id} routes). nil handler = no DB → skip.
		if jiraHandler != nil {
			r.GET("/jira/projects", jiraHandler.ListJiraProjects, middleware.Require(permission.IntegrationsRead))
		}

		// Ticket field and status mapping profiles (static paths; must be
		// before /{id} routes). Reading is integrations:read; every change is
		// integrations:manage, and publishing also needs a fresh step-up. A
		// preview renders a finding or task: the service enforces the
		// caller's data scope on that object.
		if ticketMapping != nil {
			read := middleware.Require(permission.IntegrationsRead)
			manage := middleware.Require(permission.IntegrationsManage)
			r.GET("/ticket-mappings/catalog", ticketMapping.Catalog, read)
			r.GET("/ticket-mappings", ticketMapping.List, read)
			r.POST("/ticket-mappings", ticketMapping.Create, manage)
			r.GET("/ticket-mappings/{mapping_id}", ticketMapping.Get, read)
			r.DELETE("/ticket-mappings/{mapping_id}", ticketMapping.Delete, manage)
			r.PUT("/ticket-mappings/{mapping_id}/draft", ticketMapping.SaveDraft, manage)
			r.DELETE("/ticket-mappings/{mapping_id}/draft", ticketMapping.DiscardDraft, manage)
			r.POST("/ticket-mappings/{mapping_id}/publish", ticketMapping.Publish, manage, requireStepUp())
			r.POST("/ticket-mappings/{mapping_id}/rollback", ticketMapping.Rollback, manage)
			r.POST("/ticket-mappings/{mapping_id}/dry-run", ticketMapping.SetDryRun, manage, requireStepUp())
			r.GET("/ticket-mappings/{mapping_id}/versions", ticketMapping.Versions, read)
			r.GET("/ticket-mappings/{mapping_id}/diff", ticketMapping.Diff, read)
			r.POST("/ticket-mappings/{mapping_id}/verify", ticketMapping.Validate, read)
			r.POST("/ticket-mappings/{mapping_id}/drift", ticketMapping.Drift, manage)
			r.GET("/ticket-mappings/{mapping_id}/export", ticketMapping.Export, read)
			r.POST("/ticket-mappings/{mapping_id}/import", ticketMapping.Import, manage)
			r.POST("/ticket-mappings/{mapping_id}/copy", ticketMapping.Copy, manage)
			r.POST("/ticket-mappings/{mapping_id}/suggest", ticketMapping.Suggest, read)
			r.POST("/ticket-mappings/{mapping_id}/simulate", ticketMapping.Simulate, read)
			r.POST("/ticket-mappings/{mapping_id}/preview", ticketMapping.Preview, manage)
			r.POST("/ticket-mappings/{mapping_id}/inbound-preview", ticketMapping.PreviewInbound, manage)
		}

		// DefectDojo co-existence sync (RFC-013): pull the tenant's DefectDojo
		// findings and ingest them. Static path; must be before /{id} routes.
		if defectDojoHandler != nil {
			r.POST("/defectdojo/sync", defectDojoHandler.Sync, middleware.Require(permission.IntegrationsManage))
		}

		// Get, update, delete specific integration
		r.GET("/{id}", h.Get, middleware.Require(permission.IntegrationsRead))
		r.PUT("/{id}", h.Update, middleware.Require(permission.IntegrationsManage))
		r.DELETE("/{id}", h.Delete, middleware.Require(permission.IntegrationsManage))

		// Integration actions
		r.POST("/{id}/test", h.Test, middleware.Require(permission.IntegrationsManage))
		r.POST("/{id}/sync", h.Sync, middleware.Require(permission.IntegrationsManage))
		r.POST("/{id}/coverage/reactivate", h.ResumeCoverageRotation, middleware.Require(permission.IntegrationsManage))
		// Scan chosen assets now with a Tenable.sc connector: a scan run, so
		// scans:write and the scans module, like starting any scan.
		if scanNow != nil {
			mws := []Middleware{middleware.Require(permission.ScansWrite)}
			if scansModule != nil {
				mws = append(mws, scansModule)
			}
			r.POST("/{id}/scans/run", scanNow.ConnectorScanNow, mws...)
		}
		r.POST("/{id}/enable", h.Enable, middleware.Require(permission.IntegrationsManage))
		r.POST("/{id}/disable", h.Disable, middleware.Require(permission.IntegrationsManage))

		// Notification actions
		r.PUT("/{id}/notification", h.UpdateNotification, middleware.Require(permission.IntegrationsManage))
		r.POST("/{id}/test-notification", h.TestNotification, middleware.Require(permission.IntegrationsManage))
		// NOTE: /send endpoint removed for security - notifications are triggered internally only
		// Use BroadcastNotification from FindingService/ScanService instead
		// Delivery history carries every event's title, body and metadata
		// (finding messages, asset names, owner emails) for the whole
		// tenant, ignoring data scope: channel managers only, like the
		// channel configuration that decides where those events go.
		r.GET("/{id}/notification-events", h.GetNotificationEvents, middleware.Require(permission.IntegrationsManage))

		// List repositories from SCM integration
		r.GET("/{id}/repositories", h.ListRepositories, middleware.Require(permission.IntegrationsRead))

		// Jira field and workflow metadata for the mapping editor.
		if ticketMapping != nil {
			r.GET("/{id}/jira/issue-types", ticketMapping.IssueTypes, middleware.Require(permission.IntegrationsRead))
			r.GET("/{id}/jira/metadata", ticketMapping.Metadata, middleware.Require(permission.IntegrationsRead))
		}
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

	// Tenant-scoped routes - tenant from JWT token.
	//
	// The outbox holds a row for every event, whether or not a channel is
	// configured: new findings (message, asset id, owner name and email),
	// new assets, exposures, SLA and approval events, tenant-wide and
	// without data scope. That is delivery telemetry for whoever manages the
	// channels, so every route also needs integrations:manage (owner/admin
	// by default); members and viewers hold notifications:read for their
	// own in-app notices, not for this stream. Research doc 15, L-03.
	router.Group("/api/v1/notification-outbox", func(r Router) {
		// Get outbox statistics for tenant
		r.GET("/stats", h.GetStats, middleware.RequireAll(permission.NotificationsRead, permission.IntegrationsManage))

		// List outbox entries for tenant
		r.GET("/", h.List, middleware.RequireAll(permission.NotificationsRead, permission.IntegrationsManage))

		// Get single outbox entry (must belong to tenant)
		r.GET("/{id}", h.Get, middleware.RequireAll(permission.NotificationsRead, permission.IntegrationsManage))

		// Retry failed entry (must belong to tenant)
		r.POST("/{id}/retry", h.Retry, middleware.RequireAll(permission.NotificationsWrite, permission.IntegrationsManage))

		// Delete entry (must belong to tenant)
		r.DELETE("/{id}", h.Delete, middleware.RequireAll(permission.NotificationsDelete, permission.IntegrationsManage))
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

	// Notification event-type catalog for the current tenant. Served from
	// integration.AllEventTypes(), the same registry the outbox routes on, so a
	// client no longer has to keep a hand-written copy in sync with it.
	router.Group("/api/v1/me/event-types", func(r Router) {
		r.GET("/", h.GetTenantEventTypes)
	}, tenantMiddlewares...)
}

// registerWebSocketRoutes registers the real-time WebSocket endpoint
// (RFC-045). The browser opens it on the UI's own origin and the upgrade is
// authenticated by the auth_token session cookie (or a Bearer access token),
// through realtimeMiddlewares: the same tenant gates as every tenant route.
// No credential travels in the URL. The handler then requires an Origin from
// the allowlist for a cookie-authenticated upgrade, and binds the socket to
// the session and the token's expiry.
//
// Channels follow the format: {type}:{id}. The hub authorizes every
// subscription against the connection's own user and tenant
// (websocket.Hub.defaultAuthorize):
//   - user:{tenant_id}:{user_id} - the connected user's in-app notifications (own channel only)
//   - tenant:{id}         - events for every tenant member (module toggles); never notifications
//   - finding:{id}        - Activity updates for a finding (findings:read)
//   - triage:{finding_id} - AI triage progress updates (findings:read)
//   - scan:{id}           - Scan progress updates (scans:read)
//   - group:{id}          - Scope-rule changes (group member or team:groups:read)
func registerWebSocketRoutes(
	router Router,
	h *websocket.Handler,
	authMiddleware Middleware,
	userSyncMiddleware Middleware,
) {
	router.Group("/api/v1/ws", func(r Router) {
		r.GET("/", h.ServeWS)
	}, realtimeMiddlewares(authMiddleware, userSyncMiddleware)...)
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
		r.POST("/", h.Create, middleware.Require(permission.APIKeysWrite), requireStepUp())
		r.GET("/{id}", h.Get, middleware.Require(permission.APIKeysRead))
		r.DELETE("/{id}", h.Delete, middleware.Require(permission.APIKeysDelete), requireStepUp())
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

// registerPlatformScanningRoutes registers platform scanning as a tenant sees
// it: an aggregated service, for anyone who reads sensors or scans. No tenant
// route reads or manages a platform sensor itself (admin console, RFC-022).
func registerPlatformScanningRoutes(
	router Router,
	h *handler.PlatformScanningHandler,
	authMiddleware Middleware,
	userSyncMiddleware Middleware,
) {
	tenantMiddlewares := buildTokenTenantMiddlewares(authMiddleware, userSyncMiddleware)

	router.Group("/api/v1/platform", func(r Router) {
		r.GET("/scanning", h.Get, middleware.RequireAny(permission.SensorsRead, permission.ScansRead))
	}, tenantMiddlewares...)
}

// JiraWebhookSecretResolver returns the candidate HMAC secrets for a tenant's
// inbound Jira webhooks (one per configured Jira integration). Implemented by
// the integration service.
type JiraWebhookSecretResolver interface {
	ListJiraWebhookSecrets(ctx context.Context, tenantID shared.ID) ([]string, error)
}

// registerIncomingWebhookRoutes registers public incoming webhook endpoints.
// These endpoints are NOT protected by JWT — they are called by external services (e.g. Jira).
// Tenant routing is done via a ?tenant= query parameter that each external service configures.
//
// Each request is verified with HMAC-SHA256 over the raw body
// (middleware.VerifyHMACMulti) against the requesting organization's own
// per-integration webhook secrets only, resolved from ?tenant=. An
// organization only ever holds its own secrets, so one organization cannot
// sign a delivery for another. There is no platform-wide secret. With no
// secret for the named organization the middleware rejects the request.
func registerIncomingWebhookRoutes(
	router Router,
	jiraHandler *handler.JiraWebhookHandler,
	resolver JiraWebhookSecretResolver,
	log *logger.Logger,
) {
	if jiraHandler == nil {
		return
	}
	hmacMW := middleware.VerifyHMACMulti(
		"X-OpenCTEM-Signature",
		func(r *http.Request) ([]string, bool) {
			// Failures to resolve (bad tenant id, lookup error) contribute no
			// candidates — they never widen acceptance to another tenant.
			if resolver == nil {
				return nil, false
			}
			tid, err := shared.IDFromString(r.URL.Query().Get("tenant"))
			if err != nil {
				return nil, false
			}
			secrets, err := resolver.ListJiraWebhookSecrets(r.Context(), tid)
			if err != nil {
				log.Warn("failed to resolve tenant Jira webhook secrets", "error", err)
				return nil, false
			}
			return secrets, len(secrets) > 0
		},
		log,
	)
	router.POST("/api/v1/webhooks/incoming/jira", jiraHandler.IncomingJiraWebhook, hmacMW)
}

// GitHub webhook budget per client IP. Generous: deliveries for every
// organization arrive from GitHub's shared address pool. It bounds the
// per-request secret lookup an unauthenticated caller can trigger.
const (
	githubWebhookPerIPPerSecond = 50
	githubWebhookPerIPBurst     = 500
)

// registerGitHubWebhookRoute registers the public GitHub webhook. The handler
// verifies GitHub's X-Hub-Signature-256 against the organization's own
// secrets and refuses replays of a delivery id; the route adds a per-IP
// budget in front of the secret lookup.
func registerGitHubWebhookRoute(router Router, h *handler.GitHubWebhookHandler, log *logger.Logger) {
	perIP := middleware.NewTelemetryRateLimiter(githubWebhookPerIPPerSecond, githubWebhookPerIPBurst, time.Hour, log).
		MiddlewareKeyed(middleware.ClientIPKey, "Too many webhook deliveries")
	router.POST("/api/v1/webhooks/incoming/github", h.IncomingGitHubWebhook, perIP)
}

// includeDiscoveredAssets puts include_discovered=true into the request
// context (shared.WithDiscoveredAssets): metrics then count the whole
// inventory, discovered assets included. It changes counts only.
func includeDiscoveredAssets(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("include_discovered") == "true" {
			r = r.WithContext(shared.WithDiscoveredAssets(r.Context()))
		}
		next.ServeHTTP(w, r)
	})
}

// includeProgramAssets puts include_program_assets=true into the request
// context (shared.WithProgramAssets); any other value keeps the default.
func includeProgramAssets(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("include_program_assets") == "true" {
			ctx := shared.WithProgramAssets(r.Context())
			// Private program assets stay hidden from non-members who are
			// not owners (RFC-065 §15.3); an unparseable user is a member
			// of nothing.
			uid, _ := shared.IDFromString(middleware.GetUserID(ctx))
			ctx = shared.WithProgramViewer(ctx, shared.ProgramViewer{UserID: uid, Owner: middleware.IsOwner(ctx)})
			r = r.WithContext(ctx)
		}
		next.ServeHTTP(w, r)
	})
}

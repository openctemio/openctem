package routes

import (
	"github.com/openctemio/openctem/api/internal/infra/http/handler"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/domain/permission"
)

// registerMCPOAuthRoutes mounts the authorization server of the MCP endpoint
// (RFC-062):
//
//   - public, rate limited per IP: the RFC 8414 metadata, the authorization
//     endpoint (a browser navigation that ends on the consent page), the
//     token and revocation endpoints (public clients, PKCE);
//   - the consent API the web consent page calls, on the token-tenant chain:
//     a signed-in session in its current organization. API keys are refused
//     on /api/v1/oauth (APIKeyRouteDenied) and an MCP access token is not a
//     session.
func registerMCPOAuthRoutes(router Router, h *handler.MCPOAuthHandler, rateLimit, authMiddleware, userSyncMiddleware Middleware) {
	pub := []Middleware{}
	if rateLimit != nil {
		pub = append(pub, rateLimit)
	}
	router.GET("/.well-known/oauth-authorization-server", h.ServerMetadata, pub...)
	router.GET("/oauth/authorize", h.Authorize, pub...)
	router.POST("/oauth/token", h.Token, pub...)
	router.POST("/oauth/revoke", h.Revoke, pub...)

	tenantMiddlewares := buildTokenTenantMiddlewares(authMiddleware, userSyncMiddleware)

	router.Group("/api/v1/oauth/requests", func(r Router) {
		// Any member may connect an application for themselves: the grant
		// never exceeds what they hold, so no permission gate applies.
		r.GET("/{id}", h.GetConsentRequest)
		r.POST("/{id}/approve", h.ApproveConsent)
		r.POST("/{id}/deny", h.DenyConsent)
	}, tenantMiddlewares...)
}

// registerMCPSettingsRoutes mounts the organization MCP policy (RFC-062 §8).
// Changing it needs a recent sign-in, like the other security settings; API
// keys are refused here (APIKeyRouteDenied).
func registerMCPSettingsRoutes(router Router, h *handler.MCPSettingsHandler, authMiddleware, userSyncMiddleware Middleware) {
	tenantMiddlewares := buildTokenTenantMiddlewares(authMiddleware, userSyncMiddleware)
	router.Group("/api/v1/mcp-access/settings", func(r Router) {
		r.GET("/", h.Get, middleware.Require(permission.SettingsRead))
		r.PUT("/", h.Update, middleware.Require(permission.SettingsWrite), requireStepUp())
	}, tenantMiddlewares...)
}

// registerMCPConnectionRoutes mounts the connected applications of RFC-062
// §12: everyone sees and ends their own connections; owners and
// administrators see and end every connection of the organization. API keys
// are refused (APIKeyRouteDenied: /api/v1/mcp-access).
func registerMCPConnectionRoutes(router Router, h *handler.MCPConnectionsHandler, authMiddleware, userSyncMiddleware Middleware) {
	tenantMiddlewares := buildTokenTenantMiddlewares(authMiddleware, userSyncMiddleware)
	router.Group("/api/v1/mcp-access/my-connections", func(r Router) {
		r.GET("/", h.ListMine)
		r.DELETE("/{id}", h.RevokeMine)
	}, tenantMiddlewares...)
	router.Group("/api/v1/mcp-access/connections", func(r Router) {
		r.GET("/", h.ListAll, middleware.RequireAdmin())
		r.DELETE("/{id}", h.RevokeAny, middleware.RequireAdmin())
	}, tenantMiddlewares...)
}

// registerMCPClientRoutes mounts client registration (RFC-062 §5): the
// organization's own clients (settings permissions, step-up for changes)
// and RFC 7591 dynamic registration, which answers only when the operator
// enabled it and is rate limited like account registration.
func registerMCPClientRoutes(router Router, h *handler.MCPClientsHandler, authMiddleware, userSyncMiddleware Middleware) {
	tenantMiddlewares := buildTokenTenantMiddlewares(authMiddleware, userSyncMiddleware)
	router.Group("/api/v1/mcp-access/clients", func(r Router) {
		r.GET("/", h.List, middleware.Require(permission.SettingsRead))
		r.POST("/", h.Create, middleware.Require(permission.SettingsWrite), requireStepUp())
		r.DELETE("/{id}", h.Delete, middleware.Require(permission.SettingsWrite), requireStepUp())
	}, tenantMiddlewares...)
	router.POST("/oauth/register", h.Register, newAuthRateLimiter("mcp-register").RegisterMiddleware())
}

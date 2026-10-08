package routes

import (
	"github.com/openctemio/openctem/api/internal/infra/http/handler"
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

package routes

import "github.com/openctemio/api/internal/infra/http/handler"

// registerMCPRoutes mounts the read-only Model Context Protocol endpoint. It is
// authenticated ONLY by a tenant-scoped `oct_` API key (apiKeyAuth) — never the
// browser JWT chain — because an MCP client presents a static bearer token. The
// tenant is bound by that middleware and every tool is confined to it. A per-IP
// rate limiter runs first so an unauthenticated junk-token flood can't drive the
// (double) key lookups; order is [rateLimit, apiKeyAuth].
func registerMCPRoutes(router Router, h *handler.MCPHandler, mws ...Middleware) {
	router.POST("/api/v1/mcp", h.ServeHTTP, mws...)
}

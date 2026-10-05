package routes

import "github.com/openctemio/openctem/api/internal/infra/http/handler"

// registerMCPRoutes mounts the read-only Model Context Protocol endpoint. It is
// authenticated ONLY by a tenant-scoped `oct_` API key (apiKeyAuth) — never the
// browser JWT chain — because an MCP client presents a static bearer token. The
// tenant is bound by that middleware and every tool is confined to it. A per-IP
// rate limiter runs first so an unauthenticated junk-token flood can't drive the
// (double) key lookups. See mcpMiddlewares for the order.
func registerMCPRoutes(router Router, h *handler.MCPHandler, rateLimit, apiKeyAuth Middleware) {
	router.POST("/api/v1/mcp", h.ServeHTTP, mcpMiddlewares(rateLimit, apiKeyAuth)...)
}

// mcpMiddlewares is the MCP chain: [rateLimit, apiKeyAuth, IP allowlist].
//
// The organization IP allowlist binds an `oct_` key on MCP exactly as on the
// REST API (buildBaseMiddlewares): a key leaked outside the organization's
// network must not keep reading findings, assets and pentest data through
// MCP after REST refuses it (23b S-H2). It runs after apiKeyAuth, which puts
// the key's tenant in the context, and reads the client IP through
// pkg/httpsec (trusted-proxy aware), never a raw header. nil (tests without a
// tenant repository) leaves it out, as on every other chain.
func mcpMiddlewares(rateLimit, apiKeyAuth Middleware) []Middleware {
	mws := make([]Middleware, 0, 3)
	if rateLimit != nil {
		mws = append(mws, rateLimit)
	}
	mws = append(mws, apiKeyAuth)
	if ipAllowlistMiddleware != nil {
		mws = append(mws, ipAllowlistMiddleware)
	}
	return mws
}

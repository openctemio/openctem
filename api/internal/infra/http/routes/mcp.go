package routes

import (
	"github.com/openctemio/openctem/api/internal/infra/http/handler"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/domain/mcpoauth"
)

// MCPDiscovery is the OAuth discovery of the MCP endpoint (RFC-062 §4): the
// public endpoints and the Protected Resource Metadata handler. nil (no
// public URL configured) leaves the endpoint without discovery: it still
// accepts `oct_` keys, and a 401 carries no challenge.
type MCPDiscovery struct {
	Endpoints mcpoauth.Endpoints
	Metadata  *handler.MCPResourceMetadataHandler
	// AllowedOrigins are the browser origins besides the public origin that
	// may call the endpoint (CORS_ALLOWED_ORIGINS).
	AllowedOrigins []string
}

// registerMCPRoutes mounts the read-only Model Context Protocol endpoint and
// its Protected Resource Metadata. The endpoint is authenticated ONLY by a
// tenant-scoped `oct_` API key (apiKeyAuth) — never the browser JWT chain —
// because an MCP client presents a bearer token. The tenant is bound by that
// middleware and every tool is confined to it. See mcpMiddlewares for the
// order.
func registerMCPRoutes(router Router, h *handler.MCPHandler, rateLimit, apiKeyAuth Middleware, d *MCPDiscovery) {
	router.POST("/api/v1/mcp", h.ServeHTTP, mcpMiddlewares(rateLimit, apiKeyAuth, d)...)
	if d == nil || d.Metadata == nil {
		return
	}
	// RFC 9728 §3.1: the metadata of resource https://host/api/v1/mcp is at
	// /.well-known/oauth-protected-resource/api/v1/mcp; clients that cannot
	// derive it try the root. Both describe the one MCP resource. Public
	// documents, rate limited per IP. Literal paths: the route tests read
	// them from this file (mcpoauth.MCPPath, ProtectedResourceMetadataPath).
	pub := []Middleware{}
	if rateLimit != nil {
		pub = append(pub, rateLimit)
	}
	router.GET("/.well-known/oauth-protected-resource/api/v1/mcp", d.Metadata.Serve, pub...)
	router.GET("/.well-known/oauth-protected-resource", d.Metadata.Serve, pub...)
}

// mcpMiddlewares is the MCP chain:
// [Origin guard, 401 challenge, rateLimit, apiKeyAuth, IP allowlist].
//
// The Origin guard runs first: a browser page on a foreign origin is refused
// before anything else (DNS rebinding, MCP Streamable HTTP §Security). The
// challenge wraps the rest so every 401 tells the client where the Protected
// Resource Metadata is. A per-IP rate limiter runs before auth so an
// unauthenticated junk-token flood can't drive the key lookups.
//
// The organization IP allowlist binds an `oct_` key on MCP exactly as on the
// REST API (buildBaseMiddlewares): a key leaked outside the organization's
// network must not keep reading findings, assets and pentest data through
// MCP after REST refuses it (23b S-H2). It runs after apiKeyAuth, which puts
// the key's tenant in the context, and reads the client IP through
// pkg/httpsec (trusted-proxy aware), never a raw header. nil (tests without a
// tenant repository) leaves it out, as on every other chain.
func mcpMiddlewares(rateLimit, apiKeyAuth Middleware, d *MCPDiscovery) []Middleware {
	mws := make([]Middleware, 0, 5)
	if d != nil {
		origins := append([]string{d.Endpoints.Origin()}, d.AllowedOrigins...)
		mws = append(mws, middleware.MCPOriginGuard(origins), middleware.MCPChallenge(d.Endpoints))
	}
	if rateLimit != nil {
		mws = append(mws, rateLimit)
	}
	mws = append(mws, apiKeyAuth)
	if ipAllowlistMiddleware != nil {
		mws = append(mws, ipAllowlistMiddleware)
	}
	return mws
}

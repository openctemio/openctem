# ADR-001: HTTP Router Strategy

## Status

Accepted (Updated: Chi with Abstraction Layer + Inline Middleware)

## Context

Need to choose an approach for the HTTP layer that balances:
- Clean routing syntax
- Standard net/http compatibility
- No framework lock-in
- Easy to test and maintain
- Per-route middleware without verbose wrapping

## Decision

Use **Chi router** with a **Router abstraction interface** and **inline middleware support**:

1. **Chi v5** as the primary router implementation
2. **Router interface** to abstract the routing layer
3. **Standard `net/http` handler signature** for all handlers
4. **Variadic middleware** on route methods for clean per-route authorization

This gives us clean routing syntax while keeping the ability to swap routers.

## Implementation

### Router Interface (Port)

```go
// internal/infra/http/router.go
type Middleware func(http.Handler) http.Handler

type Router interface {
    // HTTP method handlers with optional route-specific middleware
    GET(path string, handler http.HandlerFunc, middlewares ...Middleware)
    POST(path string, handler http.HandlerFunc, middlewares ...Middleware)
    PUT(path string, handler http.HandlerFunc, middlewares ...Middleware)
    PATCH(path string, handler http.HandlerFunc, middlewares ...Middleware)
    DELETE(path string, handler http.HandlerFunc, middlewares ...Middleware)

    // Group creates a new route group with prefix and optional middleware
    Group(prefix string, fn func(Router), middlewares ...Middleware)

    // Use adds middleware to the router (applies to all subsequent routes)
    Use(middlewares ...Middleware)

    // With returns a new Router with the given middleware applied
    With(middlewares ...Middleware) Router

    // Handler returns the http.Handler for use with http.Server
    Handler() http.Handler

    // Walk iterates over all registered routes
    Walk(fn func(method, path string, handler http.Handler) error) error
}
```

### Chi Implementation (Adapter)

```go
// internal/infra/http/chi_router.go
func NewChiRouter() Router {
    r := chi.NewRouter()
    r.Use(chimw.RealIP)
    r.Use(chimw.CleanPath)
    r.Use(chimw.StripSlashes)
    return &chiRouter{mux: r}
}

// GET registers a handler with optional middleware
func (r *chiRouter) GET(path string, handler http.HandlerFunc, middlewares ...Middleware) {
    r.mux.Get(path, r.wrapHandler(handler, middlewares...))
}

// wrapHandler applies middleware chain to handler
func (r *chiRouter) wrapHandler(h http.HandlerFunc, middlewares ...Middleware) http.HandlerFunc {
    if len(middlewares) == 0 {
        return h
    }
    var handler http.Handler = h
    for i := len(middlewares) - 1; i >= 0; i-- {
        handler = middlewares[i](handler)
    }
    return handler.ServeHTTP
}
```

### Handler Signature (Standard net/http)

```go
// All handlers use standard signature
func (h *AssetHandler) Get(w http.ResponseWriter, r *http.Request) {
    id := r.PathValue("id")  // Go 1.22+ stdlib
    // ... handle request
}
```

### Route Registration with Inline Middleware

```go
// internal/infra/http/routes.go
func RegisterRoutes(router Router, h Handlers, ...) {
    // Health routes (public)
    router.GET("/health", h.Health.Health)

    // Asset routes with permission-based authorization
    router.Group("/api/v1/assets", func(r Router) {
        // Read operations
        r.GET("/", h.List, middleware.Require(permission.AssetsRead))
        r.GET("/{id}", h.Get, middleware.Require(permission.AssetsRead))

        // Write operations
        r.POST("/", h.Create, middleware.Require(permission.AssetsWrite))
        r.PUT("/{id}", h.Update, middleware.Require(permission.AssetsWrite))

        // Delete operations
        r.DELETE("/{id}", h.Delete, middleware.Require(permission.AssetsDelete))
    }, authMiddleware, userSyncMiddleware, middleware.RequireTenant())

    // Team management with role-based authorization
    router.Group("/api/v1/tenants/{tenant}", func(r Router) {
        r.GET("/members", h.ListMembers)  // any member
        r.PATCH("/", h.Update, middleware.RequireTeamAdmin())
        r.DELETE("/", h.Delete, middleware.RequireTeamOwner())
    }, authMiddleware, tenantContext, requireMembership)
}
```

## Alternatives Considered

| Approach | Pros | Cons |
|----------|------|------|
| **Pure stdlib** | Zero deps | Verbose syntax, manual middleware |
| **Gin** | Feature-rich | Different handler signature, lock-in |
| **Echo** | Good perf | Different handler signature |
| **Chi only** | Clean | Direct dependency, harder to swap |
| **Chi + Abstraction** | Best of both | Slight overhead |
| **Chi + Abstraction + Inline MW** ✓ | Cleanest syntax | Minimal overhead |

## Consequences

### Positive

- Clean routing syntax (`r.GET("/", handler, middleware)`)
- Express.js-like inline middleware pattern
- Standard `func(w, r)` handlers - no framework lock-in
- Can swap to stdlib router without changing handlers
- Chi middleware compatible with net/http
- Easy to test with mock router
- Middleware chain built once at startup (no runtime overhead)

### Negative

- One external dependency (chi/v5)
- Abstraction layer adds indirection
- Need to maintain Router interface

## Data Flow

```
HTTP Request
    │
    ▼
┌─────────────────────────────────────────────────────┐
│  Chi Router (chi_router.go)                         │
│  - Implements Router interface                       │
│  - Path matching, middleware chain                   │
└─────────────────────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────────────────────┐
│  Middleware Chain                                    │
│  - Auth → UserSync → TenantContext → Permission     │
│  - Built at startup, executed per-request            │
└─────────────────────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────────────────────┐
│  Handler (asset_handler.go)                         │
│  - Standard func(w http.ResponseWriter, r *Request) │
│  - Uses r.PathValue("id") for path params           │
└─────────────────────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────────────────────┐
│  Service (asset_service.go)                         │
│  - Business logic orchestration                      │
└─────────────────────────────────────────────────────┘
```

## References

- [Chi Router](https://github.com/go-chi/chi)
- [Go 1.25 Enhanced Routing](https://go.dev/doc/go1.25)
- [Hexagonal Architecture](https://alistair.cockburn.us/hexagonal-architecture/)
- [Express.js Middleware Pattern](https://expressjs.com/en/guide/using-middleware.html)

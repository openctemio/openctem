package http

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	chimw "github.com/go-chi/chi/v5/middleware"
)

// chiRouter implements Router interface using Chi.
// This is an implementation detail - application code should use Router interface.
type chiRouter struct {
	mux         chi.Router
	middlewares []Middleware
}

// Ensure chiRouter implements Router interface.
var _ Router = (*chiRouter)(nil)

// NewChiRouter creates a new Router using Chi as the underlying implementation.
func NewChiRouter() Router {
	r := chi.NewRouter()

	// Chi built-in middleware that are battle-tested
	r.Use(chimw.RealIP)       // Sets RemoteAddr to X-Real-IP or X-Forwarded-For
	r.Use(chimw.CleanPath)    // Clean double slashes
	r.Use(chimw.StripSlashes) // Strip trailing slashes

	return &chiRouter{
		mux:         r,
		middlewares: []Middleware{},
	}
}

// NewChiRouterWithOptions creates a router with custom options.
func NewChiRouterWithOptions(opts ...ChiOption) Router {
	r := chi.NewRouter()
	cr := &chiRouter{
		mux:         r,
		middlewares: []Middleware{},
	}

	for _, opt := range opts {
		opt(cr)
	}

	return cr
}

// ChiOption is a function that configures the Chi router.
type ChiOption func(*chiRouter)

// WithChiMiddleware adds Chi's built-in middleware.
func WithChiMiddleware() ChiOption {
	return func(r *chiRouter) {
		r.mux.Use(chimw.RealIP)
		r.mux.Use(chimw.CleanPath)
		r.mux.Use(chimw.StripSlashes)
	}
}

// WithRequestID adds Chi's request ID middleware.
func WithRequestID() ChiOption {
	return func(r *chiRouter) {
		r.mux.Use(chimw.RequestID)
	}
}

// GET registers a handler for GET requests with optional middleware.
func (r *chiRouter) GET(path string, handler http.HandlerFunc, middlewares ...Middleware) {
	r.mux.Get(path, r.wrapHandler(handler, middlewares...))
}

// POST registers a handler for POST requests with optional middleware.
func (r *chiRouter) POST(path string, handler http.HandlerFunc, middlewares ...Middleware) {
	r.mux.Post(path, r.wrapHandler(handler, middlewares...))
}

// PUT registers a handler for PUT requests with optional middleware.
func (r *chiRouter) PUT(path string, handler http.HandlerFunc, middlewares ...Middleware) {
	r.mux.Put(path, r.wrapHandler(handler, middlewares...))
}

// PATCH registers a handler for PATCH requests with optional middleware.
func (r *chiRouter) PATCH(path string, handler http.HandlerFunc, middlewares ...Middleware) {
	r.mux.Patch(path, r.wrapHandler(handler, middlewares...))
}

// DELETE registers a handler for DELETE requests with optional middleware.
func (r *chiRouter) DELETE(path string, handler http.HandlerFunc, middlewares ...Middleware) {
	r.mux.Delete(path, r.wrapHandler(handler, middlewares...))
}

// Group creates a new route group with prefix and optional middleware.
func (r *chiRouter) Group(prefix string, fn func(Router), middlewares ...Middleware) {
	r.mux.Route(prefix, func(cr chi.Router) {
		// Apply group middlewares
		for _, mw := range middlewares {
			cr.Use(toChiMiddleware(mw))
		}

		// Create a new chiRouter for the group
		group := &chiRouter{
			mux:         cr,
			middlewares: middlewares,
		}
		fn(group)
	})
}

// Use adds middleware to the router.
func (r *chiRouter) Use(middlewares ...Middleware) {
	r.middlewares = append(r.middlewares, middlewares...)
	for _, mw := range middlewares {
		r.mux.Use(toChiMiddleware(mw))
	}
}

// With returns a new Router with the given middleware applied.
// This allows route-specific middleware without modifying the parent router.
//
// Example:
//
//	r.With(authMiddleware).GET("/protected", handler)
//	r.With(middleware.Require(permission.AssetsRead)).GET("/assets", h.List)
func (r *chiRouter) With(middlewares ...Middleware) Router {
	// Convert our Middleware to chi middleware
	chiMiddlewares := make([]func(http.Handler) http.Handler, len(middlewares))
	for i, mw := range middlewares {
		chiMiddlewares[i] = toChiMiddleware(mw)
	}

	// Use chi's With() to create a new router context with middleware
	return &chiRouter{
		mux:         r.mux.With(chiMiddlewares...),
		middlewares: append(r.middlewares, middlewares...),
	}
}

// Handler returns the http.Handler for use with http.Server.
func (r *chiRouter) Handler() http.Handler {
	return r.mux
}

// Walk iterates over all registered routes using chi.Walk.
func (r *chiRouter) Walk(fn func(method, path string, handler http.Handler) error) error {
	return chi.Walk(r.mux, func(method, route string, handler http.Handler, _ ...func(http.Handler) http.Handler) error {
		// Skip chi internal wildcard routes
		if route == "/*" {
			return nil
		}
		return fn(method, route, handler)
	})
}

// wrapHandler wraps a handler with optional route-specific middleware.
// Middleware is applied in order: first middleware wraps outermost.
func (r *chiRouter) wrapHandler(h http.HandlerFunc, middlewares ...Middleware) http.HandlerFunc {
	if len(middlewares) == 0 {
		return h
	}

	// Apply middleware chain
	var handler http.Handler = h
	for i := len(middlewares) - 1; i >= 0; i-- {
		handler = middlewares[i](handler)
	}
	return handler.ServeHTTP
}

// toChiMiddleware converts our Middleware to Chi's middleware format.
// Since Chi uses the same signature, this is just a type conversion.
func toChiMiddleware(mw Middleware) func(http.Handler) http.Handler {
	return mw
}

package http

import (
	"net/http"
)

// Middleware is a function that wraps an http.Handler.
// This follows the standard net/http middleware pattern.
type Middleware func(http.Handler) http.Handler

// Router defines the interface for HTTP routing.
// This abstraction allows swapping the underlying router implementation
// (Chi, stdlib, Gin, etc.) without changing application code.
type Router interface {
	// HTTP method handlers with optional route-specific middleware.
	// Middleware is applied in order: first middleware wraps outermost.
	//
	// Example:
	//   r.GET("/", handler)                                    // No middleware
	//   r.GET("/", handler, authMiddleware)                    // With auth
	//   r.GET("/", handler, authMiddleware, loggingMiddleware) // Multiple
	GET(path string, handler http.HandlerFunc, middlewares ...Middleware)
	POST(path string, handler http.HandlerFunc, middlewares ...Middleware)
	PUT(path string, handler http.HandlerFunc, middlewares ...Middleware)
	PATCH(path string, handler http.HandlerFunc, middlewares ...Middleware)
	DELETE(path string, handler http.HandlerFunc, middlewares ...Middleware)

	// Group creates a new route group with prefix and optional middleware.
	// Group middleware applies to all routes within the group.
	Group(prefix string, fn func(Router), middlewares ...Middleware)

	// Use adds middleware to the router (applies to all subsequent routes)
	Use(middlewares ...Middleware)

	// With returns a new Router with the given middleware applied.
	// Prefer using inline middleware in route methods instead.
	With(middlewares ...Middleware) Router

	// Handler returns the http.Handler for use with http.Server
	Handler() http.Handler

	// Walk iterates over all registered routes.
	// The callback receives method, path, and handler for each route.
	Walk(fn func(method, path string, handler http.Handler) error) error
}

// Chain applies middlewares to a handler.
// The first middleware in the list will be the outermost (executed first).
func Chain(handler http.Handler, middlewares ...Middleware) http.Handler {
	for i := len(middlewares) - 1; i >= 0; i-- {
		handler = middlewares[i](handler)
	}
	return handler
}

// ChainFunc is like Chain but accepts http.HandlerFunc.
func ChainFunc(handler http.HandlerFunc, middlewares ...Middleware) http.Handler {
	return Chain(handler, middlewares...)
}

package http

import (
	"net/http"

	"github.com/go-chi/chi/v5"
)

// PathParam extracts a URL path parameter from the request.
// This abstracts the underlying router implementation.
// Handlers should use this instead of directly calling chi.URLParam or r.PathValue.
func PathParam(r *http.Request, key string) string {
	// Try Chi first (works with Chi router)
	if val := chi.URLParam(r, key); val != "" {
		return val
	}

	// Fallback to Go 1.22+ stdlib (works with stdlib router)
	return r.PathValue(key)
}

// QueryParam extracts a URL query parameter from the request.
func QueryParam(r *http.Request, key string) string {
	return r.URL.Query().Get(key)
}

// QueryParamDefault extracts a URL query parameter with a default value.
func QueryParamDefault(r *http.Request, key, defaultValue string) string {
	if val := r.URL.Query().Get(key); val != "" {
		return val
	}
	return defaultValue
}

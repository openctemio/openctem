package middleware

import (
	"net/http"

	"github.com/openctemio/api/pkg/logger"
)

// ContextLogger injects a request-scoped logger into the request context.
// The logger is enriched with request_id and user_id (when available).
// Services can retrieve it via logger.FromContext(ctx) for automatic
// request correlation in logs.
func ContextLogger(log *logger.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()

			// Create a logger enriched with context values (request_id, user_id)
			ctxLogger := log.WithContext(ctx)

			// Store the enriched logger in context
			ctx = logger.ToContext(ctx, ctxLogger)

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

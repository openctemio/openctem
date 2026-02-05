package middleware

import (
	"context"
	"database/sql"
	"net/http"

	"github.com/openctemio/api/pkg/apierror"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/logger"
)

// rlsTxKey is the context key for RLS transaction.
type rlsTxKey struct{}

// RLSContextMiddleware sets the PostgreSQL session variable for Row Level Security.
// This middleware should be applied AFTER authentication middleware.
//
// How it works:
//  1. Extracts tenant_id from the authenticated context
//  2. Begins a database transaction
//  3. Sets `app.current_tenant_id` session variable for RLS policies
//  4. Stores the transaction in context for handlers to use
//  5. Commits/rollbacks based on response status
//
// Usage in routes:
//
//	router.Use(authMiddleware)
//	router.Use(RLSContextMiddleware(db, log))
//	router.Get("/findings", handler.ListFindings)  // RLS automatically filters
func RLSContextMiddleware(db *sql.DB, log *logger.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Get tenant ID from authenticated context
			tenantID, ok := GetTenantIDFromContext(r.Context())
			if !ok {
				// No tenant context - let the request proceed without RLS
				// RLS policies will block all access if no tenant is set
				next.ServeHTTP(w, r)
				return
			}

			// Begin transaction for RLS context
			tx, err := db.BeginTx(r.Context(), nil)
			if err != nil {
				log.Error("failed to begin RLS transaction", "error", err)
				apierror.InternalServerError("Database error").WriteJSON(w)
				return
			}

			// Set tenant context for RLS policies
			// SET LOCAL only affects the current transaction
			_, err = tx.ExecContext(r.Context(),
				"SET LOCAL app.current_tenant_id = $1", tenantID.String())
			if err != nil {
				_ = tx.Rollback()
				log.Error("failed to set RLS tenant context", "error", err, "tenant_id", tenantID)
				apierror.InternalServerError("Database error").WriteJSON(w)
				return
			}

			// Store transaction in context
			ctx := context.WithValue(r.Context(), rlsTxKey{}, tx)

			// Create response wrapper to detect errors
			rw := &rlsResponseWriter{ResponseWriter: w, statusCode: http.StatusOK}

			// Serve the request with RLS context
			next.ServeHTTP(rw, r.WithContext(ctx))

			// Commit or rollback based on response status
			if rw.statusCode >= 400 {
				if err := tx.Rollback(); err != nil {
					log.Error("failed to rollback RLS transaction", "error", err)
				}
			} else {
				if err := tx.Commit(); err != nil {
					log.Error("failed to commit RLS transaction", "error", err)
				}
			}
		})
	}
}

// PlatformAdminRLSMiddleware sets the platform admin bypass for RLS.
// This middleware should be used for platform admin routes that need
// cross-tenant access.
//
// Usage:
//
//	adminRouter.Use(PlatformAdminAuthMiddleware)
//	adminRouter.Use(PlatformAdminRLSMiddleware(db, log))
//	adminRouter.Get("/all-findings", handler.ListAllFindings)
func PlatformAdminRLSMiddleware(db *sql.DB, log *logger.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Begin transaction for RLS bypass
			tx, err := db.BeginTx(r.Context(), nil)
			if err != nil {
				log.Error("failed to begin admin RLS transaction", "error", err)
				apierror.InternalServerError("Database error").WriteJSON(w)
				return
			}

			// Set platform admin bypass for RLS policies
			_, err = tx.ExecContext(r.Context(),
				"SET LOCAL app.is_platform_admin = 'true'")
			if err != nil {
				_ = tx.Rollback()
				log.Error("failed to set RLS admin context", "error", err)
				apierror.InternalServerError("Database error").WriteJSON(w)
				return
			}

			// Store transaction in context
			ctx := context.WithValue(r.Context(), rlsTxKey{}, tx)

			// Create response wrapper
			rw := &rlsResponseWriter{ResponseWriter: w, statusCode: http.StatusOK}

			// Serve the request with admin bypass
			next.ServeHTTP(rw, r.WithContext(ctx))

			// Commit or rollback
			if rw.statusCode >= 400 {
				_ = tx.Rollback()
			} else {
				if err := tx.Commit(); err != nil {
					log.Error("failed to commit admin RLS transaction", "error", err)
				}
			}
		})
	}
}

// GetRLSTx retrieves the RLS transaction from context.
// Returns nil if no transaction is set.
func GetRLSTx(ctx context.Context) *sql.Tx {
	tx, ok := ctx.Value(rlsTxKey{}).(*sql.Tx)
	if !ok {
		return nil
	}
	return tx
}

// GetTenantIDFromContext extracts tenant ID from context.
// This is a helper that wraps the existing middleware function.
func GetTenantIDFromContext(ctx context.Context) (shared.ID, bool) {
	tenantIDStr := GetTenantID(ctx)
	if tenantIDStr == "" {
		return shared.ID{}, false
	}
	tenantID, err := shared.IDFromString(tenantIDStr)
	if err != nil {
		return shared.ID{}, false
	}
	return tenantID, true
}

// rlsResponseWriter wraps http.ResponseWriter to capture status code.
type rlsResponseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (rw *rlsResponseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

// Ensure rlsResponseWriter implements http.Flusher for streaming responses.
func (rw *rlsResponseWriter) Flush() {
	if flusher, ok := rw.ResponseWriter.(http.Flusher); ok {
		flusher.Flush()
	}
}

// Package middleware provides HTTP middleware for the API server.
// This file implements audit logging middleware for admin API endpoints.
package middleware

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/openctemio/api/pkg/domain/admin"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/logger"
)

// AuditMiddleware provides audit logging for admin API endpoints.
type AuditMiddleware struct {
	auditRepo admin.AuditLogRepository
	logger    *logger.Logger
}

// NewAuditMiddleware creates a new AuditMiddleware.
func NewAuditMiddleware(auditRepo admin.AuditLogRepository, log *logger.Logger) *AuditMiddleware {
	return &AuditMiddleware{
		auditRepo: auditRepo,
		logger:    log.With("middleware", "admin_audit"),
	}
}

// AuditLog creates middleware that logs admin actions to the audit log.
// Should be used after AdminAuthMiddleware.Authenticate().
//
// Parameters:
//   - action: The action being performed (e.g., "agent.create", "token.revoke")
//   - resourceType: The type of resource (e.g., "agent", "token")
//   - resourceIDParam: The chi URL param name for resource ID (e.g., "id", "agentID")
func (m *AuditMiddleware) AuditLog(action, resourceType, resourceIDParam string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Get admin user from context
			adminUser := GetAdminUser(r.Context())

			// Create audit log builder
			builder := admin.NewAuditLogBuilder(adminUser, action)

			// Set resource info
			var resourceID *shared.ID
			if resourceIDParam != "" {
				if idStr := chi.URLParam(r, resourceIDParam); idStr != "" {
					if id, err := shared.IDFromString(idStr); err == nil {
						resourceID = &id
					}
				}
			}
			builder.Resource(resourceType, resourceID, "")

			// Set request context
			builder.Context(extractIP(r), r.UserAgent())

			// Read and restore request body for logging
			var requestBody map[string]interface{}
			if r.Body != nil && r.ContentLength > 0 && r.ContentLength < 1024*1024 { // Max 1MB
				bodyBytes, err := io.ReadAll(r.Body)
				if err == nil {
					r.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
					_ = json.Unmarshal(bodyBytes, &requestBody)
				}
			}
			builder.Request(r.Method, r.URL.Path, requestBody)

			// Wrap response writer to capture status code
			wrappedWriter := &auditResponseWriter{ResponseWriter: w, statusCode: http.StatusOK}

			// Call next handler
			next.ServeHTTP(wrappedWriter, r)

			// Set response status
			builder.Response(wrappedWriter.statusCode)

			// Build and save audit log
			auditLog := builder.Build()

			// Save audit log asynchronously to not block the response
			go func() {
				if err := m.auditRepo.Create(context.Background(), auditLog); err != nil {
					m.logger.Error("failed to create audit log",
						"error", err,
						"action", action,
						"admin_id", func() string {
							if adminUser != nil {
								return adminUser.ID().String()
							}
							return ""
						}())
				}
			}()
		})
	}
}

// AuditAction creates a simpler audit middleware for actions without URL params.
func (m *AuditMiddleware) AuditAction(action string) func(http.Handler) http.Handler {
	return m.AuditLog(action, "", "")
}

// AuditResourceAction creates audit middleware for resource-specific actions.
func (m *AuditMiddleware) AuditResourceAction(action, resourceType string) func(http.Handler) http.Handler {
	return m.AuditLog(action, resourceType, "id")
}

// LogAuthFailure logs a failed authentication attempt.
func (m *AuditMiddleware) LogAuthFailure(r *http.Request, reason string) {
	auditLog := admin.NewAuditLogBuilder(nil, admin.AuditActionAuthFailure).
		Context(extractIP(r), r.UserAgent()).
		Request(r.Method, r.URL.Path, nil).
		Error(reason).
		Build()

	go func() {
		if err := m.auditRepo.Create(context.Background(), auditLog); err != nil {
			m.logger.Error("failed to log auth failure", "error", err)
		}
	}()
}

// LogAuthSuccess logs a successful authentication.
func (m *AuditMiddleware) LogAuthSuccess(r *http.Request, adminUser *admin.AdminUser) {
	auditLog := admin.NewAuditLogBuilder(adminUser, admin.AuditActionAuthSuccess).
		Context(extractIP(r), r.UserAgent()).
		Request(r.Method, r.URL.Path, nil).
		Response(http.StatusOK).
		Build()

	go func() {
		if err := m.auditRepo.Create(context.Background(), auditLog); err != nil {
			m.logger.Error("failed to log auth success", "error", err)
		}
	}()
}

// =============================================================================
// Response Writer Wrapper
// =============================================================================

// auditResponseWriter wraps http.ResponseWriter to capture the status code.
type auditResponseWriter struct {
	http.ResponseWriter
	statusCode int
	written    bool
}

func (w *auditResponseWriter) WriteHeader(statusCode int) {
	if !w.written {
		w.statusCode = statusCode
		w.written = true
	}
	w.ResponseWriter.WriteHeader(statusCode)
}

func (w *auditResponseWriter) Write(b []byte) (int, error) {
	if !w.written {
		w.statusCode = http.StatusOK
		w.written = true
	}
	return w.ResponseWriter.Write(b)
}

// Unwrap returns the original http.ResponseWriter.
// This is needed for http.ResponseController to work properly.
func (w *auditResponseWriter) Unwrap() http.ResponseWriter {
	return w.ResponseWriter
}

// =============================================================================
// Audit Action Helpers
// =============================================================================

// Common audit middleware factories for typical admin operations.

// AuditAdminCreate returns middleware for admin user creation.
func (m *AuditMiddleware) AuditAdminCreate() func(http.Handler) http.Handler {
	return m.AuditLog(admin.AuditActionAdminCreate, admin.ResourceTypeAdmin, "")
}

// AuditAdminUpdate returns middleware for admin user updates.
func (m *AuditMiddleware) AuditAdminUpdate() func(http.Handler) http.Handler {
	return m.AuditLog(admin.AuditActionAdminUpdate, admin.ResourceTypeAdmin, "id")
}

// AuditAdminDelete returns middleware for admin user deletion.
func (m *AuditMiddleware) AuditAdminDelete() func(http.Handler) http.Handler {
	return m.AuditLog(admin.AuditActionAdminDelete, admin.ResourceTypeAdmin, "id")
}

// AuditAgentCreate returns middleware for platform agent creation.
func (m *AuditMiddleware) AuditAgentCreate() func(http.Handler) http.Handler {
	return m.AuditLog(admin.AuditActionAgentCreate, admin.ResourceTypeAgent, "")
}

// AuditAgentUpdate returns middleware for platform agent updates.
func (m *AuditMiddleware) AuditAgentUpdate() func(http.Handler) http.Handler {
	return m.AuditLog(admin.AuditActionAgentUpdate, admin.ResourceTypeAgent, "id")
}

// AuditAgentDelete returns middleware for platform agent deletion.
func (m *AuditMiddleware) AuditAgentDelete() func(http.Handler) http.Handler {
	return m.AuditLog(admin.AuditActionAgentDelete, admin.ResourceTypeAgent, "id")
}

// AuditAgentEnable returns middleware for enabling platform agents.
func (m *AuditMiddleware) AuditAgentEnable() func(http.Handler) http.Handler {
	return m.AuditLog(admin.AuditActionAgentEnable, admin.ResourceTypeAgent, "id")
}

// AuditAgentDisable returns middleware for disabling platform agents.
func (m *AuditMiddleware) AuditAgentDisable() func(http.Handler) http.Handler {
	return m.AuditLog(admin.AuditActionAgentDisable, admin.ResourceTypeAgent, "id")
}

// AuditTokenCreate returns middleware for bootstrap token creation.
func (m *AuditMiddleware) AuditTokenCreate() func(http.Handler) http.Handler {
	return m.AuditLog(admin.AuditActionTokenCreate, admin.ResourceTypeToken, "")
}

// AuditTokenRevoke returns middleware for bootstrap token revocation.
func (m *AuditMiddleware) AuditTokenRevoke() func(http.Handler) http.Handler {
	return m.AuditLog(admin.AuditActionTokenRevoke, admin.ResourceTypeToken, "id")
}

// AuditJobCancel returns middleware for platform job cancellation.
func (m *AuditMiddleware) AuditJobCancel() func(http.Handler) http.Handler {
	return m.AuditLog(admin.AuditActionJobCancel, admin.ResourceTypeJob, "id")
}

// AuditTargetMappingCreate returns middleware for target mapping creation.
func (m *AuditMiddleware) AuditTargetMappingCreate() func(http.Handler) http.Handler {
	return m.AuditLog(admin.AuditActionTargetMappingCreate, admin.ResourceTypeTargetMapping, "")
}

// AuditTargetMappingUpdate returns middleware for target mapping updates.
func (m *AuditMiddleware) AuditTargetMappingUpdate() func(http.Handler) http.Handler {
	return m.AuditLog(admin.AuditActionTargetMappingUpdate, admin.ResourceTypeTargetMapping, "id")
}

// AuditTargetMappingDelete returns middleware for target mapping deletion.
func (m *AuditMiddleware) AuditTargetMappingDelete() func(http.Handler) http.Handler {
	return m.AuditLog(admin.AuditActionTargetMappingDelete, admin.ResourceTypeTargetMapping, "id")
}

// =============================================================================
// Helper to extract resource name from response
// =============================================================================

// SetAuditResourceName sets the resource name in the current request's audit log.
// Call this from handlers to provide more context for audit logs.
func SetAuditResourceName(ctx context.Context, name string) {
	// This would require storing a mutable reference in context
	// For now, resource names are captured at audit log creation time
	// This is a placeholder for future enhancement
	_ = ctx
	_ = name
}

// ExtractResourceIDFromPath extracts a resource ID from the URL path.
// Useful for DELETE operations where the ID might not be in chi params yet.
func ExtractResourceIDFromPath(path, prefix string) string {
	if !strings.HasPrefix(path, prefix) {
		return ""
	}
	remaining := strings.TrimPrefix(path, prefix)
	remaining = strings.TrimPrefix(remaining, "/")
	if idx := strings.Index(remaining, "/"); idx != -1 {
		return remaining[:idx]
	}
	return remaining
}

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
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/openctemio/openctem/api/pkg/domain/admin"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// auditWriteTimeout bounds how long a detached audit-write goroutine
// will wait on the DB before abandoning the write. Under a brute-force
// login burst the old unbounded goroutines piled up and exhausted
// memory; capping at 5s ensures at most N-concurrent-DB-slow audit
// writes are in-flight at any time.
const auditWriteTimeout = 5 * time.Second

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
//   - action: The action being performed (e.g., "sensor.create", "token.revoke")
//   - resourceType: The type of resource (e.g., "sensor", "token")
//   - resourceIDParam: The chi URL param name for resource ID (e.g., "id", "sensorID")
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

			// A create route has no id in its URL. Let the handler name what it
			// created (SetAuditResource), and remember the start of a 201 body so
			// its top-level "id" can stand in when the handler does not.
			created := &auditCreatedResource{}
			r = r.WithContext(context.WithValue(r.Context(), auditResourceKey{}, created))
			wrappedWriter := &auditResponseWriter{ResponseWriter: w, statusCode: http.StatusOK, sniff: resourceID == nil}

			// Call next handler
			next.ServeHTTP(wrappedWriter, r)

			if resourceID == nil && wrappedWriter.statusCode == http.StatusCreated {
				id := created.id
				if id == nil {
					id = topLevelID(wrappedWriter.head.Bytes())
				}
				if id != nil {
					builder.Resource(resourceType, id, created.name)
				}
			}

			// Set response status
			builder.Response(wrappedWriter.statusCode)

			if created.high {
				builder.High()
			}

			// Build and save audit log
			auditLog := builder.Build()
			if created.action != "" {
				auditLog.Action = created.action
			}

			// Save audit log asynchronously to not block the response.
			// Detach from request ctx (audit must outlive the request)
			// but cap at auditWriteTimeout so a stalled DB cannot pin
			// a goroutine forever — under a brute-force login burst the
			// old code spawned one unbounded goroutine per attempt and
			// eventually OOM'd the API process.
			go func() {
				ctx, cancel := context.WithTimeout(context.Background(), auditWriteTimeout)
				defer cancel()
				if err := m.auditRepo.Create(ctx, auditLog); err != nil {
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
		ctx, cancel := context.WithTimeout(context.Background(), auditWriteTimeout)
		defer cancel()
		if err := m.auditRepo.Create(ctx, auditLog); err != nil {
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
		ctx, cancel := context.WithTimeout(context.Background(), auditWriteTimeout)
		defer cancel()
		if err := m.auditRepo.Create(ctx, auditLog); err != nil {
			m.logger.Error("failed to log auth success", "error", err)
		}
	}()
}

// =============================================================================
// Response Writer Wrapper
// =============================================================================

// auditResponseWriter wraps http.ResponseWriter to capture the status code
// and, when sniff is set, the first auditSniffLimit bytes of the body.
type auditResponseWriter struct {
	http.ResponseWriter
	statusCode int
	written    bool
	sniff      bool
	head       bytes.Buffer
}

// auditSniffLimit bounds how much of a response body is kept to find the id
// of a created resource. Create responses are small; the id comes first.
const auditSniffLimit = 64 * 1024

func (w *auditResponseWriter) WriteHeader(statusCode int) {
	if !w.written {
		w.statusCode = statusCode
		w.written = true
	}
	w.ResponseWriter.WriteHeader(statusCode)
}

// Write implements http.ResponseWriter. CodeQL's go/reflected-xss
// rule flags this line as a response-body sink because the []byte
// `b` ultimately carries bytes written by the downstream handler
// — some of which may derive from HTTP request input. This wrapper
// does NOT introduce a new XSS surface: it is a transparent
// passthrough, added only to observe the status code for audit
// logging. Output escaping is the handler's responsibility
// (json.Encoder for JSON endpoints, html/template for HTML
// endpoints). Dismiss the alert as wrapper-level false-positive.
func (w *auditResponseWriter) Write(b []byte) (int, error) {
	if !w.written {
		w.statusCode = http.StatusOK
		w.written = true
	}
	if w.sniff && w.statusCode == http.StatusCreated {
		if room := auditSniffLimit - w.head.Len(); room > 0 {
			w.head.Write(b[:min(len(b), room)])
		}
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

// AuditAdminUpdate returns middleware for admin user updates.
func (m *AuditMiddleware) AuditAdminUpdate() func(http.Handler) http.Handler {
	return m.AuditLog(admin.AuditActionAdminUpdate, admin.ResourceTypeAdmin, "id")
}

// AuditAdminDelete returns middleware for admin user deletion.
func (m *AuditMiddleware) AuditAdminDelete() func(http.Handler) http.Handler {
	return m.AuditLog(admin.AuditActionAdminDelete, admin.ResourceTypeAdmin, "id")
}

// AuditSensorCreate returns middleware for platform sensor creation.
func (m *AuditMiddleware) AuditSensorCreate() func(http.Handler) http.Handler {
	return m.AuditLog(admin.AuditActionSensorCreate, admin.ResourceTypeSensor, "")
}

// AuditSensorUpdate returns middleware for platform sensor updates.
func (m *AuditMiddleware) AuditSensorUpdate() func(http.Handler) http.Handler {
	return m.AuditLog(admin.AuditActionSensorUpdate, admin.ResourceTypeSensor, "id")
}

// AuditSensorDelete returns middleware for platform sensor deletion.
func (m *AuditMiddleware) AuditSensorDelete() func(http.Handler) http.Handler {
	return m.AuditLog(admin.AuditActionSensorDelete, admin.ResourceTypeSensor, "id")
}

// AuditSensorEnable returns middleware for enabling platform sensors.
func (m *AuditMiddleware) AuditSensorEnable() func(http.Handler) http.Handler {
	return m.AuditLog(admin.AuditActionSensorEnable, admin.ResourceTypeSensor, "id")
}

// AuditSensorDisable returns middleware for disabling platform sensors.
func (m *AuditMiddleware) AuditSensorDisable() func(http.Handler) http.Handler {
	return m.AuditLog(admin.AuditActionSensorDisable, admin.ResourceTypeSensor, "id")
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

type auditResourceKey struct{}

// auditCreatedResource is what a handler reports about the resource it
// created, read by AuditLog after the handler returns.
type auditCreatedResource struct {
	id   *shared.ID
	name string
	// action, when set, replaces the route's action (SetAuditAction).
	action string
	high   bool
}

// SetAuditAction replaces the route's audit action for the current request,
// for a route whose request body selects a more sensitive operation (the
// first-owner route with recovery=true is organization.owner_recovery). high
// marks the row high severity. A no-op outside an audited request.
func SetAuditAction(ctx context.Context, action string, high bool) {
	if c, ok := ctx.Value(auditResourceKey{}).(*auditCreatedResource); ok && action != "" {
		c.action = action
		c.high = c.high || high
	}
}

// SetAuditResource records the id (and a display name) of the resource the
// current request created, for the admin audit row. Create routes have no id
// in their URL; without this their audit rows carried no resource_id. It is
// used only when the route has no URL id and the response is 201, so a
// sub-resource created under /admin/tenants/{tenantId}/... keeps the
// organization as its audited resource. A no-op outside an audited request.
func SetAuditResource(ctx context.Context, id shared.ID, name string) {
	if c, ok := ctx.Value(auditResourceKey{}).(*auditCreatedResource); ok && !id.IsZero() {
		c.id = &id
		c.name = name
	}
}

// topLevelID returns the top-level "id" of a JSON object body, or nil. Only
// the id is decoded; nothing else in the body is kept.
func topLevelID(body []byte) *shared.ID {
	var v struct {
		ID string `json:"id"`
	}
	if len(body) == 0 || json.Unmarshal(body, &v) != nil || v.ID == "" {
		return nil
	}
	id, err := shared.IDFromString(v.ID)
	if err != nil {
		return nil
	}
	return &id
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

package admin

import (
	"encoding/json"
	"time"

	"github.com/openctemio/api/pkg/domain/shared"
)

// =============================================================================
// Audit Log Entity
// =============================================================================

// AuditLog represents an immutable audit log entry for admin actions.
// Once created, audit logs cannot be modified or deleted (append-only).
type AuditLog struct {
	ID shared.ID

	// Who performed the action
	AdminID    *shared.ID // May be nil if admin was deleted
	AdminEmail string     // Preserved even if admin is deleted

	// What action was performed
	Action       string     // e.g., "agent.create", "token.revoke"
	ResourceType string     // e.g., "agent", "token", "admin"
	ResourceID   *shared.ID // ID of affected resource
	ResourceName string     // Name for display (preserved if resource deleted)

	// Request details (sanitized - no secrets)
	RequestMethod string
	RequestPath   string
	RequestBody   map[string]interface{} // Sensitive fields should be redacted

	// Response
	ResponseStatus int

	// Context
	IPAddress string
	UserAgent string

	// Result
	Success      bool
	ErrorMessage string

	// Timestamp (immutable)
	CreatedAt time.Time
}

// NewAuditLog creates a new AuditLog entry.
func NewAuditLog(
	admin *AdminUser,
	action string,
	resourceType string,
	resourceID *shared.ID,
	resourceName string,
) *AuditLog {
	var adminID *shared.ID
	var adminEmail string

	if admin != nil {
		id := admin.ID()
		adminID = &id
		adminEmail = admin.Email()
	}

	return &AuditLog{
		ID:           shared.NewID(),
		AdminID:      adminID,
		AdminEmail:   adminEmail,
		Action:       action,
		ResourceType: resourceType,
		ResourceID:   resourceID,
		ResourceName: resourceName,
		Success:      true, // Default to success
		CreatedAt:    time.Now(),
	}
}

// SetRequest sets the request details.
func (a *AuditLog) SetRequest(method, path string, body map[string]interface{}) {
	a.RequestMethod = method
	a.RequestPath = path
	a.RequestBody = redactSensitiveFields(body)
}

// SetResponse sets the response status.
func (a *AuditLog) SetResponse(status int) {
	a.ResponseStatus = status
	a.Success = status >= 200 && status < 400
}

// SetContext sets the request context (IP, user agent).
func (a *AuditLog) SetContext(ip, userAgent string) {
	a.IPAddress = ip
	a.UserAgent = userAgent
}

// SetError marks the audit log as failed with an error message.
func (a *AuditLog) SetError(message string) {
	a.Success = false
	a.ErrorMessage = message
}

// =============================================================================
// Audit Log Builder (fluent API)
// =============================================================================

// AuditLogBuilder provides a fluent API for creating audit logs.
type AuditLogBuilder struct {
	log *AuditLog
}

// NewAuditLogBuilder creates a new AuditLogBuilder.
func NewAuditLogBuilder(admin *AdminUser, action string) *AuditLogBuilder {
	return &AuditLogBuilder{
		log: NewAuditLog(admin, action, "", nil, ""),
	}
}

// Resource sets the resource being acted upon.
func (b *AuditLogBuilder) Resource(resourceType string, resourceID *shared.ID, resourceName string) *AuditLogBuilder {
	b.log.ResourceType = resourceType
	b.log.ResourceID = resourceID
	b.log.ResourceName = resourceName
	return b
}

// Request sets the request details.
func (b *AuditLogBuilder) Request(method, path string, body map[string]interface{}) *AuditLogBuilder {
	b.log.SetRequest(method, path, body)
	return b
}

// Response sets the response status.
func (b *AuditLogBuilder) Response(status int) *AuditLogBuilder {
	b.log.SetResponse(status)
	return b
}

// Context sets the request context.
func (b *AuditLogBuilder) Context(ip, userAgent string) *AuditLogBuilder {
	b.log.SetContext(ip, userAgent)
	return b
}

// Error marks the log as failed.
func (b *AuditLogBuilder) Error(message string) *AuditLogBuilder {
	b.log.SetError(message)
	return b
}

// Build returns the completed AuditLog.
func (b *AuditLogBuilder) Build() *AuditLog {
	return b.log
}

// =============================================================================
// Audit Actions Constants
// =============================================================================

// Audit action constants for consistent naming.
const (
	// Admin user actions
	AuditActionAdminCreate     = "admin.create"
	AuditActionAdminUpdate     = "admin.update"
	AuditActionAdminDelete     = "admin.delete"
	AuditActionAdminActivate   = "admin.activate"
	AuditActionAdminDeactivate = "admin.deactivate"
	AuditActionAdminRotateKey  = "admin.rotate_key"

	// Platform agent actions
	AuditActionAgentCreate  = "agent.create"
	AuditActionAgentUpdate  = "agent.update"
	AuditActionAgentDelete  = "agent.delete"
	AuditActionAgentEnable  = "agent.enable"
	AuditActionAgentDisable = "agent.disable"

	// Bootstrap token actions
	AuditActionTokenCreate = "token.create"
	AuditActionTokenRevoke = "token.revoke"
	AuditActionTokenDelete = "token.delete"

	// Platform job actions
	AuditActionJobCancel = "job.cancel"

	// Target mapping actions
	AuditActionTargetMappingCreate = "target_mapping.create"
	AuditActionTargetMappingUpdate = "target_mapping.update"
	AuditActionTargetMappingDelete = "target_mapping.delete"

	// Authentication actions
	AuditActionAuthSuccess = "auth.success"
	AuditActionAuthFailure = "auth.failure"
)

// Resource type constants.
const (
	ResourceTypeAdmin         = "admin"
	ResourceTypeAgent         = "agent"
	ResourceTypeToken         = "token"
	ResourceTypeJob           = "job"
	ResourceTypeTargetMapping = "target_mapping"
)

// =============================================================================
// Helper Functions
// =============================================================================

// redactSensitiveFields redacts sensitive fields from request body.
func redactSensitiveFields(body map[string]interface{}) map[string]interface{} {
	if body == nil {
		return nil
	}

	// Create a deep copy
	result := make(map[string]interface{})
	data, _ := json.Marshal(body)
	_ = json.Unmarshal(data, &result)

	// List of sensitive field names to redact
	sensitiveFields := []string{
		"password", "api_key", "apiKey", "api_key_hash",
		"token", "secret", "credential", "credentials",
		"authorization", "auth_token", "authToken",
		"private_key", "privateKey", "access_token", "accessToken",
		"refresh_token", "refreshToken", "client_secret", "clientSecret",
	}

	redactFields(result, sensitiveFields)
	return result
}

// redactFields recursively redacts sensitive fields.
func redactFields(data map[string]interface{}, sensitiveFields []string) {
	for key, value := range data {
		// Check if this key should be redacted
		for _, sensitive := range sensitiveFields {
			if key == sensitive {
				data[key] = "[REDACTED]"
				break
			}
		}

		// Recurse into nested maps
		if nested, ok := value.(map[string]interface{}); ok {
			redactFields(nested, sensitiveFields)
		}
	}
}

// =============================================================================
// Audit Log Filter (for queries)
// =============================================================================

// AuditLogFilter represents filter options for listing audit logs.
type AuditLogFilter struct {
	AdminID      *shared.ID
	AdminEmail   string
	Action       string
	ResourceType string
	ResourceID   *shared.ID
	Success      *bool
	StartTime    *time.Time
	EndTime      *time.Time
	Search       string // Search in action, resource_name, error_message
}

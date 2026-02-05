package app

import (
	"context"
	"time"

	"github.com/openctemio/api/pkg/domain/audit"
	"github.com/openctemio/api/pkg/domain/shared"
)

// ListAuditLogsFilter represents filters for listing audit logs.
type ListAuditLogsFilter struct {
	TenantID     string   `json:"tenant_id"`
	UserIDs      []string `json:"user_ids"`
	Actions      []string `json:"actions"`
	ResourceType []string `json:"resource_type"`
	ResourceID   string   `json:"resource_id"`
	Status       []string `json:"status"`
	DateFrom     *time.Time `json:"date_from"`
	DateTo       *time.Time `json:"date_to"`
	Page         int      `json:"page"`
	PerPage      int      `json:"per_page"`
	SortBy       string   `json:"sort_by"`
	SortOrder    string   `json:"sort_order"`
}

// AuditService defines the interface for audit logging operations.
// This is a base interface - Enterprise extends with advanced features.
type AuditService interface {
	// Log creates an audit log entry.
	Log(ctx context.Context, log *audit.AuditLog) error

	// LogAsync creates an audit log entry asynchronously.
	LogAsync(ctx context.Context, log *audit.AuditLog)

	// List returns paginated audit logs matching the filter.
	List(ctx context.Context, filter ListAuditLogsFilter) (*ListResult[*audit.AuditLog], error)

	// Get retrieves a specific audit log entry.
	Get(ctx context.Context, tenantID, logID shared.ID) (*audit.AuditLog, error)

	// GetByResourceID returns audit logs for a specific resource.
	GetByResourceID(ctx context.Context, tenantID shared.ID, resourceType, resourceID string) ([]*audit.AuditLog, error)
}

// AuditServiceEnterprise extends AuditService with Enterprise features.
// This interface is implemented by Enterprise edition only.
type AuditServiceEnterprise interface {
	AuditService

	// Export exports audit logs to external storage.
	Export(ctx context.Context, filter ListAuditLogsFilter, format string) ([]byte, error)

	// GetRetentionPolicy returns the audit log retention policy.
	GetRetentionPolicy(ctx context.Context, tenantID shared.ID) (*AuditRetentionPolicy, error)

	// SetRetentionPolicy sets the audit log retention policy.
	SetRetentionPolicy(ctx context.Context, tenantID shared.ID, policy *AuditRetentionPolicy) error

	// PurgeOldLogs purges logs older than retention period.
	PurgeOldLogs(ctx context.Context, tenantID shared.ID) (int64, error)
}

// AuditRetentionPolicy represents an audit log retention policy.
type AuditRetentionPolicy struct {
	RetentionDays    int  `json:"retention_days"`
	CompressAfterDays int  `json:"compress_after_days"`
	ArchiveEnabled   bool `json:"archive_enabled"`
	ArchiveLocation  string `json:"archive_location"`
}

package admin

import (
	"context"
	"time"

	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/pagination"
)

// =============================================================================
// Admin User Repository
// =============================================================================

// Filter represents filter options for listing admin users.
type Filter struct {
	Role     *AdminRole
	IsActive *bool
	Email    string // Partial match
	Search   string // Search in email and name
}

// Repository defines the interface for admin user persistence.
type Repository interface {
	// ==========================================================================
	// CRUD Operations
	// ==========================================================================

	// Create creates a new admin user.
	Create(ctx context.Context, admin *AdminUser) error

	// GetByID retrieves an admin user by ID.
	GetByID(ctx context.Context, id shared.ID) (*AdminUser, error)

	// GetByEmail retrieves an admin user by email.
	GetByEmail(ctx context.Context, email string) (*AdminUser, error)

	// List lists admin users with filters and pagination.
	List(ctx context.Context, filter Filter, page pagination.Pagination) (pagination.Result[*AdminUser], error)

	// Update updates an admin user.
	Update(ctx context.Context, admin *AdminUser) error

	// Delete deletes an admin user.
	Delete(ctx context.Context, id shared.ID) error

	// ==========================================================================
	// Console usage
	// ==========================================================================

	// RecordUsage records when and from where the administrator last opened the console.
	RecordUsage(ctx context.Context, id shared.ID, ip string) error

	// ==========================================================================
	// Human administrators (RFC-022 rev. 2)
	// ==========================================================================

	// GetByUserID returns the administrator linked to a users row, or
	// ErrAdminNotFound. The administrator signs in on the normal /login page
	// with that user account.
	GetByUserID(ctx context.Context, userID shared.ID) (*AdminUser, error)

	// LinkUser links an administrator to a users row. Returns
	// ErrUserHasMemberships when the user belongs to an organization (a
	// platform administrator belongs to none) and ErrUserAlreadyAdmin when the
	// user is already linked to another administrator.
	LinkUser(ctx context.Context, adminID, userID shared.ID) error

	// ==========================================================================
	// Statistics
	// ==========================================================================

	// Count counts admin users with optional filter.
	Count(ctx context.Context, filter Filter) (int, error)

	// CountByRole counts admin users by role.
	CountByRole(ctx context.Context, role AdminRole) (int, error)
}

// =============================================================================
// Audit Log Repository
// =============================================================================

// AuditLogRepository defines the interface for audit log persistence.
// Audit logs are append-only (no update or delete operations).
type AuditLogRepository interface {
	// Create creates a new audit log entry.
	Create(ctx context.Context, log *AuditLog) error

	// GetByID retrieves an audit log by ID.
	GetByID(ctx context.Context, id shared.ID) (*AuditLog, error)

	// List lists audit logs with filters and pagination.
	// Results are ordered by created_at DESC (newest first).
	List(ctx context.Context, filter AuditLogFilter, page pagination.Pagination) (pagination.Result[*AuditLog], error)

	// ListByAdmin lists audit logs for a specific admin.
	ListByAdmin(ctx context.Context, adminID shared.ID, page pagination.Pagination) (pagination.Result[*AuditLog], error)

	// ListByResource lists audit logs for a specific resource.
	ListByResource(ctx context.Context, resourceType string, resourceID shared.ID, page pagination.Pagination) (pagination.Result[*AuditLog], error)

	// Count counts audit logs with optional filter.
	Count(ctx context.Context, filter AuditLogFilter) (int64, error)

	// GetRecentActions returns the most recent actions (for dashboard).
	GetRecentActions(ctx context.Context, limit int) ([]*AuditLog, error)

	// GetFailedActions returns recent failed actions (for monitoring).
	GetFailedActions(ctx context.Context, since time.Duration, limit int) ([]*AuditLog, error)

	// ==========================================================================
	// Retention Management
	// ==========================================================================

	// DeleteOlderThan deletes audit logs older than the specified time.
	// This is used for compliance-based retention policies.
	// Returns the number of logs deleted.
	// Note: This is a destructive operation. Ensure proper backups before running.
	DeleteOlderThan(ctx context.Context, olderThan time.Time) (int64, error)

	// CountOlderThan counts audit logs older than the specified time.
	// Used to estimate the number of logs that will be deleted.
	CountOlderThan(ctx context.Context, olderThan time.Time) (int64, error)
}

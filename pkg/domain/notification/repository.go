package notification

import (
	"context"
	"time"

	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/pagination"
)

// ListFilter contains filter parameters for listing notifications.
type ListFilter struct {
	Severity string
	Type     string
	IsRead   *bool
}

// Repository defines the interface for user notification persistence.
type Repository interface {
	// Create inserts a new notification.
	Create(ctx context.Context, n *Notification) error

	// List returns notifications visible to a user (with audience filtering and read status).
	// Group membership is resolved via subquery internally, eliminating an extra DB roundtrip.
	List(ctx context.Context, tenantID, userID shared.ID, filter ListFilter, page pagination.Pagination) (pagination.Result[*Notification], error)

	// UnreadCount returns the number of unread notifications for a user.
	// Group membership is resolved via subquery internally, eliminating an extra DB roundtrip.
	UnreadCount(ctx context.Context, tenantID, userID shared.ID) (int, error)

	// MarkAsRead marks a single notification as read for a user.
	MarkAsRead(ctx context.Context, tenantID shared.ID, notificationID ID, userID shared.ID) error

	// MarkAllAsRead updates the watermark timestamp for a user.
	MarkAllAsRead(ctx context.Context, tenantID, userID shared.ID) error

	// DeleteOlderThan removes notifications older than the given duration.
	DeleteOlderThan(ctx context.Context, age time.Duration) (int64, error)

	// GetPreferences returns notification preferences for a user.
	GetPreferences(ctx context.Context, tenantID, userID shared.ID) (*Preferences, error)

	// UpsertPreferences creates or updates notification preferences.
	UpsertPreferences(ctx context.Context, tenantID, userID shared.ID, params PreferencesParams) (*Preferences, error)
}

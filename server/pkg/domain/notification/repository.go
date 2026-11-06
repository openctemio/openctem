package notification

import (
	"context"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/pagination"
)

// ListFilter contains filter parameters for listing notifications.
type ListFilter struct {
	Severity string
	Type     string
	IsRead   *bool

	// DataScope, when set, hides finding and asset notifications whose asset
	// is outside the reader's Layer 2 data scope (nil = unrestricted).
	DataScope *shared.DataScope
}

// Repository defines the interface for user notification persistence.
type Repository interface {
	// Create inserts a new notification.
	Create(ctx context.Context, n *Notification) error

	// List returns notifications visible to a user (with audience filtering and read status).
	// The user's preferences (in-app on/off, muted types, minimum severity) are applied.
	// Group membership is resolved via subquery internally, eliminating an extra DB roundtrip.
	List(ctx context.Context, tenantID, userID shared.ID, filter ListFilter, page pagination.Pagination) (pagination.Result[*Notification], error)

	// UnreadCount returns the number of unread notifications for a user, with the
	// same preference filtering as List.
	// Group membership is resolved via subquery internally, eliminating an extra DB roundtrip.
	// A non-nil scope applies the same data-scope rule as ListFilter.DataScope.
	UnreadCount(ctx context.Context, tenantID, userID shared.ID, scope *shared.DataScope) (int, error)

	// ListRecipients returns the users who should receive a real-time push of
	// the notification: the members of its audience (the addressed user, the
	// members of the addressed group, or every active tenant member for
	// audience "all") whose preferences allow it. It applies the same
	// audience and preference rules as List and UnreadCount, so a push never
	// reaches someone whose inbox would not show the notification.
	//
	// For a finding or asset notification it also applies the Layer 2 data
	// scope per recipient: owners/admins (team role from
	// v_user_effective_role, as in the access token), holders of a
	// has_full_data_access role, and members whose scope covers the asset. A
	// member with no scope row gets no finding or asset push.
	ListRecipients(ctx context.Context, n *Notification) ([]shared.ID, error)

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

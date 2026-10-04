package integration

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/openctemio/openctem/api/internal/app/datascope"
	notificationdom "github.com/openctemio/openctem/api/pkg/domain/notification"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/pagination"
)

// =============================================================================
// Interfaces
// =============================================================================

// WebSocketBroadcaster broadcasts messages to WebSocket channels.
type WebSocketBroadcaster interface {
	BroadcastEvent(channel string, data any, tenantID string)
}

// =============================================================================
// Input Types
// =============================================================================

// UpdatePreferencesInput represents input for updating notification preferences.
type UpdatePreferencesInput struct {
	InAppEnabled *bool    `json:"in_app_enabled"`
	EmailDigest  *string  `json:"email_digest"` // "none", "daily", "weekly"
	MutedTypes   []string `json:"muted_types"`
	MinSeverity  *string  `json:"min_severity"`
}

// =============================================================================
// Service
// =============================================================================

// NotificationService handles user notification operations (inbox).
type NotificationService struct {
	repo      notificationdom.Repository
	wsHub     WebSocketBroadcaster
	dataScope *datascope.Enforcer // Layer 2: hide out-of-scope finding/asset notices (nil = off)
	logger    *logger.Logger
}

// SetDataScope wires the Layer 2 data-scope enforcer. Finding and asset
// notifications (whose body carries the finding message or asset name) are
// then shown, counted and pushed only to users whose scope covers the asset.
func (s *NotificationService) SetDataScope(e *datascope.Enforcer) {
	s.dataScope = e
}

// NewNotificationService creates a new NotificationService.
func NewNotificationService(
	repo notificationdom.Repository,
	wsHub WebSocketBroadcaster,
	log *logger.Logger,
) *NotificationService {
	return &NotificationService{
		repo:   repo,
		wsHub:  wsHub,
		logger: log.With("service", "notification"),
	}
}

// =============================================================================
// Notification Listing & Counts
// =============================================================================

// ListNotifications returns paginated notifications visible to the user.
// Group membership is resolved via subquery in the repository, eliminating an extra DB roundtrip.
func (s *NotificationService) ListNotifications(
	ctx context.Context,
	tenantID, userID shared.ID,
	filter notificationdom.ListFilter,
	page pagination.Pagination,
) (pagination.Result[*notificationdom.Notification], error) {
	scope, err := s.readerScope(ctx, tenantID, userID)
	if err != nil {
		return pagination.Result[*notificationdom.Notification]{}, err
	}
	filter.DataScope = scope
	result, err := s.repo.List(ctx, tenantID, userID, filter, page)
	if err != nil {
		s.logger.Error("failed to list notifications", "tenant_id", tenantID, "user_id", userID, "error", err)
		return pagination.Result[*notificationdom.Notification]{}, fmt.Errorf("list notifications: %w", err)
	}

	return result, nil
}

// GetUnreadCount returns the number of unread notifications for a user.
// Group membership is resolved via subquery in the repository, eliminating an extra DB roundtrip.
func (s *NotificationService) GetUnreadCount(ctx context.Context, tenantID, userID shared.ID) (int, error) {
	scope, err := s.readerScope(ctx, tenantID, userID)
	if err != nil {
		return 0, err
	}
	count, err := s.repo.UnreadCount(ctx, tenantID, userID, scope)
	if err != nil {
		s.logger.Error("failed to get unread count", "tenant_id", tenantID, "user_id", userID, "error", err)
		return 0, fmt.Errorf("get unread count: %w", err)
	}

	return count, nil
}

// readerScope resolves the data scope of the request's caller, who is the
// inbox owner (userID). Fails closed on a resolution error.
func (s *NotificationService) readerScope(ctx context.Context, tenantID, userID shared.ID) (*shared.DataScope, error) {
	scope, err := s.dataScope.Resolve(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("resolve data scope: %w", err)
	}
	if scope != nil && scope.UserID != userID {
		// The inbox is always the caller's own; never apply someone else's scope.
		return &shared.DataScope{TenantID: tenantID, UserID: userID}, nil
	}
	return scope, nil
}

// =============================================================================
// Read Status
// =============================================================================

// MarkAsRead marks a single notification as read for a user.
func (s *NotificationService) MarkAsRead(ctx context.Context, tenantID shared.ID, notificationID notificationdom.ID, userID shared.ID) error {
	if err := s.repo.MarkAsRead(ctx, tenantID, notificationID, userID); err != nil {
		s.logger.Error("failed to mark notification as read", "tenant_id", tenantID, "notification_id", notificationID, "user_id", userID, "error", err)
		return fmt.Errorf("mark as read: %w", err)
	}

	return nil
}

// MarkAllAsRead marks all notifications as read for a user within a tenant.
func (s *NotificationService) MarkAllAsRead(ctx context.Context, tenantID, userID shared.ID) error {
	if err := s.repo.MarkAllAsRead(ctx, tenantID, userID); err != nil {
		s.logger.Error("failed to mark all notifications as read", "tenant_id", tenantID, "user_id", userID, "error", err)
		return fmt.Errorf("mark all as read: %w", err)
	}

	return nil
}

// =============================================================================
// Preferences
// =============================================================================

// GetPreferences returns notification preferences for a user.
func (s *NotificationService) GetPreferences(ctx context.Context, tenantID, userID shared.ID) (*notificationdom.Preferences, error) {
	prefs, err := s.repo.GetPreferences(ctx, tenantID, userID)
	if err != nil {
		s.logger.Error("failed to get notification preferences", "tenant_id", tenantID, "user_id", userID, "error", err)
		return nil, fmt.Errorf("get preferences: %w", err)
	}

	return prefs, nil
}

// UpdatePreferences creates or updates notification preferences for a user.
func (s *NotificationService) UpdatePreferences(
	ctx context.Context,
	tenantID, userID shared.ID,
	input UpdatePreferencesInput,
) (*notificationdom.Preferences, error) {
	if err := validatePreferencesInput(input); err != nil {
		return nil, err
	}

	// Build params from input, fetching existing preferences for defaults.
	// Note: This read-modify-write is not wrapped in a transaction. The race window is
	// negligible since only the owning user updates their own preferences.
	existing, err := s.repo.GetPreferences(ctx, tenantID, userID)
	if err != nil {
		s.logger.Error("failed to get existing preferences", "tenant_id", tenantID, "user_id", userID, "error", err)
		return nil, fmt.Errorf("get existing preferences: %w", err)
	}

	params := notificationdom.PreferencesParams{
		InAppEnabled: existing.InAppEnabled(),
		EmailDigest:  existing.EmailDigest(),
		MutedTypes:   existing.MutedTypes(),
		MinSeverity:  existing.MinSeverity(),
	}

	if input.InAppEnabled != nil {
		params.InAppEnabled = *input.InAppEnabled
	}
	if input.EmailDigest != nil {
		params.EmailDigest = *input.EmailDigest
	}
	if input.MutedTypes != nil {
		params.MutedTypes = input.MutedTypes
	}
	if input.MinSeverity != nil {
		params.MinSeverity = *input.MinSeverity
	}

	prefs, err := s.repo.UpsertPreferences(ctx, tenantID, userID, params)
	if err != nil {
		s.logger.Error("failed to upsert notification preferences", "tenant_id", tenantID, "user_id", userID, "error", err)
		return nil, fmt.Errorf("upsert preferences: %w", err)
	}

	s.logger.Info("notification preferences updated", "tenant_id", tenantID, "user_id", userID)

	return prefs, nil
}

// =============================================================================
// Notify
// =============================================================================

// Notify creates a notification and pushes it via WebSocket to appropriate channels.
func (s *NotificationService) Notify(ctx context.Context, params notificationdom.NotificationParams) error {
	// Validate required fields.
	if err := validateNotifyParams(params); err != nil {
		return err
	}

	// Sanitize URL to prevent open redirects and path traversal.
	// Only allow clean relative paths (e.g., "/findings/123").
	if params.URL != "" {
		if !strings.HasPrefix(params.URL, "/") ||
			strings.HasPrefix(params.URL, "//") ||
			strings.Contains(params.URL, "..") {
			params.URL = ""
		}
	}

	n := notificationdom.NewNotification(params)

	if err := s.repo.Create(ctx, n); err != nil {
		s.logger.Error("failed to create notification", "tenant_id", params.TenantID, "type", params.NotificationType, "error", err)
		return fmt.Errorf("create notification: %w", err)
	}

	// Push to each recipient's own WebSocket channel.
	s.pushWebSocket(ctx, n)

	s.logger.Info("notification created",
		"notification_id", n.ID(),
		"tenant_id", params.TenantID,
		"type", params.NotificationType,
		"audience", params.Audience,
	)

	return nil
}

// pushWebSocket sends the notification in real time to the users who should
// see it, each on their own user:{tenant}:{user} channel.
//
// It never uses a shared channel. The tenant channel reaches every member of
// the tenant, and a group channel can be watched by people outside the group,
// so a notification addressed to one user or one group sent there was readable
// by everyone else in the tenant. Fanning out per recipient also applies each
// recipient's preferences (in-app off, muted types, minimum severity) to the
// push, the same way the inbox list and unread count apply them.
func (s *NotificationService) pushWebSocket(ctx context.Context, n *notificationdom.Notification) {
	if s.wsHub == nil {
		return
	}

	recipients, err := s.repo.ListRecipients(ctx, n)
	if err != nil {
		// The notification is stored; the inbox and badge still pick it up on
		// the next fetch. Only the live push is lost.
		s.logger.Error("failed to resolve notification recipients",
			"tenant_id", n.TenantID(), "notification_id", n.ID(), "error", err)
		return
	}

	payload := map[string]interface{}{
		"type":     "notification",
		"id":       n.ID().String(),
		"sub_type": n.NotificationType(),
		"title":    n.Title(),
		"body":     n.Body(),
		"severity": n.Severity(),
	}

	tenantID := n.TenantID().String()
	for _, userID := range recipients {
		s.wsHub.BroadcastEvent(notificationdom.UserChannel(tenantID, userID.String()), payload, tenantID)
	}
}

// =============================================================================
// Cleanup
// =============================================================================

// CleanupOld removes notifications older than the specified retention period.
func (s *NotificationService) CleanupOld(ctx context.Context, retentionDays int) (int64, error) {
	if retentionDays <= 0 {
		return 0, fmt.Errorf("%w: retention days must be positive", shared.ErrValidation)
	}

	age := time.Duration(retentionDays) * 24 * time.Hour

	deleted, err := s.repo.DeleteOlderThan(ctx, age)
	if err != nil {
		s.logger.Error("failed to cleanup old notifications", "retention_days", retentionDays, "error", err)
		return 0, fmt.Errorf("cleanup old notifications: %w", err)
	}

	if deleted > 0 {
		s.logger.Info("cleaned up old notifications", "deleted", deleted, "retention_days", retentionDays)
	}

	return deleted, nil
}

// =============================================================================
// Validation Helpers
// =============================================================================

var validEmailDigests = map[string]bool{
	"none":   true,
	"daily":  true,
	"weekly": true,
}

var validSeverities = map[string]bool{
	notificationdom.SeverityCritical: true,
	notificationdom.SeverityHigh:     true,
	notificationdom.SeverityMedium:   true,
	notificationdom.SeverityLow:      true,
	notificationdom.SeverityInfo:     true,
	"":                               true, // allow empty to clear
}

// validAudiences defines the allowed notification audience types.
var validAudiences = map[string]bool{
	notificationdom.AudienceAll:   true,
	notificationdom.AudienceGroup: true,
	notificationdom.AudienceUser:  true,
}

func validateNotifyParams(params notificationdom.NotificationParams) error {
	if params.Title == "" {
		return fmt.Errorf("%w: notification title is required", shared.ErrValidation)
	}
	if len(params.Title) > 500 {
		return fmt.Errorf("%w: notification title exceeds 500 characters", shared.ErrValidation)
	}
	if len(params.Body) > 10000 {
		return fmt.Errorf("%w: notification body exceeds 10000 characters", shared.ErrValidation)
	}
	if !validAudiences[params.Audience] {
		return fmt.Errorf("%w: invalid audience: %s", shared.ErrValidation, params.Audience)
	}
	if (params.Audience == notificationdom.AudienceUser || params.Audience == notificationdom.AudienceGroup) && params.AudienceID == nil {
		return fmt.Errorf("%w: audience_id is required for audience type %s", shared.ErrValidation, params.Audience)
	}
	if params.NotificationType != "" && !notificationdom.IsValidType(params.NotificationType) {
		return fmt.Errorf("%w: invalid notification type: %s", shared.ErrValidation, params.NotificationType)
	}
	if params.Severity != "" && !notificationdom.IsValidSeverity(params.Severity) {
		return fmt.Errorf("%w: invalid severity: %s", shared.ErrValidation, params.Severity)
	}
	return nil
}

func validatePreferencesInput(input UpdatePreferencesInput) error {
	if input.EmailDigest != nil {
		if !validEmailDigests[*input.EmailDigest] {
			return fmt.Errorf("%w: email_digest must be one of: none, daily, weekly", shared.ErrValidation)
		}
	}

	if input.MinSeverity != nil {
		if !validSeverities[*input.MinSeverity] {
			return fmt.Errorf("%w: min_severity must be one of: critical, high, medium, low, info", shared.ErrValidation)
		}
	}

	if input.MutedTypes != nil {
		if len(input.MutedTypes) > 50 {
			return fmt.Errorf("%w: muted_types exceeds maximum of 50", shared.ErrValidation)
		}
		for _, t := range input.MutedTypes {
			if !notificationdom.IsValidType(t) {
				return fmt.Errorf("%w: invalid notification type in muted_types: %s", shared.ErrValidation, t)
			}
		}
	}

	return nil
}

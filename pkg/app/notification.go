package app

import (
	"context"

	"github.com/openctemio/api/pkg/domain/notification"
	"github.com/openctemio/api/pkg/domain/shared"
)

// SendNotificationInput represents the input for sending a notification.
type SendNotificationInput struct {
	TenantID      string `json:"tenant_id" validate:"required,uuid"`
	IntegrationID string `json:"integration_id" validate:"required,uuid"`
	Title         string `json:"title" validate:"required,max=500"`
	Body          string `json:"body" validate:"max=10000"`
	Severity      string `json:"severity" validate:"omitempty,severity"`
	URL           string `json:"url" validate:"omitempty,url"`
	EventType     string `json:"event_type" validate:"omitempty"`
}

// BroadcastNotificationInput represents the input for broadcasting a notification.
type BroadcastNotificationInput struct {
	TenantID  string `json:"tenant_id" validate:"required,uuid"`
	EventType string `json:"event_type" validate:"required"`
	Title     string `json:"title" validate:"required,max=500"`
	Body      string `json:"body" validate:"max=10000"`
	Severity  string `json:"severity" validate:"omitempty,severity"`
	URL       string `json:"url" validate:"omitempty,url"`
}

// NotificationResult represents the result of sending a notification.
type NotificationResult struct {
	IntegrationID string `json:"integration_id"`
	Success       bool   `json:"success"`
	Error         string `json:"error,omitempty"`
}

// ListNotificationEventsFilter represents filters for listing notification events.
type ListNotificationEventsFilter struct {
	TenantID      string   `json:"tenant_id"`
	IntegrationID string   `json:"integration_id"`
	EventTypes    []string `json:"event_types"`
	Status        []string `json:"status"`
	DateFrom      string   `json:"date_from"`
	DateTo        string   `json:"date_to"`
	Page          int      `json:"page"`
	PerPage       int      `json:"per_page"`
}

// NotificationService defines the interface for notification operations.
// This is a base interface - Enterprise can extend with advanced features.
type NotificationService interface {
	// Send sends a notification to a specific integration.
	Send(ctx context.Context, input SendNotificationInput) (*NotificationResult, error)

	// Broadcast sends a notification to all matching integrations.
	Broadcast(ctx context.Context, input BroadcastNotificationInput) ([]NotificationResult, error)

	// Test sends a test notification to an integration.
	Test(ctx context.Context, tenantID, integrationID shared.ID) (*NotificationResult, error)

	// ListEvents returns notification events.
	ListEvents(ctx context.Context, filter ListNotificationEventsFilter) (*ListResult[*notification.Event], error)

	// GetEvent retrieves a specific notification event.
	GetEvent(ctx context.Context, tenantID, eventID shared.ID) (*notification.Event, error)

	// RetryEvent retries a failed notification event.
	RetryEvent(ctx context.Context, tenantID, eventID shared.ID) error
}

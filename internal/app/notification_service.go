package app

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"
	notificationclient "github.com/openctemio/api/internal/infra/notification"
	"github.com/openctemio/api/pkg/domain/integration"
	"github.com/openctemio/api/pkg/domain/notification"
	"github.com/openctemio/api/pkg/domain/shared"
)

// Status constants for notification results.
const (
	notificationStatusFailed  = "failed"
	notificationStatusSuccess = "success"
)

// =============================================================================
// Service Interface
// =============================================================================

// NotificationService handles notification outbox operations.
type NotificationService struct {
	outboxRepo        notification.OutboxRepository
	eventRepo         notification.EventRepository
	notificationRepo  integration.NotificationExtensionRepository
	clientFactory     *notificationclient.ClientFactory
	credentialDecrypt func(string) (string, error)
	log               *slog.Logger
}

// NewNotificationService creates a new NotificationService.
func NewNotificationService(
	outboxRepo notification.OutboxRepository,
	eventRepo notification.EventRepository,
	notificationRepo integration.NotificationExtensionRepository,
	credentialDecrypt func(string) (string, error),
	log *slog.Logger,
) *NotificationService {
	return &NotificationService{
		outboxRepo:        outboxRepo,
		eventRepo:         eventRepo,
		notificationRepo:  notificationRepo,
		clientFactory:     notificationclient.NewClientFactory(),
		credentialDecrypt: credentialDecrypt,
		log:               log,
	}
}

// =============================================================================
// Outbox Entry Creation
// =============================================================================

// EnqueueNotificationParams contains parameters for enqueuing a notification.
type EnqueueNotificationParams struct {
	TenantID      shared.ID
	EventType     string     // e.g., "new_finding", "scan_completed"
	AggregateType string     // e.g., "finding", "scan"
	AggregateID   *uuid.UUID // ID of the source entity
	Title         string
	Body          string
	Severity      string // critical, high, medium, low, info
	URL           string
	Metadata      map[string]any
}

// EnqueueNotification creates an outbox entry for a notification.
// This should be called within the same transaction as the business event.
func (s *NotificationService) EnqueueNotification(ctx context.Context, params EnqueueNotificationParams) error {
	outbox := notification.NewOutbox(notification.OutboxParams{
		TenantID:      params.TenantID,
		EventType:     params.EventType,
		AggregateType: params.AggregateType,
		AggregateID:   params.AggregateID,
		Title:         params.Title,
		Body:          params.Body,
		Severity:      notification.Severity(params.Severity),
		URL:           params.URL,
		Metadata:      params.Metadata,
	})

	if err := s.outboxRepo.Create(ctx, outbox); err != nil {
		return fmt.Errorf("create outbox entry: %w", err)
	}

	s.log.Debug("enqueued notification",
		"outbox_id", outbox.ID().String(),
		"tenant_id", params.TenantID.String(),
		"event_type", params.EventType,
		"aggregate_type", params.AggregateType,
	)

	return nil
}

// EnqueueNotificationInTx creates an outbox entry within an existing transaction.
// This is the preferred method for the transactional outbox pattern.
func (s *NotificationService) EnqueueNotificationInTx(ctx context.Context, tx *sql.Tx, params EnqueueNotificationParams) error {
	outbox := notification.NewOutbox(notification.OutboxParams{
		TenantID:      params.TenantID,
		EventType:     params.EventType,
		AggregateType: params.AggregateType,
		AggregateID:   params.AggregateID,
		Title:         params.Title,
		Body:          params.Body,
		Severity:      notification.Severity(params.Severity),
		URL:           params.URL,
		Metadata:      params.Metadata,
	})

	if err := s.outboxRepo.CreateInTx(ctx, tx, outbox); err != nil {
		return fmt.Errorf("create outbox entry in tx: %w", err)
	}

	s.log.Debug("enqueued notification in transaction",
		"outbox_id", outbox.ID().String(),
		"tenant_id", params.TenantID.String(),
		"event_type", params.EventType,
	)

	return nil
}

// =============================================================================
// Outbox Processing (implements jobs.NotificationProcessor)
// =============================================================================

// ProcessOutboxBatch processes a batch of pending outbox entries.
func (s *NotificationService) ProcessOutboxBatch(ctx context.Context, workerID string, batchSize int) (processed, failed int, err error) {
	// Fetch and lock pending entries
	entries, err := s.outboxRepo.FetchPendingBatch(ctx, workerID, batchSize)
	if err != nil {
		return 0, 0, fmt.Errorf("fetch pending batch: %w", err)
	}

	if len(entries) == 0 {
		return 0, 0, nil
	}

	s.log.Debug("processing notification batch",
		"worker_id", workerID,
		"batch_size", len(entries),
	)

	// Process each entry
	for _, entry := range entries {
		if err := s.processOutboxEntry(ctx, entry); err != nil {
			s.log.Error("failed to process outbox entry",
				"outbox_id", entry.ID().String(),
				"error", err,
			)
			failed++
		} else {
			processed++
		}
	}

	return processed, failed, nil
}

// processOutboxEntry processes a single outbox entry.
func (s *NotificationService) processOutboxEntry(ctx context.Context, entry *notification.Outbox) error {
	// Get all notification integrations for this tenant
	integrations, err := s.getNotificationIntegrationsForTenant(ctx, entry.TenantID())
	if err != nil {
		entry.MarkFailed(fmt.Sprintf("failed to get integrations: %v", err))
		if updateErr := s.outboxRepo.Update(ctx, entry); updateErr != nil {
			s.log.Error("failed to update outbox entry after error", "error", updateErr)
		}
		return err
	}

	// Collect processing results
	results := notification.ProcessingResults{
		IntegrationsTotal:     len(integrations),
		IntegrationsMatched:   0,
		IntegrationsSucceeded: 0,
		IntegrationsFailed:    0,
		SendResults:           make([]notification.SendResult, 0),
	}

	// Send to each matching integration
	var sendErrors []string

	for _, intg := range integrations {
		// Check if this integration should receive this notification
		if !s.shouldSendToIntegration(intg, entry) {
			continue
		}

		results.IntegrationsMatched++

		// Send notification and collect result
		sendResult := s.sendToIntegration(ctx, intg, entry)
		results.SendResults = append(results.SendResults, sendResult)

		if sendResult.Status == "success" {
			results.IntegrationsSucceeded++
		} else {
			results.IntegrationsFailed++
			sendErrors = append(sendErrors, fmt.Sprintf("%s: %s", intg.Integration.Name(), sendResult.Error))
		}
	}

	// Determine final status and mark entry
	switch {
	case results.IntegrationsSucceeded > 0:
		// At least one integration succeeded
		entry.MarkCompleted()
		if len(sendErrors) > 0 {
			s.log.Warn("some integrations failed",
				"outbox_id", entry.ID().String(),
				"success_count", results.IntegrationsSucceeded,
				"errors", sendErrors,
			)
		}
	case results.IntegrationsFailed > 0:
		// All integrations failed
		entry.MarkFailed(fmt.Sprintf("all integrations failed: %v", sendErrors))
	default:
		// No matching integrations (skipped)
		entry.MarkCompleted()
	}

	// Archive to notification_events
	event := notification.NewEventFromOutbox(entry, results)
	if err := s.eventRepo.Create(ctx, event); err != nil {
		s.log.Error("failed to archive notification event",
			"outbox_id", entry.ID().String(),
			"error", err,
		)
		// Don't fail the processing, just log the error
		// Update the outbox status and continue
		return s.outboxRepo.Update(ctx, entry)
	}

	// Delete from outbox after successful archive
	if err := s.outboxRepo.Delete(ctx, entry.ID()); err != nil {
		s.log.Error("failed to delete outbox entry after archive",
			"outbox_id", entry.ID().String(),
			"error", err,
		)
		// Fall back to updating status if delete fails
		return s.outboxRepo.Update(ctx, entry)
	}

	s.log.Debug("notification processed and archived",
		"outbox_id", entry.ID().String(),
		"event_status", event.Status(),
		"integrations_matched", results.IntegrationsMatched,
		"integrations_succeeded", results.IntegrationsSucceeded,
	)

	return nil
}

// getNotificationIntegrationsForTenant gets all connected notification integrations for a tenant.
func (s *NotificationService) getNotificationIntegrationsForTenant(ctx context.Context, tenantID shared.ID) ([]*integration.IntegrationWithNotification, error) {
	// Convert shared.ID to integration.ID
	intTenantID, err := integration.ParseID(tenantID.String())
	if err != nil {
		return nil, fmt.Errorf("parse tenant id: %w", err)
	}

	// List all notification integrations with their extensions
	intgs, err := s.notificationRepo.ListIntegrationsWithNotification(ctx, intTenantID)
	if err != nil {
		return nil, fmt.Errorf("list integrations: %w", err)
	}

	// Filter to only connected integrations
	connected := make([]*integration.IntegrationWithNotification, 0, len(intgs))
	for _, intg := range intgs {
		if intg.Integration != nil && intg.Integration.Status() == integration.StatusConnected {
			connected = append(connected, intg)
		}
	}

	return connected, nil
}

// shouldSendToIntegration checks if a notification should be sent to an integration.
func (s *NotificationService) shouldSendToIntegration(intg *integration.IntegrationWithNotification, entry *notification.Outbox) bool {
	ext := intg.Notification
	if ext == nil {
		return true // No extension = send all
	}

	// Check severity filter
	if !ext.ShouldNotify(entry.Severity().String()) {
		return false
	}

	// Check event type filter
	if !ext.ShouldNotifyEventType(integration.EventType(entry.EventType())) {
		return false
	}

	return true
}

// sendToIntegration sends a notification to a specific integration.
// Returns a SendResult with success/failure status for archiving.
func (s *NotificationService) sendToIntegration(ctx context.Context, intg *integration.IntegrationWithNotification, entry *notification.Outbox) notification.SendResult {
	ext := intg.Notification
	sentAt := time.Now()

	// Base result info
	result := notification.SendResult{
		IntegrationID:   intg.Integration.ID().String(),
		IntegrationName: intg.Integration.Name(),
		Provider:        intg.Integration.Provider().String(),
		SentAt:          sentAt,
	}

	// Decrypt credentials
	credentials, err := s.credentialDecrypt(intg.Integration.CredentialsEncrypted())
	if err != nil {
		result.Status = notificationStatusFailed
		result.Error = fmt.Sprintf("decrypt credentials: %v", err)
		return result
	}

	// Build notification client config based on provider
	config := notificationclient.Config{
		Provider: notificationclient.Provider(intg.Integration.Provider().String()),
	}

	// Parse credentials and set appropriate config fields based on provider
	if err := s.configureClientFromCredentials(&config, intg.Integration, credentials, ext); err != nil {
		result.Status = notificationStatusFailed
		result.Error = fmt.Sprintf("configure client: %v", err)
		return result
	}

	// Create client
	client, err := s.clientFactory.CreateClient(config)
	if err != nil {
		result.Status = notificationStatusFailed
		result.Error = fmt.Sprintf("create client: %v", err)
		return result
	}

	// Build message
	msg := notificationclient.Message{
		Title:    entry.Title(),
		Body:     entry.Body(),
		Severity: entry.Severity().String(),
		URL:      entry.URL(),
	}

	// Apply custom template if configured
	if ext != nil && ext.MessageTemplate() != "" {
		msg = s.applyTemplate(msg, ext.MessageTemplate())
	}

	// Send with timeout
	sendCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	sendResult, err := client.Send(sendCtx, msg)
	if err != nil {
		result.Status = notificationStatusFailed
		result.Error = err.Error()
		return result
	}

	// Success
	result.Status = notificationStatusSuccess
	if sendResult != nil {
		result.MessageID = sendResult.MessageID
	}

	return result
}

// configureClientFromCredentials configures the notification client based on provider type.
// It supports both new format (metadata + sensitive credentials) and legacy format (all in credentials).
func (s *NotificationService) configureClientFromCredentials(
	config *notificationclient.Config,
	intg *integration.Integration,
	credentials string,
	ext *integration.NotificationExtension,
) error {
	provider := intg.Provider()
	metadata := intg.Metadata()

	switch provider {
	case integration.ProviderSlack, integration.ProviderTeams, integration.ProviderWebhook:
		// These providers use webhook URL as credentials
		config.WebhookURL = credentials
	case integration.ProviderTelegram:
		// Telegram uses bot token + chat ID
		config.BotToken = credentials
		// Read chat_id from metadata (new format) or fallback to extension (legacy)
		if chatID, ok := metadata["chat_id"].(string); ok && chatID != "" {
			config.ChatID = chatID
		} else if ext != nil && ext.ChannelID() != "" {
			config.ChatID = ext.ChannelID()
		}
	case integration.ProviderEmail:
		// Check if email config is in metadata (new format)
		if smtpHost, ok := metadata["smtp_host"].(string); ok && smtpHost != "" {
			// New format: read non-sensitive from metadata, sensitive from credentials
			emailConfig := &notificationclient.EmailConfig{
				SMTPHost:    smtpHost,
				FromEmail:   getStringFromMap(metadata, "from_email"),
				FromName:    getStringFromMap(metadata, "from_name"),
				UseTLS:      getBoolFromMap(metadata, "use_tls"),
				UseSTARTTLS: getBoolFromMap(metadata, "use_starttls"),
				SkipVerify:  getBoolFromMap(metadata, "skip_verify"),
				ReplyTo:     getStringFromMap(metadata, "reply_to"),
			}

			// Get smtp_port (can be float64 or int from JSON)
			if port, ok := metadata["smtp_port"].(float64); ok {
				emailConfig.SMTPPort = int(port)
			} else if port, ok := metadata["smtp_port"].(int); ok {
				emailConfig.SMTPPort = port
			}

			// Get to_emails array
			if toEmails, ok := metadata["to_emails"].([]any); ok {
				emailConfig.ToEmails = make([]string, 0, len(toEmails))
				for _, e := range toEmails {
					if email, ok := e.(string); ok {
						emailConfig.ToEmails = append(emailConfig.ToEmails, email)
					}
				}
			}

			// Parse sensitive credentials (username, password)
			if credentials != "" {
				var sensitive struct {
					Username string `json:"username"`
					Password string `json:"password"`
				}
				if err := json.Unmarshal([]byte(credentials), &sensitive); err == nil {
					emailConfig.Username = sensitive.Username
					emailConfig.Password = sensitive.Password
				}
			}

			config.Email = emailConfig
		} else {
			// Legacy format: all config in credentials
			var emailConfig notificationclient.EmailConfig
			if err := json.Unmarshal([]byte(credentials), &emailConfig); err != nil {
				return fmt.Errorf("parse email config: %w", err)
			}
			config.Email = &emailConfig
		}
	default:
		// Generic: try webhook URL
		config.WebhookURL = credentials
	}

	return nil
}

// applyTemplate applies a custom message template.
func (s *NotificationService) applyTemplate(msg notificationclient.Message, _ string) notificationclient.Message {
	// TODO: Implement template processing
	// For now, return the message as-is
	return msg
}

// =============================================================================
// Cleanup Operations
// =============================================================================

// CleanupOldEntries removes old completed and failed entries.
func (s *NotificationService) CleanupOldEntries(ctx context.Context, completedDays, failedDays int) (deletedCompleted, deletedFailed int64, err error) {
	deletedCompleted, err = s.outboxRepo.DeleteOldCompleted(ctx, completedDays)
	if err != nil {
		return 0, 0, fmt.Errorf("delete old completed: %w", err)
	}

	deletedFailed, err = s.outboxRepo.DeleteOldFailed(ctx, failedDays)
	if err != nil {
		return deletedCompleted, 0, fmt.Errorf("delete old failed: %w", err)
	}

	return deletedCompleted, deletedFailed, nil
}

// UnlockStaleEntries releases locks on stale processing entries.
func (s *NotificationService) UnlockStaleEntries(ctx context.Context, olderThanMinutes int) (unlocked int64, err error) {
	return s.outboxRepo.UnlockStale(ctx, olderThanMinutes)
}

// CleanupOldEvents removes notification events older than the specified retention days.
// If retentionDays <= 0, no deletion is performed (unlimited retention).
func (s *NotificationService) CleanupOldEvents(ctx context.Context, retentionDays int) (deleted int64, err error) {
	return s.eventRepo.DeleteOldEvents(ctx, retentionDays)
}

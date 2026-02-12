package app

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"strings"

	"github.com/openctemio/api/pkg/crypto"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/domain/webhook"
	"github.com/openctemio/api/pkg/logger"
)

// WebhookService provides business logic for webhook management.
type WebhookService struct {
	repo      webhook.Repository
	encryptor crypto.Encryptor
	logger    *logger.Logger
}

// NewWebhookService creates a new WebhookService.
func NewWebhookService(repo webhook.Repository, encryptor crypto.Encryptor, log *logger.Logger) *WebhookService {
	if encryptor == nil {
		encryptor = crypto.NewNoOpEncryptor()
	}
	return &WebhookService{
		repo:      repo,
		encryptor: encryptor,
		logger:    log.With("service", "webhook"),
	}
}

// CreateWebhookInput represents input for creating a webhook.
type CreateWebhookInput struct {
	TenantID          string   `json:"tenant_id" validate:"required,uuid"`
	Name              string   `json:"name" validate:"required,min=1,max=255"`
	Description       string   `json:"description" validate:"max=1000"`
	URL               string   `json:"url" validate:"required,url,max=1000"`
	Secret            string   `json:"secret" validate:"max=500"`
	EventTypes        []string `json:"event_types" validate:"required,min=1,max=20"`
	SeverityThreshold string   `json:"severity_threshold" validate:"omitempty,oneof=critical high medium low info"`
	MaxRetries        int      `json:"max_retries" validate:"min=0,max=10"`
	RetryInterval     int      `json:"retry_interval_seconds" validate:"min=0,max=3600"`
	CreatedBy         string   `json:"created_by" validate:"omitempty,uuid"`
}

// CreateWebhook creates a new webhook.
func (s *WebhookService) CreateWebhook(ctx context.Context, input CreateWebhookInput) (*webhook.Webhook, error) {
	tenantID, err := shared.IDFromString(input.TenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant ID", shared.ErrValidation)
	}

	// Validate webhook URL is not targeting internal/private networks
	if err := validateWebhookURL(input.URL); err != nil {
		return nil, err
	}

	id := shared.NewID()
	w := webhook.NewWebhook(id, tenantID, input.Name, input.URL, input.EventTypes)

	if input.Description != "" {
		w.SetDescription(input.Description)
	}

	if input.Secret != "" {
		encrypted, err := s.encryptor.EncryptString(input.Secret)
		if err != nil {
			return nil, fmt.Errorf("encrypt secret: %w", err)
		}
		w.SetSecret([]byte(encrypted))
	}

	if input.SeverityThreshold != "" {
		w.SetSeverityThreshold(input.SeverityThreshold)
	}

	if input.MaxRetries > 0 {
		w.SetMaxRetries(input.MaxRetries)
	}

	if input.RetryInterval > 0 {
		w.SetRetryIntervalSeconds(input.RetryInterval)
	}

	if input.CreatedBy != "" {
		cbID, err := shared.IDFromString(input.CreatedBy)
		if err == nil {
			w.SetCreatedBy(cbID)
		}
	}

	if err := s.repo.Create(ctx, w); err != nil {
		return nil, err
	}

	s.logger.Info("webhook created",
		"id", w.ID().String(),
		"tenant_id", w.TenantID().String(),
		"name", w.Name(),
	)

	return w, nil
}

// ListWebhooksInput represents input for listing webhooks.
type ListWebhooksInput struct {
	TenantID  string `json:"tenant_id" validate:"required,uuid"`
	Status    string `json:"status"`
	EventType string `json:"event_type"`
	Search    string `json:"search"`
	Page      int    `json:"page"`
	PerPage   int    `json:"per_page"`
	SortBy    string `json:"sort_by"`
	SortOrder string `json:"sort_order"`
}

// ListWebhooks retrieves a paginated list of webhooks.
func (s *WebhookService) ListWebhooks(ctx context.Context, input ListWebhooksInput) (webhook.ListResult, error) {
	tenantID, err := shared.IDFromString(input.TenantID)
	if err != nil {
		return webhook.ListResult{}, fmt.Errorf("%w: invalid tenant ID", shared.ErrValidation)
	}

	filter := webhook.Filter{
		TenantID:  &tenantID,
		EventType: input.EventType,
		Search:    input.Search,
		Page:      input.Page,
		PerPage:   input.PerPage,
		SortBy:    input.SortBy,
		SortOrder: input.SortOrder,
	}

	if input.Status != "" {
		st := webhook.Status(input.Status)
		filter.Status = &st
	}

	return s.repo.List(ctx, filter)
}

// GetWebhook retrieves a webhook by ID within a tenant.
func (s *WebhookService) GetWebhook(ctx context.Context, id, tenantIDStr string) (*webhook.Webhook, error) {
	wID, err := shared.IDFromString(id)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid ID", shared.ErrValidation)
	}
	tenantID, err := shared.IDFromString(tenantIDStr)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant ID", shared.ErrValidation)
	}
	return s.repo.GetByID(ctx, wID, tenantID)
}

// UpdateWebhookInput represents input for updating a webhook.
type UpdateWebhookInput struct {
	Name              *string  `json:"name" validate:"omitempty,min=1,max=255"`
	Description       *string  `json:"description" validate:"omitempty,max=1000"`
	URL               *string  `json:"url" validate:"omitempty,url,max=1000"`
	Secret            *string  `json:"secret" validate:"omitempty,max=500"`
	EventTypes        []string `json:"event_types" validate:"omitempty,min=1,max=20"`
	SeverityThreshold *string  `json:"severity_threshold" validate:"omitempty,oneof=critical high medium low info"`
	MaxRetries        *int     `json:"max_retries" validate:"omitempty,min=0,max=10"`
	RetryInterval     *int     `json:"retry_interval_seconds" validate:"omitempty,min=0,max=3600"`
}

// UpdateWebhook updates a webhook.
func (s *WebhookService) UpdateWebhook(ctx context.Context, id, tenantIDStr string, input UpdateWebhookInput) (*webhook.Webhook, error) {
	wID, err := shared.IDFromString(id)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid ID", shared.ErrValidation)
	}

	tenantID, err := shared.IDFromString(tenantIDStr)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant ID", shared.ErrValidation)
	}

	// Fetch with tenant isolation
	w, err := s.repo.GetByID(ctx, wID, tenantID)
	if err != nil {
		return nil, err
	}

	if input.Name != nil {
		w.SetName(*input.Name)
	}
	if input.Description != nil {
		w.SetDescription(*input.Description)
	}
	if input.URL != nil {
		if err := validateWebhookURL(*input.URL); err != nil {
			return nil, err
		}
		w.SetURL(*input.URL)
	}
	if input.Secret != nil {
		encrypted, err := s.encryptor.EncryptString(*input.Secret)
		if err != nil {
			return nil, fmt.Errorf("encrypt secret: %w", err)
		}
		w.SetSecret([]byte(encrypted))
	}
	if len(input.EventTypes) > 0 {
		w.SetEventTypes(input.EventTypes)
	}
	if input.SeverityThreshold != nil {
		w.SetSeverityThreshold(*input.SeverityThreshold)
	}
	if input.MaxRetries != nil {
		w.SetMaxRetries(*input.MaxRetries)
	}
	if input.RetryInterval != nil {
		w.SetRetryIntervalSeconds(*input.RetryInterval)
	}

	if err := s.repo.Update(ctx, w); err != nil {
		return nil, err
	}

	s.logger.Info("webhook updated", "id", w.ID().String(), "name", w.Name())
	return w, nil
}

// EnableWebhook enables a webhook.
func (s *WebhookService) EnableWebhook(ctx context.Context, id, tenantIDStr string) (*webhook.Webhook, error) {
	wID, err := shared.IDFromString(id)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid ID", shared.ErrValidation)
	}

	tenantID, err := shared.IDFromString(tenantIDStr)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant ID", shared.ErrValidation)
	}

	w, err := s.repo.GetByID(ctx, wID, tenantID)
	if err != nil {
		return nil, err
	}

	w.Enable()
	if err := s.repo.Update(ctx, w); err != nil {
		return nil, err
	}

	s.logger.Info("webhook enabled", "id", w.ID().String())
	return w, nil
}

// DisableWebhook disables a webhook.
func (s *WebhookService) DisableWebhook(ctx context.Context, id, tenantIDStr string) (*webhook.Webhook, error) {
	wID, err := shared.IDFromString(id)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid ID", shared.ErrValidation)
	}

	tenantID, err := shared.IDFromString(tenantIDStr)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant ID", shared.ErrValidation)
	}

	w, err := s.repo.GetByID(ctx, wID, tenantID)
	if err != nil {
		return nil, err
	}

	w.Disable()
	if err := s.repo.Update(ctx, w); err != nil {
		return nil, err
	}

	s.logger.Info("webhook disabled", "id", w.ID().String())
	return w, nil
}

// DeleteWebhook deletes a webhook. Tenant isolation enforced at DB level.
func (s *WebhookService) DeleteWebhook(ctx context.Context, id, tenantIDStr string) error {
	wID, err := shared.IDFromString(id)
	if err != nil {
		return fmt.Errorf("%w: invalid ID", shared.ErrValidation)
	}

	tenantID, err := shared.IDFromString(tenantIDStr)
	if err != nil {
		return fmt.Errorf("%w: invalid tenant ID", shared.ErrValidation)
	}

	// Single query: DELETE WHERE id AND tenant_id - no separate GET needed
	if err := s.repo.Delete(ctx, wID, tenantID); err != nil {
		return err
	}

	s.logger.Info("webhook deleted", "id", id)
	return nil
}

// ListDeliveriesInput represents input for listing deliveries.
type ListDeliveriesInput struct {
	WebhookID string `json:"webhook_id" validate:"required,uuid"`
	TenantID  string `json:"tenant_id" validate:"required,uuid"`
	Status    string `json:"status"`
	Page      int    `json:"page"`
	PerPage   int    `json:"per_page"`
}

// ListDeliveries retrieves delivery history for a webhook.
func (s *WebhookService) ListDeliveries(ctx context.Context, input ListDeliveriesInput) (webhook.DeliveryListResult, error) {
	wID, err := shared.IDFromString(input.WebhookID)
	if err != nil {
		return webhook.DeliveryListResult{}, fmt.Errorf("%w: invalid webhook ID", shared.ErrValidation)
	}

	tenantID, err := shared.IDFromString(input.TenantID)
	if err != nil {
		return webhook.DeliveryListResult{}, fmt.Errorf("%w: invalid tenant ID", shared.ErrValidation)
	}

	// Verify webhook exists and belongs to tenant via tenant-scoped GetByID
	if _, err := s.repo.GetByID(ctx, wID, tenantID); err != nil {
		return webhook.DeliveryListResult{}, err
	}

	filter := webhook.DeliveryFilter{
		WebhookID: &wID,
		Page:      input.Page,
		PerPage:   input.PerPage,
	}

	if input.Status != "" {
		st := webhook.DeliveryStatus(input.Status)
		filter.Status = &st
	}

	return s.repo.ListDeliveries(ctx, filter)
}

// validateWebhookURL checks that the URL is safe to use as a webhook target.
// Blocks private/internal IPs to prevent SSRF attacks.
func validateWebhookURL(rawURL string) error {
	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("%w: invalid URL", shared.ErrValidation)
	}

	// Only allow HTTPS in production (HTTP allowed for development/testing)
	scheme := strings.ToLower(u.Scheme)
	if scheme != "https" && scheme != "http" {
		return fmt.Errorf("%w: webhook URL must use HTTPS or HTTP", shared.ErrValidation)
	}

	// Block obviously dangerous hosts
	host := u.Hostname()
	if host == "" {
		return fmt.Errorf("%w: webhook URL must have a hostname", shared.ErrValidation)
	}

	// Block localhost and loopback
	lower := strings.ToLower(host)
	if lower == "localhost" || lower == "127.0.0.1" || lower == "::1" || lower == "0.0.0.0" {
		return fmt.Errorf("%w: webhook URL cannot target localhost", shared.ErrValidation)
	}

	// Block cloud metadata endpoints
	if lower == "169.254.169.254" || lower == "metadata.google.internal" {
		return fmt.Errorf("%w: webhook URL cannot target cloud metadata services", shared.ErrValidation)
	}

	// Check if IP is in private/reserved range
	ip := net.ParseIP(host)
	if ip != nil {
		if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
			return fmt.Errorf("%w: webhook URL cannot target private or reserved IP addresses", shared.ErrValidation)
		}
	}

	return nil
}

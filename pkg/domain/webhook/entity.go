package webhook

import (
	"fmt"
	"time"

	"github.com/openctemio/api/pkg/domain/shared"
)

// ID is a type alias for shared.ID.
type ID = shared.ID

// Status represents the webhook status.
type Status string

const (
	StatusActive   Status = "active"
	StatusDisabled Status = "disabled"
	StatusError    Status = "error"
)

// IsValid returns true if the status is valid.
func (s Status) IsValid() bool {
	switch s {
	case StatusActive, StatusDisabled, StatusError:
		return true
	}
	return false
}

// DeliveryStatus represents delivery status.
type DeliveryStatus string

const (
	DeliveryPending  DeliveryStatus = "pending"
	DeliverySuccess  DeliveryStatus = "success"
	DeliveryFailed   DeliveryStatus = "failed"
	DeliveryRetrying DeliveryStatus = "retrying"
)

// Webhook represents an outgoing webhook configuration.
type Webhook struct {
	id                   ID
	tenantID             ID
	name                 string
	description          string
	url                  string
	secretEncrypted      []byte
	eventTypes           []string
	severityThreshold    string
	assetGroupIDs        []string
	tags                 []string
	status               Status
	maxRetries           int
	retryIntervalSeconds int
	totalSent            int
	totalFailed          int
	lastSentAt           *time.Time
	lastError            string
	lastErrorAt          *time.Time
	createdBy            *ID
	createdAt            time.Time
	updatedAt            time.Time
}

// NewWebhook creates a new webhook entity.
func NewWebhook(id, tenantID ID, name, url string, eventTypes []string) *Webhook {
	now := time.Now()
	return &Webhook{
		id:                   id,
		tenantID:             tenantID,
		name:                 name,
		url:                  url,
		eventTypes:           eventTypes,
		severityThreshold:    "medium",
		assetGroupIDs:        []string{},
		tags:                 []string{},
		status:               StatusActive,
		maxRetries:           3,
		retryIntervalSeconds: 60,
		createdAt:            now,
		updatedAt:            now,
	}
}

// Reconstruct creates a Webhook from stored data.
func Reconstruct(
	id, tenantID ID,
	name, description, url string,
	secretEncrypted []byte,
	eventTypes []string,
	severityThreshold string,
	assetGroupIDs, tags []string,
	status Status,
	maxRetries, retryIntervalSeconds int,
	totalSent, totalFailed int,
	lastSentAt *time.Time,
	lastError string,
	lastErrorAt *time.Time,
	createdBy *ID,
	createdAt, updatedAt time.Time,
) *Webhook {
	return &Webhook{
		id:                   id,
		tenantID:             tenantID,
		name:                 name,
		description:          description,
		url:                  url,
		secretEncrypted:      secretEncrypted,
		eventTypes:           eventTypes,
		severityThreshold:    severityThreshold,
		assetGroupIDs:        assetGroupIDs,
		tags:                 tags,
		status:               status,
		maxRetries:           maxRetries,
		retryIntervalSeconds: retryIntervalSeconds,
		totalSent:            totalSent,
		totalFailed:          totalFailed,
		lastSentAt:           lastSentAt,
		lastError:            lastError,
		lastErrorAt:          lastErrorAt,
		createdBy:            createdBy,
		createdAt:            createdAt,
		updatedAt:            updatedAt,
	}
}

// --- Getters ---

func (w *Webhook) ID() ID                    { return w.id }
func (w *Webhook) TenantID() ID              { return w.tenantID }
func (w *Webhook) Name() string              { return w.name }
func (w *Webhook) Description() string       { return w.description }
func (w *Webhook) URL() string               { return w.url }
func (w *Webhook) SecretEncrypted() []byte   { return w.secretEncrypted }
func (w *Webhook) EventTypes() []string      { return w.eventTypes }
func (w *Webhook) SeverityThreshold() string { return w.severityThreshold }
func (w *Webhook) AssetGroupIDs() []string   { return w.assetGroupIDs }
func (w *Webhook) Tags() []string            { return w.tags }
func (w *Webhook) Status() Status            { return w.status }
func (w *Webhook) MaxRetries() int           { return w.maxRetries }
func (w *Webhook) RetryIntervalSeconds() int { return w.retryIntervalSeconds }
func (w *Webhook) TotalSent() int            { return w.totalSent }
func (w *Webhook) TotalFailed() int          { return w.totalFailed }
func (w *Webhook) LastSentAt() *time.Time    { return w.lastSentAt }
func (w *Webhook) LastError() string         { return w.lastError }
func (w *Webhook) LastErrorAt() *time.Time   { return w.lastErrorAt }
func (w *Webhook) CreatedBy() *ID            { return w.createdBy }
func (w *Webhook) CreatedAt() time.Time      { return w.createdAt }
func (w *Webhook) UpdatedAt() time.Time      { return w.updatedAt }

// --- Setters ---

func (w *Webhook) SetName(name string)        { w.name = name; w.updatedAt = time.Now() }
func (w *Webhook) SetDescription(desc string)  { w.description = desc; w.updatedAt = time.Now() }
func (w *Webhook) SetURL(url string)           { w.url = url; w.updatedAt = time.Now() }
func (w *Webhook) SetSecret(secret []byte)     { w.secretEncrypted = secret; w.updatedAt = time.Now() }
func (w *Webhook) SetEventTypes(types []string) { w.eventTypes = types; w.updatedAt = time.Now() }
func (w *Webhook) SetSeverityThreshold(s string) {
	w.severityThreshold = s
	w.updatedAt = time.Now()
}
func (w *Webhook) SetMaxRetries(n int)           { w.maxRetries = n; w.updatedAt = time.Now() }
func (w *Webhook) SetRetryIntervalSeconds(n int) { w.retryIntervalSeconds = n; w.updatedAt = time.Now() }
func (w *Webhook) SetCreatedBy(id ID)            { w.createdBy = &id }

// Enable enables the webhook.
func (w *Webhook) Enable() {
	w.status = StatusActive
	w.updatedAt = time.Now()
}

// Disable disables the webhook.
func (w *Webhook) Disable() {
	w.status = StatusDisabled
	w.updatedAt = time.Now()
}

// --- Delivery ---

// Delivery represents a webhook delivery attempt.
type Delivery struct {
	ID              ID
	WebhookID       ID
	EventID         *ID
	EventType       string
	Payload         map[string]any
	Status          DeliveryStatus
	ResponseCode    *int
	ResponseBody    string
	ResponseHeaders map[string]any
	Attempt         int
	NextRetryAt     *time.Time
	ErrorMessage    string
	CreatedAt       time.Time
	DeliveredAt     *time.Time
	DurationMs      *int
}

// --- Errors ---

var (
	ErrWebhookNotFound   = fmt.Errorf("%w: webhook not found", shared.ErrNotFound)
	ErrWebhookNameExists = fmt.Errorf("%w: webhook name already exists", shared.ErrAlreadyExists)
)

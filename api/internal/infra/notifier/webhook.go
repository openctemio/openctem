package notifier

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/google/uuid"

	"github.com/openctemio/openctem/api/pkg/httpsec"
	"github.com/openctemio/openctem/api/pkg/webhooksig"
)

// TestEventType is the event type of a test delivery (and of a message
// that names no type).
const TestEventType = "test"

// WebhookClient implements the Client interface for generic webhook notifications.
type WebhookClient struct {
	product    string // brand name in test messages
	webhookURL string
	httpClient *http.Client
	secrets    []string // signing secrets (pkg/webhooksig); none = unsigned
}

// NewWebhookClient creates a new generic webhook notification client.
// Validates the webhook URL up front (reject link-local, loopback,
// cloud-metadata, etc.) and uses a dialer-level SSRF guard so even if
// DNS flips to a blocked IP between construction and delivery, the
// dial fails closed. See pkg/httpsec for the ranges.
func NewWebhookClient(config Config) (*WebhookClient, error) {
	if config.WebhookURL == "" {
		return nil, fmt.Errorf("webhook URL is required")
	}
	if !config.AllowLoopback {
		if _, err := httpsec.ValidateURL(config.WebhookURL); err != nil {
			return nil, fmt.Errorf("webhook URL rejected: %w", err)
		}
	}

	// SSRF-guarded, redirects refused (newHTTPClient); AllowLoopback is
	// the unit-test path against httptest servers only.
	hc := newHTTPClient(30*time.Second, config.AllowLoopback)
	for _, sec := range config.SigningSecrets {
		if _, err := webhooksig.ParseSecret(sec); err != nil {
			return nil, fmt.Errorf("webhook signing secret: %w", err)
		}
	}
	return &WebhookClient{
		product:    config.productName(),
		webhookURL: config.WebhookURL,
		httpClient: hc,
		secrets:    config.SigningSecrets,
	}, nil
}

// Provider returns the provider name.
func (c *WebhookClient) Provider() string {
	return string(ProviderWebhook)
}

// WebhookPayload represents the JSON payload sent to the webhook.
//
// event_type is the catalog type of the event (new_finding,
// sensor.offline, ...) and event_version the version of this payload for
// that type; a receiver routes on the pair. idempotency_key is the same
// value as the Idempotency-Key header: stable across retries and
// redeliveries of one event, so a receiver can drop a duplicate.
type WebhookPayload struct {
	EventType      string              `json:"event_type"`
	EventVersion   int                 `json:"event_version"`
	IdempotencyKey string              `json:"idempotency_key,omitempty"`
	OccurredAt     string              `json:"occurred_at"`
	Timestamp      string              `json:"timestamp"`
	Title          string              `json:"title"`
	Body           string              `json:"body"`
	Severity       string              `json:"severity"`
	URL            string              `json:"url,omitempty"`
	Fields         map[string]string   `json:"fields,omitempty"`
	Color          string              `json:"color,omitempty"`
	FooterText     string              `json:"footer_text,omitempty"`
	Attachments    []WebhookAttachment `json:"attachments,omitempty"`
	Source         string              `json:"source"`
}

// WebhookAttachment represents an attachment in the webhook payload.
type WebhookAttachment struct {
	Title string `json:"title"`
	Text  string `json:"text"`
	Color string `json:"color,omitempty"`
	URL   string `json:"url,omitempty"`
}

// Send sends a notification message to the webhook.
func (c *WebhookClient) Send(ctx context.Context, msg Message) (*SendResult, error) {
	payload := c.buildPayload(msg)

	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("marshal webhook payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.webhookURL, bytes.NewReader(payloadBytes))
	if err != nil {
		return nil, fmt.Errorf("create request: %s", transportError(err))
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "OpenCTEM-Notification/1.0")
	// Standard Webhooks headers. webhook-id is the idempotency key (stable
	// across retries and redeliveries of one event); a test delivery gets a
	// fresh one. The signature covers the exact bytes sent.
	msgID := msg.IdempotencyKey
	if msgID == "" {
		msgID = "msg_" + uuid.NewString()
	}
	req.Header.Set(webhooksig.HeaderID, msgID)
	sentAt := time.Now()
	req.Header.Set(webhooksig.HeaderTimestamp, strconv.FormatInt(sentAt.Unix(), 10))
	if len(c.secrets) > 0 {
		h, err := webhooksig.Headers(msgID, sentAt, payloadBytes, c.secrets...)
		if err != nil {
			return nil, fmt.Errorf("sign webhook: %w", err)
		}
		req.Header.Set(webhooksig.HeaderSignature, h[webhooksig.HeaderSignature])
	}
	// F-6: idempotency key for duplicate-delivery suppression.
	// It is also in the JSON body (idempotency_key) for receivers that read
	// the payload rather than the headers.
	if msg.IdempotencyKey != "" {
		req.Header.Set("Idempotency-Key", msg.IdempotencyKey)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return &SendResult{
			Success: false,
			Error:   "send request failed: " + transportError(err),
		}, nil
	}
	defer func() { _ = resp.Body.Close() }()

	// SECURITY: Limit response body to 1MB to prevent memory exhaustion from malicious responses
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))

	// Accept 2xx status codes as success
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return &SendResult{
			Success: false,
			Error:   fmt.Sprintf("webhook returned status %d: %s", resp.StatusCode, echoBody(body)),
		}, nil
	}

	return &SendResult{
		Success: true,
	}, nil
}

// TestConnection tests the webhook configuration.
func (c *WebhookClient) TestConnection(ctx context.Context) (*SendResult, error) {
	testMsg := Message{
		EventType: TestEventType,
		Title:     c.product + " Test Notification",
		Body:      "This is a test notification to verify your webhook integration is working correctly.",
		Severity:  "low",
	}
	return c.Send(ctx, testMsg)
}

// buildPayload builds a webhook payload from the notification message.
func (c *WebhookClient) buildPayload(msg Message) WebhookPayload {
	color := msg.Color
	if color == "" {
		color = GetSeverityColor(msg.Severity)
	}

	attachments := make([]WebhookAttachment, 0, len(msg.Attachments))
	for _, att := range msg.Attachments {
		attachments = append(attachments, WebhookAttachment(att))
	}

	now := time.Now().UTC()
	occurred := msg.OccurredAt.UTC()
	if msg.OccurredAt.IsZero() {
		occurred = now
	}
	eventType := msg.EventType
	if eventType == "" {
		eventType = TestEventType
	}
	version := msg.EventVersion
	if version <= 0 {
		version = 1
	}
	return WebhookPayload{
		EventType:      eventType,
		EventVersion:   version,
		IdempotencyKey: msg.IdempotencyKey,
		OccurredAt:     occurred.Format(time.RFC3339),
		Timestamp:      now.Format(time.RFC3339),
		Title:          msg.Title,
		Body:           msg.Body,
		Severity:       msg.Severity,
		URL:            msg.URL,
		Fields:         msg.Fields,
		Color:          color,
		FooterText:     msg.FooterText,
		Attachments:    attachments,
		Source:         "openctem.io",
	}
}

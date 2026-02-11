package notification

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// WebhookClient implements the Client interface for generic webhook notifications.
type WebhookClient struct {
	webhookURL string
	httpClient *http.Client
}

// NewWebhookClient creates a new generic webhook notification client.
func NewWebhookClient(config Config) (*WebhookClient, error) {
	if config.WebhookURL == "" {
		return nil, fmt.Errorf("webhook URL is required")
	}

	return &WebhookClient{
		webhookURL: config.WebhookURL,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}, nil
}

// Provider returns the provider name.
func (c *WebhookClient) Provider() string {
	return string(ProviderWebhook)
}

// WebhookPayload represents the JSON payload sent to the webhook.
type WebhookPayload struct {
	EventType   string              `json:"event_type"`
	Timestamp   string              `json:"timestamp"`
	Title       string              `json:"title"`
	Body        string              `json:"body"`
	Severity    string              `json:"severity"`
	URL         string              `json:"url,omitempty"`
	Fields      map[string]string   `json:"fields,omitempty"`
	Color       string              `json:"color,omitempty"`
	FooterText  string              `json:"footer_text,omitempty"`
	Attachments []WebhookAttachment `json:"attachments,omitempty"`
	Source      string              `json:"source"`
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
		return nil, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "OpenCTEM-Notification/1.0")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return &SendResult{
			Success: false,
			Error:   fmt.Sprintf("send request failed: %v", err),
		}, nil
	}
	defer func() { _ = resp.Body.Close() }()

	// SECURITY: Limit response body to 1MB to prevent memory exhaustion from malicious responses
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))

	// Accept 2xx status codes as success
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return &SendResult{
			Success: false,
			Error:   fmt.Sprintf("webhook returned status %d: %s", resp.StatusCode, string(body)),
		}, nil
	}

	return &SendResult{
		Success: true,
	}, nil
}

// TestConnection tests the webhook configuration.
func (c *WebhookClient) TestConnection(ctx context.Context) (*SendResult, error) {
	testMsg := Message{
		Title:    "OpenCTEM Test Notification",
		Body:     "This is a test notification to verify your webhook integration is working correctly.",
		Severity: "low",
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
		attachments = append(attachments, WebhookAttachment{
			Title: att.Title,
			Text:  att.Text,
			Color: att.Color,
			URL:   att.URL,
		})
	}

	return WebhookPayload{
		EventType:   "notification",
		Timestamp:   time.Now().UTC().Format(time.RFC3339),
		Title:       msg.Title,
		Body:        msg.Body,
		Severity:    msg.Severity,
		URL:         msg.URL,
		Fields:      msg.Fields,
		Color:       color,
		FooterText:  msg.FooterText,
		Attachments: attachments,
		Source:      "openctem.io",
	}
}

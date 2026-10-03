// Package notifier provides clients for sending notifications to various providers.
package notifier

import (
	"context"
	"fmt"

	"github.com/openctemio/openctem/api/pkg/safetext"
)

// Message represents a notification message.
type Message struct {
	Title       string            // Message title/subject
	Body        string            // Main message body
	Severity    string            // critical, high, medium, low
	URL         string            // Optional link URL
	Fields      map[string]string // Additional fields to display
	Color       string            // Optional color (hex)
	FooterText  string            // Optional footer text
	IconURL     string            // Optional icon URL
	Attachments []Attachment      // Optional attachments

	// IdempotencyKey is an opaque identifier the sender uses for
	// provider-side deduplication (F-6). When non-empty, HTTP-based
	// providers (Slack, Teams, generic webhook) attach it as the
	// Idempotency-Key header so the receiving system can reject a
	// duplicate delivery that follows a worker crash + UnlockStale
	// re-queue. Providers that do not support dedup can ignore it.
	IdempotencyKey string
}

// Attachment represents a message attachment.
type Attachment struct {
	Title string
	Text  string
	Color string
	URL   string
}

// SendResult represents the result of sending a notification.
type SendResult struct {
	Success   bool
	MessageID string // Provider-specific message ID
	Error     string
}

// Client defines the interface for notification providers.
type Client interface {
	// Send sends a notification message.
	Send(ctx context.Context, msg Message) (*SendResult, error)

	// TestConnection tests the notification configuration.
	TestConnection(ctx context.Context) (*SendResult, error)

	// Provider returns the provider name.
	Provider() string
}

// Config holds the configuration for creating a notification client.
type Config struct {
	Provider    Provider
	WebhookURL  string       // For Slack, Teams, generic webhook
	BotToken    string       // For Telegram, Slack (bot token)
	ChatID      string       // For Telegram
	ChannelID   string       // For Slack
	APIEndpoint string       // Custom API endpoint
	Email       *EmailConfig // For Email (SMTP)

	// Splunk HEC. Token is the secret (HEC token); WebhookURL holds the
	// collector endpoint (e.g. https://splunk:8088). Index/Sourcetype are
	// optional routing hints written into the HEC envelope.
	Token      string // For Splunk HEC (HTTP Event Collector token)
	Index      string // For Splunk HEC (optional target index)
	Sourcetype string // For Splunk HEC (optional sourcetype; defaults to openctem:notification)

	// AllowLoopback disables the SSRF guard's private-IP block. Only
	// set true in unit tests that target httptest.NewServer (binds to
	// 127.0.0.1). Production tenants MUST NOT set this — WebhookURL
	// is tenant-controlled and the guard is the sole defense against
	// IMDS / internal-network exfil. Default zero-value is safe.
	AllowLoopback bool
}

// Provider represents a notification provider.
type Provider string

const (
	ProviderSlack    Provider = "slack"
	ProviderTeams    Provider = "teams"
	ProviderTelegram Provider = "telegram"
	ProviderWebhook  Provider = "webhook"
	ProviderEmail    Provider = "email"
	ProviderSplunk   Provider = "splunk"
)

// Severity constants.
const (
	SeverityCritical = "critical"
	SeverityHigh     = "high"
	SeverityMedium   = "medium"
	SeverityLow      = "low"
)

// String returns the string representation of the provider.
func (p Provider) String() string {
	return string(p)
}

// ClientFactory creates notification clients for different providers.
type ClientFactory struct{}

// NewClientFactory creates a new ClientFactory.
func NewClientFactory() *ClientFactory {
	return &ClientFactory{}
}

// CreateClient creates a notification client based on the configuration.
// Every client it returns cleans each message first (see Message.Cleaned).
func (f *ClientFactory) CreateClient(config Config) (Client, error) {
	c, err := newProviderClient(config)
	if err != nil {
		return nil, err
	}
	return cleaningClient{Client: c}, nil
}

func newProviderClient(config Config) (Client, error) {
	switch config.Provider {
	case ProviderSlack:
		return NewSlackClient(config)
	case ProviderTeams:
		return NewTeamsClient(config)
	case ProviderTelegram:
		return NewTelegramClient(config)
	case ProviderWebhook:
		return NewWebhookClient(config)
	case ProviderEmail:
		return NewEmailClient(config)
	case ProviderSplunk:
		return NewSplunkClient(config)
	default:
		return nil, fmt.Errorf("unsupported notification provider: %s", config.Provider)
	}
}

// Length caps applied to notification text. Generous: they bound what a
// hostile scan target can push into a channel, not normal messages.
const (
	maxNotificationTitleRunes = 300
	maxNotificationFieldRunes = 2000
	maxNotificationBodyRunes  = 20000
)

// Cleaned returns a copy of m whose text (title, body, fields, footer,
// attachments) is valid UTF-8 without control, bidi-control or zero-width
// characters, and capped in length. Titles, bodies and fields often carry
// finding text a scan target controls; an RLO override in a title would
// make a chat message display something other than what it says (Trojan
// Source). Provider-specific escaping (Slack mrkdwn, Telegram markdown,
// HTML e-mail) still applies on top. See RFC-040 §5.4.
func (m Message) Cleaned() Message {
	clean := func(s string, maxRunes int) string {
		return safetext.Truncate(safetext.Clean(s), maxRunes)
	}
	m.Title = clean(m.Title, maxNotificationTitleRunes)
	m.Body = clean(m.Body, maxNotificationBodyRunes)
	m.FooterText = clean(m.FooterText, maxNotificationFieldRunes)
	if m.Fields != nil {
		fields := make(map[string]string, len(m.Fields))
		for k, v := range m.Fields {
			fields[clean(k, maxNotificationTitleRunes)] = clean(v, maxNotificationFieldRunes)
		}
		m.Fields = fields
	}
	if m.Attachments != nil {
		atts := make([]Attachment, len(m.Attachments))
		for i, a := range m.Attachments {
			a.Title = clean(a.Title, maxNotificationTitleRunes)
			a.Text = clean(a.Text, maxNotificationBodyRunes)
			atts[i] = a
		}
		m.Attachments = atts
	}
	return m
}

// cleaningClient sends every message through Message.Cleaned.
type cleaningClient struct {
	Client
}

// Send cleans msg and sends it with the wrapped provider client.
func (c cleaningClient) Send(ctx context.Context, msg Message) (*SendResult, error) {
	return c.Client.Send(ctx, msg.Cleaned())
}

// GetSeverityColor returns a hex color for the given severity.
func GetSeverityColor(severity string) string {
	switch severity {
	case SeverityCritical:
		return "#dc2626" // Red
	case SeverityHigh:
		return "#ea580c" // Orange
	case SeverityMedium:
		return "#ca8a04" // Yellow
	case SeverityLow:
		return "#2563eb" // Blue
	default:
		return "#6b7280" // Gray
	}
}

// GetSeverityEmoji returns an emoji for the given severity.
func GetSeverityEmoji(severity string) string {
	switch severity {
	case SeverityCritical:
		return "\U0001F6A8" // 🚨
	case SeverityHigh:
		return "\U000026A0" // ⚠️
	case SeverityMedium:
		return "\U0001F7E1" // 🟡
	case SeverityLow:
		return "\U0001F535" // 🔵
	default:
		return "\U00002139" // ℹ️
	}
}

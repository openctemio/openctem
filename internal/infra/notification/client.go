// Package notification provides clients for sending notifications to various providers.
package notification

import (
	"context"
	"fmt"
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
}

// Provider represents a notification provider.
type Provider string

const (
	ProviderSlack    Provider = "slack"
	ProviderTeams    Provider = "teams"
	ProviderTelegram Provider = "telegram"
	ProviderWebhook  Provider = "webhook"
	ProviderEmail    Provider = "email"
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
func (f *ClientFactory) CreateClient(config Config) (Client, error) {
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
	default:
		return nil, fmt.Errorf("unsupported notification provider: %s", config.Provider)
	}
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

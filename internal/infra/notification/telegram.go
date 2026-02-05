package notification

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// TelegramClient implements the Client interface for Telegram notifications.
type TelegramClient struct {
	botToken   string
	chatID     string
	apiURL     string
	httpClient *http.Client
}

// NewTelegramClient creates a new Telegram notification client.
func NewTelegramClient(config Config) (*TelegramClient, error) {
	if config.BotToken == "" {
		return nil, fmt.Errorf("telegram bot token is required")
	}
	if config.ChatID == "" {
		return nil, fmt.Errorf("telegram chat ID is required")
	}

	apiURL := config.APIEndpoint
	if apiURL == "" {
		apiURL = "https://api.telegram.org"
	}

	return &TelegramClient{
		botToken: config.BotToken,
		chatID:   config.ChatID,
		apiURL:   apiURL,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}, nil
}

// Provider returns the provider name.
func (c *TelegramClient) Provider() string {
	return string(ProviderTelegram)
}

// telegramSendMessageRequest represents a Telegram sendMessage request.
type telegramSendMessageRequest struct {
	ChatID                string                        `json:"chat_id"`
	Text                  string                        `json:"text"`
	ParseMode             string                        `json:"parse_mode,omitempty"`
	DisableWebPagePreview bool                          `json:"disable_web_page_preview,omitempty"`
	ReplyMarkup           *telegramInlineKeyboardMarkup `json:"reply_markup,omitempty"`
}

type telegramInlineKeyboardMarkup struct {
	InlineKeyboard [][]telegramInlineKeyboardButton `json:"inline_keyboard"`
}

type telegramInlineKeyboardButton struct {
	Text string `json:"text"`
	URL  string `json:"url,omitempty"`
}

// telegramResponse represents a Telegram API response.
type telegramResponse struct {
	OK          bool   `json:"ok"`
	Description string `json:"description,omitempty"`
	Result      struct {
		MessageID int `json:"message_id"`
	} `json:"result,omitempty"`
}

// Send sends a notification message to Telegram.
func (c *TelegramClient) Send(ctx context.Context, msg Message) (*SendResult, error) {
	telegramMsg := c.buildMessage(msg)

	payload, err := json.Marshal(telegramMsg)
	if err != nil {
		return nil, fmt.Errorf("marshal telegram message: %w", err)
	}

	url := fmt.Sprintf("%s/bot%s/sendMessage", c.apiURL, c.botToken)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(payload))
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

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

	var telegramResp telegramResponse
	if err := json.Unmarshal(body, &telegramResp); err != nil {
		return &SendResult{
			Success: false,
			Error:   fmt.Sprintf("parse response failed: %v", err),
		}, nil
	}

	if !telegramResp.OK {
		return &SendResult{
			Success: false,
			Error:   fmt.Sprintf("telegram error: %s", telegramResp.Description),
		}, nil
	}

	return &SendResult{
		Success:   true,
		MessageID: fmt.Sprintf("%d", telegramResp.Result.MessageID),
	}, nil
}

// TestConnection tests the Telegram bot configuration.
func (c *TelegramClient) TestConnection(ctx context.Context) (*SendResult, error) {
	testMsg := Message{
		Title:    "Exploop.io Test Notification",
		Body:     "This is a test notification to verify your Telegram integration is working correctly.",
		Severity: "low",
	}
	return c.Send(ctx, testMsg)
}

// buildMessage builds a Telegram message from the notification message.
func (c *TelegramClient) buildMessage(msg Message) telegramSendMessageRequest {
	emoji := GetSeverityEmoji(msg.Severity)

	var sb strings.Builder

	// Title
	if msg.Title != "" {
		sb.WriteString(fmt.Sprintf("%s *%s*\n\n", emoji, escapeMarkdown(msg.Title)))
	}

	// Body
	if msg.Body != "" {
		sb.WriteString(escapeMarkdown(msg.Body))
		sb.WriteString("\n\n")
	}

	// Fields
	if len(msg.Fields) > 0 {
		for key, value := range msg.Fields {
			sb.WriteString(fmt.Sprintf("*%s:* %s\n", escapeMarkdown(key), escapeMarkdown(value)))
		}
		sb.WriteString("\n")
	}

	// Footer
	if msg.FooterText != "" {
		sb.WriteString(fmt.Sprintf("_%s_", escapeMarkdown(msg.FooterText)))
	}

	request := telegramSendMessageRequest{
		ChatID:                c.chatID,
		Text:                  sb.String(),
		ParseMode:             "Markdown",
		DisableWebPagePreview: true,
	}

	// Add inline button if URL is provided
	if msg.URL != "" {
		request.ReplyMarkup = &telegramInlineKeyboardMarkup{
			InlineKeyboard: [][]telegramInlineKeyboardButton{
				{
					{
						Text: "View Details",
						URL:  msg.URL,
					},
				},
			},
		}
	}

	return request
}

// escapeMarkdown escapes special characters for Telegram Markdown.
func escapeMarkdown(text string) string {
	// Escape special Markdown characters
	replacer := strings.NewReplacer(
		"_", "\\_",
		"*", "\\*",
		"[", "\\[",
		"]", "\\]",
		"`", "\\`",
	)
	return replacer.Replace(text)
}

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

// SlackClient implements the Client interface for Slack notifications.
type SlackClient struct {
	webhookURL string
	httpClient *http.Client
}

// NewSlackClient creates a new Slack notification client.
func NewSlackClient(config Config) (*SlackClient, error) {
	if config.WebhookURL == "" {
		return nil, fmt.Errorf("slack webhook URL is required")
	}

	return &SlackClient{
		webhookURL: config.WebhookURL,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}, nil
}

// Provider returns the provider name.
func (c *SlackClient) Provider() string {
	return string(ProviderSlack)
}

// slackMessage represents a Slack webhook message.
type slackMessage struct {
	Text        string            `json:"text,omitempty"`
	Blocks      []slackBlock      `json:"blocks,omitempty"`
	Attachments []slackAttachment `json:"attachments,omitempty"`
}

type slackBlock struct {
	Type     string          `json:"type"`
	Text     *slackTextBlock `json:"text,omitempty"`
	Elements []slackElement  `json:"elements,omitempty"`
	Fields   []slackField    `json:"fields,omitempty"`
}

type slackTextBlock struct {
	Type  string `json:"type"`
	Text  string `json:"text"`
	Emoji bool   `json:"emoji,omitempty"`
}

type slackElement struct {
	Type string `json:"type"`
	Text string `json:"text,omitempty"`
}

type slackField struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

type slackAttachment struct {
	Color  string       `json:"color,omitempty"`
	Blocks []slackBlock `json:"blocks,omitempty"`
}

// Send sends a notification message to Slack.
func (c *SlackClient) Send(ctx context.Context, msg Message) (*SendResult, error) {
	slackMsg := c.buildMessage(msg)

	payload, err := json.Marshal(slackMsg)
	if err != nil {
		return nil, fmt.Errorf("marshal slack message: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.webhookURL, bytes.NewReader(payload))
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

	if resp.StatusCode != http.StatusOK {
		return &SendResult{
			Success: false,
			Error:   fmt.Sprintf("slack returned status %d: %s", resp.StatusCode, string(body)),
		}, nil
	}

	return &SendResult{
		Success: true,
	}, nil
}

// TestConnection tests the Slack webhook configuration.
func (c *SlackClient) TestConnection(ctx context.Context) (*SendResult, error) {
	testMsg := Message{
		Title:    "OpenCTEM.io Test Notification",
		Body:     "This is a test notification to verify your Slack integration is working correctly.",
		Severity: "low",
	}
	return c.Send(ctx, testMsg)
}

// buildMessage builds a Slack message from the notification message.
func (c *SlackClient) buildMessage(msg Message) slackMessage {
	emoji := GetSeverityEmoji(msg.Severity)
	color := msg.Color
	if color == "" {
		color = GetSeverityColor(msg.Severity)
	}

	blocks := make([]slackBlock, 0, 4)

	// Header block
	if msg.Title != "" {
		blocks = append(blocks, slackBlock{
			Type: "header",
			Text: &slackTextBlock{
				Type:  "plain_text",
				Text:  fmt.Sprintf("%s %s", emoji, msg.Title),
				Emoji: true,
			},
		})
	}

	// Body block
	if msg.Body != "" {
		blocks = append(blocks, slackBlock{
			Type: "section",
			Text: &slackTextBlock{
				Type: "mrkdwn",
				Text: msg.Body,
			},
		})
	}

	// Fields block
	if len(msg.Fields) > 0 {
		fields := make([]slackField, 0, len(msg.Fields))
		for key, value := range msg.Fields {
			fields = append(fields, slackField{
				Type: "mrkdwn",
				Text: fmt.Sprintf("*%s:*\n%s", key, value),
			})
		}
		blocks = append(blocks, slackBlock{
			Type:   "section",
			Fields: fields,
		})
	}

	// URL button
	if msg.URL != "" {
		blocks = append(blocks, slackBlock{
			Type: "actions",
			Elements: []slackElement{
				{
					Type: "button",
					Text: fmt.Sprintf("<%s|View Details>", msg.URL),
				},
			},
		})
	}

	// Footer
	if msg.FooterText != "" {
		blocks = append(blocks, slackBlock{
			Type: "context",
			Elements: []slackElement{
				{
					Type: "mrkdwn",
					Text: msg.FooterText,
				},
			},
		})
	}

	// Use attachments for colored sidebar
	attachments := []slackAttachment{
		{
			Color:  color,
			Blocks: blocks,
		},
	}

	return slackMessage{
		Attachments: attachments,
	}
}

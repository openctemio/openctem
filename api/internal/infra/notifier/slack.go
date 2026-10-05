package notifier

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/openctemio/openctem/api/pkg/httpsec"
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
		// SSRF: SafeHTTPClient's dialer rejects connections to loopback,
		// RFC1918, link-local (169.254.169.254 / cloud IMDS), CGNAT, and
		// IPv6 private ranges. Webhook URLs are tenant-controlled, so
		// even if validation at create-time passes, DNS rebinding or
		// follow-up redirects MUST fail closed at dial time.
		httpClient: httpsec.SafeHTTPClient(30 * time.Second),
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
	Elements []any           `json:"elements,omitempty"` // slackElement or slackButton
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

// slackButton is a Block Kit button. Its label is plain_text and the link is
// the url field, so neither goes through mrkdwn parsing.
type slackButton struct {
	Type string          `json:"type"`
	Text *slackTextBlock `json:"text"`
	URL  string          `json:"url"`
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
		return nil, fmt.Errorf("create request: %s", transportError(err))
	}
	req.Header.Set("Content-Type", "application/json")
	// F-6: pass through idempotency key when provided so the receiver can
	// dedupe a duplicate delivery after a worker crash + re-queue.
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

	if resp.StatusCode != http.StatusOK {
		return &SendResult{
			Success: false,
			Error:   fmt.Sprintf("slack returned status %d: %s", resp.StatusCode, echoBody(body)),
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
				Text: slackEscape(msg.Body),
			},
		})
	}

	// Fields block
	if len(msg.Fields) > 0 {
		fields := make([]slackField, 0, len(msg.Fields))
		for key, value := range msg.Fields {
			fields = append(fields, slackField{
				Type: "mrkdwn",
				Text: fmt.Sprintf("*%s:*\n%s", slackEscape(key), slackEscape(value)),
			})
		}
		blocks = append(blocks, slackBlock{
			Type:   "section",
			Fields: fields,
		})
	}

	// URL button. A button takes a plain_text label and a url field; the old
	// "<url|label>" string was not a valid button text object.
	if msg.URL != "" {
		blocks = append(blocks, slackBlock{
			Type: "actions",
			Elements: []any{
				slackButton{
					Type: "button",
					Text: &slackTextBlock{Type: "plain_text", Text: "View Details"},
					URL:  msg.URL,
				},
			},
		})
	}

	// Footer
	if msg.FooterText != "" {
		blocks = append(blocks, slackBlock{
			Type: "context",
			Elements: []any{
				slackElement{
					Type: "mrkdwn",
					Text: slackEscape(msg.FooterText),
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

// slackEscaper escapes the three characters Slack's mrkdwn treats as control
// characters (https://api.slack.com/reference/surfaces/formatting#escaping).
// Without it, text from a finding or sensor report can write <!channel>,
// <!here>, <@U123> (mentions) or <https://evil|label> (a disguised link) into
// a channel. Formatting characters (*, _, ~, `) only change emphasis and are
// left as they are.
var slackEscaper = strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;")

// slackEscape makes untrusted text safe for a Slack mrkdwn text object.
func slackEscape(s string) string {
	return slackEscaper.Replace(s)
}

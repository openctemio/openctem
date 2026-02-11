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

// TeamsClient implements the Client interface for Microsoft Teams notifications.
type TeamsClient struct {
	webhookURL string
	httpClient *http.Client
}

// NewTeamsClient creates a new Teams notification client.
func NewTeamsClient(config Config) (*TeamsClient, error) {
	if config.WebhookURL == "" {
		return nil, fmt.Errorf("teams webhook URL is required")
	}

	return &TeamsClient{
		webhookURL: config.WebhookURL,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}, nil
}

// Provider returns the provider name.
func (c *TeamsClient) Provider() string {
	return string(ProviderTeams)
}

// teamsMessage represents a Teams Adaptive Card message.
type teamsMessage struct {
	Type        string            `json:"type"`
	Attachments []teamsAttachment `json:"attachments"`
}

type teamsAttachment struct {
	ContentType string    `json:"contentType"`
	ContentURL  *string   `json:"contentUrl"`
	Content     teamsCard `json:"content"`
}

type teamsCard struct {
	Schema  string        `json:"$schema"`
	Type    string        `json:"type"`
	Version string        `json:"version"`
	Body    []teamsBody   `json:"body"`
	Actions []teamsAction `json:"actions,omitempty"`
}

type teamsBody struct {
	Type    string        `json:"type"`
	Text    string        `json:"text,omitempty"`
	Weight  string        `json:"weight,omitempty"`
	Size    string        `json:"size,omitempty"`
	Color   string        `json:"color,omitempty"`
	Wrap    bool          `json:"wrap,omitempty"`
	Style   string        `json:"style,omitempty"`
	Columns []teamsColumn `json:"columns,omitempty"`
	Facts   []teamsFact   `json:"facts,omitempty"`
	Items   []teamsBody   `json:"items,omitempty"`
}

type teamsColumn struct {
	Type  string      `json:"type"`
	Width string      `json:"width"`
	Items []teamsBody `json:"items"`
}

type teamsFact struct {
	Title string `json:"title"`
	Value string `json:"value"`
}

type teamsAction struct {
	Type  string `json:"type"`
	Title string `json:"title"`
	URL   string `json:"url"`
}

// Send sends a notification message to Teams.
func (c *TeamsClient) Send(ctx context.Context, msg Message) (*SendResult, error) {
	teamsMsg := c.buildMessage(msg)

	payload, err := json.Marshal(teamsMsg)
	if err != nil {
		return nil, fmt.Errorf("marshal teams message: %w", err)
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

	// Teams returns 200 OK on success
	if resp.StatusCode != http.StatusOK {
		return &SendResult{
			Success: false,
			Error:   fmt.Sprintf("teams returned status %d: %s", resp.StatusCode, string(body)),
		}, nil
	}

	return &SendResult{
		Success: true,
	}, nil
}

// TestConnection tests the Teams webhook configuration.
func (c *TeamsClient) TestConnection(ctx context.Context) (*SendResult, error) {
	testMsg := Message{
		Title:    "OpenCTEM.io Test Notification",
		Body:     "This is a test notification to verify your Microsoft Teams integration is working correctly.",
		Severity: "low",
	}
	return c.Send(ctx, testMsg)
}

// buildMessage builds a Teams Adaptive Card message from the notification message.
func (c *TeamsClient) buildMessage(msg Message) teamsMessage {
	emoji := GetSeverityEmoji(msg.Severity)
	color := c.getSeverityTeamsColor(msg.Severity)

	body := make([]teamsBody, 0, 4)

	// Header with color indicator
	body = append(body, teamsBody{
		Type:  "Container",
		Style: color,
		Items: []teamsBody{
			{
				Type:   "TextBlock",
				Text:   fmt.Sprintf("%s %s", emoji, msg.Title),
				Weight: "Bolder",
				Size:   "Medium",
				Wrap:   true,
			},
		},
	})

	// Body text
	if msg.Body != "" {
		body = append(body, teamsBody{
			Type: "TextBlock",
			Text: msg.Body,
			Wrap: true,
		})
	}

	// Fields as FactSet
	if len(msg.Fields) > 0 {
		facts := make([]teamsFact, 0, len(msg.Fields))
		for key, value := range msg.Fields {
			facts = append(facts, teamsFact{
				Title: key,
				Value: value,
			})
		}
		body = append(body, teamsBody{
			Type:  "FactSet",
			Facts: facts,
		})
	}

	// Footer
	if msg.FooterText != "" {
		body = append(body, teamsBody{
			Type:  "TextBlock",
			Text:  msg.FooterText,
			Size:  "Small",
			Color: "Light",
			Wrap:  true,
		})
	}

	// Actions
	actions := make([]teamsAction, 0)
	if msg.URL != "" {
		actions = append(actions, teamsAction{
			Type:  "Action.OpenUrl",
			Title: "View Details",
			URL:   msg.URL,
		})
	}

	card := teamsCard{
		Schema:  "http://adaptivecards.io/schemas/adaptive-card.json",
		Type:    "AdaptiveCard",
		Version: "1.4",
		Body:    body,
		Actions: actions,
	}

	return teamsMessage{
		Type: "message",
		Attachments: []teamsAttachment{
			{
				ContentType: "application/vnd.microsoft.card.adaptive",
				Content:     card,
			},
		},
	}
}

// getSeverityTeamsColor returns a Teams container style for the given severity.
func (c *TeamsClient) getSeverityTeamsColor(severity string) string {
	switch severity {
	case SeverityCritical:
		return "attention"
	case SeverityHigh:
		return "warning"
	case SeverityMedium:
		return "accent"
	case SeverityLow:
		return "good"
	default:
		return "default"
	}
}

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

	"github.com/openctemio/api/pkg/httpsec"
)

// defaultSplunkSourcetype is used when the integration does not specify one.
const defaultSplunkSourcetype = "openctem:notification"

// SplunkClient delivers events to a Splunk HTTP Event Collector (HEC).
//
// HEC is a push-only receiver: we POST a JSON envelope to
// <endpoint>/services/collector/event with an "Authorization: Splunk <token>"
// header. This is the industry-standard way security tooling routes findings
// into a SIEM (mirrors Tenable/Vulcan -> SIEM). Outbound delivery rides the
// same notification fan-out (outbox + event/severity filters) as the other
// providers, so it inherits reliable, deduplicated delivery for free.
type SplunkClient struct {
	endpoint   string // full collector event URL
	token      string // HEC token (secret)
	index      string // optional target index
	sourcetype string // sourcetype written into the envelope
	httpClient *http.Client
}

// NewSplunkClient creates a Splunk HEC client. The collector base URL is
// tenant-controlled, so it is validated up front and dialed through the SSRF
// guard (fail-closed even if DNS flips to a blocked IP between construction
// and delivery) — identical to the generic webhook client.
func NewSplunkClient(config Config) (*SplunkClient, error) {
	if config.WebhookURL == "" {
		return nil, fmt.Errorf("splunk HEC endpoint URL is required")
	}
	if config.Token == "" {
		return nil, fmt.Errorf("splunk HEC token is required")
	}
	if !config.AllowLoopback {
		if _, err := httpsec.ValidateURL(config.WebhookURL); err != nil {
			return nil, fmt.Errorf("splunk HEC endpoint rejected: %w", err)
		}
	}

	hc := httpsec.SafeHTTPClient(30 * time.Second)
	if config.AllowLoopback {
		// Tests target httptest.NewServer (127.0.0.1); the SafeHTTPClient
		// dialer would refuse that at connect time. Opt-in test path only.
		hc = &http.Client{Timeout: 30 * time.Second}
	}

	sourcetype := config.Sourcetype
	if sourcetype == "" {
		sourcetype = defaultSplunkSourcetype
	}

	return &SplunkClient{
		endpoint:   splunkCollectorURL(config.WebhookURL),
		token:      config.Token,
		index:      config.Index,
		sourcetype: sourcetype,
		httpClient: hc,
	}, nil
}

// splunkCollectorURL normalizes a configured base URL to the HEC event
// endpoint. Operators may paste either the bare host
// (https://splunk:8088) or the full path
// (https://splunk:8088/services/collector/event); both resolve to the latter.
func splunkCollectorURL(raw string) string {
	u := strings.TrimRight(raw, "/")
	if strings.Contains(u, "/services/collector") {
		return u
	}
	return u + "/services/collector/event"
}

// Provider returns the provider name.
func (c *SplunkClient) Provider() string {
	return string(ProviderSplunk)
}

// splunkEvent is the HEC envelope: "event" carries the arbitrary payload,
// with optional index/sourcetype/time routing metadata alongside it.
type splunkEvent struct {
	Time       int64             `json:"time"`
	Sourcetype string            `json:"sourcetype"`
	Index      string            `json:"index,omitempty"`
	Source     string            `json:"source"`
	Event      splunkEventBody   `json:"event"`
	Fields     map[string]string `json:"fields,omitempty"`
}

// splunkEventBody is the searchable event content in Splunk.
type splunkEventBody struct {
	EventType string            `json:"event_type"`
	Title     string            `json:"title"`
	Body      string            `json:"body"`
	Severity  string            `json:"severity"`
	URL       string            `json:"url,omitempty"`
	Fields    map[string]string `json:"fields,omitempty"`
	Source    string            `json:"source"`
}

// Send posts a single event to the HEC endpoint.
func (c *SplunkClient) Send(ctx context.Context, msg Message) (*SendResult, error) {
	payloadBytes, err := json.Marshal(c.buildEvent(msg))
	if err != nil {
		return nil, fmt.Errorf("marshal splunk HEC payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint, bytes.NewReader(payloadBytes))
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Splunk "+c.token)
	req.Header.Set("User-Agent", "OpenCTEM-Notification/1.0")
	// F-6: idempotency key for duplicate-delivery suppression across retries.
	if msg.IdempotencyKey != "" {
		req.Header.Set("Idempotency-Key", msg.IdempotencyKey)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return &SendResult{Success: false, Error: fmt.Sprintf("send request failed: %v", err)}, nil
	}
	defer func() { _ = resp.Body.Close() }()

	// SECURITY: bound the response body to prevent memory exhaustion.
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return &SendResult{
			Success: false,
			Error:   fmt.Sprintf("splunk HEC returned status %d: %s", resp.StatusCode, string(body)),
		}, nil
	}
	return &SendResult{Success: true}, nil
}

// TestConnection sends a benign test event so operators can verify the token
// and endpoint from the integration settings page.
func (c *SplunkClient) TestConnection(ctx context.Context) (*SendResult, error) {
	return c.Send(ctx, Message{
		Title:    "OpenCTEM Test Notification",
		Body:     "This is a test event to verify your Splunk HEC integration is working correctly.",
		Severity: SeverityLow,
	})
}

// buildEvent maps a notification Message to a Splunk HEC envelope.
func (c *SplunkClient) buildEvent(msg Message) splunkEvent {
	return splunkEvent{
		Time:       time.Now().UTC().Unix(),
		Sourcetype: c.sourcetype,
		Index:      c.index,
		Source:     "openctem.io",
		Event: splunkEventBody{
			EventType: "notification",
			Title:     msg.Title,
			Body:      msg.Body,
			Severity:  msg.Severity,
			URL:       msg.URL,
			Fields:    msg.Fields,
			Source:    "openctem.io",
		},
	}
}

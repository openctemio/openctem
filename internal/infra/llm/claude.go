package llm

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

const (
	claudeAPIURL       = "https://api.anthropic.com/v1/messages"
	claudeAPIVersion   = "2023-06-01"
	defaultClaudeModel = "claude-sonnet-4-20250514"
)

// ClaudeProvider implements the Provider interface for Anthropic's Claude.
type ClaudeProvider struct {
	apiKey     string
	model      string
	httpClient *http.Client
	maxRetries int
}

// ClaudeConfig holds configuration for Claude provider.
type ClaudeConfig struct {
	APIKey     string
	Model      string
	Timeout    time.Duration
	MaxRetries int
}

// NewClaudeProvider creates a new Claude provider.
func NewClaudeProvider(cfg ClaudeConfig) (*ClaudeProvider, error) {
	if cfg.APIKey == "" {
		return nil, fmt.Errorf("%w: API key is required", ErrProviderNotConfigured)
	}

	model := cfg.Model
	if model == "" {
		model = defaultClaudeModel
	}

	timeout := cfg.Timeout
	if timeout == 0 {
		timeout = 30 * time.Second
	}

	maxRetries := cfg.MaxRetries
	if maxRetries == 0 {
		maxRetries = 3
	}

	return &ClaudeProvider{
		apiKey:     cfg.APIKey,
		model:      model,
		httpClient: &http.Client{Timeout: timeout},
		maxRetries: maxRetries,
	}, nil
}

// Name returns the provider name.
func (p *ClaudeProvider) Name() string {
	return "claude"
}

// Model returns the model being used.
func (p *ClaudeProvider) Model() string {
	return p.model
}

// Validate checks if the configuration is valid.
func (p *ClaudeProvider) Validate() error {
	if p.apiKey == "" {
		return fmt.Errorf("%w: API key is required", ErrProviderNotConfigured)
	}
	return nil
}

// Complete sends a prompt to Claude and returns the completion.
func (p *ClaudeProvider) Complete(ctx context.Context, req CompletionRequest) (*CompletionResponse, error) {
	maxTokens := req.MaxTokens
	if maxTokens == 0 {
		maxTokens = 2000
	}

	temperature := req.Temperature
	if temperature == 0 {
		temperature = 0.3 // Lower temperature for more deterministic responses
	}

	// Build the request body
	body := claudeRequest{
		Model:       p.model,
		MaxTokens:   maxTokens,
		Temperature: temperature,
		Messages: []claudeMessage{
			{
				Role:    "user",
				Content: req.UserPrompt,
			},
		},
	}

	if req.SystemPrompt != "" {
		body.System = req.SystemPrompt
	}

	jsonBody, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	// Create HTTP request
	httpReq, err := http.NewRequestWithContext(ctx, "POST", claudeAPIURL, bytes.NewReader(jsonBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("x-api-key", p.apiKey)
	httpReq.Header.Set("anthropic-version", claudeAPIVersion)

	// Execute with retries
	var resp *http.Response
	var lastErr error

	for attempt := 0; attempt <= p.maxRetries; attempt++ {
		if attempt > 0 {
			// Exponential backoff
			select {
			case <-ctx.Done():
				return nil, ErrContextCanceled
			case <-time.After(time.Duration(attempt*attempt) * time.Second):
			}
		}

		resp, lastErr = p.httpClient.Do(httpReq)
		if lastErr != nil {
			continue
		}

		// Check for rate limiting
		if resp.StatusCode == http.StatusTooManyRequests {
			resp.Body.Close()
			lastErr = ErrRateLimited
			continue
		}

		// Success or non-retryable error
		break
	}

	if lastErr != nil {
		return nil, lastErr
	}
	defer resp.Body.Close()

	// Read response body
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	// Check for errors
	if resp.StatusCode != http.StatusOK {
		var errResp claudeErrorResponse
		if err := json.Unmarshal(respBody, &errResp); err == nil {
			return nil, fmt.Errorf("claude API error: %s - %s", errResp.Error.Type, errResp.Error.Message)
		}
		return nil, fmt.Errorf("claude API error: status %d", resp.StatusCode)
	}

	// Parse response
	var claudeResp claudeResponse
	if err := json.Unmarshal(respBody, &claudeResp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	// Extract content
	var contentBuilder strings.Builder
	for _, block := range claudeResp.Content {
		if block.Type == "text" {
			contentBuilder.WriteString(block.Text)
		}
	}
	content := contentBuilder.String()

	return &CompletionResponse{
		Content:          content,
		PromptTokens:     claudeResp.Usage.InputTokens,
		CompletionTokens: claudeResp.Usage.OutputTokens,
		TotalTokens:      claudeResp.Usage.InputTokens + claudeResp.Usage.OutputTokens,
		Model:            claudeResp.Model,
		FinishReason:     claudeResp.StopReason,
		StopReason:       claudeResp.StopReason,
	}, nil
}

// Claude API request/response structures

type claudeRequest struct {
	Model       string          `json:"model"`
	MaxTokens   int             `json:"max_tokens"`
	Temperature float64         `json:"temperature,omitempty"`
	System      string          `json:"system,omitempty"`
	Messages    []claudeMessage `json:"messages"`
}

type claudeMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type claudeResponse struct {
	ID           string         `json:"id"`
	Type         string         `json:"type"`
	Role         string         `json:"role"`
	Content      []contentBlock `json:"content"`
	Model        string         `json:"model"`
	StopReason   string         `json:"stop_reason"`
	StopSequence *string        `json:"stop_sequence"`
	Usage        claudeUsage    `json:"usage"`
}

type contentBlock struct {
	Type string `json:"type"`
	Text string `json:"text,omitempty"`
}

type claudeUsage struct {
	InputTokens  int `json:"input_tokens"`
	OutputTokens int `json:"output_tokens"`
}

type claudeErrorResponse struct {
	Error struct {
		Type    string `json:"type"`
		Message string `json:"message"`
	} `json:"error"`
}

package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

const (
	openAIAPIURL       = "https://api.openai.com/v1/chat/completions"
	defaultOpenAIModel = "gpt-4o"
)

// OpenAIProvider implements the Provider interface for OpenAI.
type OpenAIProvider struct {
	apiKey     string
	model      string
	httpClient *http.Client
	maxRetries int
}

// OpenAIConfig holds configuration for OpenAI provider.
type OpenAIConfig struct {
	APIKey     string
	Model      string
	Timeout    time.Duration
	MaxRetries int
}

// NewOpenAIProvider creates a new OpenAI provider.
func NewOpenAIProvider(cfg OpenAIConfig) (*OpenAIProvider, error) {
	if cfg.APIKey == "" {
		return nil, fmt.Errorf("%w: API key is required", ErrProviderNotConfigured)
	}

	model := cfg.Model
	if model == "" {
		model = defaultOpenAIModel
	}

	timeout := cfg.Timeout
	if timeout == 0 {
		timeout = 30 * time.Second
	}

	maxRetries := cfg.MaxRetries
	if maxRetries == 0 {
		maxRetries = 3
	}

	return &OpenAIProvider{
		apiKey:     cfg.APIKey,
		model:      model,
		httpClient: &http.Client{Timeout: timeout},
		maxRetries: maxRetries,
	}, nil
}

// Name returns the provider name.
func (p *OpenAIProvider) Name() string {
	return "openai"
}

// Model returns the model being used.
func (p *OpenAIProvider) Model() string {
	return p.model
}

// Validate checks if the configuration is valid.
func (p *OpenAIProvider) Validate() error {
	if p.apiKey == "" {
		return fmt.Errorf("%w: API key is required", ErrProviderNotConfigured)
	}
	return nil
}

// Complete sends a prompt to OpenAI and returns the completion.
func (p *OpenAIProvider) Complete(ctx context.Context, req CompletionRequest) (*CompletionResponse, error) {
	maxTokens := req.MaxTokens
	if maxTokens == 0 {
		maxTokens = 2000
	}

	temperature := req.Temperature
	if temperature == 0 {
		temperature = 0.3 // Lower temperature for more deterministic responses
	}

	// Build messages array
	messages := make([]openAIMessage, 0, 2)

	if req.SystemPrompt != "" {
		messages = append(messages, openAIMessage{
			Role:    "system",
			Content: req.SystemPrompt,
		})
	}

	messages = append(messages, openAIMessage{
		Role:    "user",
		Content: req.UserPrompt,
	})

	// Build the request body
	body := openAIRequest{
		Model:       p.model,
		Messages:    messages,
		MaxTokens:   maxTokens,
		Temperature: temperature,
	}

	// Enable JSON mode if requested
	if req.JSONMode {
		body.ResponseFormat = &openAIResponseFormat{
			Type: "json_object",
		}
	}

	jsonBody, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	// Create HTTP request
	httpReq, err := http.NewRequestWithContext(ctx, "POST", openAIAPIURL, bytes.NewReader(jsonBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+p.apiKey)

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

			// Need to recreate body reader for retry
			httpReq, _ = http.NewRequestWithContext(ctx, "POST", openAIAPIURL, bytes.NewReader(jsonBody))
			httpReq.Header.Set("Content-Type", "application/json")
			httpReq.Header.Set("Authorization", "Bearer "+p.apiKey)
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

		// Check for server errors (5xx) - retry these
		if resp.StatusCode >= 500 {
			resp.Body.Close()
			lastErr = fmt.Errorf("server error: status %d", resp.StatusCode)
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
		var errResp openAIErrorResponse
		if err := json.Unmarshal(respBody, &errResp); err == nil && errResp.Error.Message != "" {
			return nil, fmt.Errorf("openai API error: %s - %s", errResp.Error.Type, errResp.Error.Message)
		}
		return nil, fmt.Errorf("openai API error: status %d", resp.StatusCode)
	}

	// Parse response
	var openAIResp openAIResponse
	if err := json.Unmarshal(respBody, &openAIResp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	// Extract content from first choice
	if len(openAIResp.Choices) == 0 {
		return nil, fmt.Errorf("%w: no choices in response", ErrInvalidResponse)
	}

	content := openAIResp.Choices[0].Message.Content
	finishReason := openAIResp.Choices[0].FinishReason

	return &CompletionResponse{
		Content:          content,
		PromptTokens:     openAIResp.Usage.PromptTokens,
		CompletionTokens: openAIResp.Usage.CompletionTokens,
		TotalTokens:      openAIResp.Usage.TotalTokens,
		Model:            openAIResp.Model,
		FinishReason:     finishReason,
		StopReason:       finishReason,
	}, nil
}

// OpenAI API request/response structures

type openAIRequest struct {
	Model          string                `json:"model"`
	Messages       []openAIMessage       `json:"messages"`
	MaxTokens      int                   `json:"max_tokens,omitempty"`
	Temperature    float64               `json:"temperature,omitempty"`
	ResponseFormat *openAIResponseFormat `json:"response_format,omitempty"`
}

type openAIMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type openAIResponseFormat struct {
	Type string `json:"type"` // "text" or "json_object"
}

type openAIResponse struct {
	ID      string         `json:"id"`
	Object  string         `json:"object"`
	Created int64          `json:"created"`
	Model   string         `json:"model"`
	Choices []openAIChoice `json:"choices"`
	Usage   openAIUsage    `json:"usage"`
}

type openAIChoice struct {
	Index        int           `json:"index"`
	Message      openAIMessage `json:"message"`
	FinishReason string        `json:"finish_reason"`
}

type openAIUsage struct {
	PromptTokens     int `json:"prompt_tokens"`
	CompletionTokens int `json:"completion_tokens"`
	TotalTokens      int `json:"total_tokens"`
}

type openAIErrorResponse struct {
	Error struct {
		Message string `json:"message"`
		Type    string `json:"type"`
		Code    string `json:"code"`
	} `json:"error"`
}

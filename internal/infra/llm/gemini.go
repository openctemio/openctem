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
	// Gemini API endpoint format: https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent
	geminiAPIURLBase   = "https://generativelanguage.googleapis.com/v1beta/models/"
	defaultGeminiModel = "gemini-1.5-pro"
)

// GeminiProvider implements the Provider interface for Google's Gemini.
type GeminiProvider struct {
	apiKey     string
	model      string
	httpClient *http.Client
	maxRetries int
}

// GeminiConfig holds configuration for Gemini provider.
type GeminiConfig struct {
	APIKey     string
	Model      string
	Timeout    time.Duration
	MaxRetries int
}

// NewGeminiProvider creates a new Gemini provider.
func NewGeminiProvider(cfg GeminiConfig) (*GeminiProvider, error) {
	if cfg.APIKey == "" {
		return nil, fmt.Errorf("%w: API key is required", ErrProviderNotConfigured)
	}

	model := cfg.Model
	if model == "" {
		model = defaultGeminiModel
	}

	timeout := cfg.Timeout
	if timeout == 0 {
		timeout = 30 * time.Second
	}

	maxRetries := cfg.MaxRetries
	if maxRetries == 0 {
		maxRetries = 3
	}

	return &GeminiProvider{
		apiKey:     cfg.APIKey,
		model:      model,
		httpClient: &http.Client{Timeout: timeout},
		maxRetries: maxRetries,
	}, nil
}

// Name returns the provider name.
func (p *GeminiProvider) Name() string {
	return "gemini"
}

// Model returns the model being used.
func (p *GeminiProvider) Model() string {
	return p.model
}

// Validate checks if the configuration is valid.
func (p *GeminiProvider) Validate() error {
	if p.apiKey == "" {
		return fmt.Errorf("%w: API key is required", ErrProviderNotConfigured)
	}
	return nil
}

// Complete sends a prompt to Gemini and returns the completion.
func (p *GeminiProvider) Complete(ctx context.Context, req CompletionRequest) (*CompletionResponse, error) {
	maxTokens := req.MaxTokens
	if maxTokens == 0 {
		maxTokens = 2000
	}

	temperature := req.Temperature
	if temperature == 0 {
		temperature = 0.3 // Lower temperature for more deterministic responses
	}

	// Build the request body
	body := geminiRequest{
		Contents: []geminiContent{
			{
				Parts: []geminiPart{
					{Text: req.UserPrompt},
				},
			},
		},
		GenerationConfig: geminiGenerationConfig{
			MaxOutputTokens: maxTokens,
			Temperature:     temperature,
		},
	}

	// Add system instruction if provided
	if req.SystemPrompt != "" {
		body.SystemInstruction = &geminiContent{
			Parts: []geminiPart{
				{Text: req.SystemPrompt},
			},
		}
	}

	// Request JSON mode if specified
	if req.JSONMode {
		body.GenerationConfig.ResponseMimeType = "application/json"
	}

	jsonBody, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	// Build API URL with model and API key
	apiURL := fmt.Sprintf("%s%s:generateContent?key=%s", geminiAPIURLBase, p.model, p.apiKey)

	// Create HTTP request
	httpReq, err := http.NewRequestWithContext(ctx, "POST", apiURL, bytes.NewReader(jsonBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")

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

			// Recreate request body reader for retry
			httpReq, _ = http.NewRequestWithContext(ctx, "POST", apiURL, bytes.NewReader(jsonBody))
			httpReq.Header.Set("Content-Type", "application/json")
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
			lastErr = fmt.Errorf("server error: %d", resp.StatusCode)
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
		var errResp geminiErrorResponse
		if err := json.Unmarshal(respBody, &errResp); err == nil && errResp.Error.Message != "" {
			return nil, fmt.Errorf("gemini API error: %s (code: %d)", errResp.Error.Message, errResp.Error.Code)
		}
		return nil, fmt.Errorf("gemini API error: status %d", resp.StatusCode)
	}

	// Parse response
	var geminiResp geminiResponse
	if err := json.Unmarshal(respBody, &geminiResp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	// Check for blocked content
	if geminiResp.PromptFeedback != nil && geminiResp.PromptFeedback.BlockReason != "" {
		return nil, fmt.Errorf("prompt blocked: %s", geminiResp.PromptFeedback.BlockReason)
	}

	// Extract content from candidates
	if len(geminiResp.Candidates) == 0 {
		return nil, fmt.Errorf("%w: no candidates in response", ErrInvalidResponse)
	}

	candidate := geminiResp.Candidates[0]

	// Check finish reason
	if candidate.FinishReason == "SAFETY" {
		return nil, fmt.Errorf("response blocked due to safety filters")
	}

	// Extract text from content parts
	var contentBuilder strings.Builder
	if candidate.Content != nil {
		for _, part := range candidate.Content.Parts {
			contentBuilder.WriteString(part.Text)
		}
	}
	content := contentBuilder.String()

	// Calculate token counts from usage metadata
	var promptTokens, completionTokens int
	if geminiResp.UsageMetadata != nil {
		promptTokens = geminiResp.UsageMetadata.PromptTokenCount
		completionTokens = geminiResp.UsageMetadata.CandidatesTokenCount
	}

	return &CompletionResponse{
		Content:          content,
		PromptTokens:     promptTokens,
		CompletionTokens: completionTokens,
		TotalTokens:      promptTokens + completionTokens,
		Model:            p.model,
		FinishReason:     candidate.FinishReason,
		StopReason:       candidate.FinishReason,
	}, nil
}

// Gemini API request/response structures

type geminiRequest struct {
	Contents          []geminiContent        `json:"contents"`
	SystemInstruction *geminiContent         `json:"systemInstruction,omitempty"`
	GenerationConfig  geminiGenerationConfig `json:"generationConfig,omitempty"`
	SafetySettings    []geminiSafetySetting  `json:"safetySettings,omitempty"`
}

type geminiContent struct {
	Parts []geminiPart `json:"parts"`
	Role  string       `json:"role,omitempty"`
}

type geminiPart struct {
	Text string `json:"text"`
}

type geminiGenerationConfig struct {
	MaxOutputTokens  int     `json:"maxOutputTokens,omitzero"`
	Temperature      float64 `json:"temperature,omitzero"`
	TopP             float64 `json:"topP,omitzero"`
	TopK             int     `json:"topK,omitzero"`
	ResponseMimeType string  `json:"responseMimeType,omitempty"`
}

type geminiSafetySetting struct {
	Category  string `json:"category"`
	Threshold string `json:"threshold"`
}

type geminiResponse struct {
	Candidates     []geminiCandidate     `json:"candidates"`
	PromptFeedback *geminiPromptFeedback `json:"promptFeedback,omitempty"`
	UsageMetadata  *geminiUsageMetadata  `json:"usageMetadata,omitempty"`
}

type geminiCandidate struct {
	Content       *geminiContent       `json:"content"`
	FinishReason  string               `json:"finishReason"`
	SafetyRatings []geminiSafetyRating `json:"safetyRatings,omitempty"`
}

type geminiPromptFeedback struct {
	BlockReason   string               `json:"blockReason,omitempty"`
	SafetyRatings []geminiSafetyRating `json:"safetyRatings,omitempty"`
}

type geminiSafetyRating struct {
	Category    string `json:"category"`
	Probability string `json:"probability"`
}

type geminiUsageMetadata struct {
	PromptTokenCount     int `json:"promptTokenCount"`
	CandidatesTokenCount int `json:"candidatesTokenCount"`
	TotalTokenCount      int `json:"totalTokenCount"`
}

type geminiErrorResponse struct {
	Error struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
		Status  string `json:"status"`
	} `json:"error"`
}

// Package llm provides abstractions for Large Language Model providers.
package llm

import (
	"context"
	"fmt"
)

// Provider is the interface for LLM providers (Claude, OpenAI, etc.).
type Provider interface {
	// Complete sends a prompt and returns the completion.
	Complete(ctx context.Context, req CompletionRequest) (*CompletionResponse, error)

	// Name returns the provider name for logging.
	Name() string

	// Model returns the model being used.
	Model() string

	// Validate checks if the configuration is valid.
	Validate() error
}

// CompletionRequest represents a request to the LLM.
type CompletionRequest struct {
	// SystemPrompt is the system/instruction prompt.
	SystemPrompt string

	// UserPrompt is the user's input prompt.
	UserPrompt string

	// MaxTokens is the maximum tokens in the response.
	MaxTokens int

	// Temperature controls randomness (0.0-1.0).
	Temperature float64

	// JSONMode requests structured JSON output.
	JSONMode bool

	// Metadata for tracking.
	Metadata map[string]string
}

// CompletionResponse represents a response from the LLM.
type CompletionResponse struct {
	// Content is the generated text.
	Content string

	// PromptTokens is the number of tokens in the prompt.
	PromptTokens int

	// CompletionTokens is the number of tokens in the response.
	CompletionTokens int

	// TotalTokens is PromptTokens + CompletionTokens.
	TotalTokens int

	// Model is the actual model used (may differ from requested).
	Model string

	// FinishReason indicates why the response ended.
	FinishReason string

	// StopReason is provider-specific stop information.
	StopReason string
}

// ProviderType represents supported LLM provider types.
type ProviderType string

const (
	ProviderTypeClaude      ProviderType = "claude"
	ProviderTypeOpenAI      ProviderType = "openai"
	ProviderTypeAzureOpenAI ProviderType = "azure_openai"
	ProviderTypeGemini      ProviderType = "gemini"
)

// IsValid checks if the provider type is valid.
func (p ProviderType) IsValid() bool {
	switch p {
	case ProviderTypeClaude, ProviderTypeOpenAI, ProviderTypeAzureOpenAI, ProviderTypeGemini:
		return true
	}
	return false
}

// ProviderConfig holds configuration for creating a provider.
type ProviderConfig struct {
	Type          ProviderType
	APIKey        string
	Model         string
	AzureEndpoint string // Only for Azure OpenAI
	Timeout       int    // Timeout in seconds
	MaxRetries    int
}

// Errors
var (
	ErrProviderNotConfigured = fmt.Errorf("llm provider not configured")
	ErrInvalidProvider       = fmt.Errorf("invalid llm provider")
	ErrRateLimited           = fmt.Errorf("llm rate limited")
	ErrContextCanceled       = fmt.Errorf("context canceled")
	ErrInvalidResponse       = fmt.Errorf("invalid llm response")
	ErrTokenLimitExceeded    = fmt.Errorf("token limit exceeded")
)

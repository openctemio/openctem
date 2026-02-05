package llm

import (
	"fmt"
	"strings"
	"time"

	"github.com/openctemio/api/internal/config"
	"github.com/openctemio/api/pkg/crypto"
	"github.com/openctemio/api/pkg/domain/tenant"
)

// Factory creates LLM providers based on configuration.
type Factory struct {
	platformConfig          config.AITriageConfig
	encryptor               crypto.Encryptor
	requireEncryptedAPIKeys bool // SECURITY: When true, rejects plaintext API keys
}

// NewFactory creates a new LLM provider factory.
func NewFactory(cfg config.AITriageConfig) *Factory {
	return &Factory{
		platformConfig: cfg,
		encryptor:      crypto.NewNoOpEncryptor(), // Default to no-op for backward compatibility
	}
}

// NewFactoryWithEncryption creates a new LLM provider factory with encryption support.
// SECURITY: This factory requires encrypted API keys (enc:v1: prefix) by default.
func NewFactoryWithEncryption(cfg config.AITriageConfig, encryptor crypto.Encryptor) *Factory {
	if encryptor == nil {
		encryptor = crypto.NewNoOpEncryptor()
	}
	return &Factory{
		platformConfig:          cfg,
		encryptor:               encryptor,
		requireEncryptedAPIKeys: true, // SECURITY: Enforce encryption by default
	}
}

// NewFactoryWithEncryptionLegacy creates a factory that allows plaintext keys (for migration).
// Deprecated: Use NewFactoryWithEncryption after migrating all API keys to encrypted format.
func NewFactoryWithEncryptionLegacy(cfg config.AITriageConfig, encryptor crypto.Encryptor) *Factory {
	if encryptor == nil {
		encryptor = crypto.NewNoOpEncryptor()
	}
	return &Factory{
		platformConfig:          cfg,
		encryptor:               encryptor,
		requireEncryptedAPIKeys: false, // Allow plaintext during migration
	}
}

// decryptAPIKey decrypts an API key if it's encrypted (has enc:v1: prefix).
// SECURITY: If requireEncryptedAPIKeys is true, rejects plaintext keys.
func (f *Factory) decryptAPIKey(key string) (string, error) {
	if key == "" {
		return "", nil
	}

	// Check for encryption prefix
	if !strings.HasPrefix(key, "enc:v1:") {
		// SECURITY: Reject plaintext keys if encryption is required
		if f.requireEncryptedAPIKeys {
			return "", fmt.Errorf("API key must be encrypted (missing enc:v1: prefix)")
		}
		// Legacy mode: allow plaintext (deprecated)
		return key, nil
	}

	// Remove prefix and decrypt
	ciphertext := strings.TrimPrefix(key, "enc:v1:")
	plaintext, err := f.encryptor.DecryptString(ciphertext)
	if err != nil {
		return "", fmt.Errorf("failed to decrypt API key: %w", err)
	}

	return plaintext, nil
}

// CreateProvider creates an LLM provider based on tenant settings.
// If tenant uses platform AI, uses platform config.
// If tenant uses BYOK, uses tenant's API key.
func (f *Factory) CreateProvider(aiSettings tenant.AISettings) (Provider, error) {
	switch aiSettings.Mode {
	case tenant.AIModeDisabled:
		return nil, fmt.Errorf("%w: AI is disabled for this tenant", ErrProviderNotConfigured)

	case tenant.AIModePlatform:
		return f.createPlatformProvider()

	case tenant.AIModeBYOK:
		return f.createBYOKProvider(aiSettings)

	default:
		// Default to platform if mode is empty
		if aiSettings.Mode == "" {
			return f.createPlatformProvider()
		}
		return nil, fmt.Errorf("%w: unknown AI mode: %s", ErrInvalidProvider, aiSettings.Mode)
	}
}

// createPlatformProvider creates a provider using platform configuration.
func (f *Factory) createPlatformProvider() (Provider, error) {
	if !f.platformConfig.Enabled {
		return nil, fmt.Errorf("%w: platform AI is not enabled", ErrProviderNotConfigured)
	}

	switch f.platformConfig.PlatformProvider {
	case "claude", "":
		if f.platformConfig.AnthropicAPIKey == "" {
			return nil, fmt.Errorf("%w: ANTHROPIC_API_KEY not configured", ErrProviderNotConfigured)
		}
		return NewClaudeProvider(ClaudeConfig{
			APIKey:     f.platformConfig.AnthropicAPIKey,
			Model:      f.platformConfig.PlatformModel,
			Timeout:    time.Duration(f.platformConfig.TimeoutSeconds) * time.Second,
			MaxRetries: 3,
		})

	case "openai":
		if f.platformConfig.OpenAIAPIKey == "" {
			return nil, fmt.Errorf("%w: OPENAI_API_KEY not configured", ErrProviderNotConfigured)
		}
		return NewOpenAIProvider(OpenAIConfig{
			APIKey:     f.platformConfig.OpenAIAPIKey,
			Model:      f.platformConfig.PlatformModel,
			Timeout:    time.Duration(f.platformConfig.TimeoutSeconds) * time.Second,
			MaxRetries: 3,
		})

	case "gemini":
		if f.platformConfig.GeminiAPIKey == "" {
			return nil, fmt.Errorf("%w: GEMINI_API_KEY not configured", ErrProviderNotConfigured)
		}
		return NewGeminiProvider(GeminiConfig{
			APIKey:     f.platformConfig.GeminiAPIKey,
			Model:      f.platformConfig.PlatformModel,
			Timeout:    time.Duration(f.platformConfig.TimeoutSeconds) * time.Second,
			MaxRetries: 3,
		})

	default:
		return nil, fmt.Errorf("%w: unknown platform provider: %s", ErrInvalidProvider, f.platformConfig.PlatformProvider)
	}
}

// createBYOKProvider creates a provider using tenant's own API key.
func (f *Factory) createBYOKProvider(settings tenant.AISettings) (Provider, error) {
	if settings.APIKey == "" {
		return nil, fmt.Errorf("%w: tenant API key not configured", ErrProviderNotConfigured)
	}

	// Decrypt API key if encrypted
	apiKey, err := f.decryptAPIKey(settings.APIKey)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrProviderNotConfigured, err)
	}

	switch settings.Provider {
	case tenant.LLMProviderClaude:
		model := settings.ModelOverride
		if model == "" {
			model = defaultClaudeModel
		}
		return NewClaudeProvider(ClaudeConfig{
			APIKey:     apiKey,
			Model:      model,
			Timeout:    time.Duration(f.platformConfig.TimeoutSeconds) * time.Second,
			MaxRetries: 3,
		})

	case tenant.LLMProviderOpenAI:
		model := settings.ModelOverride
		if model == "" {
			model = defaultOpenAIModel
		}
		return NewOpenAIProvider(OpenAIConfig{
			APIKey:     apiKey,
			Model:      model,
			Timeout:    time.Duration(f.platformConfig.TimeoutSeconds) * time.Second,
			MaxRetries: 3,
		})

	case tenant.LLMProviderGemini:
		model := settings.ModelOverride
		if model == "" {
			model = defaultGeminiModel
		}
		return NewGeminiProvider(GeminiConfig{
			APIKey:     apiKey,
			Model:      model,
			Timeout:    time.Duration(f.platformConfig.TimeoutSeconds) * time.Second,
			MaxRetries: 3,
		})

	case tenant.LLMProviderAzureOpenAI:
		// TODO: Implement Azure OpenAI provider
		return nil, fmt.Errorf("%w: Azure OpenAI provider not yet implemented", ErrInvalidProvider)

	default:
		return nil, fmt.Errorf("%w: unknown provider: %s", ErrInvalidProvider, settings.Provider)
	}
}

// IsPlatformEnabled checks if platform AI is both enabled and has at least one LLM provider configured.
func (f *Factory) IsPlatformEnabled() bool {
	return f.platformConfig.Enabled && f.platformConfig.IsConfigured()
}

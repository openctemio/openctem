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

	// limiters enforce AI_RATE_LIMIT_RPM. One limiter per budget scope,
	// shared process-wide, so the cap holds across concurrent triage jobs
	// rather than per-call. See ratelimit.go.
	limiters *limiterRegistry
}

// NewFactory creates a new LLM provider factory.
func NewFactory(cfg config.AITriageConfig) *Factory {
	return &Factory{
		platformConfig: cfg,
		encryptor:      crypto.NewNoOpEncryptor(), // Default to no-op for backward compatibility
		limiters:       newLimiterRegistry(),
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
		limiters:                newLimiterRegistry(),
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
		limiters:                newLimiterRegistry(),
	}
}

// rateLimited wraps p with the shared limiter for the given budget scope.
// AI_RATE_LIMIT_RPM <= 0 disables the cap and returns p unchanged.
//
// Without this, AI_RATE_LIMIT_RPM was parsed and never read: an operator could
// set it to bound LLM spend and nothing enforced it.
func (f *Factory) rateLimited(p Provider, err error, scope string) (Provider, error) {
	if err != nil || p == nil {
		return p, err
	}
	rpm := f.platformConfig.RateLimitRPM
	if rpm <= 0 {
		return p, nil
	}
	if f.limiters == nil {
		// Factory built as a zero value (tests); still enforce, just unshared.
		f.limiters = newLimiterRegistry()
	}
	return newRateLimitedProvider(p, f.limiters.get(scope, rpm), rpm, DefaultRateLimitMaxWait), nil
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
//
// BYOK providers built this way share one rate-limit budget. Prefer
// CreateProviderForTenant, which gives each BYOK tenant its own.
func (f *Factory) CreateProvider(aiSettings tenant.AISettings) (Provider, error) {
	return f.CreateProviderForTenant("", aiSettings)
}

// CreateProviderForTenant is CreateProvider with the caller's tenant identity,
// which scopes the AI_RATE_LIMIT_RPM budget: platform-mode tenants share the
// platform key's allowance because they share its bill, while each BYOK tenant
// gets its own.
func (f *Factory) CreateProviderForTenant(tenantID string, aiSettings tenant.AISettings) (Provider, error) {
	scope := budgetScope(aiSettings.Mode, tenantID)

	switch aiSettings.Mode {
	case tenant.AIModeDisabled:
		return nil, fmt.Errorf("%w: AI is disabled for this tenant", ErrProviderNotConfigured)

	case tenant.AIModePlatform:
		return f.createPlatformProvider(scope)

	case tenant.AIModeBYOK:
		return f.createBYOKProvider(aiSettings, scope)

	default:
		// Default to platform if mode is empty
		if aiSettings.Mode == "" {
			return f.createPlatformProvider(scope)
		}
		return nil, fmt.Errorf("%w: unknown AI mode: %s", ErrInvalidProvider, aiSettings.Mode)
	}
}

// createPlatformProvider creates a provider using platform configuration.
func (f *Factory) createPlatformProvider(scope string) (Provider, error) {
	if !f.platformConfig.Enabled {
		return nil, fmt.Errorf("%w: platform AI is not enabled", ErrProviderNotConfigured)
	}

	switch f.platformConfig.PlatformProvider {
	case "claude", "":
		if f.platformConfig.AnthropicAPIKey == "" {
			return nil, fmt.Errorf("%w: ANTHROPIC_API_KEY not configured", ErrProviderNotConfigured)
		}
		p, err := NewClaudeProvider(ClaudeConfig{
			APIKey:     f.platformConfig.AnthropicAPIKey,
			Model:      f.platformConfig.PlatformModel,
			Timeout:    time.Duration(f.platformConfig.TimeoutSeconds) * time.Second,
			MaxRetries: 3,
		})
		return f.rateLimited(p, err, scope)

	case "openai":
		if f.platformConfig.OpenAIAPIKey == "" {
			return nil, fmt.Errorf("%w: OPENAI_API_KEY not configured", ErrProviderNotConfigured)
		}
		p, err := NewOpenAIProvider(OpenAIConfig{
			APIKey:     f.platformConfig.OpenAIAPIKey,
			Model:      f.platformConfig.PlatformModel,
			Timeout:    time.Duration(f.platformConfig.TimeoutSeconds) * time.Second,
			MaxRetries: 3,
		})
		return f.rateLimited(p, err, scope)

	case "gemini":
		if f.platformConfig.GeminiAPIKey == "" {
			return nil, fmt.Errorf("%w: GEMINI_API_KEY not configured", ErrProviderNotConfigured)
		}
		p, err := NewGeminiProvider(GeminiConfig{
			APIKey:     f.platformConfig.GeminiAPIKey,
			Model:      f.platformConfig.PlatformModel,
			Timeout:    time.Duration(f.platformConfig.TimeoutSeconds) * time.Second,
			MaxRetries: 3,
		})
		return f.rateLimited(p, err, scope)

	default:
		return nil, fmt.Errorf("%w: unknown platform provider: %s", ErrInvalidProvider, f.platformConfig.PlatformProvider)
	}
}

// createBYOKProvider creates a provider using tenant's own API key.
func (f *Factory) createBYOKProvider(settings tenant.AISettings, scope string) (Provider, error) {
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
		p, err := NewClaudeProvider(ClaudeConfig{
			APIKey:     apiKey,
			Model:      model,
			Timeout:    time.Duration(f.platformConfig.TimeoutSeconds) * time.Second,
			MaxRetries: 3,
		})
		return f.rateLimited(p, err, scope)

	case tenant.LLMProviderOpenAI:
		model := settings.ModelOverride
		if model == "" {
			model = defaultOpenAIModel
		}
		p, err := NewOpenAIProvider(OpenAIConfig{
			APIKey:     apiKey,
			Model:      model,
			Timeout:    time.Duration(f.platformConfig.TimeoutSeconds) * time.Second,
			MaxRetries: 3,
		})
		return f.rateLimited(p, err, scope)

	case tenant.LLMProviderGemini:
		model := settings.ModelOverride
		if model == "" {
			model = defaultGeminiModel
		}
		p, err := NewGeminiProvider(GeminiConfig{
			APIKey:     apiKey,
			Model:      model,
			Timeout:    time.Duration(f.platformConfig.TimeoutSeconds) * time.Second,
			MaxRetries: 3,
		})
		return f.rateLimited(p, err, scope)

	case tenant.LLMProviderAzureOpenAI:
		// Azure OpenAI support planned for Phase 2.
		return nil, fmt.Errorf("%w: Azure OpenAI provider not yet implemented", ErrInvalidProvider)

	default:
		return nil, fmt.Errorf("%w: unknown provider: %s", ErrInvalidProvider, settings.Provider)
	}
}

// IsPlatformEnabled checks if platform AI is both enabled and has at least one LLM provider configured.
func (f *Factory) IsPlatformEnabled() bool {
	return f.platformConfig.Enabled && f.platformConfig.IsConfigured()
}

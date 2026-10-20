package llm

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/openctemio/openctem/api/internal/config"
	"github.com/openctemio/openctem/api/pkg/crypto"
	"github.com/openctemio/openctem/api/pkg/domain/tenant"
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

	// platformSource is the console's platform AI provider, used when no
	// environment key is set (platformai.Service).
	platformSource PlatformSource
}

// PlatformSource answers the console's platform AI configuration.
type PlatformSource interface {
	// PlatformAI returns the provider, model and key when platform AI is on.
	PlatformAI(ctx context.Context) (provider, model, apiKey string, ok bool)
	// PlatformAIEndpoint is the OpenAI-compatible base URL and whether an
	// administrator allowed it on a private network.
	PlatformAIEndpoint(ctx context.Context) (baseURL string, allowPrivate bool)
}

// Spec is a provider configuration: the platform's (environment or console)
// or an organization's own.
type Spec struct {
	Provider string
	Model    string
	APIKey   string
	// BaseURL is for ProviderOpenAICompatible only.
	BaseURL string
	// AllowPrivate is honored only for the platform's provider (a console
	// toggle); an organization's URL is always public-only.
	AllowPrivate bool
}

// SetPlatformSource wires the console's platform AI configuration.
func (f *Factory) SetPlatformSource(src PlatformSource) { f.platformSource = src }

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
		return f.createPlatformProvider(scope, tenantID)

	case tenant.AIModeBYOK:
		return f.createBYOKProvider(aiSettings, scope)

	default:
		// Default to platform if mode is empty
		if aiSettings.Mode == "" {
			return f.createPlatformProvider(scope, tenantID)
		}
		return nil, fmt.Errorf("%w: unknown AI mode: %s", ErrInvalidProvider, aiSettings.Mode)
	}
}

// createPlatformProvider creates a provider using platform configuration:
// the environment keys when set, otherwise the console's platform AI setting
// when it is on. The organization's own bucket sits in front of the
// platform key's shared one.
func (f *Factory) createPlatformProvider(scope, tenantID string) (Provider, error) {
	if !f.platformConfig.IsConfigured() && f.platformSource != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		provider, model, key, ok := f.platformSource.PlatformAI(ctx)
		if !ok {
			return nil, fmt.Errorf("%w: platform AI is not turned on", ErrProviderNotConfigured)
		}
		baseURL, allowPrivate := f.platformSource.PlatformAIEndpoint(ctx)
		p, err := f.BuildPlatformProvider(Spec{Provider: provider, Model: model, APIKey: key, BaseURL: baseURL, AllowPrivate: allowPrivate})
		return f.tenantShare(f.rateLimited(p, err, scope))(tenantID)
	}
	var key, envName string
	switch f.platformConfig.PlatformProvider {
	case "claude", "":
		key, envName = f.platformConfig.AnthropicAPIKey, "ANTHROPIC_API_KEY"
	case "openai":
		key, envName = f.platformConfig.OpenAIAPIKey, "OPENAI_API_KEY"
	case "gemini":
		key, envName = f.platformConfig.GeminiAPIKey, "GEMINI_API_KEY"
	default:
		return nil, fmt.Errorf("%w: unknown platform provider: %s", ErrInvalidProvider, f.platformConfig.PlatformProvider)
	}
	if key == "" {
		return nil, fmt.Errorf("%w: %s not configured", ErrProviderNotConfigured, envName)
	}
	p, err := f.BuildPlatformProvider(Spec{Provider: f.platformConfig.PlatformProvider, Model: f.platformConfig.PlatformModel, APIKey: key})
	return f.tenantShare(f.rateLimited(p, err, scope))(tenantID)
}

// tenantShare puts the organization's share of the platform allowance
// (AI_RATE_LIMIT_TENANT_RPM) in front of a platform provider. A call waits
// for its organization's bucket first, then for the shared one, so one
// organization cannot use up the whole platform allowance.
func (f *Factory) tenantShare(p Provider, err error) func(tenantID string) (Provider, error) {
	return func(tenantID string) (Provider, error) {
		rpm := f.platformConfig.TenantShareRPM()
		if err != nil || p == nil || rpm <= 0 || tenantID == "" {
			return p, err
		}
		if f.limiters == nil {
			f.limiters = newLimiterRegistry()
		}
		return newRateLimitedProvider(p, f.limiters.get(platformTenantScopePrefix+tenantID, rpm), rpm, DefaultRateLimitMaxWait), nil
	}
}

// BuildPlatformProvider builds a provider from a configuration (also the
// console's key test), without the rate limit.
func (f *Factory) BuildPlatformProvider(spec Spec) (Provider, error) {
	return f.build(spec)
}

// build is the one place a provider is constructed, for the platform's
// configuration and an organization's own alike.
func (f *Factory) build(spec Spec) (Provider, error) {
	timeout := time.Duration(f.platformConfig.TimeoutSeconds) * time.Second
	switch spec.Provider {
	case "claude", "":
		return NewClaudeProvider(ClaudeConfig{APIKey: spec.APIKey, Model: spec.Model, Timeout: timeout, MaxRetries: 3})
	case "openai":
		return NewOpenAIProvider(OpenAIConfig{APIKey: spec.APIKey, Model: spec.Model, Timeout: timeout, MaxRetries: 3})
	case "gemini":
		return NewGeminiProvider(GeminiConfig{APIKey: spec.APIKey, Model: spec.Model, Timeout: timeout, MaxRetries: 3})
	case ProviderOpenAICompatible:
		return NewOpenAICompatibleProvider(OpenAICompatibleConfig{BaseURL: spec.BaseURL, APIKey: spec.APIKey,
			Model: spec.Model, AllowPrivate: spec.AllowPrivate, Timeout: timeout, MaxRetries: 3})
	default:
		return nil, fmt.Errorf("%w: unknown provider: %s", ErrInvalidProvider, spec.Provider)
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

	provider := string(settings.Provider)
	if !settings.Provider.IsValid() {
		return nil, fmt.Errorf("%w: unknown provider: %s", ErrInvalidProvider, settings.Provider)
	}
	model := settings.ModelOverride
	if model == "" {
		model = defaultModel(provider)
	}
	// SECURITY: an organization's own endpoint is public-only (AllowPrivate
	// is never set here), so it cannot reach the platform's network. It is
	// vetted again here (a stored URL may predate a rule) and at every dial.
	if provider == ProviderOpenAICompatible {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if _, err := ValidateBaseURL(ctx, settings.BaseURL, false); err != nil {
			return nil, err
		}
	}
	p, err := f.build(Spec{Provider: provider, Model: model, APIKey: apiKey, BaseURL: settings.BaseURL})
	return f.rateLimited(p, err, scope)
}

func defaultModel(provider string) string {
	switch provider {
	case "claude":
		return defaultClaudeModel
	case "openai":
		return defaultOpenAIModel
	case "gemini":
		return defaultGeminiModel
	}
	return "" // openai_compatible: the organization names the model
}

// IsPlatformEnabled reports whether an environment provider key is set.
func (f *Factory) IsPlatformEnabled() bool {
	return f.platformConfig.IsConfigured()
}

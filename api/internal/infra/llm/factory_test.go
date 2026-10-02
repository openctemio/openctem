package llm

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/openctemio/api/internal/config"
	"github.com/openctemio/api/pkg/domain/tenant"
)

func TestFactory_CreateProvider(t *testing.T) {
	tests := []struct {
		name           string
		platformConfig config.AITriageConfig
		aiSettings     tenant.AISettings
		wantProvider   string
		wantErr        bool
		errContains    string
	}{
		{
			name: "platform mode with claude",
			platformConfig: config.AITriageConfig{
				Enabled:          true,
				PlatformProvider: "claude",
				AnthropicAPIKey:  "test-key",
			},
			aiSettings: tenant.AISettings{
				Mode: tenant.AIModePlatform,
			},
			wantProvider: "claude",
			wantErr:      false,
		},
		{
			name: "platform mode with openai",
			platformConfig: config.AITriageConfig{
				Enabled:          true,
				PlatformProvider: "openai",
				OpenAIAPIKey:     "test-key",
			},
			aiSettings: tenant.AISettings{
				Mode: tenant.AIModePlatform,
			},
			wantProvider: "openai",
			wantErr:      false,
		},
		{
			name: "byok mode with claude",
			platformConfig: config.AITriageConfig{
				Enabled: true,
			},
			aiSettings: tenant.AISettings{
				Mode:     tenant.AIModeBYOK,
				Provider: tenant.LLMProviderClaude,
				APIKey:   "tenant-key",
			},
			wantProvider: "claude",
			wantErr:      false,
		},
		{
			name: "byok mode with openai",
			platformConfig: config.AITriageConfig{
				Enabled: true,
			},
			aiSettings: tenant.AISettings{
				Mode:     tenant.AIModeBYOK,
				Provider: tenant.LLMProviderOpenAI,
				APIKey:   "tenant-key",
			},
			wantProvider: "openai",
			wantErr:      false,
		},
		{
			name: "disabled mode",
			platformConfig: config.AITriageConfig{
				Enabled: true,
			},
			aiSettings: tenant.AISettings{
				Mode: tenant.AIModeDisabled,
			},
			wantErr:     true,
			errContains: "disabled",
		},
		{
			name: "platform not enabled",
			platformConfig: config.AITriageConfig{
				Enabled: false,
			},
			aiSettings: tenant.AISettings{
				Mode: tenant.AIModePlatform,
			},
			wantErr:     true,
			errContains: "not enabled",
		},
		{
			name: "byok without API key",
			platformConfig: config.AITriageConfig{
				Enabled: true,
			},
			aiSettings: tenant.AISettings{
				Mode:     tenant.AIModeBYOK,
				Provider: tenant.LLMProviderClaude,
				APIKey:   "",
			},
			wantErr:     true,
			errContains: "not configured",
		},
		{
			name: "empty mode defaults to platform",
			platformConfig: config.AITriageConfig{
				Enabled:          true,
				PlatformProvider: "claude",
				AnthropicAPIKey:  "test-key",
			},
			aiSettings: tenant.AISettings{
				Mode: "", // empty
			},
			wantProvider: "claude",
			wantErr:      false,
		},
		{
			name: "platform claude without API key",
			platformConfig: config.AITriageConfig{
				Enabled:          true,
				PlatformProvider: "claude",
				AnthropicAPIKey:  "", // missing
			},
			aiSettings: tenant.AISettings{
				Mode: tenant.AIModePlatform,
			},
			wantErr:     true,
			errContains: "ANTHROPIC_API_KEY",
		},
		{
			name: "platform openai without API key",
			platformConfig: config.AITriageConfig{
				Enabled:          true,
				PlatformProvider: "openai",
				OpenAIAPIKey:     "", // missing
			},
			aiSettings: tenant.AISettings{
				Mode: tenant.AIModePlatform,
			},
			wantErr:     true,
			errContains: "OPENAI_API_KEY",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			factory := NewFactory(tt.platformConfig)

			provider, err := factory.CreateProvider(tt.aiSettings)

			if tt.wantErr {
				assert.Error(t, err)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
				return
			}

			assert.NoError(t, err)
			assert.NotNil(t, provider)
			assert.Equal(t, tt.wantProvider, provider.Name())
		})
	}
}

func TestFactory_IsPlatformEnabled(t *testing.T) {
	tests := []struct {
		name           string
		platformConfig config.AITriageConfig
		want           bool
	}{
		{
			name: "enabled with claude key",
			platformConfig: config.AITriageConfig{
				Enabled:          true,
				PlatformProvider: "claude",
				AnthropicAPIKey:  "test-key",
			},
			want: true,
		},
		{
			name: "enabled with openai key",
			platformConfig: config.AITriageConfig{
				Enabled:          true,
				PlatformProvider: "openai",
				OpenAIAPIKey:     "test-key",
			},
			want: true,
		},
		{
			name: "disabled",
			platformConfig: config.AITriageConfig{
				Enabled:         false,
				AnthropicAPIKey: "test-key",
			},
			want: false,
		},
		{
			name: "enabled but no keys",
			platformConfig: config.AITriageConfig{
				Enabled: true,
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			factory := NewFactory(tt.platformConfig)
			assert.Equal(t, tt.want, factory.IsPlatformEnabled())
		})
	}
}

func TestFactory_CreateProvider_WithModelOverride(t *testing.T) {
	factory := NewFactory(config.AITriageConfig{
		Enabled: true,
	})

	t.Run("BYOK claude with model override", func(t *testing.T) {
		provider, err := factory.CreateProvider(tenant.AISettings{
			Mode:          tenant.AIModeBYOK,
			Provider:      tenant.LLMProviderClaude,
			APIKey:        "test-key",
			ModelOverride: "claude-3-haiku-20240307",
		})

		assert.NoError(t, err)
		assert.Equal(t, "claude-3-haiku-20240307", provider.Model())
	})

	t.Run("BYOK openai with model override", func(t *testing.T) {
		provider, err := factory.CreateProvider(tenant.AISettings{
			Mode:          tenant.AIModeBYOK,
			Provider:      tenant.LLMProviderOpenAI,
			APIKey:        "test-key",
			ModelOverride: "gpt-4-turbo",
		})

		assert.NoError(t, err)
		assert.Equal(t, "gpt-4-turbo", provider.Model())
	})

	t.Run("BYOK claude without model override uses default", func(t *testing.T) {
		provider, err := factory.CreateProvider(tenant.AISettings{
			Mode:     tenant.AIModeBYOK,
			Provider: tenant.LLMProviderClaude,
			APIKey:   "test-key",
		})

		assert.NoError(t, err)
		assert.Equal(t, defaultClaudeModel, provider.Model())
	})

	t.Run("BYOK openai without model override uses default", func(t *testing.T) {
		provider, err := factory.CreateProvider(tenant.AISettings{
			Mode:     tenant.AIModeBYOK,
			Provider: tenant.LLMProviderOpenAI,
			APIKey:   "test-key",
		})

		assert.NoError(t, err)
		assert.Equal(t, defaultOpenAIModel, provider.Model())
	})
}

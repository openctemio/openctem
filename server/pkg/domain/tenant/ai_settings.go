package tenant

import (
	"context"
	"fmt"
	"net/url"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// AIMode represents how the tenant uses AI services. The API calls the same
// choice a source: platform, own (BYOK) or off.
type AIMode string

const (
	// AIModeDisabled means AI features are disabled.
	AIModeDisabled AIMode = "disabled"
	// AIModePlatform uses the platform's AI (included in subscription).
	AIModePlatform AIMode = "platform"
	// AIModeBYOK means tenant brings their own provider and key.
	AIModeBYOK AIMode = "byok"
)

// IsValid checks if the AI mode is valid.
func (m AIMode) IsValid() bool {
	switch m {
	case AIModeDisabled, AIModePlatform, AIModeBYOK:
		return true
	}
	return false
}

// LLMProvider represents supported LLM providers.
type LLMProvider string

const (
	LLMProviderClaude LLMProvider = "claude"
	LLMProviderOpenAI LLMProvider = "openai"
	// LLMProviderOpenAICompatible is any server speaking the OpenAI chat
	// completions API, at a base URL the organization sets (public only).
	LLMProviderOpenAICompatible LLMProvider = "openai_compatible"
	LLMProviderGemini           LLMProvider = "gemini"
)

// IsValid checks if the LLM provider is valid.
func (p LLMProvider) IsValid() bool {
	switch p {
	case LLMProviderClaude, LLMProviderOpenAI, LLMProviderOpenAICompatible, LLMProviderGemini:
		return true
	}
	return false
}

// AISettings is an organization's AI triage configuration, stored in
// tenant_ai_settings (docs/architecture/ai-triage.md).
type AISettings struct {
	// Mode determines how AI is used: disabled, platform, or byok.
	Mode AIMode

	// Own provider (BYOK), used when Mode = byok.
	Provider      LLMProvider
	BaseURL       string // openai_compatible only; public https
	ModelOverride string
	// APIKey is the ENCRYPTED key (APP_ENCRYPTION_KEY); it never leaves the
	// server. KeyLast4, KeyUpdatedAt and KeyUpdatedBy describe it for display.
	APIKey       string
	KeyLast4     string
	KeyUpdatedAt *time.Time
	KeyUpdatedBy string
	UpdatedAt    *time.Time
	UpdatedBy    string

	// Auto-triage policy.
	AutoTriageEnabled      bool     // auto-triage new findings
	AutoTriageSeverities   []string // critical, high, ...
	AutoTriageDelaySeconds int      // delay before auto-triage (for dedup)

	// Consent. Finding content goes to an AI provider only after an
	// organization administrator turned AI triage on: EnabledAt is when,
	// EnabledBy is who (a user id, or AIEnabledByUpgrade for organizations
	// that used AI triage before consent existed). nil EnabledAt: off.
	EnabledAt *time.Time
	EnabledBy string
}

// AIEnabledByUpgrade marks the consent of an organization that already used
// AI triage when organization consent was introduced (migration).
const AIEnabledByUpgrade = "upgrade"

// OptedIn reports whether an organization administrator turned AI triage on.
func (s AISettings) OptedIn() bool { return s.EnabledAt != nil }

// EffectiveMode is the mode that applies: disabled until the organization
// opted in, platform when no mode was chosen.
func (s AISettings) EffectiveMode() AIMode {
	if !s.OptedIn() || s.Mode == AIModeDisabled {
		return AIModeDisabled
	}
	if s.Mode == "" {
		return AIModePlatform
	}
	return s.Mode
}

// SetOptIn records the organization's consent (on) or withdraws it (off).
func (s *AISettings) SetOptIn(on bool, by string, at time.Time) {
	if !on {
		s.EnabledAt, s.EnabledBy = nil, ""
		return
	}
	at = at.UTC()
	s.EnabledAt, s.EnabledBy = &at, by
}

// Validate validates AI settings.
func (s *AISettings) Validate() error {
	if s.Mode != "" && !s.Mode.IsValid() {
		return fmt.Errorf("%w: invalid AI mode", shared.ErrValidation)
	}
	if s.Mode == AIModeBYOK {
		if s.Provider == "" {
			return fmt.Errorf("%w: provider is required for an own provider", shared.ErrValidation)
		}
		if !s.Provider.IsValid() {
			return fmt.Errorf("%w: invalid LLM provider", shared.ErrValidation)
		}
		if s.Provider == LLMProviderOpenAICompatible {
			if s.BaseURL == "" || s.ModelOverride == "" {
				return fmt.Errorf("%w: base_url and model are required for an OpenAI-compatible provider", shared.ErrValidation)
			}
			if u, err := url.ParseRequestURI(s.BaseURL); err != nil || u.Scheme != "https" {
				return fmt.Errorf("%w: invalid base URL (https required)", shared.ErrValidation)
			}
		}
	}
	validSeverities := map[string]bool{"critical": true, "high": true, "medium": true, "low": true, "info": true}
	for _, sev := range s.AutoTriageSeverities {
		if !validSeverities[sev] {
			return fmt.Errorf("%w: invalid severity: %s", shared.ErrValidation, sev)
		}
	}
	if s.AutoTriageDelaySeconds < 0 {
		return fmt.Errorf("%w: auto_triage_delay_seconds must be non-negative", shared.ErrValidation)
	}
	return nil
}

// AISettingsRepository stores the organization's AI settings (one row per
// organization).
type AISettingsRepository interface {
	// Get returns the organization's settings. An organization with no row
	// gets defaults; a stored policy overrides the defaults key by key (an
	// explicit "auto-triage off" always wins over a platform default).
	Get(ctx context.Context, tenantID shared.ID, defaults AISettings) (AISettings, error)
	// Save writes the source, provider, key and consent. The auto-triage
	// policy is not touched. expected is the UpdatedAt the caller read (nil
	// when it read no row): when the stored row has changed since, nothing is
	// written and the error wraps shared.ErrConflict.
	Save(ctx context.Context, tenantID shared.ID, s AISettings, expected *time.Time) error
}

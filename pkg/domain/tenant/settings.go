package tenant

import (
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/openctemio/api/pkg/domain/branch"
	"github.com/openctemio/api/pkg/domain/shared"
)

// =============================================================================
// Tenant Settings - Typed settings for tenant configuration
// =============================================================================

// Settings represents the typed settings for a tenant.
type Settings struct {
	General  GeneralSettings  `json:"general"`
	Security SecuritySettings `json:"security"`
	API      APISettings      `json:"api"`
	Branding BrandingSettings `json:"branding"`
	Branch   BranchSettings   `json:"branch"`
	AI       AISettings       `json:"ai"`
}

// BranchSettings contains branch naming convention configuration.
// When TypeRules is nil or empty, system defaults are used.
type BranchSettings struct {
	// TypeRules defines custom prefix/exact-match rules for branch type detection.
	// Rules are ordered; first match wins. If no rule matches, falls through
	// to system defaults (feature/, release/, hotfix/, main, master, etc.).
	TypeRules branch.BranchTypeRules `json:"type_rules,omitempty"`
}

// GeneralSettings contains general tenant configuration.
type GeneralSettings struct {
	Timezone string `json:"timezone"` // e.g., "Asia/Ho_Chi_Minh", "UTC"
	Language string `json:"language"` // e.g., "en", "vi"
	Industry string `json:"industry"` // e.g., "technology", "finance", "healthcare"
	Website  string `json:"website"`  // Company website URL
}

// SecuritySettings contains security-related configuration.
type SecuritySettings struct {
	SSOEnabled        bool     `json:"sso_enabled"`         // Enable SSO (SAML 2.0, OIDC)
	SSOProvider       string   `json:"sso_provider"`        // e.g., "saml", "oidc"
	SSOConfigURL      string   `json:"sso_config_url"`      // SSO metadata/config URL
	MFARequired       bool     `json:"mfa_required"`        // Require MFA for all users
	SessionTimeoutMin int      `json:"session_timeout_min"` // Session timeout in minutes (15-480)
	IPWhitelist       []string `json:"ip_whitelist"`        // Allowed IP addresses/CIDR ranges
	AllowedDomains    []string `json:"allowed_domains"`     // Allowed email domains for signup
}

// APISettings contains API and webhook configuration.
type APISettings struct {
	APIKeyEnabled bool           `json:"api_key_enabled"` // Enable API key access
	WebhookURL    string         `json:"webhook_url"`     // Webhook endpoint URL
	WebhookSecret string         `json:"webhook_secret"`  // Webhook signing secret
	WebhookEvents []WebhookEvent `json:"webhook_events"`  // Events to send to webhook
}

// WebhookEvent represents a webhook event type.
type WebhookEvent string

const (
	WebhookEventFindingCreated  WebhookEvent = "finding.created"
	WebhookEventFindingResolved WebhookEvent = "finding.resolved"
	WebhookEventFindingUpdated  WebhookEvent = "finding.updated"
	WebhookEventScanCompleted   WebhookEvent = "scan.completed"
	WebhookEventScanFailed      WebhookEvent = "scan.failed"
	WebhookEventAssetDiscovered WebhookEvent = "asset.discovered"
	WebhookEventAssetUpdated    WebhookEvent = "asset.updated"
	WebhookEventMemberJoined    WebhookEvent = "member.joined"
	WebhookEventMemberRemoved   WebhookEvent = "member.removed"
)

// ValidWebhookEvents returns all valid webhook events.
func ValidWebhookEvents() []WebhookEvent {
	return []WebhookEvent{
		WebhookEventFindingCreated,
		WebhookEventFindingResolved,
		WebhookEventFindingUpdated,
		WebhookEventScanCompleted,
		WebhookEventScanFailed,
		WebhookEventAssetDiscovered,
		WebhookEventAssetUpdated,
		WebhookEventMemberJoined,
		WebhookEventMemberRemoved,
	}
}

// IsValid checks if the webhook event is valid.
func (e WebhookEvent) IsValid() bool {
	for _, v := range ValidWebhookEvents() {
		if e == v {
			return true
		}
	}
	return false
}

// BrandingSettings contains branding configuration.
type BrandingSettings struct {
	PrimaryColor string `json:"primary_color"` // Hex color code, e.g., "#3B82F6"
	LogoDarkURL  string `json:"logo_dark_url"` // Logo for dark theme (URL)
	LogoData     string `json:"logo_data"`     // Logo as base64 data URL (max 150KB)
}

// =============================================================================
// AI Settings
// =============================================================================

// AIMode represents how the tenant uses AI services.
type AIMode string

const (
	// AIModeDisabled means AI features are disabled.
	AIModeDisabled AIMode = "disabled"
	// AIModePlatform uses the platform's AI (included in subscription).
	AIModePlatform AIMode = "platform"
	// AIModeBYOK means tenant brings their own API key.
	AIModeBYOK AIMode = "byok"
	// AIModeAgent means tenant uses a self-hosted AI agent.
	AIModeAgent AIMode = "agent"
)

// IsValid checks if the AI mode is valid.
func (m AIMode) IsValid() bool {
	switch m {
	case AIModeDisabled, AIModePlatform, AIModeBYOK, AIModeAgent:
		return true
	}
	return false
}

// LLMProvider represents supported LLM providers.
type LLMProvider string

const (
	LLMProviderClaude      LLMProvider = "claude"
	LLMProviderOpenAI      LLMProvider = "openai"
	LLMProviderAzureOpenAI LLMProvider = "azure_openai"
	LLMProviderGemini      LLMProvider = "gemini"
)

// IsValid checks if the LLM provider is valid.
func (p LLMProvider) IsValid() bool {
	switch p {
	case LLMProviderClaude, LLMProviderOpenAI, LLMProviderAzureOpenAI, LLMProviderGemini:
		return true
	}
	return false
}

// AISettings contains AI/LLM configuration for the tenant.
type AISettings struct {
	// Mode determines how AI is used: disabled, platform, or byok
	Mode AIMode `json:"mode"`

	// BYOK (Bring Your Own Key) Configuration - only used when Mode = "byok"
	Provider      LLMProvider `json:"provider,omitempty"`       // claude, openai, azure_openai
	APIKey        string      `json:"api_key,omitempty"`        // Encrypted API key (set via special endpoint)
	AzureEndpoint string      `json:"azure_endpoint,omitempty"` // For Azure OpenAI
	ModelOverride string      `json:"model_override,omitempty"` // Optional model preference

	// Auto-Triage Configuration
	AutoTriageEnabled      bool     `json:"auto_triage_enabled"`              // Enable auto-triage on new findings
	AutoTriageSeverities   []string `json:"auto_triage_severities,omitempty"` // Severities to auto-triage: critical, high, etc.
	AutoTriageDelaySeconds int      `json:"auto_triage_delay_seconds"`        // Delay before auto-triage (for dedup)

	// Usage Limits
	MonthlyTokenLimit   int `json:"monthly_token_limit,omitempty"` // Optional cost control (0 = unlimited)
	TokensUsedThisMonth int `json:"tokens_used_this_month"`        // Tracked internally
}

// =============================================================================
// Default Settings
// =============================================================================

// DefaultSettings returns the default settings for a new tenant.
func DefaultSettings() Settings {
	return Settings{
		General: GeneralSettings{
			Timezone: "UTC",
			Language: "en",
			Industry: "",
			Website:  "",
		},
		Security: SecuritySettings{
			SSOEnabled:        false,
			SSOProvider:       "",
			SSOConfigURL:      "",
			MFARequired:       false,
			SessionTimeoutMin: 60, // 1 hour default
			IPWhitelist:       []string{},
			AllowedDomains:    []string{},
		},
		API: APISettings{
			APIKeyEnabled: false,
			WebhookURL:    "",
			WebhookSecret: "",
			WebhookEvents: []WebhookEvent{},
		},
		Branding: BrandingSettings{
			PrimaryColor: "#3B82F6", // Blue
			LogoDarkURL:  "",
		},
		AI: AISettings{
			Mode:                   AIModePlatform, // Use platform AI by default
			AutoTriageEnabled:      false,          // Disabled by default
			AutoTriageSeverities:   []string{"critical", "high"},
			AutoTriageDelaySeconds: 60,
		},
	}
}

// =============================================================================
// Settings Validation
// =============================================================================

// Validate validates the settings.
func (s *Settings) Validate() error {
	if err := s.General.Validate(); err != nil {
		return fmt.Errorf("general settings: %w", err)
	}
	if err := s.Security.Validate(); err != nil {
		return fmt.Errorf("security settings: %w", err)
	}
	if err := s.API.Validate(); err != nil {
		return fmt.Errorf("api settings: %w", err)
	}
	if err := s.Branding.Validate(); err != nil {
		return fmt.Errorf("branding settings: %w", err)
	}
	if err := s.Branch.Validate(); err != nil {
		return fmt.Errorf("branch settings: %w", err)
	}
	if err := s.AI.Validate(); err != nil {
		return fmt.Errorf("ai settings: %w", err)
	}
	return nil
}

// Validate validates branch settings.
func (s *BranchSettings) Validate() error {
	if len(s.TypeRules) > 0 {
		return s.TypeRules.Validate()
	}
	return nil
}

// Validate validates general settings.
func (s *GeneralSettings) Validate() error {
	// Validate timezone
	if s.Timezone != "" && !isValidTimezone(s.Timezone) {
		return fmt.Errorf("%w: invalid timezone", shared.ErrValidation)
	}
	// Validate language
	if s.Language != "" && !isValidLanguage(s.Language) {
		return fmt.Errorf("%w: invalid language", shared.ErrValidation)
	}
	// Validate website URL
	if s.Website != "" {
		if _, err := url.ParseRequestURI(s.Website); err != nil {
			return fmt.Errorf("%w: invalid website URL", shared.ErrValidation)
		}
	}
	return nil
}

// Validate validates security settings.
func (s *SecuritySettings) Validate() error {
	// Validate session timeout
	if s.SessionTimeoutMin < 15 || s.SessionTimeoutMin > 480 {
		if s.SessionTimeoutMin != 0 { // Allow 0 for default
			return fmt.Errorf("%w: session timeout must be between 15 and 480 minutes", shared.ErrValidation)
		}
	}
	// Validate IP whitelist
	for _, ip := range s.IPWhitelist {
		if !isValidIPOrCIDR(ip) {
			return fmt.Errorf("%w: invalid IP address or CIDR: %s", shared.ErrValidation, ip)
		}
	}
	// Validate SSO config URL
	if s.SSOEnabled && s.SSOConfigURL != "" {
		if _, err := url.ParseRequestURI(s.SSOConfigURL); err != nil {
			return fmt.Errorf("%w: invalid SSO config URL", shared.ErrValidation)
		}
	}
	// Validate allowed domains
	for _, domain := range s.AllowedDomains {
		if !isValidDomain(domain) {
			return fmt.Errorf("%w: invalid domain: %s", shared.ErrValidation, domain)
		}
	}
	return nil
}

// Validate validates API settings.
func (s *APISettings) Validate() error {
	// Validate webhook URL
	if s.WebhookURL != "" {
		if _, err := url.ParseRequestURI(s.WebhookURL); err != nil {
			return fmt.Errorf("%w: invalid webhook URL", shared.ErrValidation)
		}
	}
	// Validate webhook events
	for _, event := range s.WebhookEvents {
		if !event.IsValid() {
			return fmt.Errorf("%w: invalid webhook event: %s", shared.ErrValidation, event)
		}
	}
	return nil
}

// Validate validates branding settings.
func (s *BrandingSettings) Validate() error {
	// Validate primary color (hex format)
	if s.PrimaryColor != "" && !isValidHexColor(s.PrimaryColor) {
		return fmt.Errorf("%w: invalid primary color (use hex format, e.g., #3B82F6)", shared.ErrValidation)
	}
	// Validate logo dark URL
	if s.LogoDarkURL != "" {
		if _, err := url.ParseRequestURI(s.LogoDarkURL); err != nil {
			return fmt.Errorf("%w: invalid logo dark URL", shared.ErrValidation)
		}
	}
	// Validate logo data (base64)
	if s.LogoData != "" {
		if err := validateLogoData(s.LogoData); err != nil {
			return err
		}
	}
	return nil
}

// Validate validates AI settings.
func (s *AISettings) Validate() error {
	// Validate mode
	if s.Mode != "" && !s.Mode.IsValid() {
		return fmt.Errorf("%w: invalid AI mode", shared.ErrValidation)
	}

	// BYOK-specific validation
	if s.Mode == AIModeBYOK {
		if s.Provider == "" {
			return fmt.Errorf("%w: provider is required for BYOK mode", shared.ErrValidation)
		}
		if !s.Provider.IsValid() {
			return fmt.Errorf("%w: invalid LLM provider", shared.ErrValidation)
		}
		// API key validation is done separately (encrypted storage)
		if s.Provider == LLMProviderAzureOpenAI && s.AzureEndpoint == "" {
			return fmt.Errorf("%w: azure_endpoint is required for Azure OpenAI", shared.ErrValidation)
		}
		if s.AzureEndpoint != "" {
			if _, err := url.ParseRequestURI(s.AzureEndpoint); err != nil {
				return fmt.Errorf("%w: invalid Azure endpoint URL", shared.ErrValidation)
			}
		}
	}

	// Validate auto-triage severities
	validSeverities := map[string]bool{
		"critical": true, "high": true, "medium": true, "low": true, "info": true,
	}
	for _, sev := range s.AutoTriageSeverities {
		if !validSeverities[sev] {
			return fmt.Errorf("%w: invalid severity: %s", shared.ErrValidation, sev)
		}
	}

	// Validate delay
	if s.AutoTriageDelaySeconds < 0 {
		return fmt.Errorf("%w: auto_triage_delay_seconds must be non-negative", shared.ErrValidation)
	}

	// Validate token limit
	if s.MonthlyTokenLimit < 0 {
		return fmt.Errorf("%w: monthly_token_limit must be non-negative", shared.ErrValidation)
	}

	return nil
}

// =============================================================================
// Conversion Helpers
// =============================================================================

// ToMap converts Settings to map[string]any for storage.
func (s *Settings) ToMap() map[string]any {
	data, _ := json.Marshal(s)
	var result map[string]any
	_ = json.Unmarshal(data, &result)
	return result
}

// SettingsFromMap converts map[string]any to Settings.
func SettingsFromMap(m map[string]any) Settings {
	if m == nil {
		return DefaultSettings()
	}
	data, _ := json.Marshal(m)
	var settings Settings
	if err := json.Unmarshal(data, &settings); err != nil {
		return DefaultSettings()
	}
	return settings
}

// =============================================================================
// Validation Helpers
// =============================================================================

// Valid timezones (simplified list - in production, use time.LoadLocation)
var validTimezones = map[string]bool{
	"UTC":                 true,
	"Asia/Ho_Chi_Minh":    true,
	"Asia/Bangkok":        true,
	"Asia/Singapore":      true,
	"Asia/Tokyo":          true,
	"Asia/Seoul":          true,
	"Asia/Shanghai":       true,
	"Asia/Hong_Kong":      true,
	"Europe/London":       true,
	"Europe/Paris":        true,
	"Europe/Berlin":       true,
	"America/New_York":    true,
	"America/Los_Angeles": true,
	"America/Chicago":     true,
	"Australia/Sydney":    true,
}

func isValidTimezone(tz string) bool {
	return validTimezones[tz]
}

// Valid languages
var validLanguages = map[string]bool{
	"en": true,
	"vi": true,
	"ja": true,
	"ko": true,
	"zh": true,
}

func isValidLanguage(lang string) bool {
	return validLanguages[lang]
}

func isValidIPOrCIDR(s string) bool {
	// Try parsing as CIDR
	if _, _, err := net.ParseCIDR(s); err == nil {
		return true
	}
	// Try parsing as IP
	if ip := net.ParseIP(s); ip != nil {
		return true
	}
	return false
}

func isValidDomain(domain string) bool {
	// Simple domain validation
	if len(domain) < 3 || len(domain) > 253 {
		return false
	}
	// Must contain at least one dot
	if !strings.Contains(domain, ".") {
		return false
	}
	// No spaces or special characters
	for _, c := range domain {
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '.' || c == '-') {
			return false
		}
	}
	return true
}

func isValidHexColor(color string) bool {
	if len(color) != 7 || color[0] != '#' {
		return false
	}
	for _, c := range color[1:] {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

// validateLogoData validates base64 logo data.
// Max size: 150KB (after base64 encoding ~200KB string)
// Allowed formats: image/jpeg, image/png, image/webp
func validateLogoData(data string) error {
	// Check for data URL prefix
	if !strings.HasPrefix(data, "data:image/") {
		return fmt.Errorf("%w: logo must be a data URL (data:image/...)", shared.ErrValidation)
	}

	// Check allowed formats
	validPrefixes := []string{
		"data:image/jpeg;base64,",
		"data:image/jpg;base64,",
		"data:image/png;base64,",
		"data:image/webp;base64,",
	}

	hasValidPrefix := false
	for _, prefix := range validPrefixes {
		if strings.HasPrefix(data, prefix) {
			hasValidPrefix = true
			break
		}
	}
	if !hasValidPrefix {
		return fmt.Errorf("%w: logo must be JPEG, PNG, or WebP format", shared.ErrValidation)
	}

	// Check size (base64 encoded string length)
	// 150KB binary = ~200KB base64
	maxLen := 200 * 1024 // 200KB
	if len(data) > maxLen {
		return fmt.Errorf("%w: logo too large (max 150KB)", shared.ErrValidation)
	}

	return nil
}

// =============================================================================
// Tenant Settings Methods
// =============================================================================

// TypedSettings returns the settings as a typed Settings struct.
func (t *Tenant) TypedSettings() Settings {
	return SettingsFromMap(t.settings)
}

// UpdateSettings updates the tenant settings with a typed Settings struct.
func (t *Tenant) UpdateSettings(settings Settings) error {
	if err := settings.Validate(); err != nil {
		return err
	}
	t.settings = settings.ToMap()
	t.updatedAt = time.Now().UTC()
	return nil
}

// UpdateGeneralSettings updates only the general settings.
func (t *Tenant) UpdateGeneralSettings(general GeneralSettings) error {
	if err := general.Validate(); err != nil {
		return err
	}
	settings := t.TypedSettings()
	settings.General = general
	return t.UpdateSettings(settings)
}

// UpdateSecuritySettings updates only the security settings.
func (t *Tenant) UpdateSecuritySettings(security SecuritySettings) error {
	if err := security.Validate(); err != nil {
		return err
	}
	settings := t.TypedSettings()
	settings.Security = security
	return t.UpdateSettings(settings)
}

// UpdateAPISettings updates only the API settings.
func (t *Tenant) UpdateAPISettings(api APISettings) error {
	if err := api.Validate(); err != nil {
		return err
	}
	settings := t.TypedSettings()
	settings.API = api
	return t.UpdateSettings(settings)
}

// UpdateBrandingSettings updates only the branding settings.
func (t *Tenant) UpdateBrandingSettings(branding BrandingSettings) error {
	if err := branding.Validate(); err != nil {
		return err
	}
	settings := t.TypedSettings()
	settings.Branding = branding
	return t.UpdateSettings(settings)
}

// UpdateBranchSettings updates only the branch naming convention settings.
func (t *Tenant) UpdateBranchSettings(bs BranchSettings) error {
	if err := bs.Validate(); err != nil {
		return err
	}
	settings := t.TypedSettings()
	settings.Branch = bs
	return t.UpdateSettings(settings)
}

// UpdateAISettings updates only the AI settings.
func (t *Tenant) UpdateAISettings(ai AISettings) error {
	if err := ai.Validate(); err != nil {
		return err
	}
	settings := t.TypedSettings()
	settings.AI = ai
	return t.UpdateSettings(settings)
}

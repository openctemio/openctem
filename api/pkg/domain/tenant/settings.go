package tenant

import (
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/branch"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// =============================================================================
// Tenant Settings - Typed settings for tenant configuration
// =============================================================================

// Settings represents the typed settings for a tenant.
type Settings struct {
	General        GeneralSettings        `json:"general"`
	Security       SecuritySettings       `json:"security"`
	Branding       BrandingSettings       `json:"branding"`
	Branch         BranchSettings         `json:"branch"`
	AI             AISettings             `json:"ai"`
	RiskScoring    RiskScoringSettings    `json:"risk_scoring"`
	Pentest        PentestSettings        `json:"pentest"`
	AssetIdentity  AssetIdentitySettings  `json:"asset_identity"`
	AssetLifecycle AssetLifecycleSettings `json:"asset_lifecycle"`
	Retest         RetestSettings         `json:"retest"`
	// Evidence is finding evidence retention (docs/architecture/finding-evidence.md).
	Evidence EvidenceSettings `json:"evidence,omitempty"`
	// EASM is attack-surface monitoring (research/22 P0-11).
	EASM EASMSettings `json:"easm,omitempty"`
	// Scope is the organization's scope knobs (RFC-054 §6.3).
	Scope ScopeSettings `json:"scope,omitempty"`
	// MCP is the policy for AI applications on the MCP server (RFC-062 §8).
	MCP MCPSettings `json:"mcp,omitempty"`
	// VulnMatching is the policy of inventory vulnerability matching (RFC-066 §9).
	VulnMatching VulnMatchingSettings `json:"vuln_matching,omitempty"`

	// SubscribedBundles is the set of product-bundle IDs the tenant runs
	// (e.g. ["asm","aspm"]). Empty = no subscription = every module on (the
	// backward-compatible default). When non-empty, the module service
	// resolves the enabled set live as the union of these bundles (+core+
	// mandatory+deps), with per-module tenant_modules overrides layered on top.
	SubscribedBundles []string `json:"subscribed_bundles,omitempty"`
}

// AssetIdentitySettings controls asset dedup behavior per tenant.
// RFC-001: Asset Identity Resolution & Deduplication.
type AssetIdentitySettings struct {
	// StaleAssetDays is the IP trust window: an IP match with an existing asset
	// counts only when that asset was seen within this many days. Outside it,
	// an incoming asset with a different name is not merged or renamed. This
	// prevents false merges due to IP reuse (DHCP).
	// 0 = use system default (7 days).
	StaleAssetDays int `json:"stale_asset_days,omitempty"`

	// MaxIPsPerAsset limits the number of IPs stored per asset.
	// Assets with more IPs than this skip IP correlation (prevents DoS).
	// 0 = use system default (20).
	MaxIPsPerAsset int `json:"max_ips_per_asset,omitempty"`
}

// EffectiveStaleAssetDays returns the stale threshold, falling back to system default.
func (s AssetIdentitySettings) EffectiveStaleAssetDays(systemDefault int) int {
	if s.StaleAssetDays > 0 {
		return s.StaleAssetDays
	}
	return systemDefault
}

// EffectiveMaxIPsPerAsset returns the max IPs limit, falling back to system default.
func (s AssetIdentitySettings) EffectiveMaxIPsPerAsset(systemDefault int) int {
	if s.MaxIPsPerAsset > 0 {
		return s.MaxIPsPerAsset
	}
	return systemDefault
}

// BranchSettings contains branch naming convention configuration.
// When TypeRules is nil or empty, system defaults are used.
type BranchSettings struct {
	// TypeRules defines custom prefix/exact-match rules for branch type detection.
	// Rules are ordered; first match wins. If no rule matches, falls through
	// to system defaults (feature/, release/, hotfix/, main, master, etc.).
	TypeRules branch.BranchTypeRules `json:"type_rules,omitempty"`
}

// PentestSettings holds pentest-related configuration per tenant.
//
// A nil list means "never configured" (clients show their built-in
// defaults); an empty, non-nil list means the organization cleared it on
// purpose. The fields therefore have no omitempty: with it, a cleared list was
// dropped on save and came back as the defaults on the next read.
type PentestSettings struct {
	CampaignTypes []ConfigOption `json:"campaign_types"`
	Methodologies []ConfigOption `json:"methodologies"`
}

// ConfigOption represents a configurable option with value and label.
type ConfigOption struct {
	Value string `json:"value"`
	Label string `json:"label"`
}

// Validate validates pentest settings.
func (s *PentestSettings) Validate() error {
	seen := make(map[string]bool, len(s.CampaignTypes))
	for _, ct := range s.CampaignTypes {
		if ct.Value == "" {
			return fmt.Errorf("%w: campaign type value cannot be empty", shared.ErrValidation)
		}
		if ct.Label == "" {
			return fmt.Errorf("%w: campaign type label cannot be empty", shared.ErrValidation)
		}
		if seen[ct.Value] {
			return fmt.Errorf("%w: duplicate campaign type value: %s", shared.ErrValidation, ct.Value)
		}
		seen[ct.Value] = true
	}

	seen = make(map[string]bool, len(s.Methodologies))
	for _, m := range s.Methodologies {
		if m.Value == "" {
			return fmt.Errorf("%w: methodology value cannot be empty", shared.ErrValidation)
		}
		if m.Label == "" {
			return fmt.Errorf("%w: methodology label cannot be empty", shared.ErrValidation)
		}
		if seen[m.Value] {
			return fmt.Errorf("%w: duplicate methodology value: %s", shared.ErrValidation, m.Value)
		}
		seen[m.Value] = true
	}

	return nil
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
	// SSO itself is configured per organization by the platform administrator
	// (SAML / identity providers, RFC-022). The old sso_enabled / sso_provider /
	// sso_config_url flags were written here but never read by the login path,
	// so they were removed; stale keys in stored JSON are ignored.
	// SSOEnforced requires members of this tenant to authenticate via SSO — a
	// local password login is refused access to this tenant. The tenant OWNER is
	// the break-glass exception and can ALWAYS password-login, so enabling this
	// can never lock every administrator out. It may only be enabled when the
	// tenant has a usable SSO path (an active identity provider or the opted-in
	// env fallback); see TenantService.UpdateSecuritySettings. Enforcement itself
	// lives in AuthService.ExchangeToken / RefreshToken (the tenant-selection /
	// token-mint gate).
	SSOEnforced bool `json:"sso_enforced"`
	MFARequired bool `json:"mfa_required"` // Require MFA for all users
	// MFARequiredForAdmins requires two-factor authentication for owners and
	// administrators (the people who can change the organization). On for
	// every organization created after it shipped (NewTenant); organizations
	// created before keep their stored value (off) until an owner turns it
	// on. MFARequired, when on, covers everyone anyway.
	MFARequiredForAdmins bool     `json:"mfa_required_for_admins,omitempty"`
	SessionTimeoutMin    int      `json:"session_timeout_min"` // Session timeout in minutes (15-480)
	IPWhitelist          []string `json:"ip_whitelist"`        // Allowed IP addresses/CIDR ranges
	AllowedDomains       []string `json:"allowed_domains"`     // Allowed email domains for signup

	// PersonalAccounts says whether members with a personal address may use
	// the organization (RFC-058): allowed (empty), allowed_with_mfa (the
	// default for new organizations) or blocked.
	PersonalAccounts PersonalAccountsPolicy `json:"personal_accounts,omitempty"`
	// SSOExceptions lets named members sign in without SSO (with a second
	// factor) while SSO is enforced, each with a reason and an end at most
	// MaxSSOExceptionDays away. Changed by an owner with step-up.
	SSOExceptions []SSOException `json:"sso_exceptions,omitempty"`
	// JITRequiresApproval holds everyone the organization's SSO admits for
	// the first time until an administrator approves them (RFC-058).
	// Changed by an owner with step-up.
	JITRequiresApproval bool `json:"jit_requires_approval,omitempty"`

	// A restricted_data_scope key left in stored JSON is ignored: members
	// without a scope row see nothing in every organization (owner decision
	// D2), there is no data-scope setting.

	// EmailVerificationMode controls whether new users must verify their email.
	//   "auto"   = (default) require verification IFF SMTP is configured (smart)
	//   "always" = always require verification (operator must configure SMTP)
	//   "never"  = never require verification (open registration; security risk)
	EmailVerificationMode EmailVerificationMode `json:"email_verification_mode,omitempty"`

	// RequireSensorLocalPolicyForPrivateTargets keeps jobs with private
	// targets (RFC 1918, ULA, link-local, CGNAT, private DNS suffixes) away
	// from sensors that report no enforced local policy (RFC-040 §5.7, owner
	// decision Q3 (a)): such sensors neither see nor can claim them, and the
	// jobs wait for a sensor whose network owner installed a policy. Off by
	// default: sensors without a policy work as before.
	RequireSensorLocalPolicyForPrivateTargets bool `json:"require_sensor_local_policy_for_private_targets,omitempty"`

	// AllowSensorInteractsh and AllowSensorCustomTemplates are the
	// organization's switches for out-of-band callbacks (interactsh) and
	// custom templates in sensor jobs (research/25 D3). Off by default, for
	// existing and new organizations: the platform then refuses scans that
	// ask for them, strips allow_interactsh at trigger and never dispatches
	// such a job, whatever the sensor's own policy allows. Turning one on is
	// an owner action, audited at critical severity and alerted (D9).
	AllowSensorInteractsh      bool `json:"allow_sensor_interactsh,omitempty"`
	AllowSensorCustomTemplates bool `json:"allow_sensor_custom_templates,omitempty"`

	// ToolHTTPUserAgent and ForbidToolInsecureTLS are the organization's
	// layer of the tools' HTTP settings (api RFC-060 §4.1): a User-Agent its
	// sensors' tools send unless a sensor's local policy forces one, and a
	// refusal of tools that skip TLS verification toward targets. Sent with
	// every scan job; they only narrow (a sensor's local policy decides
	// first).
	ToolHTTPUserAgent     string `json:"tool_http_user_agent,omitempty"`
	ForbidToolInsecureTLS bool   `json:"forbid_tool_insecure_tls,omitempty"`
}

// ToolHTTPPolicy is the organization's tool HTTP layer for sensor jobs.
func (s *SecuritySettings) ToolHTTPPolicy() sensorHTTPPolicy {
	p := sensorHTTPPolicy{UserAgent: s.ToolHTTPUserAgent}
	if s.ForbidToolInsecureTLS {
		f := false
		p.AllowInsecureTLS = &f
	}
	return p
}

// sensorHTTPPolicy mirrors sensor.ToolHTTPPolicy (the tenant domain does not
// import the sensor domain); the tenant service converts it.
type sensorHTTPPolicy struct {
	UserAgent        string
	AllowInsecureTLS *bool
}

// MFARequiredFor reports whether a member with this role must use two-factor
// authentication in the organization.
func (s SecuritySettings) MFARequiredFor(role string) bool {
	if s.MFARequired {
		return true
	}
	if !s.MFARequiredForAdmins {
		return false
	}
	switch Role(role) {
	case RoleOwner, RoleAdmin:
		return true
	}
	return false
}

// EmailVerificationMode controls per-tenant email verification behavior.
type EmailVerificationMode string

const (
	// EmailVerificationAuto requires verification only when SMTP is configured.
	// This is the default and prevents the chicken-and-egg problem where a new
	// deployment can't register users because no SMTP is set up yet.
	EmailVerificationAuto EmailVerificationMode = "auto"
	// EmailVerificationAlways forces verification regardless of SMTP availability.
	// If SMTP is not configured, registered users will be unable to verify and
	// thus unable to log in — operator must configure SMTP first.
	EmailVerificationAlways EmailVerificationMode = "always"
	// EmailVerificationNever skips verification for all users in this tenant.
	// Use only for closed/internal deployments. Opens the door to account
	// hijacking via email spoofing.
	EmailVerificationNever EmailVerificationMode = "never"
)

// IsValid reports whether the mode is one of the allowed values.
func (m EmailVerificationMode) IsValid() bool {
	switch m {
	case EmailVerificationAuto, EmailVerificationAlways, EmailVerificationNever, "":
		return true
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
// Risk Scoring Settings
// =============================================================================

// Score composition modes control how the exposure multiplier is combined with
// the weighted raw score. These mirror the constants in pkg/domain/asset and are
// duplicated here to keep the tenant domain free of an asset import.
const (
	// ScoreCompositionMultiply is the historical behavior (final = raw × multiplier).
	// Default; kept byte-identical for risk-trend continuity.
	ScoreCompositionMultiply = "multiply"
	// ScoreCompositionAmplifyHeadroom de-saturates the top of the range by filling
	// remaining headroom rather than overflowing past 100 (opt-in).
	ScoreCompositionAmplifyHeadroom = "amplify_headroom"
)

// RiskScoringSettings configures the risk scoring formula per tenant.
type RiskScoringSettings struct {
	Preset              string                   `json:"preset,omitempty"`
	Weights             ComponentWeights         `json:"weights"`
	ExposureScores      ExposureScoreConfig      `json:"exposure_scores"`
	ExposureMultipliers ExposureMultiplierConfig `json:"exposure_multipliers"`
	CriticalityScores   CriticalityScoreConfig   `json:"criticality_scores"`
	FindingImpact       FindingImpactConfig      `json:"finding_impact"`
	CTEMPoints          CTEMPointsConfig         `json:"ctem_points"`
	RiskLevels          RiskLevelConfig          `json:"risk_levels"`

	// ScoreCompositionMode selects how the exposure multiplier composes with the
	// weighted raw score: "multiply" (default) or "amplify_headroom". Empty / unset
	// resolves to "multiply" so pre-existing tenant settings are unchanged.
	ScoreCompositionMode string `json:"score_composition_mode,omitempty"`

	// FloorUnownedAtP2 opts the tenant into the CTEM "ownership unknown defaults to
	// P2 minimum" rule for finding priority: a finding on an asset with NO assigned
	// owner is never classified below P2 (an unowned finding cannot be safely
	// deprioritized). It is a strict FLOOR — it only ever raises a P3 to P2, never
	// lowers anything and never touches P0/P1/P2.
	//
	// Default false (opt-in): existing tenants see NO change, and tenants with poor
	// ownership hygiene early on aren't flooded with an inflated P2 backlog. Toggle
	// it via PATCH /settings/risk-scoring. When false the classifier does not even
	// look up owner presence, so there is zero behavior or cost change.
	FloorUnownedAtP2 bool `json:"floor_unowned_at_p2,omitempty"`
}

type ComponentWeights struct {
	Exposure    int `json:"exposure"`
	Criticality int `json:"criticality"`
	Findings    int `json:"findings"`
	CTEM        int `json:"ctem"`
}

type ExposureScoreConfig struct {
	Public     int `json:"public"`
	Restricted int `json:"restricted"`
	Private    int `json:"private"`
	Isolated   int `json:"isolated"`
	Unknown    int `json:"unknown"`
}

type ExposureMultiplierConfig struct {
	Public     float64 `json:"public"`
	Restricted float64 `json:"restricted"`
	Private    float64 `json:"private"`
	Isolated   float64 `json:"isolated"`
	Unknown    float64 `json:"unknown"`
}

type CriticalityScoreConfig struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	None     int `json:"none"`
}

type FindingImpactConfig struct {
	Mode             string               `json:"mode"`
	PerFindingPoints int                  `json:"per_finding_points"`
	FindingCap       int                  `json:"finding_cap"`
	SeverityWeights  SeverityWeightConfig `json:"severity_weights"`
}

type SeverityWeightConfig struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	Info     int `json:"info"`
}

type CTEMPointsConfig struct {
	Enabled            bool `json:"enabled"`
	InternetAccessible int  `json:"internet_accessible"`
	PIIExposed         int  `json:"pii_exposed"`
	PHIExposed         int  `json:"phi_exposed"`
	HighRiskCompliance int  `json:"high_risk_compliance"`
	RestrictedData     int  `json:"restricted_data"`
}

type RiskLevelConfig struct {
	CriticalMin int `json:"critical_min"`
	HighMin     int `json:"high_min"`
	MediumMin   int `json:"medium_min"`
	LowMin      int `json:"low_min"`
}

// LegacyRiskScoringSettings returns settings that reproduce the exact current
// hardcoded risk scoring formula for backward compatibility.
func LegacyRiskScoringSettings() RiskScoringSettings {
	return RiskScoringSettings{
		Preset: "legacy",
		Weights: ComponentWeights{
			Exposure: 40, Criticality: 25, Findings: 35, CTEM: 0,
		},
		ExposureScores: ExposureScoreConfig{
			Public: 100, Restricted: 62, Private: 37, Isolated: 12, Unknown: 50,
		},
		ExposureMultipliers: ExposureMultiplierConfig{
			Public: 1.5, Restricted: 1.2, Private: 1.0, Isolated: 0.8, Unknown: 1.0,
		},
		CriticalityScores: CriticalityScoreConfig{
			Critical: 100, High: 72, Medium: 48, Low: 24, None: 0,
		},
		FindingImpact: FindingImpactConfig{
			Mode:             "count",
			PerFindingPoints: 14,
			FindingCap:       100,
			SeverityWeights: SeverityWeightConfig{
				Critical: 20, High: 10, Medium: 5, Low: 2, Info: 1,
			},
		},
		CTEMPoints: CTEMPointsConfig{Enabled: false},
		RiskLevels: RiskLevelConfig{
			CriticalMin: 80, HighMin: 60, MediumMin: 40, LowMin: 20,
		},
		ScoreCompositionMode: ScoreCompositionMultiply,
	}
}

// DefaultRiskScoringPreset returns the recommended risk scoring settings
// for new tenants who opt-in to configurable risk scoring.
func DefaultRiskScoringPreset() RiskScoringSettings {
	return RiskScoringSettings{
		Preset: "default",
		Weights: ComponentWeights{
			Exposure: 35, Criticality: 25, Findings: 30, CTEM: 10,
		},
		ExposureScores: ExposureScoreConfig{
			Public: 80, Restricted: 50, Private: 30, Isolated: 10, Unknown: 40,
		},
		ExposureMultipliers: ExposureMultiplierConfig{
			Public: 1.3, Restricted: 1.1, Private: 1.0, Isolated: 0.9, Unknown: 1.0,
		},
		CriticalityScores: CriticalityScoreConfig{
			Critical: 100, High: 75, Medium: 50, Low: 25, None: 0,
		},
		FindingImpact: FindingImpactConfig{
			Mode:             "severity_weighted",
			PerFindingPoints: 5,
			FindingCap:       100,
			SeverityWeights: SeverityWeightConfig{
				Critical: 20, High: 10, Medium: 5, Low: 2, Info: 1,
			},
		},
		CTEMPoints: CTEMPointsConfig{
			Enabled:            false,
			InternetAccessible: 30,
			PIIExposed:         20,
			PHIExposed:         25,
			HighRiskCompliance: 15,
			RestrictedData:     20,
		},
		RiskLevels: RiskLevelConfig{
			CriticalMin: 80, HighMin: 60, MediumMin: 40, LowMin: 20,
		},
		ScoreCompositionMode: ScoreCompositionMultiply,
	}
}

// AllRiskScoringPresets contains all available risk scoring presets.
var AllRiskScoringPresets = map[string]RiskScoringSettings{
	"legacy":     LegacyRiskScoringSettings(),
	"default":    DefaultRiskScoringPreset(),
	"banking":    bankingRiskScoringPreset(),
	"healthcare": healthcareRiskScoringPreset(),
	"ecommerce":  ecommerceRiskScoringPreset(),
	"government": governmentRiskScoringPreset(),
}

// RiskScoringPreset returns a preset by name.
func RiskScoringPreset(name string) (RiskScoringSettings, bool) {
	preset, ok := AllRiskScoringPresets[name]
	return preset, ok
}

func bankingRiskScoringPreset() RiskScoringSettings {
	base := DefaultRiskScoringPreset()
	base.Preset = "banking"
	base.Weights = ComponentWeights{Exposure: 25, Criticality: 30, Findings: 25, CTEM: 20}
	base.CTEMPoints.Enabled = true
	base.CTEMPoints.PIIExposed = 30
	base.CTEMPoints.HighRiskCompliance = 25
	base.FindingImpact.SeverityWeights.Critical = 25
	return base
}

func healthcareRiskScoringPreset() RiskScoringSettings {
	base := DefaultRiskScoringPreset()
	base.Preset = "healthcare"
	base.Weights = ComponentWeights{Exposure: 20, Criticality: 25, Findings: 25, CTEM: 30}
	base.CTEMPoints.Enabled = true
	base.CTEMPoints.PHIExposed = 40
	base.CTEMPoints.PIIExposed = 30
	base.CTEMPoints.HighRiskCompliance = 25
	return base
}

func ecommerceRiskScoringPreset() RiskScoringSettings {
	base := DefaultRiskScoringPreset()
	base.Preset = "ecommerce"
	base.Weights = ComponentWeights{Exposure: 40, Criticality: 20, Findings: 30, CTEM: 10}
	base.ExposureScores.Public = 90
	return base
}

func governmentRiskScoringPreset() RiskScoringSettings {
	base := DefaultRiskScoringPreset()
	base.Preset = "government"
	base.Weights = ComponentWeights{Exposure: 20, Criticality: 30, Findings: 20, CTEM: 30}
	base.CTEMPoints.Enabled = true
	base.CTEMPoints.RestrictedData = 35
	base.CTEMPoints.HighRiskCompliance = 30
	return base
}

// Validate validates the risk scoring settings.
func (s *RiskScoringSettings) Validate() error {
	sum := s.Weights.Exposure + s.Weights.Criticality + s.Weights.Findings + s.Weights.CTEM
	if sum != 100 {
		return fmt.Errorf("%w: component weights must sum to 100, got %d", shared.ErrValidation, sum)
	}
	for name, w := range map[string]int{
		"exposure": s.Weights.Exposure, "criticality": s.Weights.Criticality,
		"findings": s.Weights.Findings, "ctem": s.Weights.CTEM,
	} {
		if w < 0 || w > 100 {
			return fmt.Errorf("%w: weight '%s' must be 0-100, got %d", shared.ErrValidation, name, w)
		}
	}
	for name, v := range map[string]int{
		"public": s.ExposureScores.Public, "restricted": s.ExposureScores.Restricted,
		"private": s.ExposureScores.Private, "isolated": s.ExposureScores.Isolated,
		"unknown": s.ExposureScores.Unknown,
	} {
		if v < 0 || v > 100 {
			return fmt.Errorf("%w: exposure score '%s' must be 0-100", shared.ErrValidation, name)
		}
	}
	for name, v := range map[string]int{
		"critical": s.CriticalityScores.Critical, "high": s.CriticalityScores.High,
		"medium": s.CriticalityScores.Medium, "low": s.CriticalityScores.Low,
		"none": s.CriticalityScores.None,
	} {
		if v < 0 || v > 100 {
			return fmt.Errorf("%w: criticality score '%s' must be 0-100", shared.ErrValidation, name)
		}
	}
	for name, m := range map[string]float64{
		"public": s.ExposureMultipliers.Public, "restricted": s.ExposureMultipliers.Restricted,
		"private": s.ExposureMultipliers.Private, "isolated": s.ExposureMultipliers.Isolated,
		"unknown": s.ExposureMultipliers.Unknown,
	} {
		if m < 0.1 || m > 3.0 {
			return fmt.Errorf("%w: exposure multiplier '%s' must be 0.1-3.0", shared.ErrValidation, name)
		}
	}
	if s.FindingImpact.Mode != "count" && s.FindingImpact.Mode != "severity_weighted" {
		return fmt.Errorf("%w: finding impact mode must be 'count' or 'severity_weighted'", shared.ErrValidation)
	}
	if s.FindingImpact.FindingCap < 1 || s.FindingImpact.FindingCap > 100 {
		return fmt.Errorf("%w: finding_cap must be 1-100", shared.ErrValidation)
	}
	if s.FindingImpact.PerFindingPoints < 1 || s.FindingImpact.PerFindingPoints > 50 {
		return fmt.Errorf("%w: per_finding_points must be 1-50", shared.ErrValidation)
	}
	for name, w := range map[string]int{
		"critical": s.FindingImpact.SeverityWeights.Critical,
		"high":     s.FindingImpact.SeverityWeights.High,
		"medium":   s.FindingImpact.SeverityWeights.Medium,
		"low":      s.FindingImpact.SeverityWeights.Low,
		"info":     s.FindingImpact.SeverityWeights.Info,
	} {
		if w < 0 || w > 50 {
			return fmt.Errorf("%w: severity weight '%s' must be 0-50", shared.ErrValidation, name)
		}
	}
	if s.CTEMPoints.Enabled {
		for name, p := range map[string]int{
			"internet_accessible":  s.CTEMPoints.InternetAccessible,
			"pii_exposed":          s.CTEMPoints.PIIExposed,
			"phi_exposed":          s.CTEMPoints.PHIExposed,
			"high_risk_compliance": s.CTEMPoints.HighRiskCompliance,
			"restricted_data":      s.CTEMPoints.RestrictedData,
		} {
			if p < 0 || p > 100 {
				return fmt.Errorf("%w: CTEM points '%s' must be 0-100", shared.ErrValidation, name)
			}
		}
	}
	if !(s.RiskLevels.CriticalMin > s.RiskLevels.HighMin &&
		s.RiskLevels.HighMin > s.RiskLevels.MediumMin &&
		s.RiskLevels.MediumMin > s.RiskLevels.LowMin &&
		s.RiskLevels.LowMin > 0) {
		return fmt.Errorf("%w: risk levels must be ordered: critical > high > medium > low > 0", shared.ErrValidation)
	}
	if s.RiskLevels.CriticalMin > 100 || s.RiskLevels.LowMin < 1 {
		return fmt.Errorf("%w: risk levels must be between 1-100", shared.ErrValidation)
	}
	switch s.ScoreCompositionMode {
	case "", ScoreCompositionMultiply, ScoreCompositionAmplifyHeadroom:
		// "" resolves to multiply (backward compatible).
	default:
		return fmt.Errorf("%w: score_composition_mode must be 'multiply' or 'amplify_headroom'", shared.ErrValidation)
	}
	return nil
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
			MFARequired:           false,
			SessionTimeoutMin:     60, // 1 hour default
			IPWhitelist:           []string{},
			AllowedDomains:        []string{},
			EmailVerificationMode: EmailVerificationAuto, // Smart: require iff SMTP configured
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
		RiskScoring: LegacyRiskScoringSettings(),
		Pentest: PentestSettings{
			CampaignTypes: []ConfigOption{
				{Value: "external", Label: "External Pentest"},
				{Value: "internal", Label: "Internal Pentest"},
				{Value: "web_app", Label: "Web Application"},
				{Value: "mobile", Label: "Mobile Application"},
				{Value: "api", Label: "API Testing"},
				{Value: "network", Label: "Network Pentest"},
				{Value: "social_engineering", Label: "Social Engineering"},
				{Value: "physical", Label: "Physical Security"},
				{Value: "cloud", Label: "Cloud Infrastructure"},
				{Value: "wireless", Label: "Wireless Network"},
			},
			Methodologies: []ConfigOption{
				{Value: "OWASP", Label: "OWASP Testing Guide"},
				{Value: "PTES", Label: "PTES"},
				{Value: "NIST", Label: "NIST SP 800-115"},
				{Value: "OSSTMM", Label: "OSSTMM"},
				{Value: "CREST", Label: "CREST"},
			},
		},
		// New organizations get vulnerability matching on (RFC-066 O4);
		// organizations created before keep it off until an admin enables it.
		VulnMatching: VulnMatchingSettings{Enabled: true},
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
	if err := s.Branding.Validate(); err != nil {
		return fmt.Errorf("branding settings: %w", err)
	}
	if err := s.Branch.Validate(); err != nil {
		return fmt.Errorf("branch settings: %w", err)
	}
	if err := s.AI.Validate(); err != nil {
		return fmt.Errorf("ai settings: %w", err)
	}
	if err := s.RiskScoring.Validate(); err != nil {
		return fmt.Errorf("risk scoring settings: %w", err)
	}
	if err := s.Pentest.Validate(); err != nil {
		return fmt.Errorf("pentest settings: %w", err)
	}
	if err := s.AssetLifecycle.Validate(); err != nil {
		return fmt.Errorf("asset_lifecycle settings: %w", err)
	}
	if err := s.Retest.Validate(); err != nil {
		return fmt.Errorf("retest settings: %w", err)
	}
	if err := s.VulnMatching.Validate(); err != nil {
		return fmt.Errorf("vuln_matching settings: %w", err)
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
	if ua := s.ToolHTTPUserAgent; ua != "" && (len(ua) > 256 || strings.IndexFunc(ua, func(r rune) bool { return r < 0x20 || r > 0x7e }) >= 0) {
		return fmt.Errorf("%w: tool_http_user_agent must be at most 256 printable ASCII characters", shared.ErrValidation)
	}
	// Validate email verification mode
	if !s.EmailVerificationMode.IsValid() {
		return fmt.Errorf("%w: email_verification_mode must be one of: auto, always, never", shared.ErrValidation)
	}
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
	// Validate allowed domains
	for _, domain := range s.AllowedDomains {
		if !isValidDomain(domain) {
			return fmt.Errorf("%w: invalid domain: %s", shared.ErrValidation, domain)
		}
	}
	if !s.PersonalAccounts.IsValid() {
		return fmt.Errorf("%w: personal_accounts must be one of: allowed, allowed_with_mfa, blocked", shared.ErrValidation)
	}
	if len(s.SSOExceptions) > 100 {
		return fmt.Errorf("%w: at most 100 sso exceptions", shared.ErrValidation)
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
//
// Each section is decoded on its own (SettingsFromMapChecked): a section that
// cannot be decoded falls back to its default without affecting the others.
// Enforcement points that must fail closed on a corrupt security section use
// Tenant.SecuritySettingsStrict instead.
func SettingsFromMap(m map[string]any) Settings {
	settings, _ := SettingsFromMapChecked(m)
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

// UpdatePentestSettings updates only the pentest settings.
func (t *Tenant) UpdatePentestSettings(ps PentestSettings) error {
	if err := ps.Validate(); err != nil {
		return err
	}
	settings := t.TypedSettings()
	settings.Pentest = ps
	return t.UpdateSettings(settings)
}

// UpdateRiskScoringSettings updates only the risk scoring settings.
func (t *Tenant) UpdateRiskScoringSettings(rs RiskScoringSettings) error {
	if err := rs.Validate(); err != nil {
		return err
	}
	settings := t.TypedSettings()
	settings.RiskScoring = rs
	return t.UpdateSettings(settings)
}

// UpdateRetestSettings updates only the auto-retest settings (RFC-039).
// UpdateVulnMatchingSettings updates only the vulnerability matching policy.
func (t *Tenant) UpdateVulnMatchingSettings(vm VulnMatchingSettings) error {
	if err := vm.Validate(); err != nil {
		return err
	}
	settings := t.TypedSettings()
	settings.VulnMatching = vm
	return t.UpdateSettings(settings)
}

func (t *Tenant) UpdateRetestSettings(rs RetestSettings) error {
	if err := rs.Validate(); err != nil {
		return err
	}
	settings := t.TypedSettings()
	settings.Retest = rs
	return t.UpdateSettings(settings)
}

// UpdateAssetLifecycleSettings updates only the asset-lifecycle
// settings. The DryRunCompletedAt-before-Enabled guard lives in
// AssetLifecycleSettings.Validate; the service layer is responsible
// for stamping that timestamp after a successful dry-run, not this
// entity method.
func (t *Tenant) UpdateAssetLifecycleSettings(al AssetLifecycleSettings) error {
	if err := al.Validate(); err != nil {
		return err
	}
	settings := t.TypedSettings()
	settings.AssetLifecycle = al
	return t.UpdateSettings(settings)
}

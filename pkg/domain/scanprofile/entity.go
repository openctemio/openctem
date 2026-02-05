// Package scanprofile defines the ScanProfile domain entity for reusable scan configurations.
package scanprofile

import (
	"maps"
	"time"

	"github.com/openctemio/api/pkg/domain/shared"
)

// Intensity represents the scan intensity level.
type Intensity string

const (
	IntensityLow    Intensity = "low"    // Fast, less thorough
	IntensityMedium Intensity = "medium" // Balanced
	IntensityHigh   Intensity = "high"   // Slow, comprehensive
)

// IsValid checks if the intensity is valid.
func (i Intensity) IsValid() bool {
	switch i {
	case IntensityLow, IntensityMedium, IntensityHigh:
		return true
	}
	return false
}

// Severity represents tool finding severity level.
type Severity string

const (
	SeverityInfo     Severity = "info"
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

// IsValid checks if the severity is valid.
func (s Severity) IsValid() bool {
	switch s {
	case SeverityInfo, SeverityLow, SeverityMedium, SeverityHigh, SeverityCritical:
		return true
	}
	return false
}

// TemplateMode represents the mode for using scanner templates.
type TemplateMode string

const (
	// TemplateModeDefault uses only the tool's built-in/official templates.
	TemplateModeDefault TemplateMode = "default"
	// TemplateModeCustom uses only tenant-uploaded custom templates.
	TemplateModeCustom TemplateMode = "custom"
	// TemplateModeBoth runs both default and custom templates together.
	TemplateModeBoth TemplateMode = "both"
)

// IsValid checks if the template mode is valid.
func (m TemplateMode) IsValid() bool {
	switch m {
	case TemplateModeDefault, TemplateModeCustom, TemplateModeBoth, "":
		return true
	}
	return false
}

// ToolConfig represents the configuration for a specific tool.
type ToolConfig struct {
	Enabled           bool           `json:"enabled"`
	Severity          string         `json:"severity,omitempty"`            // Minimum severity to report
	Timeout           int            `json:"timeout,omitempty"`             // Timeout in seconds
	Options           map[string]any `json:"options,omitempty"`             // Tool-specific options
	TemplateMode      TemplateMode   `json:"template_mode,omitempty"`       // "default", "custom", "both"
	CustomTemplateIDs []string       `json:"custom_template_ids,omitempty"` // IDs of custom templates to use
}

// QualityGate defines thresholds for CI/CD pass/fail decisions.
// When enabled, scan results are evaluated against these thresholds to determine
// if the scan passes quality requirements.
type QualityGate struct {
	Enabled         bool   `json:"enabled"`
	FailOnCritical  bool   `json:"fail_on_critical"`            // Fail immediately if any critical finding
	FailOnHigh      bool   `json:"fail_on_high"`                // Fail immediately if any high finding
	MaxCritical     int    `json:"max_critical"`                // Maximum allowed critical findings (-1 = unlimited)
	MaxHigh         int    `json:"max_high"`                    // Maximum allowed high findings (-1 = unlimited)
	MaxMedium       int    `json:"max_medium"`                  // Maximum allowed medium findings (-1 = unlimited)
	MaxTotal        int    `json:"max_total"`                   // Maximum allowed total findings (-1 = unlimited)
	NewFindingsOnly bool   `json:"new_findings_only,omitempty"` // Only count new findings (not in baseline)
	BaselineBranch  string `json:"baseline_branch,omitempty"`   // Branch to compare against for new findings
}

// NewQualityGate creates a QualityGate with default values (disabled).
func NewQualityGate() QualityGate {
	return QualityGate{
		Enabled:     false,
		MaxCritical: -1, // unlimited by default
		MaxHigh:     -1,
		MaxMedium:   -1,
		MaxTotal:    -1,
	}
}

// QualityGateResult represents the result of evaluating findings against a quality gate.
type QualityGateResult struct {
	Passed   bool          `json:"passed"`
	Reason   string        `json:"reason,omitempty"`
	Breaches []GateBreach  `json:"breaches,omitempty"`
	Counts   FindingCounts `json:"counts"`
}

// GateBreach represents a single threshold violation.
type GateBreach struct {
	Metric string `json:"metric"` // "critical", "high", "medium", "total"
	Limit  int    `json:"limit"`
	Actual int    `json:"actual"`
}

// FindingCounts holds the count of findings by severity.
type FindingCounts struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	Info     int `json:"info"`
	Total    int `json:"total"`
}

// Evaluate checks if the given finding counts pass the quality gate.
// Returns a QualityGateResult with pass/fail status and any breaches.
func (g *QualityGate) Evaluate(counts FindingCounts) *QualityGateResult {
	result := &QualityGateResult{
		Passed: true,
		Counts: counts,
	}

	if !g.Enabled {
		return result
	}

	// Check fail-on conditions (immediate failure)
	if g.FailOnCritical && counts.Critical > 0 {
		result.Passed = false
		result.Breaches = append(result.Breaches, GateBreach{
			Metric: "critical",
			Limit:  0,
			Actual: counts.Critical,
		})
	}

	if g.FailOnHigh && counts.High > 0 {
		result.Passed = false
		result.Breaches = append(result.Breaches, GateBreach{
			Metric: "high",
			Limit:  0,
			Actual: counts.High,
		})
	}

	// Check threshold limits (-1 = unlimited)
	if g.MaxCritical >= 0 && counts.Critical > g.MaxCritical {
		result.Passed = false
		result.Breaches = append(result.Breaches, GateBreach{
			Metric: "critical",
			Limit:  g.MaxCritical,
			Actual: counts.Critical,
		})
	}

	if g.MaxHigh >= 0 && counts.High > g.MaxHigh {
		result.Passed = false
		result.Breaches = append(result.Breaches, GateBreach{
			Metric: "high",
			Limit:  g.MaxHigh,
			Actual: counts.High,
		})
	}

	if g.MaxMedium >= 0 && counts.Medium > g.MaxMedium {
		result.Passed = false
		result.Breaches = append(result.Breaches, GateBreach{
			Metric: "medium",
			Limit:  g.MaxMedium,
			Actual: counts.Medium,
		})
	}

	if g.MaxTotal >= 0 && counts.Total > g.MaxTotal {
		result.Passed = false
		result.Breaches = append(result.Breaches, GateBreach{
			Metric: "total",
			Limit:  g.MaxTotal,
			Actual: counts.Total,
		})
	}

	// Set reason if failed
	if !result.Passed {
		result.Reason = "Quality gate thresholds exceeded"
	}

	return result
}

// ScanProfile represents a reusable scan configuration.
type ScanProfile struct {
	ID                 shared.ID
	TenantID           shared.ID
	Name               string
	Description        string
	IsDefault          bool
	IsSystem           bool
	ToolsConfig        map[string]ToolConfig
	Intensity          Intensity
	MaxConcurrentScans int
	TimeoutSeconds     int
	Tags               []string
	Metadata           map[string]any
	QualityGate        QualityGate // Quality gate thresholds for CI/CD pass/fail
	CreatedBy          *shared.ID
	CreatedAt          time.Time
	UpdatedAt          time.Time
}

// NewScanProfile creates a new ScanProfile entity.
func NewScanProfile(
	tenantID shared.ID,
	name string,
	description string,
	toolsConfig map[string]ToolConfig,
	intensity Intensity,
	createdBy *shared.ID,
) (*ScanProfile, error) {
	if name == "" {
		return nil, shared.NewDomainError("VALIDATION", "name is required", shared.ErrValidation)
	}

	if len(name) > 100 {
		return nil, shared.NewDomainError("VALIDATION", "name must be less than 100 characters", shared.ErrValidation)
	}

	if !intensity.IsValid() {
		intensity = IntensityMedium
	}

	if toolsConfig == nil {
		toolsConfig = make(map[string]ToolConfig)
	}

	now := time.Now()
	return &ScanProfile{
		ID:                 shared.NewID(),
		TenantID:           tenantID,
		Name:               name,
		Description:        description,
		IsDefault:          false,
		IsSystem:           false,
		ToolsConfig:        toolsConfig,
		Intensity:          intensity,
		MaxConcurrentScans: 5,
		TimeoutSeconds:     3600,
		Tags:               []string{},
		Metadata:           make(map[string]any),
		QualityGate:        NewQualityGate(),
		CreatedBy:          createdBy,
		CreatedAt:          now,
		UpdatedAt:          now,
	}, nil
}

// Update updates the scan profile properties.
func (p *ScanProfile) Update(
	name string,
	description string,
	toolsConfig map[string]ToolConfig,
	intensity Intensity,
	maxConcurrentScans int,
	timeoutSeconds int,
	tags []string,
) error {
	if p.IsSystem {
		return shared.NewDomainError("FORBIDDEN", "system profiles cannot be modified", shared.ErrForbidden)
	}

	if name != "" {
		if len(name) > 100 {
			return shared.NewDomainError("VALIDATION", "name must be less than 100 characters", shared.ErrValidation)
		}
		p.Name = name
	}

	p.Description = description

	if toolsConfig != nil {
		p.ToolsConfig = toolsConfig
	}

	if intensity.IsValid() {
		p.Intensity = intensity
	}

	if maxConcurrentScans > 0 {
		p.MaxConcurrentScans = maxConcurrentScans
	}

	if timeoutSeconds > 0 {
		p.TimeoutSeconds = timeoutSeconds
	}

	if tags != nil {
		p.Tags = tags
	}

	p.UpdatedAt = time.Now()
	return nil
}

// UpdateQualityGate updates the quality gate configuration.
func (p *ScanProfile) UpdateQualityGate(gate QualityGate) error {
	if p.IsSystem {
		return shared.NewDomainError("FORBIDDEN", "system profiles cannot be modified", shared.ErrForbidden)
	}
	p.QualityGate = gate
	p.UpdatedAt = time.Now()
	return nil
}

// SetAsDefault marks this profile as the default for the tenant.
func (p *ScanProfile) SetAsDefault() {
	p.IsDefault = true
	p.UpdatedAt = time.Now()
}

// UnsetDefault removes the default flag.
func (p *ScanProfile) UnsetDefault() {
	p.IsDefault = false
	p.UpdatedAt = time.Now()
}

// EnableTool enables a tool with the given configuration.
func (p *ScanProfile) EnableTool(tool string, config ToolConfig) error {
	if p.IsSystem {
		return shared.NewDomainError("FORBIDDEN", "system profiles cannot be modified", shared.ErrForbidden)
	}

	if tool == "" {
		return shared.NewDomainError("VALIDATION", "tool name is required", shared.ErrValidation)
	}

	config.Enabled = true
	p.ToolsConfig[tool] = config
	p.UpdatedAt = time.Now()
	return nil
}

// DisableTool disables a tool.
func (p *ScanProfile) DisableTool(tool string) error {
	if p.IsSystem {
		return shared.NewDomainError("FORBIDDEN", "system profiles cannot be modified", shared.ErrForbidden)
	}

	if config, exists := p.ToolsConfig[tool]; exists {
		config.Enabled = false
		p.ToolsConfig[tool] = config
	}
	p.UpdatedAt = time.Now()
	return nil
}

// GetEnabledTools returns a list of enabled tool names.
func (p *ScanProfile) GetEnabledTools() []string {
	var tools []string
	for name, config := range p.ToolsConfig {
		if config.Enabled {
			tools = append(tools, name)
		}
	}
	return tools
}

// GetToolConfig returns the configuration for a specific tool.
func (p *ScanProfile) GetToolConfig(tool string) (ToolConfig, bool) {
	config, exists := p.ToolsConfig[tool]
	return config, exists
}

// HasTool checks if a tool is enabled in this profile.
func (p *ScanProfile) HasTool(tool string) bool {
	config, exists := p.ToolsConfig[tool]
	return exists && config.Enabled
}

// Clone creates a copy of this profile with a new name.
func (p *ScanProfile) Clone(newName string, createdBy *shared.ID) (*ScanProfile, error) {
	if newName == "" {
		return nil, shared.NewDomainError("VALIDATION", "new name is required", shared.ErrValidation)
	}

	// Deep copy tools config
	toolsConfig := make(map[string]ToolConfig, len(p.ToolsConfig))
	for k, v := range p.ToolsConfig {
		options := make(map[string]any)
		maps.Copy(options, v.Options)
		customTemplateIDs := make([]string, len(v.CustomTemplateIDs))
		copy(customTemplateIDs, v.CustomTemplateIDs)
		toolsConfig[k] = ToolConfig{
			Enabled:           v.Enabled,
			Severity:          v.Severity,
			Timeout:           v.Timeout,
			Options:           options,
			TemplateMode:      v.TemplateMode,
			CustomTemplateIDs: customTemplateIDs,
		}
	}

	// Deep copy tags
	tags := make([]string, len(p.Tags))
	copy(tags, p.Tags)

	// Deep copy metadata
	metadata := make(map[string]any, len(p.Metadata))
	maps.Copy(metadata, p.Metadata)

	now := time.Now()
	return &ScanProfile{
		ID:                 shared.NewID(),
		TenantID:           p.TenantID,
		Name:               newName,
		Description:        p.Description,
		IsDefault:          false,
		IsSystem:           false,
		ToolsConfig:        toolsConfig,
		Intensity:          p.Intensity,
		MaxConcurrentScans: p.MaxConcurrentScans,
		TimeoutSeconds:     p.TimeoutSeconds,
		Tags:               tags,
		Metadata:           metadata,
		QualityGate:        p.QualityGate, // Copy quality gate settings
		CreatedBy:          createdBy,
		CreatedAt:          now,
		UpdatedAt:          now,
	}, nil
}

// CanDelete checks if the profile can be deleted.
func (p *ScanProfile) CanDelete() error {
	if p.IsSystem {
		return shared.NewDomainError("FORBIDDEN", "system profiles cannot be deleted", shared.ErrForbidden)
	}
	return nil
}

// CanManage checks if the given tenant can manage (edit/delete) this profile.
// System profiles cannot be managed; they must be cloned first.
// Tenants can only manage profiles they own.
func (p *ScanProfile) CanManage(tenantID shared.ID) error {
	if p.IsSystem {
		return shared.NewDomainError("FORBIDDEN", "system profiles cannot be modified; clone it first to customize", shared.ErrForbidden)
	}
	if !p.TenantID.Equals(tenantID) {
		return shared.NewDomainError("FORBIDDEN", "profile belongs to another tenant", shared.ErrForbidden)
	}
	return nil
}

// BelongsToTenant checks if this profile belongs to the specified tenant.
func (p *ScanProfile) BelongsToTenant(tenantID shared.ID) bool {
	return p.TenantID.Equals(tenantID)
}

// IsSystemProfile returns true if this is a platform-provided system profile.
func (p *ScanProfile) IsSystemProfile() bool {
	return p.IsSystem
}

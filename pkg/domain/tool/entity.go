// Package tool defines the Tool domain entity for the tool registry.
// Tools are system-wide definitions with versioning and configuration management.
// Tenants can have custom configurations that override default tool settings.
package tool

import (
	"slices"
	"time"

	"github.com/openctemio/api/pkg/domain/shared"
)

// InstallMethod represents how the tool is installed.
type InstallMethod string

const (
	InstallGo     InstallMethod = "go"     // go install
	InstallPip    InstallMethod = "pip"    // pip install
	InstallNpm    InstallMethod = "npm"    // npm install
	InstallDocker InstallMethod = "docker" // docker pull
	InstallBinary InstallMethod = "binary" // Direct binary download
)

// IsValid checks if the install method is valid.
func (m InstallMethod) IsValid() bool {
	switch m {
	case InstallGo, InstallPip, InstallNpm, InstallDocker, InstallBinary:
		return true
	}
	return false
}

// Tool represents a security tool in the registry.
// Platform tools (TenantID = nil, IsBuiltin = true) are available to all tenants.
// Tenant custom tools (TenantID = UUID, IsBuiltin = false) are private to that tenant.
type Tool struct {
	ID          shared.ID
	TenantID    *shared.ID // nil = platform tool, UUID = tenant custom tool
	Name        string     // Unique identifier: 'semgrep', 'nuclei', etc.
	DisplayName string
	Description string
	LogoURL     string
	CategoryID  *shared.ID // Foreign key to tool_categories table

	// Installation
	InstallMethod InstallMethod
	InstallCmd    string
	UpdateCmd     string

	// Version tracking
	VersionCmd     string // Command to check version
	VersionRegex   string // Regex to extract version from output
	CurrentVersion string // Currently installed version
	LatestVersion  string // Latest available version

	// Configuration
	ConfigFilePath string         // Path to config file, e.g., '/root/.config/nuclei/config.yaml'
	ConfigSchema   map[string]any // JSON Schema for validating tool config
	DefaultConfig  map[string]any // Default configuration

	// Capabilities this tool provides (maps to agent capabilities)
	Capabilities []string

	// Supported input/output
	SupportedTargets []string // 'url', 'domain', 'ip', 'file', 'repository', 'container'
	OutputFormats    []string // 'json', 'sarif', 'csv', 'txt'

	// Documentation
	DocsURL   string
	GithubURL string

	// Status
	IsActive  bool // Tool is available for use
	IsBuiltin bool // System tool vs custom installed

	// Metadata
	Tags     []string
	Metadata map[string]any

	// Audit
	CreatedBy *shared.ID // User who created the tool (for custom tools)
	CreatedAt time.Time
	UpdatedAt time.Time
}

// NewTool creates a new platform Tool entity (TenantID = nil, IsBuiltin = true).
// Use NewTenantCustomTool for creating tenant-specific tools.
func NewTool(
	name string,
	displayName string,
	categoryID *shared.ID,
	installMethod InstallMethod,
) (*Tool, error) {
	return newTool(nil, nil, name, displayName, categoryID, installMethod, true)
}

// NewTenantCustomTool creates a new tenant custom Tool entity.
// Custom tools are private to the tenant and can be fully managed by them.
func NewTenantCustomTool(
	tenantID shared.ID,
	createdBy shared.ID,
	name string,
	displayName string,
	categoryID *shared.ID,
	installMethod InstallMethod,
) (*Tool, error) {
	if tenantID.IsZero() {
		return nil, shared.NewDomainError("VALIDATION", "tenant_id is required for custom tools", shared.ErrValidation)
	}
	var createdByPtr *shared.ID
	if !createdBy.IsZero() {
		createdByPtr = &createdBy
	}
	return newTool(&tenantID, createdByPtr, name, displayName, categoryID, installMethod, false)
}

// newTool is the internal constructor for Tool entities.
func newTool(
	tenantID *shared.ID,
	createdBy *shared.ID,
	name string,
	displayName string,
	categoryID *shared.ID,
	installMethod InstallMethod,
	isBuiltin bool,
) (*Tool, error) {
	if name == "" {
		return nil, shared.NewDomainError("VALIDATION", "name is required", shared.ErrValidation)
	}

	if len(name) > 50 {
		return nil, shared.NewDomainError("VALIDATION", "name must be less than 50 characters", shared.ErrValidation)
	}

	if displayName == "" {
		displayName = name
	}

	if !installMethod.IsValid() {
		return nil, shared.NewDomainError("VALIDATION", "invalid install method", shared.ErrValidation)
	}

	now := time.Now()
	return &Tool{
		ID:               shared.NewID(),
		TenantID:         tenantID,
		Name:             name,
		DisplayName:      displayName,
		CategoryID:       categoryID,
		InstallMethod:    installMethod,
		DefaultConfig:    make(map[string]any),
		ConfigSchema:     make(map[string]any),
		Capabilities:     []string{},
		SupportedTargets: []string{},
		OutputFormats:    []string{},
		Tags:             []string{},
		Metadata:         make(map[string]any),
		IsActive:         true,
		IsBuiltin:        isBuiltin,
		CreatedBy:        createdBy,
		CreatedAt:        now,
		UpdatedAt:        now,
	}, nil
}

// Update updates the tool properties.
func (t *Tool) Update(
	displayName string,
	description string,
	installCmd string,
	updateCmd string,
	defaultConfig map[string]any,
) error {
	if displayName != "" {
		t.DisplayName = displayName
	}

	t.Description = description
	t.InstallCmd = installCmd
	t.UpdateCmd = updateCmd

	if defaultConfig != nil {
		t.DefaultConfig = defaultConfig
	}

	t.UpdatedAt = time.Now()
	return nil
}

// SetVersion updates the version information.
func (t *Tool) SetVersion(current, latest string) {
	t.CurrentVersion = current
	t.LatestVersion = latest
	t.UpdatedAt = time.Now()
}

// HasUpdateAvailable checks if an update is available.
func (t *Tool) HasUpdateAvailable() bool {
	if t.CurrentVersion == "" || t.LatestVersion == "" {
		return false
	}
	return t.CurrentVersion != t.LatestVersion
}

// Activate enables the tool.
func (t *Tool) Activate() {
	t.IsActive = true
	t.UpdatedAt = time.Now()
}

// Deactivate disables the tool.
func (t *Tool) Deactivate() {
	t.IsActive = false
	t.UpdatedAt = time.Now()
}

// HasCapability checks if the tool has a specific capability.
func (t *Tool) HasCapability(capability string) bool {
	return slices.Contains(t.Capabilities, capability)
}

// SupportsTarget checks if the tool supports a specific target type.
func (t *Tool) SupportsTarget(targetType string) bool {
	return slices.Contains(t.SupportedTargets, targetType)
}

// IsPlatformTool returns true if this is a platform-provided tool.
func (t *Tool) IsPlatformTool() bool {
	return t.TenantID == nil
}

// IsCustomTool returns true if this is a tenant custom tool.
func (t *Tool) IsCustomTool() bool {
	return t.TenantID != nil
}

// BelongsToTenant checks if the tool belongs to a specific tenant.
func (t *Tool) BelongsToTenant(tenantID shared.ID) bool {
	if t.TenantID == nil {
		return false
	}
	return *t.TenantID == tenantID
}

// CanDelete checks if the tool can be deleted.
func (t *Tool) CanDelete() error {
	if t.IsBuiltin {
		return shared.NewDomainError("FORBIDDEN", "platform builtin tools cannot be deleted", shared.ErrForbidden)
	}
	return nil
}

// CanManage checks if a tenant can manage (edit/delete/enable/disable) this tool.
func (t *Tool) CanManage(tenantID shared.ID) error {
	// Platform tools cannot be managed by tenants
	if t.IsPlatformTool() {
		return shared.NewDomainError("FORBIDDEN", "platform tools cannot be managed by tenants", shared.ErrForbidden)
	}
	// Custom tools can only be managed by their owner
	if !t.BelongsToTenant(tenantID) {
		return shared.NewDomainError("FORBIDDEN", "tool belongs to another tenant", shared.ErrForbidden)
	}
	return nil
}

// TenantToolConfig represents tenant-specific tool configuration.
// This allows tenants to override default tool settings without
// modifying the system-wide tool definition.
type TenantToolConfig struct {
	ID       shared.ID
	TenantID shared.ID
	ToolID   shared.ID

	// Configuration override (merged with tool's DefaultConfig)
	Config map[string]any

	// Custom templates (e.g., Nuclei templates)
	CustomTemplates []CustomTemplate

	// Custom patterns (e.g., GF patterns, regex patterns)
	CustomPatterns []CustomPattern

	// Custom wordlists
	CustomWordlists []CustomWordlist

	// Status
	IsEnabled bool

	// Audit
	UpdatedBy *shared.ID
	CreatedAt time.Time
	UpdatedAt time.Time
}

// CustomTemplate represents a custom template file.
type CustomTemplate struct {
	Name    string `json:"name"`
	Path    string `json:"path,omitempty"`    // File path if stored on disk
	Content string `json:"content,omitempty"` // Content if stored in DB
}

// CustomPattern represents a custom pattern definition.
type CustomPattern struct {
	Name    string `json:"name"`
	Pattern string `json:"pattern"`
}

// CustomWordlist represents a custom wordlist reference.
type CustomWordlist struct {
	Name string `json:"name"`
	Path string `json:"path"`
}

// NewTenantToolConfig creates a new tenant tool configuration.
func NewTenantToolConfig(
	tenantID shared.ID,
	toolID shared.ID,
	config map[string]any,
	updatedBy *shared.ID,
) (*TenantToolConfig, error) {
	if tenantID.IsZero() {
		return nil, shared.NewDomainError("VALIDATION", "tenant_id is required", shared.ErrValidation)
	}

	if toolID.IsZero() {
		return nil, shared.NewDomainError("VALIDATION", "tool_id is required", shared.ErrValidation)
	}

	if config == nil {
		config = make(map[string]any)
	}

	now := time.Now()
	return &TenantToolConfig{
		ID:              shared.NewID(),
		TenantID:        tenantID,
		ToolID:          toolID,
		Config:          config,
		CustomTemplates: []CustomTemplate{},
		CustomPatterns:  []CustomPattern{},
		CustomWordlists: []CustomWordlist{},
		IsEnabled:       true,
		UpdatedBy:       updatedBy,
		CreatedAt:       now,
		UpdatedAt:       now,
	}, nil
}

// Update updates the tenant tool configuration.
func (c *TenantToolConfig) Update(
	config map[string]any,
	isEnabled bool,
	updatedBy *shared.ID,
) error {
	if config != nil {
		c.Config = config
	}

	c.IsEnabled = isEnabled
	c.UpdatedBy = updatedBy
	c.UpdatedAt = time.Now()
	return nil
}

// AddCustomTemplate adds a custom template.
func (c *TenantToolConfig) AddCustomTemplate(template CustomTemplate) error {
	if template.Name == "" {
		return shared.NewDomainError("VALIDATION", "template name is required", shared.ErrValidation)
	}

	// Check for duplicates
	for _, t := range c.CustomTemplates {
		if t.Name == template.Name {
			return shared.NewDomainError("CONFLICT", "template with this name already exists", shared.ErrConflict)
		}
	}

	c.CustomTemplates = append(c.CustomTemplates, template)
	c.UpdatedAt = time.Now()
	return nil
}

// RemoveCustomTemplate removes a custom template by name.
func (c *TenantToolConfig) RemoveCustomTemplate(name string) {
	var templates []CustomTemplate
	for _, t := range c.CustomTemplates {
		if t.Name != name {
			templates = append(templates, t)
		}
	}
	c.CustomTemplates = templates
	c.UpdatedAt = time.Now()
}

// AddCustomPattern adds a custom pattern.
func (c *TenantToolConfig) AddCustomPattern(pattern CustomPattern) error {
	if pattern.Name == "" {
		return shared.NewDomainError("VALIDATION", "pattern name is required", shared.ErrValidation)
	}

	if pattern.Pattern == "" {
		return shared.NewDomainError("VALIDATION", "pattern is required", shared.ErrValidation)
	}

	c.CustomPatterns = append(c.CustomPatterns, pattern)
	c.UpdatedAt = time.Now()
	return nil
}

// RemoveCustomPattern removes a custom pattern by name.
func (c *TenantToolConfig) RemoveCustomPattern(name string) {
	var patterns []CustomPattern
	for _, p := range c.CustomPatterns {
		if p.Name != name {
			patterns = append(patterns, p)
		}
	}
	c.CustomPatterns = patterns
	c.UpdatedAt = time.Now()
}

// Enable enables the tool for this tenant.
func (c *TenantToolConfig) Enable() {
	c.IsEnabled = true
	c.UpdatedAt = time.Now()
}

// Disable disables the tool for this tenant.
func (c *TenantToolConfig) Disable() {
	c.IsEnabled = false
	c.UpdatedAt = time.Now()
}

// ToolExecution represents a single tool execution record.
// Used for analytics and debugging.
type ToolExecution struct {
	ID       shared.ID
	TenantID shared.ID
	ToolID   shared.ID
	AgentID  *shared.ID

	// Execution context
	PipelineRunID *shared.ID
	StepRunID     *shared.ID

	// Status
	Status ExecutionStatus

	// Input/Output
	InputConfig   map[string]any
	TargetsCount  int
	FindingsCount int
	OutputSummary map[string]any
	ErrorMessage  string

	// Timing
	StartedAt   time.Time
	CompletedAt *time.Time
	DurationMs  int

	CreatedAt time.Time
}

// ExecutionStatus represents the status of a tool execution.
type ExecutionStatus string

const (
	ExecutionStatusRunning   ExecutionStatus = "running"
	ExecutionStatusCompleted ExecutionStatus = "completed"
	ExecutionStatusFailed    ExecutionStatus = "failed"
	ExecutionStatusTimeout   ExecutionStatus = "timeout"
)

// IsValid checks if the execution status is valid.
func (s ExecutionStatus) IsValid() bool {
	switch s {
	case ExecutionStatusRunning, ExecutionStatusCompleted, ExecutionStatusFailed, ExecutionStatusTimeout:
		return true
	}
	return false
}

// NewToolExecution creates a new tool execution record.
func NewToolExecution(
	tenantID shared.ID,
	toolID shared.ID,
	agentID *shared.ID,
	inputConfig map[string]any,
	targetsCount int,
) *ToolExecution {
	now := time.Now()
	return &ToolExecution{
		ID:           shared.NewID(),
		TenantID:     tenantID,
		ToolID:       toolID,
		AgentID:      agentID,
		Status:       ExecutionStatusRunning,
		InputConfig:  inputConfig,
		TargetsCount: targetsCount,
		StartedAt:    now,
		CreatedAt:    now,
	}
}

// Complete marks the execution as completed.
func (e *ToolExecution) Complete(findingsCount int, outputSummary map[string]any) {
	now := time.Now()
	e.Status = ExecutionStatusCompleted
	e.FindingsCount = findingsCount
	e.OutputSummary = outputSummary
	e.CompletedAt = &now
	e.DurationMs = int(now.Sub(e.StartedAt).Milliseconds())
}

// Fail marks the execution as failed.
func (e *ToolExecution) Fail(errorMessage string) {
	now := time.Now()
	e.Status = ExecutionStatusFailed
	e.ErrorMessage = errorMessage
	e.CompletedAt = &now
	e.DurationMs = int(now.Sub(e.StartedAt).Milliseconds())
}

// Timeout marks the execution as timed out.
func (e *ToolExecution) Timeout() {
	now := time.Now()
	e.Status = ExecutionStatusTimeout
	e.CompletedAt = &now
	e.DurationMs = int(now.Sub(e.StartedAt).Milliseconds())
}

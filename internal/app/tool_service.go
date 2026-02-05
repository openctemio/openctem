package app

import (
	"context"
	"fmt"

	"github.com/openctemio/api/pkg/domain/agent"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/domain/tool"
	"github.com/openctemio/api/pkg/domain/toolcategory"
	"github.com/openctemio/api/pkg/logger"
	"github.com/openctemio/api/pkg/pagination"
)

// PipelineDeactivator interface for cascade deactivation when tools are disabled/deleted.
// This decouples ToolService from PipelineService while allowing the cascade behavior.
type PipelineDeactivator interface {
	// DeactivatePipelinesByTool deactivates all active pipelines using the specified tool.
	// Returns the count of deactivated pipelines and their IDs.
	DeactivatePipelinesByTool(ctx context.Context, toolName string) (int, []shared.ID, error)

	// GetPipelinesUsingTool returns all active pipeline IDs that use a specific tool.
	GetPipelinesUsingTool(ctx context.Context, toolName string) ([]shared.ID, error)
}

// ToolService handles tool registry business operations.
type ToolService struct {
	toolRepo            tool.Repository
	configRepo          tool.TenantToolConfigRepository
	executionRepo       tool.ToolExecutionRepository
	agentRepo           agent.Repository        // For checking tool availability
	categoryRepo        toolcategory.Repository // For fetching category info
	pipelineDeactivator PipelineDeactivator     // For cascade deactivation when tool is disabled/deleted
	logger              *logger.Logger
}

// NewToolService creates a new ToolService.
func NewToolService(
	toolRepo tool.Repository,
	configRepo tool.TenantToolConfigRepository,
	executionRepo tool.ToolExecutionRepository,
	log *logger.Logger,
) *ToolService {
	return &ToolService{
		toolRepo:      toolRepo,
		configRepo:    configRepo,
		executionRepo: executionRepo,
		logger:        log.With("service", "tool"),
	}
}

// SetAgentRepo sets the agent repository for tool availability checks.
// This is optional - if not set, IsAvailable will always be true.
func (s *ToolService) SetAgentRepo(repo agent.Repository) {
	s.agentRepo = repo
}

// SetCategoryRepo sets the category repository for fetching category info.
// This is optional - if not set, Category will be nil in responses.
func (s *ToolService) SetCategoryRepo(repo toolcategory.Repository) {
	s.categoryRepo = repo
}

// SetPipelineDeactivator sets the pipeline deactivator for cascade deactivation.
// This is optional - if not set, pipelines will not be auto-deactivated when tools are disabled.
func (s *ToolService) SetPipelineDeactivator(deactivator PipelineDeactivator) {
	s.pipelineDeactivator = deactivator
}

// =============================================================================
// Tool Operations (System-wide)
// =============================================================================

// CreateToolInput represents the input for creating a tool.
type CreateToolInput struct {
	Name             string         `json:"name" validate:"required,min=1,max=50"`
	DisplayName      string         `json:"display_name" validate:"max=100"`
	Description      string         `json:"description" validate:"max=1000"`
	CategoryID       string         `json:"category_id" validate:"omitempty,uuid"` // UUID of tool_categories
	InstallMethod    string         `json:"install_method" validate:"required,oneof=go pip npm docker binary"`
	InstallCmd       string         `json:"install_cmd" validate:"max=500"`
	UpdateCmd        string         `json:"update_cmd" validate:"max=500"`
	VersionCmd       string         `json:"version_cmd" validate:"max=500"`
	VersionRegex     string         `json:"version_regex" validate:"max=200"`
	ConfigSchema     map[string]any `json:"config_schema"`
	DefaultConfig    map[string]any `json:"default_config"`
	Capabilities     []string       `json:"capabilities" validate:"max=20,dive,max=50"`
	SupportedTargets []string       `json:"supported_targets" validate:"max=10,dive,max=50"`
	OutputFormats    []string       `json:"output_formats" validate:"max=10,dive,max=20"`
	DocsURL          string         `json:"docs_url" validate:"omitempty,url,max=500"`
	GithubURL        string         `json:"github_url" validate:"omitempty,url,max=500"`
	LogoURL          string         `json:"logo_url" validate:"omitempty,url,max=500"`
	Tags             []string       `json:"tags" validate:"max=20,dive,max=50"`
}

// CreateTool creates a new tool in the registry.
func (s *ToolService) CreateTool(ctx context.Context, input CreateToolInput) (*tool.Tool, error) {
	s.logger.Info("creating tool", "name", input.Name, "category_id", input.CategoryID)

	installMethod := tool.InstallMethod(input.InstallMethod)
	if !installMethod.IsValid() {
		return nil, fmt.Errorf("%w: invalid install method", shared.ErrValidation)
	}

	// Parse category_id if provided
	var categoryID *shared.ID
	if input.CategoryID != "" {
		catID, err := shared.IDFromString(input.CategoryID)
		if err != nil {
			return nil, fmt.Errorf("%w: invalid category_id", shared.ErrValidation)
		}
		categoryID = &catID
	}

	t, err := tool.NewTool(input.Name, input.DisplayName, categoryID, installMethod)
	if err != nil {
		return nil, err
	}

	// Set optional fields
	t.Description = input.Description
	t.InstallCmd = input.InstallCmd
	t.UpdateCmd = input.UpdateCmd
	t.VersionCmd = input.VersionCmd
	t.VersionRegex = input.VersionRegex
	t.ConfigFilePath = ""
	t.DocsURL = input.DocsURL
	t.GithubURL = input.GithubURL
	t.LogoURL = input.LogoURL

	if input.ConfigSchema != nil {
		t.ConfigSchema = input.ConfigSchema
	}
	if input.DefaultConfig != nil {
		t.DefaultConfig = input.DefaultConfig
	}
	if input.Capabilities != nil {
		t.Capabilities = input.Capabilities
	}
	if input.SupportedTargets != nil {
		t.SupportedTargets = input.SupportedTargets
	}
	if input.OutputFormats != nil {
		t.OutputFormats = input.OutputFormats
	}
	if input.Tags != nil {
		t.Tags = input.Tags
	}

	if err := s.toolRepo.Create(ctx, t); err != nil {
		return nil, err
	}

	return t, nil
}

// GetTool retrieves a tool by ID.
func (s *ToolService) GetTool(ctx context.Context, toolID string) (*tool.Tool, error) {
	id, err := shared.IDFromString(toolID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tool id", shared.ErrValidation)
	}

	return s.toolRepo.GetByID(ctx, id)
}

// GetToolByName retrieves a tool by name.
func (s *ToolService) GetToolByName(ctx context.Context, name string) (*tool.Tool, error) {
	if name == "" {
		return nil, fmt.Errorf("%w: name is required", shared.ErrValidation)
	}

	return s.toolRepo.GetByName(ctx, name)
}

// ListToolsInput represents the input for listing tools.
type ListToolsInput struct {
	Category     string   `json:"category" validate:"omitempty,max=50"` // Category name (dynamic from tool_categories)
	Capabilities []string `json:"capabilities"`
	IsActive     *bool    `json:"is_active"`
	IsBuiltin    *bool    `json:"is_builtin"`
	Search       string   `json:"search" validate:"max=255"`
	Tags         []string `json:"tags"`
	Page         int      `json:"page"`
	PerPage      int      `json:"per_page"`
}

// ListTools lists tools with filters.
func (s *ToolService) ListTools(ctx context.Context, input ListToolsInput) (pagination.Result[*tool.Tool], error) {
	filter := tool.ToolFilter{
		Capabilities: input.Capabilities,
		IsActive:     input.IsActive,
		IsBuiltin:    input.IsBuiltin,
		Search:       input.Search,
		Tags:         input.Tags,
	}

	if input.Category != "" {
		filter.CategoryName = &input.Category
	}

	page := pagination.New(input.Page, input.PerPage)
	return s.toolRepo.List(ctx, filter, page)
}

// ListToolsByCategory lists tools by category name.
func (s *ToolService) ListToolsByCategory(ctx context.Context, category string) ([]*tool.Tool, error) {
	if category == "" {
		return nil, fmt.Errorf("%w: category is required", shared.ErrValidation)
	}

	return s.toolRepo.ListByCategoryName(ctx, category)
}

// ListToolsByCapability lists tools by capability.
func (s *ToolService) ListToolsByCapability(ctx context.Context, capability string) ([]*tool.Tool, error) {
	if capability == "" {
		return nil, fmt.Errorf("%w: capability is required", shared.ErrValidation)
	}

	return s.toolRepo.ListByCapability(ctx, capability)
}

// UpdateToolInput represents the input for updating a tool.
type UpdateToolInput struct {
	ToolID           string         `json:"tool_id" validate:"required,uuid"`
	DisplayName      string         `json:"display_name" validate:"max=100"`
	Description      string         `json:"description" validate:"max=1000"`
	InstallCmd       string         `json:"install_cmd" validate:"max=500"`
	UpdateCmd        string         `json:"update_cmd" validate:"max=500"`
	VersionCmd       string         `json:"version_cmd" validate:"max=500"`
	VersionRegex     string         `json:"version_regex" validate:"max=200"`
	ConfigSchema     map[string]any `json:"config_schema"`
	DefaultConfig    map[string]any `json:"default_config"`
	Capabilities     []string       `json:"capabilities" validate:"max=20,dive,max=50"`
	SupportedTargets []string       `json:"supported_targets" validate:"max=10,dive,max=50"`
	OutputFormats    []string       `json:"output_formats" validate:"max=10,dive,max=20"`
	DocsURL          string         `json:"docs_url" validate:"omitempty,url,max=500"`
	GithubURL        string         `json:"github_url" validate:"omitempty,url,max=500"`
	LogoURL          string         `json:"logo_url" validate:"omitempty,url,max=500"`
	Tags             []string       `json:"tags" validate:"max=20,dive,max=50"`
}

// UpdateTool updates an existing tool.
func (s *ToolService) UpdateTool(ctx context.Context, input UpdateToolInput) (*tool.Tool, error) {
	s.logger.Info("updating tool", "tool_id", input.ToolID)

	t, err := s.GetTool(ctx, input.ToolID)
	if err != nil {
		return nil, err
	}

	if err := t.Update(input.DisplayName, input.Description, input.InstallCmd, input.UpdateCmd, input.DefaultConfig); err != nil {
		return nil, err
	}

	// Update additional fields
	t.VersionCmd = input.VersionCmd
	t.VersionRegex = input.VersionRegex
	t.DocsURL = input.DocsURL
	t.GithubURL = input.GithubURL
	t.LogoURL = input.LogoURL

	if input.ConfigSchema != nil {
		t.ConfigSchema = input.ConfigSchema
	}
	if input.Capabilities != nil {
		t.Capabilities = input.Capabilities
	}
	if input.SupportedTargets != nil {
		t.SupportedTargets = input.SupportedTargets
	}
	if input.OutputFormats != nil {
		t.OutputFormats = input.OutputFormats
	}
	if input.Tags != nil {
		t.Tags = input.Tags
	}

	if err := s.toolRepo.Update(ctx, t); err != nil {
		return nil, err
	}

	return t, nil
}

// DeleteTool deletes a tool from the registry.
// Before deleting, cascade deactivates any active pipelines that use this tool.
func (s *ToolService) DeleteTool(ctx context.Context, toolID string) error {
	s.logger.Info("deleting tool", "tool_id", toolID)

	t, err := s.GetTool(ctx, toolID)
	if err != nil {
		return err
	}

	if err := t.CanDelete(); err != nil {
		return err
	}

	// Cascade deactivate pipelines using this tool before deletion
	if s.pipelineDeactivator != nil {
		count, pipelineIDs, err := s.pipelineDeactivator.DeactivatePipelinesByTool(ctx, t.Name)
		if err != nil {
			s.logger.Warn("failed to deactivate pipelines before tool deletion",
				"tool_id", toolID,
				"tool_name", t.Name,
				"error", err)
			// Don't fail the deletion - log and continue
		} else if count > 0 {
			s.logger.Info("cascade deactivated pipelines before tool deletion",
				"tool_id", toolID,
				"tool_name", t.Name,
				"deactivated_count", count,
				"pipeline_ids", pipelineIDs)
		}
	}

	return s.toolRepo.Delete(ctx, t.ID)
}

// ActivateTool activates a tool.
func (s *ToolService) ActivateTool(ctx context.Context, toolID string) (*tool.Tool, error) {
	s.logger.Info("activating tool", "tool_id", toolID)

	t, err := s.GetTool(ctx, toolID)
	if err != nil {
		return nil, err
	}

	t.Activate()

	if err := s.toolRepo.Update(ctx, t); err != nil {
		return nil, err
	}

	return t, nil
}

// DeactivateTool deactivates a tool.
// Also cascade deactivates any active pipelines that use this tool.
func (s *ToolService) DeactivateTool(ctx context.Context, toolID string) (*tool.Tool, error) {
	s.logger.Info("deactivating tool", "tool_id", toolID)

	t, err := s.GetTool(ctx, toolID)
	if err != nil {
		return nil, err
	}

	// Cascade deactivate pipelines using this tool
	if s.pipelineDeactivator != nil {
		count, pipelineIDs, err := s.pipelineDeactivator.DeactivatePipelinesByTool(ctx, t.Name)
		if err != nil {
			s.logger.Warn("failed to deactivate pipelines for tool",
				"tool_id", toolID,
				"tool_name", t.Name,
				"error", err)
			// Don't fail the tool deactivation - log and continue
		} else if count > 0 {
			s.logger.Info("cascade deactivated pipelines for tool",
				"tool_id", toolID,
				"tool_name", t.Name,
				"deactivated_count", count,
				"pipeline_ids", pipelineIDs)
		}
	}

	t.Deactivate()

	if err := s.toolRepo.Update(ctx, t); err != nil {
		return nil, err
	}

	return t, nil
}

// UpdateToolVersionInput represents the input for updating tool version.
type UpdateToolVersionInput struct {
	ToolID         string `json:"tool_id" validate:"required,uuid"`
	CurrentVersion string `json:"current_version" validate:"max=50"`
	LatestVersion  string `json:"latest_version" validate:"max=50"`
}

// UpdateToolVersion updates the version information of a tool.
func (s *ToolService) UpdateToolVersion(ctx context.Context, input UpdateToolVersionInput) (*tool.Tool, error) {
	s.logger.Info("updating tool version", "tool_id", input.ToolID, "current", input.CurrentVersion, "latest", input.LatestVersion)

	t, err := s.GetTool(ctx, input.ToolID)
	if err != nil {
		return nil, err
	}

	t.SetVersion(input.CurrentVersion, input.LatestVersion)

	if err := s.toolRepo.Update(ctx, t); err != nil {
		return nil, err
	}

	return t, nil
}

// =============================================================================
// Tenant Custom Tool Operations
// =============================================================================

// CreateCustomToolInput represents the input for creating a tenant custom tool.
type CreateCustomToolInput struct {
	TenantID         string         `json:"tenant_id" validate:"required,uuid"`
	CreatedBy        string         `json:"created_by" validate:"omitempty,uuid"` // User ID who created the tool
	Name             string         `json:"name" validate:"required,min=1,max=50"`
	DisplayName      string         `json:"display_name" validate:"max=100"`
	Description      string         `json:"description" validate:"max=1000"`
	CategoryID       string         `json:"category_id" validate:"omitempty,uuid"` // UUID of tool_categories
	InstallMethod    string         `json:"install_method" validate:"required,oneof=go pip npm docker binary"`
	InstallCmd       string         `json:"install_cmd" validate:"max=500"`
	UpdateCmd        string         `json:"update_cmd" validate:"max=500"`
	VersionCmd       string         `json:"version_cmd" validate:"max=500"`
	VersionRegex     string         `json:"version_regex" validate:"max=200"`
	ConfigSchema     map[string]any `json:"config_schema"`
	DefaultConfig    map[string]any `json:"default_config"`
	Capabilities     []string       `json:"capabilities" validate:"max=20,dive,max=50"`
	SupportedTargets []string       `json:"supported_targets" validate:"max=10,dive,max=50"`
	OutputFormats    []string       `json:"output_formats" validate:"max=10,dive,max=20"`
	DocsURL          string         `json:"docs_url" validate:"omitempty,url,max=500"`
	GithubURL        string         `json:"github_url" validate:"omitempty,url,max=500"`
	LogoURL          string         `json:"logo_url" validate:"omitempty,url,max=500"`
	Tags             []string       `json:"tags" validate:"max=20,dive,max=50"`
}

// CreateCustomTool creates a new tenant custom tool.
func (s *ToolService) CreateCustomTool(ctx context.Context, input CreateCustomToolInput) (*tool.Tool, error) {
	s.logger.Info("creating custom tool", "tenant_id", input.TenantID, "created_by", input.CreatedBy, "name", input.Name, "category_id", input.CategoryID)

	tenantID, err := shared.IDFromString(input.TenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}

	// Parse createdBy (optional, but typically always present)
	var createdBy shared.ID
	if input.CreatedBy != "" {
		createdBy, err = shared.IDFromString(input.CreatedBy)
		if err != nil {
			return nil, fmt.Errorf("%w: invalid created_by user id", shared.ErrValidation)
		}
	}

	// Parse category_id if provided
	var categoryID *shared.ID
	if input.CategoryID != "" {
		catID, err := shared.IDFromString(input.CategoryID)
		if err != nil {
			return nil, fmt.Errorf("%w: invalid category_id", shared.ErrValidation)
		}
		categoryID = &catID
	}

	installMethod := tool.InstallMethod(input.InstallMethod)
	if !installMethod.IsValid() {
		return nil, fmt.Errorf("%w: invalid install method", shared.ErrValidation)
	}

	t, err := tool.NewTenantCustomTool(tenantID, createdBy, input.Name, input.DisplayName, categoryID, installMethod)
	if err != nil {
		return nil, err
	}

	// Set optional fields
	t.Description = input.Description
	t.InstallCmd = input.InstallCmd
	t.UpdateCmd = input.UpdateCmd
	t.VersionCmd = input.VersionCmd
	t.VersionRegex = input.VersionRegex
	t.ConfigFilePath = ""
	t.DocsURL = input.DocsURL
	t.GithubURL = input.GithubURL
	t.LogoURL = input.LogoURL

	if input.ConfigSchema != nil {
		t.ConfigSchema = input.ConfigSchema
	}
	if input.DefaultConfig != nil {
		t.DefaultConfig = input.DefaultConfig
	}
	if input.Capabilities != nil {
		t.Capabilities = input.Capabilities
	}
	if input.SupportedTargets != nil {
		t.SupportedTargets = input.SupportedTargets
	}
	if input.OutputFormats != nil {
		t.OutputFormats = input.OutputFormats
	}
	if input.Tags != nil {
		t.Tags = input.Tags
	}

	if err := s.toolRepo.Create(ctx, t); err != nil {
		return nil, err
	}

	return t, nil
}

// GetCustomTool retrieves a tenant custom tool.
func (s *ToolService) GetCustomTool(ctx context.Context, tenantID, toolID string) (*tool.Tool, error) {
	tid, err := shared.IDFromString(tenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}

	toid, err := shared.IDFromString(toolID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tool id", shared.ErrValidation)
	}

	return s.toolRepo.GetByTenantAndID(ctx, tid, toid)
}

// ListPlatformToolsInput represents the input for listing platform tools.
type ListPlatformToolsInput struct {
	Category     string   `json:"category" validate:"omitempty,max=50"` // Category name (dynamic from tool_categories)
	Capabilities []string `json:"capabilities"`
	IsActive     *bool    `json:"is_active"`
	Search       string   `json:"search" validate:"max=255"`
	Tags         []string `json:"tags"`
	Page         int      `json:"page"`
	PerPage      int      `json:"per_page"`
}

// ListPlatformTools lists platform tools (system-provided, available to all tenants).
func (s *ToolService) ListPlatformTools(ctx context.Context, input ListPlatformToolsInput) (pagination.Result[*tool.Tool], error) {
	filter := tool.ToolFilter{
		Capabilities: input.Capabilities,
		IsActive:     input.IsActive,
		Search:       input.Search,
		Tags:         input.Tags,
	}

	if input.Category != "" {
		filter.CategoryName = &input.Category
	}

	page := pagination.New(input.Page, input.PerPage)
	return s.toolRepo.ListPlatformTools(ctx, filter, page)
}

// ListCustomToolsInput represents the input for listing tenant custom tools.
type ListCustomToolsInput struct {
	TenantID     string   `json:"tenant_id" validate:"required,uuid"`
	Category     string   `json:"category" validate:"omitempty,max=50"` // Category name (dynamic from tool_categories)
	Capabilities []string `json:"capabilities"`
	IsActive     *bool    `json:"is_active"`
	Search       string   `json:"search" validate:"max=255"`
	Tags         []string `json:"tags"`
	Page         int      `json:"page"`
	PerPage      int      `json:"per_page"`
}

// ListCustomTools lists tenant's custom tools.
func (s *ToolService) ListCustomTools(ctx context.Context, input ListCustomToolsInput) (pagination.Result[*tool.Tool], error) {
	tenantID, err := shared.IDFromString(input.TenantID)
	if err != nil {
		return pagination.Result[*tool.Tool]{}, fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}

	filter := tool.ToolFilter{
		Capabilities: input.Capabilities,
		IsActive:     input.IsActive,
		Search:       input.Search,
		Tags:         input.Tags,
	}

	if input.Category != "" {
		filter.CategoryName = &input.Category
	}

	page := pagination.New(input.Page, input.PerPage)
	return s.toolRepo.ListTenantCustomTools(ctx, tenantID, filter, page)
}

// ListAvailableToolsInput represents the input for listing all available tools.
type ListAvailableToolsInput struct {
	TenantID     string   `json:"tenant_id" validate:"required,uuid"`
	Category     string   `json:"category" validate:"omitempty,max=50"` // Category name (dynamic from tool_categories)
	Capabilities []string `json:"capabilities"`
	IsActive     *bool    `json:"is_active"`
	Search       string   `json:"search" validate:"max=255"`
	Tags         []string `json:"tags"`
	Page         int      `json:"page"`
	PerPage      int      `json:"per_page"`
}

// ListAvailableTools lists all tools available to a tenant (platform + custom).
func (s *ToolService) ListAvailableTools(ctx context.Context, input ListAvailableToolsInput) (pagination.Result[*tool.Tool], error) {
	tenantID, err := shared.IDFromString(input.TenantID)
	if err != nil {
		return pagination.Result[*tool.Tool]{}, fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}

	filter := tool.ToolFilter{
		Capabilities: input.Capabilities,
		IsActive:     input.IsActive,
		Search:       input.Search,
		Tags:         input.Tags,
	}

	if input.Category != "" {
		filter.CategoryName = &input.Category
	}

	page := pagination.New(input.Page, input.PerPage)
	return s.toolRepo.ListAvailableTools(ctx, tenantID, filter, page)
}

// UpdateCustomToolInput represents the input for updating a tenant custom tool.
type UpdateCustomToolInput struct {
	TenantID         string         `json:"tenant_id" validate:"required,uuid"`
	ToolID           string         `json:"tool_id" validate:"required,uuid"`
	DisplayName      string         `json:"display_name" validate:"max=100"`
	Description      string         `json:"description" validate:"max=1000"`
	InstallCmd       string         `json:"install_cmd" validate:"max=500"`
	UpdateCmd        string         `json:"update_cmd" validate:"max=500"`
	VersionCmd       string         `json:"version_cmd" validate:"max=500"`
	VersionRegex     string         `json:"version_regex" validate:"max=200"`
	ConfigSchema     map[string]any `json:"config_schema"`
	DefaultConfig    map[string]any `json:"default_config"`
	Capabilities     []string       `json:"capabilities" validate:"max=20,dive,max=50"`
	SupportedTargets []string       `json:"supported_targets" validate:"max=10,dive,max=50"`
	OutputFormats    []string       `json:"output_formats" validate:"max=10,dive,max=20"`
	DocsURL          string         `json:"docs_url" validate:"omitempty,url,max=500"`
	GithubURL        string         `json:"github_url" validate:"omitempty,url,max=500"`
	LogoURL          string         `json:"logo_url" validate:"omitempty,url,max=500"`
	Tags             []string       `json:"tags" validate:"max=20,dive,max=50"`
}

// UpdateCustomTool updates a tenant custom tool.
func (s *ToolService) UpdateCustomTool(ctx context.Context, input UpdateCustomToolInput) (*tool.Tool, error) {
	s.logger.Info("updating custom tool", "tenant_id", input.TenantID, "tool_id", input.ToolID)

	tenantID, err := shared.IDFromString(input.TenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}

	t, err := s.GetCustomTool(ctx, input.TenantID, input.ToolID)
	if err != nil {
		return nil, err
	}

	// Verify ownership
	if err := t.CanManage(tenantID); err != nil {
		return nil, err
	}

	if err := t.Update(input.DisplayName, input.Description, input.InstallCmd, input.UpdateCmd, input.DefaultConfig); err != nil {
		return nil, err
	}

	// Update additional fields
	t.VersionCmd = input.VersionCmd
	t.VersionRegex = input.VersionRegex
	t.DocsURL = input.DocsURL
	t.GithubURL = input.GithubURL
	t.LogoURL = input.LogoURL

	if input.ConfigSchema != nil {
		t.ConfigSchema = input.ConfigSchema
	}
	if input.Capabilities != nil {
		t.Capabilities = input.Capabilities
	}
	if input.SupportedTargets != nil {
		t.SupportedTargets = input.SupportedTargets
	}
	if input.OutputFormats != nil {
		t.OutputFormats = input.OutputFormats
	}
	if input.Tags != nil {
		t.Tags = input.Tags
	}

	if err := s.toolRepo.Update(ctx, t); err != nil {
		return nil, err
	}

	return t, nil
}

// DeleteCustomTool deletes a tenant custom tool.
// Before deleting, cascade deactivates any active pipelines that use this tool.
func (s *ToolService) DeleteCustomTool(ctx context.Context, tenantID, toolID string) error {
	s.logger.Info("deleting custom tool", "tenant_id", tenantID, "tool_id", toolID)

	tid, err := shared.IDFromString(tenantID)
	if err != nil {
		return fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}

	toid, err := shared.IDFromString(toolID)
	if err != nil {
		return fmt.Errorf("%w: invalid tool id", shared.ErrValidation)
	}

	// Get the tool to verify ownership
	t, err := s.toolRepo.GetByTenantAndID(ctx, tid, toid)
	if err != nil {
		return err
	}

	// Verify ownership
	if err := t.CanManage(tid); err != nil {
		return err
	}

	// Cascade deactivate pipelines using this tool before deletion
	if s.pipelineDeactivator != nil {
		count, pipelineIDs, err := s.pipelineDeactivator.DeactivatePipelinesByTool(ctx, t.Name)
		if err != nil {
			s.logger.Warn("failed to deactivate pipelines before custom tool deletion",
				"tenant_id", tenantID,
				"tool_id", toolID,
				"tool_name", t.Name,
				"error", err)
		} else if count > 0 {
			s.logger.Info("cascade deactivated pipelines before custom tool deletion",
				"tenant_id", tenantID,
				"tool_id", toolID,
				"tool_name", t.Name,
				"deactivated_count", count,
				"pipeline_ids", pipelineIDs)
		}
	}

	return s.toolRepo.DeleteTenantTool(ctx, tid, toid)
}

// ActivateCustomTool activates a tenant custom tool.
func (s *ToolService) ActivateCustomTool(ctx context.Context, tenantID, toolID string) (*tool.Tool, error) {
	s.logger.Info("activating custom tool", "tenant_id", tenantID, "tool_id", toolID)

	tid, err := shared.IDFromString(tenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}

	t, err := s.GetCustomTool(ctx, tenantID, toolID)
	if err != nil {
		return nil, err
	}

	// Verify ownership
	if err := t.CanManage(tid); err != nil {
		return nil, err
	}

	t.Activate()

	if err := s.toolRepo.Update(ctx, t); err != nil {
		return nil, err
	}

	return t, nil
}

// DeactivateCustomTool deactivates a tenant custom tool.
// Also cascade deactivates any active pipelines that use this tool.
func (s *ToolService) DeactivateCustomTool(ctx context.Context, tenantID, toolID string) (*tool.Tool, error) {
	s.logger.Info("deactivating custom tool", "tenant_id", tenantID, "tool_id", toolID)

	tid, err := shared.IDFromString(tenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}

	t, err := s.GetCustomTool(ctx, tenantID, toolID)
	if err != nil {
		return nil, err
	}

	// Verify ownership
	if err := t.CanManage(tid); err != nil {
		return nil, err
	}

	// Cascade deactivate pipelines using this tool
	if s.pipelineDeactivator != nil {
		count, pipelineIDs, err := s.pipelineDeactivator.DeactivatePipelinesByTool(ctx, t.Name)
		if err != nil {
			s.logger.Warn("failed to deactivate pipelines for custom tool",
				"tenant_id", tenantID,
				"tool_id", toolID,
				"tool_name", t.Name,
				"error", err)
		} else if count > 0 {
			s.logger.Info("cascade deactivated pipelines for custom tool",
				"tenant_id", tenantID,
				"tool_id", toolID,
				"tool_name", t.Name,
				"deactivated_count", count,
				"pipeline_ids", pipelineIDs)
		}
	}

	t.Deactivate()

	if err := s.toolRepo.Update(ctx, t); err != nil {
		return nil, err
	}

	return t, nil
}

// =============================================================================
// Tenant Tool Config Operations
// =============================================================================

// CreateTenantToolConfigInput represents the input for creating a tenant tool config.
type CreateTenantToolConfigInput struct {
	TenantID  string         `json:"tenant_id" validate:"required,uuid"`
	ToolID    string         `json:"tool_id" validate:"required,uuid"`
	Config    map[string]any `json:"config"`
	IsEnabled bool           `json:"is_enabled"`
	UpdatedBy string         `json:"updated_by" validate:"omitempty,uuid"`
}

// CreateTenantToolConfig creates a new tenant tool configuration.
func (s *ToolService) CreateTenantToolConfig(ctx context.Context, input CreateTenantToolConfigInput) (*tool.TenantToolConfig, error) {
	s.logger.Info("creating tenant tool config", "tenant_id", input.TenantID, "tool_id", input.ToolID)

	tenantID, err := shared.IDFromString(input.TenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}

	toolID, err := shared.IDFromString(input.ToolID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tool id", shared.ErrValidation)
	}

	// Verify tool exists
	if _, err := s.toolRepo.GetByID(ctx, toolID); err != nil {
		return nil, fmt.Errorf("tool not found: %w", err)
	}

	var updatedBy *shared.ID
	if input.UpdatedBy != "" {
		uid, err := shared.IDFromString(input.UpdatedBy)
		if err != nil {
			return nil, fmt.Errorf("%w: invalid updated_by id", shared.ErrValidation)
		}
		updatedBy = &uid
	}

	config, err := tool.NewTenantToolConfig(tenantID, toolID, input.Config, updatedBy)
	if err != nil {
		return nil, err
	}

	config.IsEnabled = input.IsEnabled

	if err := s.configRepo.Create(ctx, config); err != nil {
		return nil, err
	}

	return config, nil
}

// GetTenantToolConfig retrieves a tenant tool configuration.
func (s *ToolService) GetTenantToolConfig(ctx context.Context, tenantID, toolID string) (*tool.TenantToolConfig, error) {
	tid, err := shared.IDFromString(tenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}

	toid, err := shared.IDFromString(toolID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tool id", shared.ErrValidation)
	}

	return s.configRepo.GetByTenantAndTool(ctx, tid, toid)
}

// GetEffectiveToolConfig retrieves the effective (merged) configuration for a tool.
func (s *ToolService) GetEffectiveToolConfig(ctx context.Context, tenantID, toolID string) (map[string]any, error) {
	tid, err := shared.IDFromString(tenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}

	toid, err := shared.IDFromString(toolID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tool id", shared.ErrValidation)
	}

	return s.configRepo.GetEffectiveConfig(ctx, tid, toid)
}

// ListTenantToolConfigsInput represents the input for listing tenant tool configs.
type ListTenantToolConfigsInput struct {
	TenantID  string `json:"tenant_id" validate:"required,uuid"`
	ToolID    string `json:"tool_id" validate:"omitempty,uuid"`
	IsEnabled *bool  `json:"is_enabled"`
	Page      int    `json:"page"`
	PerPage   int    `json:"per_page"`
}

// ListTenantToolConfigs lists tenant tool configurations.
func (s *ToolService) ListTenantToolConfigs(ctx context.Context, input ListTenantToolConfigsInput) (pagination.Result[*tool.TenantToolConfig], error) {
	tenantID, err := shared.IDFromString(input.TenantID)
	if err != nil {
		return pagination.Result[*tool.TenantToolConfig]{}, fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}

	filter := tool.TenantToolConfigFilter{
		TenantID:  tenantID,
		IsEnabled: input.IsEnabled,
	}

	if input.ToolID != "" {
		toolID, err := shared.IDFromString(input.ToolID)
		if err != nil {
			return pagination.Result[*tool.TenantToolConfig]{}, fmt.Errorf("%w: invalid tool id", shared.ErrValidation)
		}
		filter.ToolID = &toolID
	}

	page := pagination.New(input.Page, input.PerPage)
	return s.configRepo.List(ctx, filter, page)
}

// UpdateTenantToolConfigInput represents the input for updating a tenant tool config.
type UpdateTenantToolConfigInput struct {
	TenantID  string         `json:"tenant_id" validate:"required,uuid"`
	ToolID    string         `json:"tool_id" validate:"required,uuid"`
	Config    map[string]any `json:"config"`
	IsEnabled bool           `json:"is_enabled"`
	UpdatedBy string         `json:"updated_by" validate:"omitempty,uuid"`
}

// UpdateTenantToolConfig updates a tenant tool configuration (upsert).
func (s *ToolService) UpdateTenantToolConfig(ctx context.Context, input UpdateTenantToolConfigInput) (*tool.TenantToolConfig, error) {
	s.logger.Info("updating tenant tool config", "tenant_id", input.TenantID, "tool_id", input.ToolID)

	tenantID, err := shared.IDFromString(input.TenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}

	toolID, err := shared.IDFromString(input.ToolID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tool id", shared.ErrValidation)
	}

	// Verify tool exists
	if _, err := s.toolRepo.GetByID(ctx, toolID); err != nil {
		return nil, fmt.Errorf("tool not found: %w", err)
	}

	var updatedBy *shared.ID
	if input.UpdatedBy != "" {
		uid, err := shared.IDFromString(input.UpdatedBy)
		if err != nil {
			return nil, fmt.Errorf("%w: invalid updated_by id", shared.ErrValidation)
		}
		updatedBy = &uid
	}

	// Try to get existing config
	config, err := s.configRepo.GetByTenantAndTool(ctx, tenantID, toolID)
	if err != nil {
		// Create new if not found
		config, err = tool.NewTenantToolConfig(tenantID, toolID, input.Config, updatedBy)
		if err != nil {
			return nil, err
		}
		config.IsEnabled = input.IsEnabled
	} else {
		// Update existing
		if err := config.Update(input.Config, input.IsEnabled, updatedBy); err != nil {
			return nil, err
		}
	}

	if err := s.configRepo.Upsert(ctx, config); err != nil {
		return nil, err
	}

	return config, nil
}

// DeleteTenantToolConfig deletes a tenant tool configuration.
func (s *ToolService) DeleteTenantToolConfig(ctx context.Context, tenantID, toolID string) error {
	s.logger.Info("deleting tenant tool config", "tenant_id", tenantID, "tool_id", toolID)

	config, err := s.GetTenantToolConfig(ctx, tenantID, toolID)
	if err != nil {
		return err
	}

	return s.configRepo.Delete(ctx, config.ID)
}

// EnableToolForTenant enables a tool for a tenant.
func (s *ToolService) EnableToolForTenant(ctx context.Context, tenantID, toolID string) error {
	s.logger.Info("enabling tool for tenant", "tenant_id", tenantID, "tool_id", toolID)

	tid, err := shared.IDFromString(tenantID)
	if err != nil {
		return fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}

	toid, err := shared.IDFromString(toolID)
	if err != nil {
		return fmt.Errorf("%w: invalid tool id", shared.ErrValidation)
	}

	return s.configRepo.BulkEnable(ctx, tid, []shared.ID{toid})
}

// DisableToolForTenant disables a tool for a tenant.
func (s *ToolService) DisableToolForTenant(ctx context.Context, tenantID, toolID string) error {
	s.logger.Info("disabling tool for tenant", "tenant_id", tenantID, "tool_id", toolID)

	tid, err := shared.IDFromString(tenantID)
	if err != nil {
		return fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}

	toid, err := shared.IDFromString(toolID)
	if err != nil {
		return fmt.Errorf("%w: invalid tool id", shared.ErrValidation)
	}

	return s.configRepo.BulkDisable(ctx, tid, []shared.ID{toid})
}

// BulkEnableToolsInput represents the input for bulk enabling tools.
type BulkEnableToolsInput struct {
	TenantID string   `json:"tenant_id" validate:"required,uuid"`
	ToolIDs  []string `json:"tool_ids" validate:"required,min=1,dive,uuid"`
}

// BulkEnableTools enables multiple tools for a tenant.
func (s *ToolService) BulkEnableTools(ctx context.Context, input BulkEnableToolsInput) error {
	s.logger.Info("bulk enabling tools", "tenant_id", input.TenantID, "count", len(input.ToolIDs))

	tenantID, err := shared.IDFromString(input.TenantID)
	if err != nil {
		return fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}

	toolIDs := make([]shared.ID, 0, len(input.ToolIDs))
	for _, tid := range input.ToolIDs {
		id, err := shared.IDFromString(tid)
		if err != nil {
			return fmt.Errorf("%w: invalid tool id %s", shared.ErrValidation, tid)
		}
		toolIDs = append(toolIDs, id)
	}

	return s.configRepo.BulkEnable(ctx, tenantID, toolIDs)
}

// BulkDisableToolsInput represents the input for bulk disabling tools.
type BulkDisableToolsInput struct {
	TenantID string   `json:"tenant_id" validate:"required,uuid"`
	ToolIDs  []string `json:"tool_ids" validate:"required,min=1,dive,uuid"`
}

// BulkDisableTools disables multiple tools for a tenant.
func (s *ToolService) BulkDisableTools(ctx context.Context, input BulkDisableToolsInput) error {
	s.logger.Info("bulk disabling tools", "tenant_id", input.TenantID, "count", len(input.ToolIDs))

	tenantID, err := shared.IDFromString(input.TenantID)
	if err != nil {
		return fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}

	toolIDs := make([]shared.ID, 0, len(input.ToolIDs))
	for _, tid := range input.ToolIDs {
		id, err := shared.IDFromString(tid)
		if err != nil {
			return fmt.Errorf("%w: invalid tool id %s", shared.ErrValidation, tid)
		}
		toolIDs = append(toolIDs, id)
	}

	return s.configRepo.BulkDisable(ctx, tenantID, toolIDs)
}

// ListEnabledToolsForTenant lists all enabled tools for a tenant.
func (s *ToolService) ListEnabledToolsForTenant(ctx context.Context, tenantID string) ([]*tool.TenantToolConfig, error) {
	tid, err := shared.IDFromString(tenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}

	return s.configRepo.ListEnabledTools(ctx, tid)
}

// ListToolsWithConfigInput represents the input for listing tools with config.
type ListToolsWithConfigInput struct {
	TenantID  string   `json:"tenant_id" validate:"required,uuid"`
	Category  string   `json:"category" validate:"omitempty,max=50"` // Category name (dynamic from tool_categories)
	IsActive  *bool    `json:"is_active"`
	IsBuiltin *bool    `json:"is_builtin"`
	Search    string   `json:"search" validate:"max=255"`
	Tags      []string `json:"tags"`
	Page      int      `json:"page"`
	PerPage   int      `json:"per_page"`
}

// ListToolsWithConfig lists tools with their tenant-specific config.
func (s *ToolService) ListToolsWithConfig(ctx context.Context, input ListToolsWithConfigInput) (pagination.Result[*tool.ToolWithConfig], error) {
	tenantID, err := shared.IDFromString(input.TenantID)
	if err != nil {
		return pagination.Result[*tool.ToolWithConfig]{}, fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}

	filter := tool.ToolFilter{
		IsActive:  input.IsActive,
		IsBuiltin: input.IsBuiltin,
		Search:    input.Search,
		Tags:      input.Tags,
	}

	if input.Category != "" {
		filter.CategoryName = &input.Category
	}

	page := pagination.New(input.Page, input.PerPage)
	result, err := s.configRepo.ListToolsWithConfig(ctx, tenantID, filter, page)
	if err != nil {
		return result, err
	}

	// Enrich with tool availability info if agentRepo is available
	if s.agentRepo != nil {
		// Get all tools that have at least one agent available
		availableTools, err := s.agentRepo.GetAvailableToolsForTenant(ctx, tenantID)
		if err != nil {
			s.logger.Warn("Failed to get available tools, defaulting to all available",
				"error", err, "tenant_id", tenantID)
			// On error, mark all as available to not block UI
			for _, twc := range result.Data {
				twc.IsAvailable = true
			}
		} else {
			// Create a set for O(1) lookup
			availableSet := make(map[string]bool, len(availableTools))
			for _, t := range availableTools {
				availableSet[t] = true
			}

			// Mark each tool's availability
			for _, twc := range result.Data {
				twc.IsAvailable = availableSet[twc.Tool.Name]
			}
		}
	} else {
		// No agent repo, default to all available
		for _, twc := range result.Data {
			twc.IsAvailable = true
		}
	}

	return result, nil
}

// GetToolWithConfig retrieves a tool with its tenant-specific configuration.
func (s *ToolService) GetToolWithConfig(ctx context.Context, tenantID, toolID string) (*tool.ToolWithConfig, error) {
	tid, err := shared.IDFromString(tenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}

	toid, err := shared.IDFromString(toolID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tool id", shared.ErrValidation)
	}

	// Get tool
	t, err := s.toolRepo.GetByID(ctx, toid)
	if err != nil {
		return nil, err
	}

	// Get tenant config (may not exist)
	tenantConfig, _ := s.configRepo.GetByTenantAndTool(ctx, tid, toid)

	// Get effective config
	effectiveConfig, err := s.configRepo.GetEffectiveConfig(ctx, tid, toid)
	if err != nil {
		// If error, use default config
		effectiveConfig = t.DefaultConfig
	}

	isEnabled := true // Default enabled if no tenant config
	if tenantConfig != nil {
		isEnabled = tenantConfig.IsEnabled
	}

	// Fetch category info if available
	var embeddedCat *tool.EmbeddedCategory
	if t.CategoryID != nil && s.categoryRepo != nil {
		cat, err := s.categoryRepo.GetByID(ctx, *t.CategoryID)
		if err == nil && cat != nil {
			embeddedCat = &tool.EmbeddedCategory{
				ID:          cat.ID,
				Name:        cat.Name,
				DisplayName: cat.DisplayName,
				Icon:        cat.Icon,
				Color:       cat.Color,
			}
		}
	}

	return &tool.ToolWithConfig{
		Tool:            t,
		Category:        embeddedCat,
		TenantConfig:    tenantConfig,
		EffectiveConfig: effectiveConfig,
		IsEnabled:       isEnabled,
	}, nil
}

// =============================================================================
// Tool Execution Operations
// =============================================================================

// RecordToolExecutionInput represents the input for recording a tool execution.
type RecordToolExecutionInput struct {
	TenantID      string         `json:"tenant_id" validate:"required,uuid"`
	ToolID        string         `json:"tool_id" validate:"required,uuid"`
	AgentID       string         `json:"agent_id" validate:"omitempty,uuid"`
	PipelineRunID string         `json:"pipeline_run_id" validate:"omitempty,uuid"`
	StepRunID     string         `json:"step_run_id" validate:"omitempty,uuid"`
	InputConfig   map[string]any `json:"input_config"`
	TargetsCount  int            `json:"targets_count"`
}

// RecordToolExecution records a new tool execution.
func (s *ToolService) RecordToolExecution(ctx context.Context, input RecordToolExecutionInput) (*tool.ToolExecution, error) {
	tenantID, err := shared.IDFromString(input.TenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}

	toolID, err := shared.IDFromString(input.ToolID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tool id", shared.ErrValidation)
	}

	var agentID *shared.ID
	if input.AgentID != "" {
		aid, err := shared.IDFromString(input.AgentID)
		if err != nil {
			return nil, fmt.Errorf("%w: invalid agent id", shared.ErrValidation)
		}
		agentID = &aid
	}

	execution := tool.NewToolExecution(tenantID, toolID, agentID, input.InputConfig, input.TargetsCount)

	// Set optional pipeline/step run IDs
	if input.PipelineRunID != "" {
		prid, err := shared.IDFromString(input.PipelineRunID)
		if err != nil {
			return nil, fmt.Errorf("%w: invalid pipeline_run id", shared.ErrValidation)
		}
		execution.PipelineRunID = &prid
	}

	if input.StepRunID != "" {
		srid, err := shared.IDFromString(input.StepRunID)
		if err != nil {
			return nil, fmt.Errorf("%w: invalid step_run id", shared.ErrValidation)
		}
		execution.StepRunID = &srid
	}

	if err := s.executionRepo.Create(ctx, execution); err != nil {
		return nil, err
	}

	return execution, nil
}

// CompleteToolExecutionInput represents the input for completing a tool execution.
type CompleteToolExecutionInput struct {
	ExecutionID   string         `json:"execution_id" validate:"required,uuid"`
	FindingsCount int            `json:"findings_count"`
	OutputSummary map[string]any `json:"output_summary"`
}

// CompleteToolExecution marks a tool execution as completed.
func (s *ToolService) CompleteToolExecution(ctx context.Context, input CompleteToolExecutionInput) (*tool.ToolExecution, error) {
	s.logger.Info("completing tool execution", "execution_id", input.ExecutionID)

	executionID, err := shared.IDFromString(input.ExecutionID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid execution id", shared.ErrValidation)
	}

	execution, err := s.executionRepo.GetByID(ctx, executionID)
	if err != nil {
		return nil, err
	}

	execution.Complete(input.FindingsCount, input.OutputSummary)

	if err := s.executionRepo.Update(ctx, execution); err != nil {
		return nil, err
	}

	return execution, nil
}

// FailToolExecutionInput represents the input for failing a tool execution.
type FailToolExecutionInput struct {
	ExecutionID  string `json:"execution_id" validate:"required,uuid"`
	ErrorMessage string `json:"error_message" validate:"required,max=2000"`
}

// FailToolExecution marks a tool execution as failed.
func (s *ToolService) FailToolExecution(ctx context.Context, input FailToolExecutionInput) (*tool.ToolExecution, error) {
	s.logger.Info("failing tool execution", "execution_id", input.ExecutionID)

	executionID, err := shared.IDFromString(input.ExecutionID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid execution id", shared.ErrValidation)
	}

	execution, err := s.executionRepo.GetByID(ctx, executionID)
	if err != nil {
		return nil, err
	}

	execution.Fail(input.ErrorMessage)

	if err := s.executionRepo.Update(ctx, execution); err != nil {
		return nil, err
	}

	return execution, nil
}

// TimeoutToolExecution marks a tool execution as timed out.
func (s *ToolService) TimeoutToolExecution(ctx context.Context, executionID string) (*tool.ToolExecution, error) {
	s.logger.Info("timing out tool execution", "execution_id", executionID)

	eid, err := shared.IDFromString(executionID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid execution id", shared.ErrValidation)
	}

	execution, err := s.executionRepo.GetByID(ctx, eid)
	if err != nil {
		return nil, err
	}

	execution.Timeout()

	if err := s.executionRepo.Update(ctx, execution); err != nil {
		return nil, err
	}

	return execution, nil
}

// GetToolStats retrieves statistics for a specific tool.
func (s *ToolService) GetToolStats(ctx context.Context, tenantID, toolID string, days int) (*tool.ToolStats, error) {
	tid, err := shared.IDFromString(tenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}

	toid, err := shared.IDFromString(toolID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tool id", shared.ErrValidation)
	}

	if days <= 0 {
		days = 30 // Default to 30 days
	}

	return s.executionRepo.GetToolStats(ctx, tid, toid, days)
}

// GetTenantToolStats retrieves aggregated tool statistics for a tenant.
func (s *ToolService) GetTenantToolStats(ctx context.Context, tenantID string, days int) (*tool.TenantToolStats, error) {
	tid, err := shared.IDFromString(tenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}

	if days <= 0 {
		days = 30 // Default to 30 days
	}

	return s.executionRepo.GetTenantStats(ctx, tid, days)
}

// ListToolExecutionsInput represents the input for listing tool executions.
type ListToolExecutionsInput struct {
	TenantID      string `json:"tenant_id" validate:"required,uuid"`
	ToolID        string `json:"tool_id" validate:"omitempty,uuid"`
	AgentID       string `json:"agent_id" validate:"omitempty,uuid"`
	PipelineRunID string `json:"pipeline_run_id" validate:"omitempty,uuid"`
	Status        string `json:"status" validate:"omitempty,oneof=running completed failed timeout"`
	Page          int    `json:"page"`
	PerPage       int    `json:"per_page"`
}

// ListToolExecutions lists tool executions with filters.
func (s *ToolService) ListToolExecutions(ctx context.Context, input ListToolExecutionsInput) (pagination.Result[*tool.ToolExecution], error) {
	tenantID, err := shared.IDFromString(input.TenantID)
	if err != nil {
		return pagination.Result[*tool.ToolExecution]{}, fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}

	filter := tool.ToolExecutionFilter{
		TenantID: tenantID,
	}

	if input.ToolID != "" {
		toolID, err := shared.IDFromString(input.ToolID)
		if err != nil {
			return pagination.Result[*tool.ToolExecution]{}, fmt.Errorf("%w: invalid tool id", shared.ErrValidation)
		}
		filter.ToolID = &toolID
	}

	if input.AgentID != "" {
		agentID, err := shared.IDFromString(input.AgentID)
		if err != nil {
			return pagination.Result[*tool.ToolExecution]{}, fmt.Errorf("%w: invalid agent id", shared.ErrValidation)
		}
		filter.AgentID = &agentID
	}

	if input.PipelineRunID != "" {
		pipelineRunID, err := shared.IDFromString(input.PipelineRunID)
		if err != nil {
			return pagination.Result[*tool.ToolExecution]{}, fmt.Errorf("%w: invalid pipeline_run id", shared.ErrValidation)
		}
		filter.PipelineRunID = &pipelineRunID
	}

	if input.Status != "" {
		status := tool.ExecutionStatus(input.Status)
		filter.Status = &status
	}

	page := pagination.New(input.Page, input.PerPage)
	return s.executionRepo.List(ctx, filter, page)
}

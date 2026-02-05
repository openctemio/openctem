package handler

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/openctemio/api/internal/app"
	"github.com/openctemio/api/internal/infra/http/middleware"
	"github.com/openctemio/api/pkg/apierror"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/domain/tool"
	"github.com/openctemio/api/pkg/logger"
	"github.com/openctemio/api/pkg/validator"
)

// ToolHandler handles HTTP requests for tool registry.
type ToolHandler struct {
	service   *app.ToolService
	validator *validator.Validator
	logger    *logger.Logger
}

// NewToolHandler creates a new ToolHandler.
func NewToolHandler(service *app.ToolService, v *validator.Validator, log *logger.Logger) *ToolHandler {
	return &ToolHandler{
		service:   service,
		validator: v,
		logger:    log.With("handler", "tool"),
	}
}

// =============================================================================
// Request/Response Types
// =============================================================================

// CreateToolRequest represents the request body for creating a tool.
type CreateToolRequest struct {
	Name             string         `json:"name" validate:"required,min=1,max=50"`
	DisplayName      string         `json:"display_name" validate:"max=100"`
	Description      string         `json:"description" validate:"max=1000"`
	CategoryID       string         `json:"category_id" validate:"omitempty,uuid"` // UUID reference to tool_categories table
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

// UpdateToolRequest represents the request body for updating a tool.
type UpdateToolRequest struct {
	DisplayName      string         `json:"display_name" validate:"max=100"`
	Description      string         `json:"description" validate:"max=1000"`
	CategoryID       string         `json:"category_id" validate:"omitempty,uuid"` // Optional: link to tool_categories table
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

// EmbeddedCategoryResponse is a minimal category response for embedding in tools.
type EmbeddedCategoryResponse struct {
	ID          string `json:"id"`
	Name        string `json:"name"`         // slug: 'sast', 'dast', etc.
	DisplayName string `json:"display_name"` // 'SAST', 'DAST', etc.
	Icon        string `json:"icon"`
	Color       string `json:"color"`
}

// ToolResponse represents the response for a tool.
type ToolResponse struct {
	ID               string                    `json:"id"`
	TenantID         *string                   `json:"tenant_id,omitempty"` // nil for platform tools, UUID for custom tools
	Name             string                    `json:"name"`
	DisplayName      string                    `json:"display_name"`
	Description      string                    `json:"description,omitempty"`
	LogoURL          string                    `json:"logo_url,omitempty"`
	CategoryID       *string                   `json:"category_id,omitempty"` // Foreign key to tool_categories table
	Category         *EmbeddedCategoryResponse `json:"category,omitempty"`    // Embedded category info for UI grouping
	InstallMethod    string                    `json:"install_method"`
	InstallCmd       string                    `json:"install_cmd,omitempty"`
	UpdateCmd        string                    `json:"update_cmd,omitempty"`
	VersionCmd       string                    `json:"version_cmd,omitempty"`
	VersionRegex     string                    `json:"version_regex,omitempty"`
	CurrentVersion   string                    `json:"current_version,omitempty"`
	LatestVersion    string                    `json:"latest_version,omitempty"`
	HasUpdate        bool                      `json:"has_update"`
	ConfigFilePath   string                    `json:"config_file_path,omitempty"`
	ConfigSchema     map[string]any            `json:"config_schema,omitempty"`
	DefaultConfig    map[string]any            `json:"default_config,omitempty"`
	Capabilities     []string                  `json:"capabilities"`
	SupportedTargets []string                  `json:"supported_targets"`
	OutputFormats    []string                  `json:"output_formats"`
	DocsURL          string                    `json:"docs_url,omitempty"`
	GithubURL        string                    `json:"github_url,omitempty"`
	IsActive         bool                      `json:"is_active"`
	IsBuiltin        bool                      `json:"is_builtin"`
	IsPlatformTool   bool                      `json:"is_platform_tool"` // true for platform tools, false for custom
	Tags             []string                  `json:"tags"`
	Metadata         map[string]any            `json:"metadata,omitempty"`
	CreatedBy        *string                   `json:"created_by,omitempty"` // User ID who created the tool (for custom tools)
	CreatedAt        string                    `json:"created_at"`
	UpdatedAt        string                    `json:"updated_at"`
}

// TenantToolConfigRequest represents the request for tenant tool config.
type TenantToolConfigRequest struct {
	Config    map[string]any `json:"config"`
	IsEnabled bool           `json:"is_enabled"`
}

// TenantToolConfigResponse represents the response for tenant tool config.
type TenantToolConfigResponse struct {
	ID              string                   `json:"id"`
	TenantID        string                   `json:"tenant_id"`
	ToolID          string                   `json:"tool_id"`
	Config          map[string]any           `json:"config"`
	CustomTemplates []CustomTemplateResponse `json:"custom_templates,omitempty"`
	CustomPatterns  []CustomPatternResponse  `json:"custom_patterns,omitempty"`
	IsEnabled       bool                     `json:"is_enabled"`
	UpdatedBy       *string                  `json:"updated_by,omitempty"`
	CreatedAt       string                   `json:"created_at"`
	UpdatedAt       string                   `json:"updated_at"`
}

// CustomTemplateResponse represents a custom template in response.
type CustomTemplateResponse struct {
	Name    string `json:"name"`
	Path    string `json:"path,omitempty"`
	Content string `json:"content,omitempty"`
}

// CustomPatternResponse represents a custom pattern in response.
type CustomPatternResponse struct {
	Name    string `json:"name"`
	Pattern string `json:"pattern"`
}

// BulkToolIDsRequest represents request for bulk tool operations.
type BulkToolIDsRequest struct {
	ToolIDs []string `json:"tool_ids" validate:"required,min=1,dive,uuid"`
}

// ToolWithConfigResponse represents a tool with its tenant config.
type ToolWithConfigResponse struct {
	Tool            *ToolResponse             `json:"tool"`
	TenantConfig    *TenantToolConfigResponse `json:"tenant_config,omitempty"`
	EffectiveConfig map[string]any            `json:"effective_config"`
	IsEnabled       bool                      `json:"is_enabled"`
	IsAvailable     bool                      `json:"is_available"` // True if at least one agent supports this tool
}

// ToolStatsResponse represents tool statistics.
type ToolStatsResponse struct {
	ToolID         string `json:"tool_id"`
	TotalRuns      int64  `json:"total_runs"`
	SuccessfulRuns int64  `json:"successful_runs"`
	FailedRuns     int64  `json:"failed_runs"`
	TotalFindings  int64  `json:"total_findings"`
	AvgDurationMs  int64  `json:"avg_duration_ms"`
}

// TenantToolStatsResponse represents tenant tool statistics.
type TenantToolStatsResponse struct {
	TenantID       string              `json:"tenant_id"`
	TotalRuns      int64               `json:"total_runs"`
	SuccessfulRuns int64               `json:"successful_runs"`
	FailedRuns     int64               `json:"failed_runs"`
	TotalFindings  int64               `json:"total_findings"`
	ToolBreakdown  []ToolStatsResponse `json:"tool_breakdown"`
}

// =============================================================================
// Tool Handlers (System-wide)
// =============================================================================

// List handles GET /api/v1/tools
// @Summary      List tools
// @Description  Get a paginated list of available tools
// @Tags         Tools
// @Accept       json
// @Produce      json
// @Param        category      query     string   false  "Filter by category"
// @Param        capabilities  query     string   false  "Filter by capabilities (comma-separated)"
// @Param        is_active     query     boolean  false  "Filter by active status"
// @Param        is_builtin    query     boolean  false  "Filter by builtin status"
// @Param        search        query     string   false  "Search by name or description"
// @Param        tags          query     string   false  "Filter by tags (comma-separated)"
// @Param        page          query     int      false  "Page number" default(1)
// @Param        per_page      query     int      false  "Items per page" default(20)
// @Success      200  {object}  ListResponse[ToolResponse]
// @Failure      400  {object}  apierror.Error
// @Failure      500  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /tools [get]
func (h *ToolHandler) List(w http.ResponseWriter, r *http.Request) {
	input := app.ListToolsInput{
		Category: r.URL.Query().Get("category"),
		Search:   r.URL.Query().Get("search"),
		Page:     parseQueryInt(r.URL.Query().Get("page"), 1),
		PerPage:  parseQueryInt(r.URL.Query().Get("per_page"), 20),
	}

	if capabilities := r.URL.Query().Get("capabilities"); capabilities != "" {
		input.Capabilities = parseQueryArray(capabilities)
	}

	if tags := r.URL.Query().Get("tags"); tags != "" {
		input.Tags = parseQueryArray(tags)
	}

	if isActive := r.URL.Query().Get("is_active"); isActive != "" {
		val := isActive == queryParamTrue
		input.IsActive = &val
	}

	if isBuiltin := r.URL.Query().Get("is_builtin"); isBuiltin != "" {
		val := isBuiltin == queryParamTrue
		input.IsBuiltin = &val
	}

	result, err := h.service.ListTools(r.Context(), input)
	if err != nil {
		h.handleServiceError(w, err, "Tool")
		return
	}

	items := make([]*ToolResponse, len(result.Data))
	for i, t := range result.Data {
		items[i] = toToolResponse(t)
	}

	resp := map[string]any{
		"items":    items,
		"total":    result.Total,
		"page":     result.Page,
		"per_page": result.PerPage,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// Get handles GET /api/v1/tools/{id}
// @Summary      Get tool
// @Description  Get a single tool by ID
// @Tags         Tools
// @Accept       json
// @Produce      json
// @Param        id   path      string  true  "Tool ID"
// @Success      200  {object}  ToolResponse
// @Failure      400  {object}  apierror.Error
// @Failure      404  {object}  apierror.Error
// @Failure      500  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /tools/{id} [get]
func (h *ToolHandler) Get(w http.ResponseWriter, r *http.Request) {
	toolID := chi.URLParam(r, "id")

	t, err := h.service.GetTool(r.Context(), toolID)
	if err != nil {
		h.handleServiceError(w, err, "Tool")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(toToolResponse(t))
}

// GetByName handles GET /api/v1/tools/name/{name}
// @Summary      Get tool by name
// @Description  Get a single tool by name
// @Tags         Tools
// @Accept       json
// @Produce      json
// @Param        name  path      string  true  "Tool name"
// @Success      200   {object}  ToolResponse
// @Failure      400   {object}  apierror.Error
// @Failure      404   {object}  apierror.Error
// @Failure      500   {object}  apierror.Error
// @Security     BearerAuth
// @Router       /tools/name/{name} [get]
func (h *ToolHandler) GetByName(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")

	t, err := h.service.GetToolByName(r.Context(), name)
	if err != nil {
		h.handleServiceError(w, err, "Tool")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(toToolResponse(t))
}

// Create handles POST /api/v1/tools
// @Summary      Create tool
// @Description  Create a new tool in the registry (admin only)
// @Tags         Tools
// @Accept       json
// @Produce      json
// @Param        body  body      CreateToolRequest  true  "Tool data"
// @Success      201   {object}  ToolResponse
// @Failure      400   {object}  apierror.Error
// @Failure      409   {object}  apierror.Error
// @Failure      500   {object}  apierror.Error
// @Security     BearerAuth
// @Router       /tools [post]
func (h *ToolHandler) Create(w http.ResponseWriter, r *http.Request) {
	var req CreateToolRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}

	if err := h.validator.Validate(req); err != nil {
		h.handleValidationError(w, err)
		return
	}

	input := app.CreateToolInput{
		Name:             req.Name,
		DisplayName:      req.DisplayName,
		Description:      req.Description,
		CategoryID:       req.CategoryID,
		InstallMethod:    req.InstallMethod,
		InstallCmd:       req.InstallCmd,
		UpdateCmd:        req.UpdateCmd,
		VersionCmd:       req.VersionCmd,
		VersionRegex:     req.VersionRegex,
		ConfigSchema:     req.ConfigSchema,
		DefaultConfig:    req.DefaultConfig,
		Capabilities:     req.Capabilities,
		SupportedTargets: req.SupportedTargets,
		OutputFormats:    req.OutputFormats,
		DocsURL:          req.DocsURL,
		GithubURL:        req.GithubURL,
		LogoURL:          req.LogoURL,
		Tags:             req.Tags,
	}

	t, err := h.service.CreateTool(r.Context(), input)
	if err != nil {
		h.handleServiceError(w, err, "Tool")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(toToolResponse(t))
}

// Update handles PUT /api/v1/tools/{id}
// @Summary      Update tool
// @Description  Update an existing tool (admin only)
// @Tags         Tools
// @Accept       json
// @Produce      json
// @Param        id    path      string             true  "Tool ID"
// @Param        body  body      UpdateToolRequest  true  "Update data"
// @Success      200   {object}  ToolResponse
// @Failure      400   {object}  apierror.Error
// @Failure      404   {object}  apierror.Error
// @Failure      500   {object}  apierror.Error
// @Security     BearerAuth
// @Router       /tools/{id} [put]
func (h *ToolHandler) Update(w http.ResponseWriter, r *http.Request) {
	toolID := chi.URLParam(r, "id")

	var req UpdateToolRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}

	if err := h.validator.Validate(req); err != nil {
		h.handleValidationError(w, err)
		return
	}

	input := app.UpdateToolInput{
		ToolID:           toolID,
		DisplayName:      req.DisplayName,
		Description:      req.Description,
		InstallCmd:       req.InstallCmd,
		UpdateCmd:        req.UpdateCmd,
		VersionCmd:       req.VersionCmd,
		VersionRegex:     req.VersionRegex,
		ConfigSchema:     req.ConfigSchema,
		DefaultConfig:    req.DefaultConfig,
		Capabilities:     req.Capabilities,
		SupportedTargets: req.SupportedTargets,
		OutputFormats:    req.OutputFormats,
		DocsURL:          req.DocsURL,
		GithubURL:        req.GithubURL,
		LogoURL:          req.LogoURL,
		Tags:             req.Tags,
	}

	t, err := h.service.UpdateTool(r.Context(), input)
	if err != nil {
		h.handleServiceError(w, err, "Tool")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(toToolResponse(t))
}

// Delete handles DELETE /api/v1/tools/{id}
// @Summary      Delete tool
// @Description  Delete a tool from the registry (admin only, builtin tools cannot be deleted)
// @Tags         Tools
// @Accept       json
// @Produce      json
// @Param        id   path      string  true  "Tool ID"
// @Success      204  "No Content"
// @Failure      400  {object}  apierror.Error
// @Failure      403  {object}  apierror.Error
// @Failure      404  {object}  apierror.Error
// @Failure      500  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /tools/{id} [delete]
func (h *ToolHandler) Delete(w http.ResponseWriter, r *http.Request) {
	toolID := chi.URLParam(r, "id")

	if err := h.service.DeleteTool(r.Context(), toolID); err != nil {
		h.handleServiceError(w, err, "Tool")
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// Activate handles POST /api/v1/tools/{id}/activate
// @Summary      Activate tool
// @Description  Activate a tool to make it available for use
// @Tags         Tools
// @Accept       json
// @Produce      json
// @Param        id   path      string  true  "Tool ID"
// @Success      200  {object}  ToolResponse
// @Failure      400  {object}  apierror.Error
// @Failure      404  {object}  apierror.Error
// @Failure      500  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /tools/{id}/activate [post]
func (h *ToolHandler) Activate(w http.ResponseWriter, r *http.Request) {
	toolID := chi.URLParam(r, "id")

	t, err := h.service.ActivateTool(r.Context(), toolID)
	if err != nil {
		h.handleServiceError(w, err, "Tool")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(toToolResponse(t))
}

// Deactivate handles POST /api/v1/tools/{id}/deactivate
// @Summary      Deactivate tool
// @Description  Deactivate a tool to make it unavailable for use
// @Tags         Tools
// @Accept       json
// @Produce      json
// @Param        id   path      string  true  "Tool ID"
// @Success      200  {object}  ToolResponse
// @Failure      400  {object}  apierror.Error
// @Failure      404  {object}  apierror.Error
// @Failure      500  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /tools/{id}/deactivate [post]
func (h *ToolHandler) Deactivate(w http.ResponseWriter, r *http.Request) {
	toolID := chi.URLParam(r, "id")

	t, err := h.service.DeactivateTool(r.Context(), toolID)
	if err != nil {
		h.handleServiceError(w, err, "Tool")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(toToolResponse(t))
}

// =============================================================================
// Platform Tools Handlers
// =============================================================================

// ListPlatformTools handles GET /api/v1/tools/platform
// @Summary      List platform tools
// @Description  Get a paginated list of platform-provided tools (available to all tenants)
// @Tags         Tools
// @Accept       json
// @Produce      json
// @Param        category      query     string   false  "Filter by category"
// @Param        capabilities  query     string   false  "Filter by capabilities (comma-separated)"
// @Param        is_active     query     boolean  false  "Filter by active status"
// @Param        search        query     string   false  "Search by name or description"
// @Param        tags          query     string   false  "Filter by tags (comma-separated)"
// @Param        page          query     int      false  "Page number" default(1)
// @Param        per_page      query     int      false  "Items per page" default(20)
// @Success      200  {object}  ListResponse[ToolResponse]
// @Failure      400  {object}  apierror.Error
// @Failure      500  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /tools/platform [get]
func (h *ToolHandler) ListPlatformTools(w http.ResponseWriter, r *http.Request) {
	input := app.ListPlatformToolsInput{
		Category: r.URL.Query().Get("category"),
		Search:   r.URL.Query().Get("search"),
		Page:     parseQueryInt(r.URL.Query().Get("page"), 1),
		PerPage:  parseQueryInt(r.URL.Query().Get("per_page"), 20),
	}

	if capabilities := r.URL.Query().Get("capabilities"); capabilities != "" {
		input.Capabilities = parseQueryArray(capabilities)
	}

	if tags := r.URL.Query().Get("tags"); tags != "" {
		input.Tags = parseQueryArray(tags)
	}

	if isActive := r.URL.Query().Get("is_active"); isActive != "" {
		val := isActive == queryParamTrue
		input.IsActive = &val
	}

	result, err := h.service.ListPlatformTools(r.Context(), input)
	if err != nil {
		h.handleServiceError(w, err, "Platform tools")
		return
	}

	items := make([]*ToolResponse, len(result.Data))
	for i, t := range result.Data {
		items[i] = toToolResponse(t)
	}

	resp := map[string]any{
		"items":    items,
		"total":    result.Total,
		"page":     result.Page,
		"per_page": result.PerPage,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// =============================================================================
// Tenant Custom Tools Handlers
// =============================================================================

// ListCustomTools handles GET /api/v1/custom-tools
// @Summary      List custom tools
// @Description  Get a paginated list of tenant's custom tools
// @Tags         Custom Tools
// @Accept       json
// @Produce      json
// @Param        category      query     string   false  "Filter by category"
// @Param        capabilities  query     string   false  "Filter by capabilities (comma-separated)"
// @Param        is_active     query     boolean  false  "Filter by active status"
// @Param        search        query     string   false  "Search by name or description"
// @Param        tags          query     string   false  "Filter by tags (comma-separated)"
// @Param        page          query     int      false  "Page number" default(1)
// @Param        per_page      query     int      false  "Items per page" default(20)
// @Success      200  {object}  ListResponse[ToolResponse]
// @Failure      400  {object}  apierror.Error
// @Failure      500  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /custom-tools [get]
func (h *ToolHandler) ListCustomTools(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.GetTenantID(r.Context())

	input := app.ListCustomToolsInput{
		TenantID: tenantID,
		Category: r.URL.Query().Get("category"),
		Search:   r.URL.Query().Get("search"),
		Page:     parseQueryInt(r.URL.Query().Get("page"), 1),
		PerPage:  parseQueryInt(r.URL.Query().Get("per_page"), 20),
	}

	if capabilities := r.URL.Query().Get("capabilities"); capabilities != "" {
		input.Capabilities = parseQueryArray(capabilities)
	}

	if tags := r.URL.Query().Get("tags"); tags != "" {
		input.Tags = parseQueryArray(tags)
	}

	if isActive := r.URL.Query().Get("is_active"); isActive != "" {
		val := isActive == queryParamTrue
		input.IsActive = &val
	}

	result, err := h.service.ListCustomTools(r.Context(), input)
	if err != nil {
		h.handleServiceError(w, err, "Custom tools")
		return
	}

	items := make([]*ToolResponse, len(result.Data))
	for i, t := range result.Data {
		items[i] = toToolResponse(t)
	}

	resp := map[string]any{
		"items":    items,
		"total":    result.Total,
		"page":     result.Page,
		"per_page": result.PerPage,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// CreateCustomTool handles POST /api/v1/custom-tools
// @Summary      Create custom tool
// @Description  Create a new tenant custom tool
// @Tags         Custom Tools
// @Accept       json
// @Produce      json
// @Param        body  body      CreateToolRequest  true  "Tool data"
// @Success      201   {object}  ToolResponse
// @Failure      400   {object}  apierror.Error
// @Failure      409   {object}  apierror.Error
// @Failure      500   {object}  apierror.Error
// @Security     BearerAuth
// @Router       /custom-tools [post]
func (h *ToolHandler) CreateCustomTool(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.GetTenantID(r.Context())
	userID := middleware.GetUserID(r.Context())

	var req CreateToolRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}

	if err := h.validator.Validate(req); err != nil {
		h.handleValidationError(w, err)
		return
	}

	input := app.CreateCustomToolInput{
		TenantID:         tenantID,
		CreatedBy:        userID,
		Name:             req.Name,
		DisplayName:      req.DisplayName,
		Description:      req.Description,
		CategoryID:       req.CategoryID,
		InstallMethod:    req.InstallMethod,
		InstallCmd:       req.InstallCmd,
		UpdateCmd:        req.UpdateCmd,
		VersionCmd:       req.VersionCmd,
		VersionRegex:     req.VersionRegex,
		ConfigSchema:     req.ConfigSchema,
		DefaultConfig:    req.DefaultConfig,
		Capabilities:     req.Capabilities,
		SupportedTargets: req.SupportedTargets,
		OutputFormats:    req.OutputFormats,
		DocsURL:          req.DocsURL,
		GithubURL:        req.GithubURL,
		LogoURL:          req.LogoURL,
		Tags:             req.Tags,
	}

	t, err := h.service.CreateCustomTool(r.Context(), input)
	if err != nil {
		h.handleServiceError(w, err, "Custom tool")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(toToolResponse(t))
}

// GetCustomTool handles GET /api/v1/custom-tools/{id}
// @Summary      Get custom tool
// @Description  Get a single tenant custom tool by ID
// @Tags         Custom Tools
// @Accept       json
// @Produce      json
// @Param        id   path      string  true  "Tool ID"
// @Success      200  {object}  ToolResponse
// @Failure      400  {object}  apierror.Error
// @Failure      404  {object}  apierror.Error
// @Failure      500  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /custom-tools/{id} [get]
func (h *ToolHandler) GetCustomTool(w http.ResponseWriter, r *http.Request) {
	toolID := chi.URLParam(r, "id")
	tenantID := middleware.GetTenantID(r.Context())

	t, err := h.service.GetCustomTool(r.Context(), tenantID, toolID)
	if err != nil {
		h.handleServiceError(w, err, "Custom tool")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(toToolResponse(t))
}

// UpdateCustomTool handles PUT /api/v1/custom-tools/{id}
// @Summary      Update custom tool
// @Description  Update a tenant custom tool
// @Tags         Custom Tools
// @Accept       json
// @Produce      json
// @Param        id    path      string             true  "Tool ID"
// @Param        body  body      UpdateToolRequest  true  "Update data"
// @Success      200   {object}  ToolResponse
// @Failure      400   {object}  apierror.Error
// @Failure      403   {object}  apierror.Error
// @Failure      404   {object}  apierror.Error
// @Failure      500   {object}  apierror.Error
// @Security     BearerAuth
// @Router       /custom-tools/{id} [put]
func (h *ToolHandler) UpdateCustomTool(w http.ResponseWriter, r *http.Request) {
	toolID := chi.URLParam(r, "id")
	tenantID := middleware.GetTenantID(r.Context())

	var req UpdateToolRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}

	if err := h.validator.Validate(req); err != nil {
		h.handleValidationError(w, err)
		return
	}

	input := app.UpdateCustomToolInput{
		TenantID:         tenantID,
		ToolID:           toolID,
		DisplayName:      req.DisplayName,
		Description:      req.Description,
		InstallCmd:       req.InstallCmd,
		UpdateCmd:        req.UpdateCmd,
		VersionCmd:       req.VersionCmd,
		VersionRegex:     req.VersionRegex,
		ConfigSchema:     req.ConfigSchema,
		DefaultConfig:    req.DefaultConfig,
		Capabilities:     req.Capabilities,
		SupportedTargets: req.SupportedTargets,
		OutputFormats:    req.OutputFormats,
		DocsURL:          req.DocsURL,
		GithubURL:        req.GithubURL,
		LogoURL:          req.LogoURL,
		Tags:             req.Tags,
	}

	t, err := h.service.UpdateCustomTool(r.Context(), input)
	if err != nil {
		h.handleServiceError(w, err, "Custom tool")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(toToolResponse(t))
}

// DeleteCustomTool handles DELETE /api/v1/custom-tools/{id}
// @Summary      Delete custom tool
// @Description  Delete a tenant custom tool
// @Tags         Custom Tools
// @Accept       json
// @Produce      json
// @Param        id   path      string  true  "Tool ID"
// @Success      204  "No Content"
// @Failure      400  {object}  apierror.Error
// @Failure      403  {object}  apierror.Error
// @Failure      404  {object}  apierror.Error
// @Failure      500  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /custom-tools/{id} [delete]
func (h *ToolHandler) DeleteCustomTool(w http.ResponseWriter, r *http.Request) {
	toolID := chi.URLParam(r, "id")
	tenantID := middleware.GetTenantID(r.Context())

	if err := h.service.DeleteCustomTool(r.Context(), tenantID, toolID); err != nil {
		h.handleServiceError(w, err, "Custom tool")
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// ActivateCustomTool handles POST /api/v1/custom-tools/{id}/activate
// @Summary      Activate custom tool
// @Description  Activate a tenant custom tool
// @Tags         Custom Tools
// @Accept       json
// @Produce      json
// @Param        id   path      string  true  "Tool ID"
// @Success      200  {object}  ToolResponse
// @Failure      400  {object}  apierror.Error
// @Failure      403  {object}  apierror.Error
// @Failure      404  {object}  apierror.Error
// @Failure      500  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /custom-tools/{id}/activate [post]
func (h *ToolHandler) ActivateCustomTool(w http.ResponseWriter, r *http.Request) {
	toolID := chi.URLParam(r, "id")
	tenantID := middleware.GetTenantID(r.Context())

	t, err := h.service.ActivateCustomTool(r.Context(), tenantID, toolID)
	if err != nil {
		h.handleServiceError(w, err, "Custom tool")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(toToolResponse(t))
}

// DeactivateCustomTool handles POST /api/v1/custom-tools/{id}/deactivate
// @Summary      Deactivate custom tool
// @Description  Deactivate a tenant custom tool
// @Tags         Custom Tools
// @Accept       json
// @Produce      json
// @Param        id   path      string  true  "Tool ID"
// @Success      200  {object}  ToolResponse
// @Failure      400  {object}  apierror.Error
// @Failure      403  {object}  apierror.Error
// @Failure      404  {object}  apierror.Error
// @Failure      500  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /custom-tools/{id}/deactivate [post]
func (h *ToolHandler) DeactivateCustomTool(w http.ResponseWriter, r *http.Request) {
	toolID := chi.URLParam(r, "id")
	tenantID := middleware.GetTenantID(r.Context())

	t, err := h.service.DeactivateCustomTool(r.Context(), tenantID, toolID)
	if err != nil {
		h.handleServiceError(w, err, "Custom tool")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(toToolResponse(t))
}

// =============================================================================
// Tenant Tool Config Handlers
// =============================================================================

// ListTenantConfigs handles GET /api/v1/tenant-tools
// @Summary      List tenant tool configs
// @Description  Get a paginated list of tenant tool configurations
// @Tags         Tenant Tools
// @Accept       json
// @Produce      json
// @Param        tool_id    query     string   false  "Filter by tool ID"
// @Param        is_enabled query     boolean  false  "Filter by enabled status"
// @Param        page       query     int      false  "Page number" default(1)
// @Param        per_page   query     int      false  "Items per page" default(20)
// @Success      200  {object}  ListResponse[TenantToolConfigResponse]
// @Failure      400  {object}  apierror.Error
// @Failure      500  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /tenant-tools [get]
func (h *ToolHandler) ListTenantConfigs(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.GetTenantID(r.Context())

	input := app.ListTenantToolConfigsInput{
		TenantID: tenantID,
		ToolID:   r.URL.Query().Get("tool_id"),
		Page:     parseQueryInt(r.URL.Query().Get("page"), 1),
		PerPage:  parseQueryInt(r.URL.Query().Get("per_page"), 20),
	}

	if isEnabled := r.URL.Query().Get("is_enabled"); isEnabled != "" {
		val := isEnabled == queryParamTrue
		input.IsEnabled = &val
	}

	result, err := h.service.ListTenantToolConfigs(r.Context(), input)
	if err != nil {
		h.handleServiceError(w, err, "Tenant tool config")
		return
	}

	items := make([]*TenantToolConfigResponse, len(result.Data))
	for i, c := range result.Data {
		items[i] = toTenantToolConfigResponse(c)
	}

	resp := map[string]any{
		"items":    items,
		"total":    result.Total,
		"page":     result.Page,
		"per_page": result.PerPage,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// GetTenantConfig handles GET /api/v1/tenant-tools/{tool_id}
// @Summary      Get tenant tool config
// @Description  Get tenant-specific configuration for a tool
// @Tags         Tenant Tools
// @Accept       json
// @Produce      json
// @Param        tool_id  path      string  true  "Tool ID"
// @Success      200      {object}  TenantToolConfigResponse
// @Failure      400      {object}  apierror.Error
// @Failure      404      {object}  apierror.Error
// @Failure      500      {object}  apierror.Error
// @Security     BearerAuth
// @Router       /tenant-tools/{tool_id} [get]
func (h *ToolHandler) GetTenantConfig(w http.ResponseWriter, r *http.Request) {
	toolID := chi.URLParam(r, "tool_id")
	tenantID := middleware.GetTenantID(r.Context())

	config, err := h.service.GetTenantToolConfig(r.Context(), tenantID, toolID)
	if err != nil {
		h.handleServiceError(w, err, "Tenant tool config")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(toTenantToolConfigResponse(config))
}

// UpdateTenantConfig handles PUT /api/v1/tenant-tools/{tool_id}
// @Summary      Update tenant tool config
// @Description  Update or create tenant-specific configuration for a tool
// @Tags         Tenant Tools
// @Accept       json
// @Produce      json
// @Param        tool_id  path      string                   true  "Tool ID"
// @Param        body     body      TenantToolConfigRequest  true  "Config data"
// @Success      200      {object}  TenantToolConfigResponse
// @Failure      400      {object}  apierror.Error
// @Failure      404      {object}  apierror.Error
// @Failure      500      {object}  apierror.Error
// @Security     BearerAuth
// @Router       /tenant-tools/{tool_id} [put]
func (h *ToolHandler) UpdateTenantConfig(w http.ResponseWriter, r *http.Request) {
	toolID := chi.URLParam(r, "tool_id")
	tenantID := middleware.GetTenantID(r.Context())
	userID := middleware.GetUserID(r.Context())

	var req TenantToolConfigRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}

	input := app.UpdateTenantToolConfigInput{
		TenantID:  tenantID,
		ToolID:    toolID,
		Config:    req.Config,
		IsEnabled: req.IsEnabled,
		UpdatedBy: userID,
	}

	config, err := h.service.UpdateTenantToolConfig(r.Context(), input)
	if err != nil {
		h.handleServiceError(w, err, "Tenant tool config")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(toTenantToolConfigResponse(config))
}

// DeleteTenantConfig handles DELETE /api/v1/tenant-tools/{tool_id}
// @Summary      Delete tenant tool config
// @Description  Delete tenant-specific configuration for a tool
// @Tags         Tenant Tools
// @Accept       json
// @Produce      json
// @Param        tool_id  path      string  true  "Tool ID"
// @Success      204      "No Content"
// @Failure      400      {object}  apierror.Error
// @Failure      404      {object}  apierror.Error
// @Failure      500      {object}  apierror.Error
// @Security     BearerAuth
// @Router       /tenant-tools/{tool_id} [delete]
func (h *ToolHandler) DeleteTenantConfig(w http.ResponseWriter, r *http.Request) {
	toolID := chi.URLParam(r, "tool_id")
	tenantID := middleware.GetTenantID(r.Context())

	if err := h.service.DeleteTenantToolConfig(r.Context(), tenantID, toolID); err != nil {
		h.handleServiceError(w, err, "Tenant tool config")
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// GetEffectiveConfig handles GET /api/v1/tenant-tools/{tool_id}/effective-config
// @Summary      Get effective tool config
// @Description  Get the merged configuration (default + tenant overrides) for a tool
// @Tags         Tenant Tools
// @Accept       json
// @Produce      json
// @Param        tool_id  path      string  true  "Tool ID"
// @Success      200      {object}  map[string]any
// @Failure      400      {object}  apierror.Error
// @Failure      404      {object}  apierror.Error
// @Failure      500      {object}  apierror.Error
// @Security     BearerAuth
// @Router       /tenant-tools/{tool_id}/effective-config [get]
func (h *ToolHandler) GetEffectiveConfig(w http.ResponseWriter, r *http.Request) {
	toolID := chi.URLParam(r, "tool_id")
	tenantID := middleware.GetTenantID(r.Context())

	config, err := h.service.GetEffectiveToolConfig(r.Context(), tenantID, toolID)
	if err != nil {
		h.handleServiceError(w, err, "Effective config")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(config)
}

// BulkEnable handles POST /api/v1/tenant-tools/bulk-enable
// @Summary      Bulk enable tools
// @Description  Enable multiple tools for the current tenant
// @Tags         Tenant Tools
// @Accept       json
// @Produce      json
// @Param        body  body      BulkToolIDsRequest  true  "Tool IDs"
// @Success      204   "No Content"
// @Failure      400   {object}  apierror.Error
// @Failure      500   {object}  apierror.Error
// @Security     BearerAuth
// @Router       /tenant-tools/bulk-enable [post]
func (h *ToolHandler) BulkEnable(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.GetTenantID(r.Context())

	var req BulkToolIDsRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}

	if err := h.validator.Validate(req); err != nil {
		h.handleValidationError(w, err)
		return
	}

	input := app.BulkEnableToolsInput{
		TenantID: tenantID,
		ToolIDs:  req.ToolIDs,
	}

	if err := h.service.BulkEnableTools(r.Context(), input); err != nil {
		h.handleServiceError(w, err, "Bulk enable")
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// BulkDisable handles POST /api/v1/tenant-tools/bulk-disable
// @Summary      Bulk disable tools
// @Description  Disable multiple tools for the current tenant
// @Tags         Tenant Tools
// @Accept       json
// @Produce      json
// @Param        body  body      BulkToolIDsRequest  true  "Tool IDs"
// @Success      204   "No Content"
// @Failure      400   {object}  apierror.Error
// @Failure      500   {object}  apierror.Error
// @Security     BearerAuth
// @Router       /tenant-tools/bulk-disable [post]
func (h *ToolHandler) BulkDisable(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.GetTenantID(r.Context())

	var req BulkToolIDsRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}

	if err := h.validator.Validate(req); err != nil {
		h.handleValidationError(w, err)
		return
	}

	input := app.BulkDisableToolsInput{
		TenantID: tenantID,
		ToolIDs:  req.ToolIDs,
	}

	if err := h.service.BulkDisableTools(r.Context(), input); err != nil {
		h.handleServiceError(w, err, "Bulk disable")
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// ListAllTools handles GET /api/v1/tenant-tools/all-tools
// @Summary      List all tools with tenant config
// @Description  Get a paginated list of all tools with their tenant-specific enabled status
// @Tags         Tenant Tools
// @Accept       json
// @Produce      json
// @Param        category   query     string   false  "Filter by category"
// @Param        is_active  query     boolean  false  "Filter by system-wide active status"
// @Param        is_builtin query     boolean  false  "Filter by builtin status"
// @Param        search     query     string   false  "Search by name or description"
// @Param        page       query     int      false  "Page number" default(1)
// @Param        per_page   query     int      false  "Items per page" default(20)
// @Success      200  {object}  ListResponse[ToolWithConfigResponse]
// @Failure      400  {object}  apierror.Error
// @Failure      500  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /tenant-tools/all-tools [get]
func (h *ToolHandler) ListAllTools(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.GetTenantID(r.Context())

	input := app.ListToolsWithConfigInput{
		TenantID: tenantID,
		Category: r.URL.Query().Get("category"),
		Search:   r.URL.Query().Get("search"),
		Page:     parseQueryInt(r.URL.Query().Get("page"), 1),
		PerPage:  parseQueryInt(r.URL.Query().Get("per_page"), 20),
	}

	if isActive := r.URL.Query().Get("is_active"); isActive != "" {
		val := isActive == queryParamTrue
		input.IsActive = &val
	}

	if isBuiltin := r.URL.Query().Get("is_builtin"); isBuiltin != "" {
		val := isBuiltin == queryParamTrue
		input.IsBuiltin = &val
	}

	result, err := h.service.ListToolsWithConfig(r.Context(), input)
	if err != nil {
		h.handleServiceError(w, err, "Tools with config")
		return
	}

	items := make([]*ToolWithConfigResponse, len(result.Data))
	for i, twc := range result.Data {
		resp := &ToolWithConfigResponse{
			Tool:            toToolResponseWithCategory(twc.Tool, twc.Category),
			EffectiveConfig: twc.EffectiveConfig,
			IsEnabled:       twc.IsEnabled,
			IsAvailable:     twc.IsAvailable,
		}
		if twc.TenantConfig != nil {
			resp.TenantConfig = toTenantToolConfigResponse(twc.TenantConfig)
		}
		items[i] = resp
	}

	respData := map[string]any{
		"items":    items,
		"total":    result.Total,
		"page":     result.Page,
		"per_page": result.PerPage,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(respData)
}

// GetToolWithConfig handles GET /api/v1/tenant-tools/{tool_id}/with-config
// @Summary      Get tool with tenant config
// @Description  Get a tool with its tenant-specific configuration and effective config
// @Tags         Tenant Tools
// @Accept       json
// @Produce      json
// @Param        tool_id  path      string  true  "Tool ID"
// @Success      200      {object}  ToolWithConfigResponse
// @Failure      400      {object}  apierror.Error
// @Failure      404      {object}  apierror.Error
// @Failure      500      {object}  apierror.Error
// @Security     BearerAuth
// @Router       /tenant-tools/{tool_id}/with-config [get]
func (h *ToolHandler) GetToolWithConfig(w http.ResponseWriter, r *http.Request) {
	toolID := chi.URLParam(r, "tool_id")
	tenantID := middleware.GetTenantID(r.Context())

	twc, err := h.service.GetToolWithConfig(r.Context(), tenantID, toolID)
	if err != nil {
		h.handleServiceError(w, err, "Tool with config")
		return
	}

	resp := &ToolWithConfigResponse{
		Tool:            toToolResponseWithCategory(twc.Tool, twc.Category),
		EffectiveConfig: twc.EffectiveConfig,
		IsEnabled:       twc.IsEnabled,
		IsAvailable:     twc.IsAvailable,
	}

	if twc.TenantConfig != nil {
		resp.TenantConfig = toTenantToolConfigResponse(twc.TenantConfig)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// =============================================================================
// Stats Handlers
// =============================================================================

// GetTenantStats handles GET /api/v1/tool-stats
// @Summary      Get tenant tool stats
// @Description  Get aggregated tool execution statistics for the current tenant
// @Tags         Tool Stats
// @Accept       json
// @Produce      json
// @Param        days  query     int  false  "Number of days to include" default(30)
// @Success      200   {object}  TenantToolStatsResponse
// @Failure      400   {object}  apierror.Error
// @Failure      500   {object}  apierror.Error
// @Security     BearerAuth
// @Router       /tool-stats [get]
func (h *ToolHandler) GetTenantStats(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.GetTenantID(r.Context())
	days := parseQueryInt(r.URL.Query().Get("days"), 30)

	// Enforce maximum days limit to prevent expensive queries
	const maxDays = 365
	if days < 1 {
		days = 1
	}
	if days > maxDays {
		days = maxDays
	}

	stats, err := h.service.GetTenantToolStats(r.Context(), tenantID, days)
	if err != nil {
		h.handleServiceError(w, err, "Tool stats")
		return
	}

	resp := toTenantToolStatsResponse(stats)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// GetToolStats handles GET /api/v1/tool-stats/{tool_id}
// @Summary      Get tool stats
// @Description  Get execution statistics for a specific tool
// @Tags         Tool Stats
// @Accept       json
// @Produce      json
// @Param        tool_id  path      string  true   "Tool ID"
// @Param        days     query     int     false  "Number of days to include" default(30)
// @Success      200      {object}  ToolStatsResponse
// @Failure      400      {object}  apierror.Error
// @Failure      404      {object}  apierror.Error
// @Failure      500      {object}  apierror.Error
// @Security     BearerAuth
// @Router       /tool-stats/{tool_id} [get]
func (h *ToolHandler) GetToolStats(w http.ResponseWriter, r *http.Request) {
	toolID := chi.URLParam(r, "tool_id")
	tenantID := middleware.GetTenantID(r.Context())
	days := parseQueryInt(r.URL.Query().Get("days"), 30)

	// Enforce maximum days limit to prevent expensive queries
	const maxDays = 365
	if days < 1 {
		days = 1
	}
	if days > maxDays {
		days = maxDays
	}

	stats, err := h.service.GetToolStats(r.Context(), tenantID, toolID, days)
	if err != nil {
		h.handleServiceError(w, err, "Tool stats")
		return
	}

	resp := &ToolStatsResponse{
		ToolID:         stats.ToolID.String(),
		TotalRuns:      stats.TotalRuns,
		SuccessfulRuns: stats.SuccessfulRuns,
		FailedRuns:     stats.FailedRuns,
		TotalFindings:  stats.TotalFindings,
		AvgDurationMs:  stats.AvgDurationMs,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// =============================================================================
// Helper Functions
// =============================================================================

func toToolResponse(t *tool.Tool) *ToolResponse {
	resp := &ToolResponse{
		ID:               t.ID.String(),
		Name:             t.Name,
		DisplayName:      t.DisplayName,
		Description:      t.Description,
		LogoURL:          t.LogoURL,
		InstallMethod:    string(t.InstallMethod),
		InstallCmd:       t.InstallCmd,
		UpdateCmd:        t.UpdateCmd,
		VersionCmd:       t.VersionCmd,
		VersionRegex:     t.VersionRegex,
		CurrentVersion:   t.CurrentVersion,
		LatestVersion:    t.LatestVersion,
		HasUpdate:        t.HasUpdateAvailable(),
		ConfigFilePath:   t.ConfigFilePath,
		ConfigSchema:     t.ConfigSchema,
		DefaultConfig:    t.DefaultConfig,
		Capabilities:     t.Capabilities,
		SupportedTargets: t.SupportedTargets,
		OutputFormats:    t.OutputFormats,
		DocsURL:          t.DocsURL,
		GithubURL:        t.GithubURL,
		IsActive:         t.IsActive,
		IsBuiltin:        t.IsBuiltin,
		IsPlatformTool:   t.IsPlatformTool(),
		Tags:             t.Tags,
		Metadata:         t.Metadata,
		CreatedAt:        t.CreatedAt.Format("2006-01-02T15:04:05Z07:00"),
		UpdatedAt:        t.UpdatedAt.Format("2006-01-02T15:04:05Z07:00"),
	}

	// Set tenant_id for custom tools
	if t.TenantID != nil {
		tenantIDStr := t.TenantID.String()
		resp.TenantID = &tenantIDStr
	}

	// Set category_id
	if t.CategoryID != nil {
		categoryIDStr := t.CategoryID.String()
		resp.CategoryID = &categoryIDStr
	}

	// Set created_by for custom tools
	if t.CreatedBy != nil {
		createdByStr := t.CreatedBy.String()
		resp.CreatedBy = &createdByStr
	}

	// Ensure slices are not nil
	if resp.Capabilities == nil {
		resp.Capabilities = []string{}
	}
	if resp.SupportedTargets == nil {
		resp.SupportedTargets = []string{}
	}
	if resp.OutputFormats == nil {
		resp.OutputFormats = []string{}
	}
	if resp.Tags == nil {
		resp.Tags = []string{}
	}

	return resp
}

// toToolResponseWithCategory converts tool to response with embedded category.
func toToolResponseWithCategory(t *tool.Tool, cat *tool.EmbeddedCategory) *ToolResponse {
	resp := toToolResponse(t)
	if cat != nil {
		resp.Category = &EmbeddedCategoryResponse{
			ID:          cat.ID.String(),
			Name:        cat.Name,
			DisplayName: cat.DisplayName,
			Icon:        cat.Icon,
			Color:       cat.Color,
		}
	}
	return resp
}

func toTenantToolConfigResponse(c *tool.TenantToolConfig) *TenantToolConfigResponse {
	resp := &TenantToolConfigResponse{
		ID:        c.ID.String(),
		TenantID:  c.TenantID.String(),
		ToolID:    c.ToolID.String(),
		Config:    c.Config,
		IsEnabled: c.IsEnabled,
		CreatedAt: c.CreatedAt.Format("2006-01-02T15:04:05Z07:00"),
		UpdatedAt: c.UpdatedAt.Format("2006-01-02T15:04:05Z07:00"),
	}

	if c.UpdatedBy != nil {
		updatedByStr := c.UpdatedBy.String()
		resp.UpdatedBy = &updatedByStr
	}

	if c.Config == nil {
		resp.Config = make(map[string]any)
	}

	// Convert custom templates
	if len(c.CustomTemplates) > 0 {
		resp.CustomTemplates = make([]CustomTemplateResponse, len(c.CustomTemplates))
		for i, t := range c.CustomTemplates {
			resp.CustomTemplates[i] = CustomTemplateResponse{
				Name:    t.Name,
				Path:    t.Path,
				Content: t.Content,
			}
		}
	}

	// Convert custom patterns
	if len(c.CustomPatterns) > 0 {
		resp.CustomPatterns = make([]CustomPatternResponse, len(c.CustomPatterns))
		for i, p := range c.CustomPatterns {
			resp.CustomPatterns[i] = CustomPatternResponse{
				Name:    p.Name,
				Pattern: p.Pattern,
			}
		}
	}

	return resp
}

func toTenantToolStatsResponse(s *tool.TenantToolStats) *TenantToolStatsResponse {
	resp := &TenantToolStatsResponse{
		TenantID:       s.TenantID.String(),
		TotalRuns:      s.TotalRuns,
		SuccessfulRuns: s.SuccessfulRuns,
		FailedRuns:     s.FailedRuns,
		TotalFindings:  s.TotalFindings,
	}

	if len(s.ToolBreakdown) > 0 {
		resp.ToolBreakdown = make([]ToolStatsResponse, len(s.ToolBreakdown))
		for i, ts := range s.ToolBreakdown {
			resp.ToolBreakdown[i] = ToolStatsResponse{
				ToolID:         ts.ToolID.String(),
				TotalRuns:      ts.TotalRuns,
				SuccessfulRuns: ts.SuccessfulRuns,
				FailedRuns:     ts.FailedRuns,
				TotalFindings:  ts.TotalFindings,
				AvgDurationMs:  ts.AvgDurationMs,
			}
		}
	} else {
		resp.ToolBreakdown = []ToolStatsResponse{}
	}

	return resp
}

func (h *ToolHandler) handleValidationError(w http.ResponseWriter, err error) {
	var validationErrors validator.ValidationErrors
	if errors.As(err, &validationErrors) {
		apiErrors := make([]apierror.ValidationError, len(validationErrors))
		for i, ve := range validationErrors {
			apiErrors[i] = apierror.ValidationError{
				Field:   ve.Field,
				Message: ve.Message,
			}
		}
		apierror.ValidationFailed("Validation failed", apiErrors).WriteJSON(w)
		return
	}
	apierror.BadRequest("Validation error").WriteJSON(w)
}

func (h *ToolHandler) handleServiceError(w http.ResponseWriter, err error, resource string) {
	switch {
	case errors.Is(err, shared.ErrNotFound):
		apierror.NotFound(resource).WriteJSON(w)
	case errors.Is(err, shared.ErrAlreadyExists):
		apierror.Conflict(resource + " already exists").WriteJSON(w)
	case errors.Is(err, shared.ErrValidation):
		apierror.BadRequest(err.Error()).WriteJSON(w)
	case errors.Is(err, shared.ErrUnauthorized):
		apierror.Unauthorized("").WriteJSON(w)
	case errors.Is(err, shared.ErrForbidden):
		apierror.Forbidden("Builtin tools cannot be deleted").WriteJSON(w)
	default:
		h.logger.Error("service error", "error", err)
		apierror.InternalError(err).WriteJSON(w)
	}
}

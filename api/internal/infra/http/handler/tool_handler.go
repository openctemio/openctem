package handler

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	auditsvc "github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/internal/app/tool"
	"github.com/openctemio/openctem/api/pkg/domain/scan"

	"github.com/go-chi/chi/v5"

	"github.com/openctemio/openctem/api/internal/infra/http/include"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/apierror"
	"github.com/openctemio/openctem/api/pkg/domain/audit"
	"github.com/openctemio/openctem/api/pkg/domain/permission"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	tooldom "github.com/openctemio/openctem/api/pkg/domain/tool"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/validator"
)

// ToolHandler handles HTTP requests for tool registry.
type ToolHandler struct {
	service   *tool.Service
	audit     *auditsvc.AuditService
	validator *validator.Validator
	logger    *logger.Logger
}

// NewToolHandler creates a new ToolHandler.
func NewToolHandler(service *tool.Service, v *validator.Validator, log *logger.Logger) *ToolHandler {
	return &ToolHandler{
		service:   service,
		validator: v,
		logger:    log.With("handler", "tool"),
	}
}

// SetAuditService records changes to tools and to the tenant's tool
// configuration in the tenant's audit log, with the state before and after
// (RFC-040 §5.11).
func (h *ToolHandler) SetAuditService(svc *auditsvc.AuditService) {
	h.audit = svc
}

func (h *ToolHandler) auditTool(r *http.Request, action audit.Action, id string, before, after *tooldom.Tool) {
	name := ""
	var b, a map[string]any
	if before != nil {
		b, name = auditSnapshot(toToolResponse(before)), before.Name
	}
	if after != nil {
		a, name = auditSnapshot(toToolResponse(after)), after.Name
	}
	auditResourceChange(h.audit, h.logger, r, action, audit.ResourceTypeTool, id, name, b, a)
}

// toolBefore reads the custom tool a change starts from; a failed read
// answers the request (a platform tool or another tenant's tool is not
// found), as the change would fail the same way.
func (h *ToolHandler) toolBefore(w http.ResponseWriter, r *http.Request, id string) (*tooldom.Tool, bool) {
	t, err := h.service.GetCustomTool(r.Context(), middleware.GetTenantID(r.Context()), id)
	if err != nil {
		h.handleServiceError(w, err, "Tool")
		return nil, false
	}
	return t, true
}

// tenantConfigSnapshot is the tenant's config of a tool for the audit log,
// nil when there is none yet.
func (h *ToolHandler) tenantConfigSnapshot(r *http.Request, tenantID, toolID string) map[string]any {
	c, err := h.service.GetTenantToolConfig(r.Context(), tenantID, toolID)
	if err != nil || c == nil {
		return nil
	}
	return auditSnapshot(toTenantToolConfigResponse(c))
}

// =============================================================================
// Request/Response Types
// =============================================================================

// CreateToolRequest represents the request body for creating a tool.
type CreateToolRequest struct {
	Name          string `json:"name" validate:"required,min=1,max=50"`
	DisplayName   string `json:"display_name" validate:"max=100"`
	Description   string `json:"description" validate:"max=1000"`
	CategoryID    string `json:"category_id" validate:"omitempty,uuid"` // UUID reference to tool_categories table
	InstallMethod string `json:"install_method" validate:"required,oneof=go pip npm docker binary"`
	InstallCmd    string `json:"install_cmd" validate:"max=500"`
	UpdateCmd     string `json:"update_cmd" validate:"max=500"`
	VersionCmd    string `json:"version_cmd" validate:"max=500"`
	VersionRegex  string `json:"version_regex" validate:"max=200"`
	// MinVersion is the oldest tool version the catalog accepts (a release
	// version such as "3.2.0"; empty: no minimum).
	MinVersion       string         `json:"min_version" validate:"max=50"`
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
	DisplayName  string `json:"display_name" validate:"max=100"`
	Description  string `json:"description" validate:"max=1000"`
	CategoryID   string `json:"category_id" validate:"omitempty,uuid"` // Optional: link to tool_categories table
	InstallCmd   string `json:"install_cmd" validate:"max=500"`
	UpdateCmd    string `json:"update_cmd" validate:"max=500"`
	VersionCmd   string `json:"version_cmd" validate:"max=500"`
	VersionRegex string `json:"version_regex" validate:"max=200"`
	// MinVersion is the oldest tool version the catalog accepts (a release
	// version such as "3.2.0"; empty: no minimum).
	MinVersion       string         `json:"min_version" validate:"max=50"`
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
	MinVersion       string                    `json:"min_version,omitempty"`
	HasUpdate        bool                      `json:"has_update"`
	ConfigFilePath   string                    `json:"config_file_path,omitempty"`
	ConfigSchema     map[string]any            `json:"config_schema,omitempty"`
	DefaultConfig    map[string]any            `json:"default_config,omitempty"`
	Capabilities     []string                  `json:"capabilities"`
	SupportedTargets []string                  `json:"supported_targets"`
	OutputFormats    []string                  `json:"output_formats"`
	// OutputTypes are the asset types a report of the tool may create
	// (scan stage catalog); read-only.
	OutputTypes    []string       `json:"output_types"`
	DocsURL        string         `json:"docs_url,omitempty"`
	GithubURL      string         `json:"github_url,omitempty"`
	IsActive       bool           `json:"is_active"`
	IsBuiltin      bool           `json:"is_builtin"`
	IsPlatformTool bool           `json:"is_platform_tool"` // true for platform tools, false for custom
	Tags           []string       `json:"tags"`
	Metadata       map[string]any `json:"metadata,omitempty"`
	CreatedBy      *string        `json:"created_by,omitempty"` // User ID who created the tool (for custom tools)
	CreatedAt      string         `json:"created_at"`
	UpdatedAt      string         `json:"updated_at"`
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

// ToolStatsResponse represents tool statistics.
type ToolStatsResponse struct {
	ToolID         string `json:"tool_id"`
	TotalRuns      int64  `json:"total_runs"`
	SuccessfulRuns int64  `json:"successful_runs"`
	FailedRuns     int64  `json:"failed_runs"`
	TotalFindings  int64  `json:"total_findings"`
	AvgDurationMs  int64  `json:"avg_duration_ms"`
}

// ToolSettingsResponse is the tenant's settings of one tool.
type ToolSettingsResponse struct {
	// IsEnabled is the tenant's switch (a tool never configured is on).
	IsEnabled bool `json:"is_enabled"`
	// Config is the tenant's overrides of the tool's default config.
	Config map[string]any `json:"config"`
	// EffectiveConfig is the default config with the overrides applied.
	EffectiveConfig map[string]any           `json:"effective_config"`
	CustomTemplates []CustomTemplateResponse `json:"custom_templates,omitempty"`
	CustomPatterns  []CustomPatternResponse  `json:"custom_patterns,omitempty"`
	UpdatedBy       *string                  `json:"updated_by,omitempty"`
	UpdatedAt       *string                  `json:"updated_at,omitempty"`
}

// ToolViewResponse is one tool of the tenant's view of the catalog: the
// catalog entry plus what was asked for with include=.
type ToolViewResponse struct {
	ToolResponse
	// Source: platform (shared, managed by the platform) or custom (this
	// organization's own tool).
	Source string `json:"source" enums:"platform,custom"`
	// Settings: include=settings.
	Settings *ToolSettingsResponse `json:"settings,omitempty"`
	// Availability: include=availability.
	Availability *ToolAvailabilityInfo `json:"availability,omitempty"`
	// Stats: include=stats.
	Stats *ToolStatsResponse `json:"stats,omitempty"`
	// Meta lists the includes left out (GET /tools/{id} only).
	Meta *include.Meta `json:"meta,omitempty"`
}

// ToolListAvailability is the availability view of every tool (filters not
// applied), returned with include=availability.
type ToolListAvailability struct {
	// Summary counts the tools per status (every status present).
	Summary map[string]int `json:"summary"`
	// ZoneID is the scan zone the view is limited to.
	ZoneID     string `json:"zone_id,omitempty"`
	ComputedAt string `json:"computed_at"`
	// Unlisted are the tools the sensors report that the catalog does not
	// list (never enabled; not filtered or paginated).
	Unlisted []UnlistedToolResponse `json:"unlisted"`
}

// ToolListResponse is a page of the tenant's view of the catalog.
type ToolListResponse struct {
	Items        []ToolViewResponse    `json:"items"`
	Total        int64                 `json:"total"`
	Page         int                   `json:"page"`
	PerPage      int                   `json:"per_page"`
	TotalPages   int                   `json:"total_pages"`
	Availability *ToolListAvailability `json:"availability,omitempty"`
	// Meta lists the includes asked for but left out.
	Meta include.Meta `json:"meta"`
}

// ToolSettingsRequest changes the tenant's settings of one tool. An omitted
// (or null) field is left as it is; "config": {} clears the overrides.
// Config overrides need scans:tools:write and never carry secrets.
type ToolSettingsRequest struct {
	IsEnabled *bool          `json:"is_enabled"`
	Config    map[string]any `json:"config"`
}

// BulkToolSettingsRequest switches several tools on or off for the tenant.
// Ids of tools the tenant cannot see are ignored.
type BulkToolSettingsRequest struct {
	ToolIDs   []string `json:"tool_ids" validate:"required,min=1,max=500,dive,uuid"`
	IsEnabled *bool    `json:"is_enabled" validate:"required"`
}

// =============================================================================
// Tool Handlers: the tenant's view of the catalog
// =============================================================================

// Include values of GET /tools and GET /tools/{id}.
const (
	includeSettings     = "settings"
	includeAvailability = "availability"
	includeStats        = "stats"
)

// ToolIncludes is the tool resource's include whitelist. Each include needs
// the permission of its former standalone route: scans:tenant_tools:read.
// The statistics are tenant-wide counts over every scan (not limited to a
// caller's data scope), so they also need scans:read. The sensor names and
// zones inside the availability additionally need sensors:read (otherwise
// counts only). Availability and statistics are expensive: they cost 2 more
// read-limiter tokens each and cap the page at 50.
var ToolIncludes = include.NewRegistry(
	include.Spec{Name: includeSettings, Permissions: []permission.Permission{permission.TenantToolsRead}},
	include.Spec{Name: includeAvailability, Permissions: []permission.Permission{permission.TenantToolsRead}, Cost: 2, Expensive: true},
	include.Spec{Name: includeStats, Permissions: []permission.Permission{permission.TenantToolsRead, permission.ScansRead}, Cost: 2, Expensive: true},
)

// Bounds of the list: the filters, and the page size, lower when an include
// that reads sensors or statistics is loaded.
const (
	maxToolSearchLen     = 255
	maxToolCategoryLen   = 50
	toolTenantFilterNeed = "the enabled and available filters need "
)

// optionalBool reads a true/false query parameter (nil when absent).
func optionalBool(r *http.Request, name string) (*bool, *apierror.Error) {
	switch r.URL.Query().Get(name) {
	case "":
		return nil, nil
	case queryParamTrue:
		v := true
		return &v, nil
	case "false":
		v := false
		return &v, nil
	}
	return nil, apierror.BadRequest(name + " must be true or false")
}

// List handles GET /api/v1/tools
// @Summary      List tools
// @Description  The organization's view of the tool catalog: platform tools and its own custom tools. include= adds the organization's settings (credential-like config values masked), the availability from its sensors (sensor names and zones only with sensors:read) and run statistics; each needs scans:tenant_tools:read (stats, tenant-wide counts, also scans:read) and is otherwise left out and listed in meta.omitted_includes. A response that took include= is Cache-Control: private, no-store; availability and stats cost 2 more read-limit tokens each. The enabled/available filters need scans:tenant_tools:read. With include=availability the response also carries the availability summary and the tools the sensors report that the catalog does not list.
// @Tags         Tools
// @Produce      json
// @Param        source     query     string   false  "platform or custom"  Enums(platform, custom)
// @Param        category   query     string   false  "Category name"
// @Param        q          query     string   false  "Search the name, display name and description"
// @Param        enabled    query     boolean  false  "Active in the catalog and switched on for the organization"
// @Param        available  query     boolean  false  "A scan job can be dispatched now (an online sensor may run it)"
// @Param        zone_id    query     string   false  "Availability from this scan zone's sensors only"
// @Param        include    query     string   false  "Comma-separated, at most 3: settings, availability, stats (per_page is capped at 50 with availability or stats); one the caller may not read is left out and listed in meta.omitted_includes"
// @Param        days       query     int      false  "Statistics window in days (1-365)" default(30)
// @Param        sort       query     string   false  "name, created_at or updated_at; '-' prefix for descending (default: category, then name)"
// @Param        page       query     int      false  "Page number" default(1)
// @Param        per_page   query     int      false  "Items per page (max 100)" default(20)
// @Success      200  {object}  ToolListResponse
// @Failure      400  {object}  apierror.Error
// @Failure      403  {object}  apierror.Error
// @Failure      404  {object}  apierror.Error
// @Failure      500  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /tools [get]
func (h *ToolHandler) List(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	enabled, aerr := optionalBool(r, "enabled")
	if aerr != nil {
		aerr.WriteJSON(w)
		return
	}
	available, aerr := optionalBool(r, "available")
	if aerr != nil {
		aerr.WriteJSON(w)
		return
	}
	if (enabled != nil || available != nil) && !middleware.HasPermission(r.Context(), permission.TenantToolsRead.String()) {
		apierror.Forbidden(toolTenantFilterNeed + permission.TenantToolsRead.String()).WriteJSON(w)
		return
	}
	inc, aerr := ToolIncludes.Parse(r)
	if aerr != nil {
		aerr.WriteJSON(w)
		return
	}
	if !include.Prepare(w, r, inc) {
		return
	}
	maxPerPage := inc.PerPageCap(MaxPerPage)
	if len(q.Get("q")) > maxToolSearchLen || len(q.Get("category")) > maxToolCategoryLen || len(q.Get("sort")) > maxToolCategoryLen {
		apierror.BadRequest("q is limited to 255 characters, category and sort to 50").WriteJSON(w)
		return
	}

	res, err := h.service.ListToolView(r.Context(), tool.ListToolViewInput{
		TenantID:  middleware.GetTenantID(r.Context()),
		Source:    q.Get("source"),
		Category:  q.Get("category"),
		Search:    q.Get("q"),
		Enabled:   enabled,
		Available: available,
		Sort:      q.Get("sort"),
		Page:      parseQueryInt(q.Get("page"), 1),
		PerPage:   parseQueryIntBounded(q.Get("per_page"), 20, 1, maxPerPage),
		ToolViewOptions: tool.ToolViewOptions{
			Availability: inc.Has(includeAvailability),
			ZoneID:       q.Get("zone_id"),
			Stats:        inc.Has(includeStats),
			StatsDays:    parseQueryIntBounded(q.Get("days"), 30, 1, 365),
		},
	})
	if err != nil {
		h.handleViewError(w, err)
		return
	}

	withSensors := middleware.HasPermission(r.Context(), permission.SensorsRead.String())
	resp := ToolListResponse{
		Items:      make([]ToolViewResponse, 0, len(res.Data)),
		Total:      res.Total,
		Page:       res.Page,
		PerPage:    res.PerPage,
		TotalPages: res.TotalPages,
		Meta:       inc.Meta(),
	}
	var zones map[shared.ID]string
	if res.Availability != nil {
		zones = res.Availability.Zones
		resp.Availability = toToolListAvailability(res, withSensors)
	}
	for _, v := range res.Data {
		resp.Items = append(resp.Items, toToolViewResponse(v, inc, withSensors, zones))
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

// Get handles GET /api/v1/tools/{id}
// @Summary      Get tool
// @Description  One tool of the organization's view: a platform tool or its own custom tool (any other id is not found). include= as on the list.
// @Tags         Tools
// @Produce      json
// @Param        id       path      string  true   "Tool ID"
// @Param        zone_id  query     string  false  "Availability from this scan zone's sensors only"
// @Param        include  query     string  false  "Comma-separated, at most 3: settings, availability, stats; one the caller may not read is left out and listed in meta.omitted_includes"
// @Param        days     query     int     false  "Statistics window in days (1-365)" default(30)
// @Success      200  {object}  ToolViewResponse
// @Failure      400  {object}  apierror.Error
// @Failure      403  {object}  apierror.Error
// @Failure      404  {object}  apierror.Error
// @Failure      500  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /tools/{id} [get]
func (h *ToolHandler) Get(w http.ResponseWriter, r *http.Request) {
	inc, aerr := ToolIncludes.Parse(r)
	if aerr != nil {
		aerr.WriteJSON(w)
		return
	}
	if !include.Prepare(w, r, inc) {
		return
	}
	v, err := h.service.GetToolView(r.Context(), middleware.GetTenantID(r.Context()), chi.URLParam(r, "id"),
		tool.ToolViewOptions{
			Availability: inc.Has(includeAvailability),
			ZoneID:       r.URL.Query().Get("zone_id"),
			Stats:        inc.Has(includeStats),
			StatsDays:    parseQueryIntBounded(r.URL.Query().Get("days"), 30, 1, 365),
		})
	if err != nil {
		h.handleViewError(w, err)
		return
	}
	withSensors := middleware.HasPermission(r.Context(), permission.SensorsRead.String())
	w.Header().Set("Content-Type", "application/json")
	resp := toToolViewResponse(v, inc, withSensors, v.Zones)
	meta := inc.Meta()
	resp.Meta = &meta
	_ = json.NewEncoder(w).Encode(resp)
}

// Create handles POST /api/v1/tools
// @Summary      Create custom tool
// @Description  Create a custom tool owned by the organization. Platform tools are managed by the platform and cannot be created here.
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

	// The tenant comes from the token, never the body: the tool is always a
	// private custom tool of the caller's organization.
	t, err := h.service.CreateCustomTool(r.Context(), tool.CreateCustomToolInput{
		TenantID:         middleware.GetTenantID(r.Context()),
		CreatedBy:        middleware.GetUserID(r.Context()),
		Name:             req.Name,
		DisplayName:      req.DisplayName,
		Description:      req.Description,
		CategoryID:       req.CategoryID,
		InstallMethod:    req.InstallMethod,
		InstallCmd:       req.InstallCmd,
		UpdateCmd:        req.UpdateCmd,
		VersionCmd:       req.VersionCmd,
		VersionRegex:     req.VersionRegex,
		MinVersion:       req.MinVersion,
		ConfigSchema:     req.ConfigSchema,
		DefaultConfig:    req.DefaultConfig,
		Capabilities:     req.Capabilities,
		SupportedTargets: req.SupportedTargets,
		OutputFormats:    req.OutputFormats,
		DocsURL:          req.DocsURL,
		GithubURL:        req.GithubURL,
		LogoURL:          req.LogoURL,
		Tags:             req.Tags,
	})
	if err != nil {
		h.handleServiceError(w, err, "Tool")
		return
	}
	h.auditTool(r, audit.ActionToolCreated, t.ID.String(), nil, t)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(toToolResponse(t))
}

// Update handles PUT /api/v1/tools/{id}
// @Summary      Update custom tool
// @Description  Update one of the organization's custom tools. A platform tool or another organization's tool is not found.
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

	before, ok := h.toolBefore(w, r, toolID)
	if !ok {
		return
	}
	t, err := h.service.UpdateCustomTool(r.Context(), tool.UpdateCustomToolInput{
		TenantID:         middleware.GetTenantID(r.Context()),
		ToolID:           toolID,
		DisplayName:      req.DisplayName,
		Description:      req.Description,
		InstallCmd:       req.InstallCmd,
		UpdateCmd:        req.UpdateCmd,
		VersionCmd:       req.VersionCmd,
		VersionRegex:     req.VersionRegex,
		MinVersion:       req.MinVersion,
		ConfigSchema:     req.ConfigSchema,
		DefaultConfig:    req.DefaultConfig,
		Capabilities:     req.Capabilities,
		SupportedTargets: req.SupportedTargets,
		OutputFormats:    req.OutputFormats,
		DocsURL:          req.DocsURL,
		GithubURL:        req.GithubURL,
		LogoURL:          req.LogoURL,
		Tags:             req.Tags,
	})
	if err != nil {
		h.handleServiceError(w, err, "Tool")
		return
	}
	h.auditTool(r, audit.ActionToolUpdated, toolID, before, t)

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(toToolResponse(t))
}

// Delete handles DELETE /api/v1/tools/{id}
// @Summary      Delete custom tool
// @Description  Delete one of the organization's custom tools; active workflows using it are deactivated. A platform tool or another organization's tool is not found.
// @Tags         Tools
// @Param        id   path      string  true  "Tool ID"
// @Success      204  "No Content"
// @Failure      400  {object}  apierror.Error
// @Failure      404  {object}  apierror.Error
// @Failure      500  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /tools/{id} [delete]
func (h *ToolHandler) Delete(w http.ResponseWriter, r *http.Request) {
	toolID := chi.URLParam(r, "id")

	before, ok := h.toolBefore(w, r, toolID)
	if !ok {
		return
	}
	if err := h.service.DeleteCustomTool(r.Context(), middleware.GetTenantID(r.Context()), toolID); err != nil {
		h.handleServiceError(w, err, "Tool")
		return
	}
	h.auditTool(r, audit.ActionToolDeleted, toolID, before, nil)

	w.WriteHeader(http.StatusNoContent)
}

// UpdateSettings handles PATCH /api/v1/tools/{id}/settings
// @Summary      Change tool settings
// @Description  Change the organization's switch (scans:tenant_tools:write) and config overrides (also scans:tools:write: they change what the sensors run) of a platform tool or of its own custom tool. An omitted field is left as it is; "config": {} clears the overrides. A config holding a secret (by key or by value) is refused: credentials belong in the secret store, referenced by id.
// @Tags         Tools
// @Accept       json
// @Produce      json
// @Param        id    path      string               true  "Tool ID"
// @Param        body  body      ToolSettingsRequest  true  "Settings to change"
// @Success      200   {object}  ToolViewResponse
// @Failure      400   {object}  apierror.Error
// @Failure      404   {object}  apierror.Error
// @Failure      500   {object}  apierror.Error
// @Security     BearerAuth
// @Router       /tools/{id}/settings [patch]
func (h *ToolHandler) UpdateSettings(w http.ResponseWriter, r *http.Request) {
	toolID := chi.URLParam(r, "id")
	tenantID := middleware.GetTenantID(r.Context())

	var req ToolSettingsRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}
	// The switch is scans:tenant_tools:write (the route gate). Config
	// overrides change what the sensors run (arguments, templates, rates),
	// so they need the same permission as the custom tool definitions.
	if req.Config != nil && !middleware.HasPermission(r.Context(), permission.ToolsWrite.String()) {
		apierror.Forbidden("changing config overrides needs " + permission.ToolsWrite.String()).WriteJSON(w)
		return
	}

	before := h.tenantConfigSnapshot(r, tenantID, toolID)
	config, err := h.service.UpdateToolSettings(r.Context(), tool.UpdateToolSettingsInput{
		TenantID:  tenantID,
		ToolID:    toolID,
		IsEnabled: req.IsEnabled,
		Config:    req.Config,
		UpdatedBy: middleware.GetUserID(r.Context()),
	})
	if err != nil {
		h.handleServiceError(w, err, "Tool")
		return
	}
	auditResourceChange(h.audit, h.logger, r, audit.ActionToolConfigUpdated, audit.ResourceTypeTool, toolID, "",
		before, auditSnapshot(toTenantToolConfigResponse(config)))

	v, err := h.service.GetToolView(r.Context(), tenantID, toolID, tool.ToolViewOptions{})
	if err != nil {
		h.handleServiceError(w, err, "Tool")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(toToolViewResponse(v, include.Granted(ToolIncludes, includeSettings), false, nil))
}

// BulkUpdateSettings handles PATCH /api/v1/tools/settings
// @Summary      Switch tools on or off
// @Description  Switch several tools on or off for the organization. Ids of tools it cannot see (another organization's custom tools, unknown ids) are ignored.
// @Tags         Tools
// @Accept       json
// @Param        body  body  BulkToolSettingsRequest  true  "Tools and the switch"
// @Success      204   "No Content"
// @Failure      400   {object}  apierror.Error
// @Failure      500   {object}  apierror.Error
// @Security     BearerAuth
// @Router       /tools/settings [patch]
func (h *ToolHandler) BulkUpdateSettings(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.GetTenantID(r.Context())

	var req BulkToolSettingsRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}
	if err := h.validator.Validate(req); err != nil {
		h.handleValidationError(w, err)
		return
	}

	var err error
	if *req.IsEnabled {
		err = h.service.BulkEnableTools(r.Context(), tool.BulkEnableToolsInput{TenantID: tenantID, ToolIDs: req.ToolIDs})
	} else {
		err = h.service.BulkDisableTools(r.Context(), tool.BulkDisableToolsInput{TenantID: tenantID, ToolIDs: req.ToolIDs})
	}
	if err != nil {
		h.handleServiceError(w, err, "Tool settings")
		return
	}
	auditResourceChange(h.audit, h.logger, r, audit.ActionToolConfigUpdated, audit.ResourceTypeTool, "bulk", "",
		nil, map[string]any{"tool_ids": req.ToolIDs, "is_enabled": *req.IsEnabled})

	w.WriteHeader(http.StatusNoContent)
}

// handleViewError answers a failed read of the view. The only lookup by a
// caller-given id besides the tool is the scan zone (another tenant's zone
// reads as missing).
func (h *ToolHandler) handleViewError(w http.ResponseWriter, err error) {
	if errors.Is(err, tool.ErrZoneNotFound) {
		apierror.NotFound("Scan zone").WriteJSON(w)
		return
	}
	h.handleServiceError(w, err, "Tool")
}

func toolSource(t *tooldom.Tool) string {
	if t.IsPlatformTool() {
		return tool.SourcePlatform
	}
	return tool.SourceCustom
}

func toToolViewResponse(v *tool.ToolView, inc include.Set, withSensors bool, zones map[shared.ID]string) ToolViewResponse {
	resp := ToolViewResponse{
		ToolResponse: *toToolResponseWithCategory(v.Tool, v.Category),
		Source:       toolSource(v.Tool),
	}
	if inc.Has(includeSettings) {
		resp.Settings = toToolSettingsResponse(v.ToolWithConfig)
	}
	if inc.Has(includeAvailability) && v.Availability != nil {
		info := toToolAvailabilityInfo(*v.Availability, zones, withSensors)
		resp.Availability = &info
	}
	if inc.Has(includeStats) && v.Stats != nil {
		resp.Stats = &ToolStatsResponse{
			ToolID:         v.Stats.ToolID.String(),
			TotalRuns:      v.Stats.TotalRuns,
			SuccessfulRuns: v.Stats.SuccessfulRuns,
			FailedRuns:     v.Stats.FailedRuns,
			TotalFindings:  v.Stats.TotalFindings,
			AvgDurationMs:  v.Stats.AvgDurationMs,
		}
	}
	return resp
}

func toToolSettingsResponse(twc *tooldom.ToolWithConfig) *ToolSettingsResponse {
	// Secrets are refused when a config is written; values that still look
	// like credentials (rows written before that rule) are masked: the
	// settings are for review and switches, never a way to read a secret.
	s := &ToolSettingsResponse{
		IsEnabled:       twc.IsEnabled,
		Config:          map[string]any{},
		EffectiveConfig: map[string]any{},
	}
	if twc.EffectiveConfig != nil {
		s.EffectiveConfig = scan.RedactConfigSecrets(twc.EffectiveConfig)
	}
	if c := twc.TenantConfig; c != nil {
		cr := toTenantToolConfigResponse(c)
		s.Config = scan.RedactConfigSecrets(cr.Config)
		s.CustomTemplates = cr.CustomTemplates
		s.CustomPatterns = cr.CustomPatterns
		s.UpdatedBy = cr.UpdatedBy
		s.UpdatedAt = &cr.UpdatedAt
	}
	return s
}

func toToolListAvailability(res *tool.ToolViewList, withSensors bool) *ToolListAvailability {
	av := res.Availability
	out := &ToolListAvailability{
		Summary:    make(map[string]int, len(av.Summary)),
		ComputedAt: av.ComputedAt.UTC().Format(time.RFC3339),
		Unlisted:   make([]UnlistedToolResponse, 0, len(res.Unlisted)),
	}
	for st, n := range av.Summary {
		out.Summary[string(st)] = n
	}
	if av.ZoneID != nil {
		out.ZoneID = av.ZoneID.String()
	}
	for _, u := range res.Unlisted {
		out.Unlisted = append(out.Unlisted, UnlistedToolResponse{
			Name:                 u.Name,
			ToolAvailabilityInfo: toToolAvailabilityInfo(u.ToolAvailability, av.Zones, withSensors),
		})
	}
	return out
}

// =============================================================================
// Helper Functions
// =============================================================================

func toToolResponse(t *tooldom.Tool) *ToolResponse {
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
		MinVersion:       t.MinVersion,
		HasUpdate:        t.HasUpdateAvailable(),
		ConfigFilePath:   t.ConfigFilePath,
		ConfigSchema:     t.ConfigSchema,
		DefaultConfig:    t.DefaultConfig,
		Capabilities:     t.Capabilities,
		SupportedTargets: t.SupportedTargets,
		OutputFormats:    t.OutputFormats,
		OutputTypes:      t.OutputTypes,
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
	if resp.OutputTypes == nil {
		resp.OutputTypes = []string{}
	}
	if resp.Tags == nil {
		resp.Tags = []string{}
	}

	return resp
}

// toToolResponseWithCategory converts tool to response with embedded category.
func toToolResponseWithCategory(t *tooldom.Tool, cat *tooldom.EmbeddedCategory) *ToolResponse {
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

func toTenantToolConfigResponse(c *tooldom.TenantToolConfig) *TenantToolConfigResponse {
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

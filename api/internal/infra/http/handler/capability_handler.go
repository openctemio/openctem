package handler

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/openctemio/openctem/api/internal/app/audit"
	capabilitysvc "github.com/openctemio/openctem/api/internal/app/capability"
	"github.com/openctemio/openctem/api/internal/infra/http/include"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/apierror"
	"github.com/openctemio/openctem/api/pkg/domain/capability"
	"github.com/openctemio/openctem/api/pkg/domain/permission"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/validator"
)

// CapabilityHandler serves /api/v1/capabilities: one collection with the
// platform capabilities and the organization's own custom ones. Reads need
// scans:tools:read; creating, changing and deleting a custom capability need
// the custom-tool permissions (scans:tools:write, scans:tools:delete), as
// custom tools do. A platform capability or another organization's custom
// one is never changed here: it is not found.
type CapabilityHandler struct {
	service   *capabilitysvc.CapabilityService
	validator *validator.Validator
	logger    *logger.Logger
}

// NewCapabilityHandler creates a new CapabilityHandler.
func NewCapabilityHandler(service *capabilitysvc.CapabilityService, v *validator.Validator, log *logger.Logger) *CapabilityHandler {
	return &CapabilityHandler{
		service:   service,
		validator: v,
		logger:    log.With("handler", "capability"),
	}
}

// =============================================================================
// Request/Response Types
// =============================================================================

// CreateCapabilityRequest represents the request body for creating a capability.
type CreateCapabilityRequest struct {
	Name        string `json:"name" validate:"required,min=2,max=50"`
	DisplayName string `json:"display_name" validate:"required,max=100"`
	Description string `json:"description" validate:"max=500"`
	Icon        string `json:"icon" validate:"max=50"`
	Color       string `json:"color" validate:"max=20"`
	Category    string `json:"category" validate:"max=50"`
}

// UpdateCapabilityRequest represents the request body for updating a capability.
type UpdateCapabilityRequest struct {
	DisplayName string `json:"display_name" validate:"required,max=100"`
	Description string `json:"description" validate:"max=500"`
	Icon        string `json:"icon" validate:"max=50"`
	Color       string `json:"color" validate:"max=20"`
	Category    string `json:"category" validate:"max=50"`
}

// CapabilityResponse represents a capability.
type CapabilityResponse struct {
	ID          string  `json:"id"`
	TenantID    *string `json:"tenant_id,omitempty"`
	Name        string  `json:"name"`
	DisplayName string  `json:"display_name"`
	Description string  `json:"description,omitempty"`
	Icon        string  `json:"icon"`
	Color       string  `json:"color"`
	Category    string  `json:"category,omitempty"`
	IsBuiltin   bool    `json:"is_builtin"`
	// Source: platform (shared, managed by the platform) or custom (this
	// organization's own capability).
	Source    string  `json:"source" enums:"platform,custom"`
	SortOrder int     `json:"sort_order"`
	CreatedBy *string `json:"created_by,omitempty"`
	CreatedAt string  `json:"created_at"`
	UpdatedAt string  `json:"updated_at"`
	// Usage: include=usage.
	Usage *CapabilityUsageResponse `json:"usage,omitempty"`
	// Meta lists the includes left out (GET /capabilities/{id} only).
	Meta *include.Meta `json:"meta,omitempty"`
}

// CapabilityUsageResponse is which of the organization's tools and sensors
// (and the platform tools) have the capability. The list carries the counts;
// one capability (GET /capabilities/{id}) also names up to ten of each.
// Sensor names need sensors:read; without it only the count is returned.
type CapabilityUsageResponse struct {
	ToolCount   int      `json:"tool_count"`
	SensorCount int      `json:"sensor_count"`
	ToolNames   []string `json:"tool_names,omitempty"`
	SensorNames []string `json:"sensor_names,omitempty"`
}

// CapabilityListResponse is a page of capabilities.
type CapabilityListResponse struct {
	Items      []CapabilityResponse `json:"items"`
	Total      int64                `json:"total"`
	Page       int                  `json:"page"`
	PerPage    int                  `json:"per_page"`
	TotalPages int                  `json:"total_pages"`
	// Meta lists the includes asked for but left out.
	Meta include.Meta `json:"meta"`
}

// CapabilityCategoriesResponse lists the categories in use.
type CapabilityCategoriesResponse struct {
	Items []string `json:"items"`
}

// includeUsage is the include value of GET /capabilities and /capabilities/{id}.
const includeUsage = "usage"

// CapabilityIncludes is the capability resource's include whitelist. usage
// is the organization's own data in the catalog (which of its tools and
// sensors have a capability), so it needs scans:tenant_tools:read as well as
// the catalog read, as the tool settings include does. It reads once per
// page and costs one more read-limiter token.
var CapabilityIncludes = include.NewRegistry(
	include.Spec{Name: includeUsage, Permissions: []permission.Permission{permission.ToolsRead, permission.TenantToolsRead}, Cost: 1},
)

const (
	maxCapabilitySearchLen   = 255
	maxCapabilityCategoryLen = 50
)

func capabilitySource(c *capability.Capability) string {
	if c.TenantID == nil {
		return "platform"
	}
	return "custom"
}

// toCapabilityResponse converts a domain capability to a response.
func toCapabilityResponse(c *capability.Capability) CapabilityResponse {
	resp := CapabilityResponse{
		ID:          c.ID.String(),
		Name:        c.Name,
		DisplayName: c.DisplayName,
		Description: c.Description,
		Icon:        c.Icon,
		Color:       c.Color,
		Category:    c.Category,
		IsBuiltin:   c.IsBuiltin,
		Source:      capabilitySource(c),
		SortOrder:   c.SortOrder,
		CreatedAt:   c.CreatedAt.Format("2006-01-02T15:04:05Z07:00"),
		UpdatedAt:   c.UpdatedAt.Format("2006-01-02T15:04:05Z07:00"),
	}
	if c.TenantID != nil {
		tid := c.TenantID.String()
		resp.TenantID = &tid
	}
	if c.CreatedBy != nil {
		cid := c.CreatedBy.String()
		resp.CreatedBy = &cid
	}
	return resp
}

func toCapabilityUsage(s *capabilitysvc.CapabilityUsageStatsOutput, withSensors bool) *CapabilityUsageResponse {
	u := &CapabilityUsageResponse{}
	if s == nil {
		return u
	}
	u.ToolCount, u.SensorCount, u.ToolNames = s.ToolCount, s.SensorCount, s.ToolNames
	if withSensors {
		u.SensorNames = s.SensorNames
	}
	return u
}

// =============================================================================
// Reads
// =============================================================================

// List handles GET /api/v1/capabilities
// @Summary      List capabilities
// @Description  The platform capabilities and the organization's own custom capabilities. include=usage adds which of the organization's tools and sensors (and the platform tools) have each capability; it needs scans:tenant_tools:read (otherwise it is left out and listed in meta.omitted_includes), and sensor names need sensors:read. A response that took include= is Cache-Control: private, no-store.
// @Tags         Capabilities
// @Produce      json
// @Param        source    query     string  false  "platform or custom"  Enums(platform, custom)
// @Param        category  query     string  false  "Category"
// @Param        q         query     string  false  "Search the name and display name"
// @Param        include   query     string  false  "usage; one the caller may not read is left out and listed in meta.omitted_includes"
// @Param        page      query     int     false  "Page number" default(1)
// @Param        per_page  query     int     false  "Items per page (max 100)" default(50)
// @Success      200  {object}  CapabilityListResponse
// @Failure      400  {object}  apierror.Error
// @Failure      403  {object}  apierror.Error
// @Failure      500  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /capabilities [get]
func (h *CapabilityHandler) List(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	inc, aerr := CapabilityIncludes.Parse(r)
	if aerr != nil {
		aerr.WriteJSON(w)
		return
	}
	if len(q.Get("q")) > maxCapabilitySearchLen || len(q.Get("category")) > maxCapabilityCategoryLen {
		apierror.BadRequest("q is limited to 255 characters, category to 50").WriteJSON(w)
		return
	}
	var isBuiltin *bool
	switch q.Get("source") {
	case "":
	case "platform":
		v := true
		isBuiltin = &v
	case "custom":
		v := false
		isBuiltin = &v
	default:
		apierror.BadRequest("source must be platform or custom").WriteJSON(w)
		return
	}
	if !include.Prepare(w, r, inc) {
		return
	}
	var category *string
	if c := q.Get("category"); c != "" {
		category = &c
	}
	paging, ok := listPage(w, r, 50)
	if !ok {
		return
	}
	tenantID := middleware.GetTenantID(r.Context())
	result, err := h.service.ListCapabilities(r.Context(), capabilitysvc.ListCapabilitiesInput{
		TenantID:  tenantID,
		IsBuiltin: isBuiltin,
		Category:  category,
		Search:    q.Get("q"),
		Page:      paging.Page,
		PerPage:   min(paging.PerPage, inc.PerPageCap(MaxPerPage)),
	})
	if err != nil {
		h.handleError(w, err, "capability")
		return
	}

	var usage map[shared.ID]*capabilitysvc.CapabilityUsageStatsOutput
	if inc.Has(includeUsage) {
		ids := make([]shared.ID, 0, len(result.Data))
		for _, c := range result.Data {
			ids = append(ids, c.ID)
		}
		if usage, err = h.service.UsageStats(r.Context(), tenantID, ids); err != nil {
			h.handleError(w, err, "capability")
			return
		}
	}
	withSensors := middleware.HasPermission(r.Context(), permission.SensorsRead.String())

	resp := CapabilityListResponse{
		Items:      make([]CapabilityResponse, 0, len(result.Data)),
		Total:      result.Total,
		Page:       result.Page,
		PerPage:    result.PerPage,
		TotalPages: result.TotalPages,
		Meta:       inc.Meta(),
	}
	for _, c := range result.Data {
		item := toCapabilityResponse(c)
		if inc.Has(includeUsage) {
			item.Usage = toCapabilityUsage(usage[c.ID], withSensors)
		}
		resp.Items = append(resp.Items, item)
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

// Get handles GET /api/v1/capabilities/{id}
// @Summary      Get capability
// @Description  A platform capability or one of the organization's own (any other id is not found). include= as on the list.
// @Tags         Capabilities
// @Produce      json
// @Param        id       path      string  true   "Capability ID"
// @Param        include  query     string  false  "usage; one the caller may not read is left out and listed in meta.omitted_includes"
// @Success      200  {object}  CapabilityResponse
// @Failure      400  {object}  apierror.Error
// @Failure      404  {object}  apierror.Error
// @Failure      500  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /capabilities/{id} [get]
func (h *CapabilityHandler) Get(w http.ResponseWriter, r *http.Request) {
	inc, aerr := CapabilityIncludes.Parse(r)
	if aerr != nil {
		aerr.WriteJSON(w)
		return
	}
	if !include.Prepare(w, r, inc) {
		return
	}
	tenantID := middleware.GetTenantID(r.Context())
	c, err := h.service.GetCapability(r.Context(), tenantID, chi.URLParam(r, "id"))
	if err != nil {
		h.handleError(w, err, "capability")
		return
	}
	resp := toCapabilityResponse(c)
	if inc.Has(includeUsage) {
		// One capability: the counts and the names (the list carries counts).
		usage, err := h.service.GetCapabilityUsageStats(r.Context(), tenantID, c.ID.String())
		if err != nil {
			h.handleError(w, err, "capability")
			return
		}
		resp.Usage = toCapabilityUsage(usage, middleware.HasPermission(r.Context(), permission.SensorsRead.String()))
	}
	meta := inc.Meta()
	resp.Meta = &meta
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

// GetCategories handles GET /api/v1/capabilities/categories
// @Summary      List capability categories
// @Description  The categories of the capabilities the organization sees.
// @Tags         Capabilities
// @Produce      json
// @Success      200  {object}  CapabilityCategoriesResponse
// @Failure      500  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /capabilities/categories [get]
func (h *CapabilityHandler) GetCategories(w http.ResponseWriter, r *http.Request) {
	categories, err := h.service.GetCategories(r.Context(), middleware.GetTenantID(r.Context()))
	if err != nil {
		h.handleError(w, err, "capability")
		return
	}
	if categories == nil {
		categories = []string{}
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(CapabilityCategoriesResponse{Items: categories})
}

// =============================================================================
// The organization's custom capabilities
// =============================================================================

// Create handles POST /api/v1/capabilities
// @Summary      Create custom capability
// @Description  Create a custom capability owned by the organization. Platform capabilities are managed by the platform.
// @Tags         Capabilities
// @Accept       json
// @Produce      json
// @Param        body  body      CreateCapabilityRequest  true  "Capability"
// @Success      201   {object}  CapabilityResponse
// @Failure      400   {object}  apierror.Error
// @Failure      409   {object}  apierror.Error
// @Failure      500   {object}  apierror.Error
// @Security     BearerAuth
// @Router       /capabilities [post]
func (h *CapabilityHandler) Create(w http.ResponseWriter, r *http.Request) {
	var req CreateCapabilityRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10)).Decode(&req); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}
	if err := h.validator.Validate(req); err != nil {
		apierror.BadRequest(err.Error()).WriteJSON(w)
		return
	}
	c, err := h.service.CreateCapability(r.Context(), capabilitysvc.CreateCapabilityInput{
		TenantID:     middleware.GetTenantID(r.Context()),
		CreatedBy:    middleware.GetUserID(r.Context()),
		Name:         req.Name,
		DisplayName:  req.DisplayName,
		Description:  req.Description,
		Icon:         req.Icon,
		Color:        req.Color,
		Category:     req.Category,
		AuditContext: h.buildAuditContext(r),
	})
	if err != nil {
		h.handleError(w, err, "capability")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(toCapabilityResponse(c))
}

// Update handles PUT /api/v1/capabilities/{id}
// @Summary      Update custom capability
// @Description  Change one of the organization's custom capabilities. A platform capability or another organization's is not found.
// @Tags         Capabilities
// @Accept       json
// @Produce      json
// @Param        id    path      string                   true  "Capability ID"
// @Param        body  body      UpdateCapabilityRequest  true  "Capability"
// @Success      200   {object}  CapabilityResponse
// @Failure      400   {object}  apierror.Error
// @Failure      404   {object}  apierror.Error
// @Failure      500   {object}  apierror.Error
// @Security     BearerAuth
// @Router       /capabilities/{id} [put]
func (h *CapabilityHandler) Update(w http.ResponseWriter, r *http.Request) {
	var req UpdateCapabilityRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10)).Decode(&req); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}
	if err := h.validator.Validate(req); err != nil {
		apierror.BadRequest(err.Error()).WriteJSON(w)
		return
	}
	c, err := h.service.UpdateCapability(r.Context(), capabilitysvc.UpdateCapabilityInput{
		TenantID:     middleware.GetTenantID(r.Context()),
		ID:           chi.URLParam(r, "id"),
		DisplayName:  req.DisplayName,
		Description:  req.Description,
		Icon:         req.Icon,
		Color:        req.Color,
		Category:     req.Category,
		AuditContext: h.buildAuditContext(r),
	})
	if err != nil {
		h.handleError(w, err, "capability")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(toCapabilityResponse(c))
}

// Delete handles DELETE /api/v1/capabilities/{id}
// @Summary      Delete custom capability
// @Description  Delete one of the organization's custom capabilities. In use by a tool or sensor: 409 unless force=true. A platform capability or another organization's is not found.
// @Tags         Capabilities
// @Param        id     path   string   true   "Capability ID"
// @Param        force  query  boolean  false  "Delete even when tools or sensors use it"
// @Success      204
// @Failure      404  {object}  apierror.Error
// @Failure      409  {object}  apierror.Error
// @Failure      500  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /capabilities/{id} [delete]
func (h *CapabilityHandler) Delete(w http.ResponseWriter, r *http.Request) {
	if err := h.service.DeleteCapability(r.Context(), capabilitysvc.DeleteCapabilityInput{
		TenantID:     middleware.GetTenantID(r.Context()),
		CapabilityID: chi.URLParam(r, "id"),
		Force:        r.URL.Query().Get("force") == queryParamTrue,
		AuditContext: h.buildAuditContext(r),
	}); err != nil {
		h.handleError(w, err, "capability")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// =============================================================================
// Helpers
// =============================================================================

// buildAuditContext builds an AuditContext from the HTTP request.
func (h *CapabilityHandler) buildAuditContext(r *http.Request) audit.AuditContext {
	return audit.AuditContext{
		TenantID:   middleware.GetTenantID(r.Context()),
		ActorID:    middleware.GetUserID(r.Context()),
		ActorEmail: middleware.GetUsername(r.Context()),
		ActorIP:    getClientIP(r),
		UserAgent:  r.UserAgent(),
		RequestID:  r.Header.Get("X-Request-ID"),
	}
}

// handleError answers with generic client messages and logs the details:
// wrapped internal error chains are never echoed to the client.
func (h *CapabilityHandler) handleError(w http.ResponseWriter, err error, resource string) {
	switch {
	case errors.Is(err, shared.ErrNotFound):
		apierror.NotFound(resource).WriteJSON(w)
	case errors.Is(err, shared.ErrConflict):
		h.logger.Warn("capability conflict", "resource", resource, "error", err)
		apierror.Conflict(resource + " conflict").WriteJSON(w)
	case errors.Is(err, shared.ErrValidation):
		h.logger.Warn("capability validation failed", "resource", resource, "error", err)
		apierror.BadRequest("invalid " + resource + " request").WriteJSON(w)
	case errors.Is(err, shared.ErrForbidden):
		h.logger.Warn("capability forbidden", "resource", resource, "error", err)
		apierror.Forbidden("operation not permitted").WriteJSON(w)
	default:
		h.logger.Error("unexpected error", "resource", resource, "error", err)
		apierror.InternalError(err).WriteJSON(w)
	}
}

package handler

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/openctemio/api/internal/app"
	"github.com/openctemio/api/internal/infra/http/middleware"
	"github.com/openctemio/api/pkg/apierror"
	"github.com/openctemio/api/pkg/domain/capability"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/logger"
	"github.com/openctemio/api/pkg/validator"
)

// CapabilityHandler handles HTTP requests for capabilities.
type CapabilityHandler struct {
	service   *app.CapabilityService
	validator *validator.Validator
	logger    *logger.Logger
}

// NewCapabilityHandler creates a new CapabilityHandler.
func NewCapabilityHandler(service *app.CapabilityService, v *validator.Validator, log *logger.Logger) *CapabilityHandler {
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

// CapabilityResponse represents the response for a capability.
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
	SortOrder   int     `json:"sort_order"`
	CreatedBy   *string `json:"created_by,omitempty"`
	CreatedAt   string  `json:"created_at"`
	UpdatedAt   string  `json:"updated_at"`
}

// CapabilityUsageStatsResponse represents usage statistics for a capability.
type CapabilityUsageStatsResponse struct {
	ToolCount  int      `json:"tool_count"`
	AgentCount int      `json:"agent_count"`
	ToolNames  []string `json:"tool_names,omitempty"`
	AgentNames []string `json:"agent_names,omitempty"`
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

// =============================================================================
// List Operations (Read)
// =============================================================================

// ListCapabilities lists all capabilities (platform + tenant custom).
// GET /api/v1/capabilities
func (h *CapabilityHandler) ListCapabilities(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.GetTenantID(r.Context())

	page := parseQueryInt(r.URL.Query().Get("page"), 1)
	perPage := parseQueryInt(r.URL.Query().Get("per_page"), 50)
	search := r.URL.Query().Get("search")

	var isBuiltin *bool
	if b := r.URL.Query().Get("is_builtin"); b != "" {
		val := b == queryParamTrue
		isBuiltin = &val
	}

	var category *string
	if c := r.URL.Query().Get("category"); c != "" {
		category = &c
	}

	result, err := h.service.ListCapabilities(r.Context(), app.ListCapabilitiesInput{
		TenantID:  tenantID,
		IsBuiltin: isBuiltin,
		Category:  category,
		Search:    search,
		Page:      page,
		PerPage:   perPage,
	})
	if err != nil {
		h.handleError(w, err, "capability")
		return
	}

	// Convert to response
	items := make([]CapabilityResponse, 0, len(result.Data))
	for _, c := range result.Data {
		items = append(items, toCapabilityResponse(c))
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

// ListAllCapabilities lists all capabilities for dropdowns (no pagination).
// GET /api/v1/capabilities/all
func (h *CapabilityHandler) ListAllCapabilities(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.GetTenantID(r.Context())

	capabilities, err := h.service.ListAllCapabilities(r.Context(), tenantID)
	if err != nil {
		h.handleError(w, err, "capability")
		return
	}

	items := make([]CapabilityResponse, 0, len(capabilities))
	for _, c := range capabilities {
		items = append(items, toCapabilityResponse(c))
	}

	resp := map[string]any{
		"items": items,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// ListCapabilitiesByCategory lists capabilities filtered by category.
// GET /api/v1/capabilities/by-category/:category
func (h *CapabilityHandler) ListCapabilitiesByCategory(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.GetTenantID(r.Context())
	category := chi.URLParam(r, "category")

	capabilities, err := h.service.ListCapabilitiesByCategory(r.Context(), tenantID, category)
	if err != nil {
		h.handleError(w, err, "capability")
		return
	}

	items := make([]CapabilityResponse, 0, len(capabilities))
	for _, c := range capabilities {
		items = append(items, toCapabilityResponse(c))
	}

	resp := map[string]any{
		"items": items,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// GetCapability returns a capability by ID.
// GET /api/v1/capabilities/:id
func (h *CapabilityHandler) GetCapability(w http.ResponseWriter, r *http.Request) {
	capabilityID := chi.URLParam(r, "id")

	c, err := h.service.GetCapability(r.Context(), capabilityID)
	if err != nil {
		h.handleError(w, err, "capability")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(toCapabilityResponse(c))
}

// GetCategories returns all unique capability categories.
// GET /api/v1/capabilities/categories
func (h *CapabilityHandler) GetCategories(w http.ResponseWriter, r *http.Request) {
	categories, err := h.service.GetCategories(r.Context())
	if err != nil {
		h.handleError(w, err, "capability")
		return
	}

	resp := map[string]any{
		"items": categories,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// GetCapabilityUsageStats returns usage statistics for a capability.
// GET /api/v1/capabilities/:id/usage-stats
// Security: Validates tenant access for custom capabilities.
func (h *CapabilityHandler) GetCapabilityUsageStats(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.GetTenantID(r.Context())
	capabilityID := chi.URLParam(r, "id")

	stats, err := h.service.GetCapabilityUsageStats(r.Context(), tenantID, capabilityID)
	if err != nil {
		h.handleError(w, err, "capability")
		return
	}

	resp := CapabilityUsageStatsResponse{
		ToolCount:  stats.ToolCount,
		AgentCount: stats.AgentCount,
		ToolNames:  stats.ToolNames,
		AgentNames: stats.AgentNames,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// GetCapabilitiesUsageStatsBatch returns usage statistics for multiple capabilities.
// POST /api/v1/capabilities/usage-stats
// Security: Validates tenant access for custom capabilities in batch.
func (h *CapabilityHandler) GetCapabilitiesUsageStatsBatch(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.GetTenantID(r.Context())

	var req struct {
		IDs []string `json:"ids" validate:"required,min=1,max=100"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}

	if err := h.validator.Validate(req); err != nil {
		apierror.BadRequest(err.Error()).WriteJSON(w)
		return
	}

	stats, err := h.service.GetCapabilitiesUsageStatsBatch(r.Context(), tenantID, req.IDs)
	if err != nil {
		h.handleError(w, err, "capability")
		return
	}

	// Convert to response format
	resp := make(map[string]CapabilityUsageStatsResponse, len(stats))
	for id, stat := range stats {
		resp[id] = CapabilityUsageStatsResponse{
			ToolCount:  stat.ToolCount,
			AgentCount: stat.AgentCount,
			ToolNames:  stat.ToolNames,
			AgentNames: stat.AgentNames,
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// =============================================================================
// Tenant Custom Capability Operations (Write)
// =============================================================================

// CreateCustomCapability creates a new tenant custom capability.
// POST /api/v1/custom-capabilities
func (h *CapabilityHandler) CreateCustomCapability(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.GetTenantID(r.Context())
	userID := middleware.GetUserID(r.Context())

	var req CreateCapabilityRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}

	if err := h.validator.Validate(req); err != nil {
		apierror.BadRequest(err.Error()).WriteJSON(w)
		return
	}

	c, err := h.service.CreateCapability(r.Context(), app.CreateCapabilityInput{
		TenantID:     tenantID,
		CreatedBy:    userID,
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
	json.NewEncoder(w).Encode(toCapabilityResponse(c))
}

// UpdateCustomCapability updates a tenant custom capability.
// PUT /api/v1/custom-capabilities/:id
func (h *CapabilityHandler) UpdateCustomCapability(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.GetTenantID(r.Context())
	capabilityID := chi.URLParam(r, "id")

	var req UpdateCapabilityRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}

	if err := h.validator.Validate(req); err != nil {
		apierror.BadRequest(err.Error()).WriteJSON(w)
		return
	}

	c, err := h.service.UpdateCapability(r.Context(), app.UpdateCapabilityInput{
		TenantID:     tenantID,
		ID:           capabilityID,
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
	json.NewEncoder(w).Encode(toCapabilityResponse(c))
}

// DeleteCustomCapability deletes a tenant custom capability.
// DELETE /api/v1/custom-capabilities/:id?force=true
func (h *CapabilityHandler) DeleteCustomCapability(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.GetTenantID(r.Context())
	capabilityID := chi.URLParam(r, "id")
	force := r.URL.Query().Get("force") == queryParamTrue

	if err := h.service.DeleteCapability(r.Context(), app.DeleteCapabilityInput{
		TenantID:     tenantID,
		CapabilityID: capabilityID,
		Force:        force,
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
func (h *CapabilityHandler) buildAuditContext(r *http.Request) app.AuditContext {
	actx := app.AuditContext{
		ActorIP:   r.RemoteAddr,
		UserAgent: r.UserAgent(),
		RequestID: r.Header.Get("X-Request-ID"),
	}

	actx.TenantID = middleware.GetTenantID(r.Context())
	actx.ActorID = middleware.GetUserID(r.Context())
	actx.ActorEmail = middleware.GetUsername(r.Context())

	return actx
}

// =============================================================================
// Error Handling
// =============================================================================

func (h *CapabilityHandler) handleError(w http.ResponseWriter, err error, resource string) {
	switch {
	case errors.Is(err, shared.ErrNotFound):
		apierror.NotFound(resource).WriteJSON(w)
	case errors.Is(err, shared.ErrConflict):
		apierror.Conflict(err.Error()).WriteJSON(w)
	case errors.Is(err, shared.ErrValidation):
		apierror.BadRequest(err.Error()).WriteJSON(w)
	case errors.Is(err, shared.ErrForbidden):
		apierror.Forbidden(err.Error()).WriteJSON(w)
	default:
		h.logger.Error("unexpected error", "error", err)
		apierror.InternalError(err).WriteJSON(w)
	}
}

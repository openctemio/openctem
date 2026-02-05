package handler

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/openctemio/api/internal/app"
	"github.com/openctemio/api/internal/infra/http/middleware"
	"github.com/openctemio/api/pkg/apierror"
	"github.com/openctemio/api/pkg/domain/component"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/logger"
	"github.com/openctemio/api/pkg/validator"
)

// ComponentHandler handles component-related HTTP requests.
type ComponentHandler struct {
	service   *app.ComponentService
	validator *validator.Validator
	logger    *logger.Logger
}

// NewComponentHandler creates a new component handler.
func NewComponentHandler(svc *app.ComponentService, v *validator.Validator, log *logger.Logger) *ComponentHandler {
	return &ComponentHandler{
		service:   svc,
		validator: v,
		logger:    log,
	}
}

// ComponentResponse represents a component in API responses.
type ComponentResponse struct {
	ID                 string         `json:"id"`
	TenantID           string         `json:"tenant_id"`
	AssetID            string         `json:"asset_id"`
	Name               string         `json:"name"`
	Version            string         `json:"version"`
	Ecosystem          string         `json:"ecosystem"`
	PackageManager     string         `json:"package_manager,omitempty"`
	Namespace          string         `json:"namespace,omitempty"`
	ManifestFile       string         `json:"manifest_file,omitempty"`
	ManifestPath       string         `json:"manifest_path,omitempty"`
	DependencyType     string         `json:"dependency_type"`
	License            string         `json:"license,omitempty"`
	PURL               string         `json:"purl"`
	VulnerabilityCount int            `json:"vulnerability_count"`
	Status             string         `json:"status"`
	Metadata           map[string]any `json:"metadata,omitempty"`
	CreatedAt          time.Time      `json:"created_at"`
	UpdatedAt          time.Time      `json:"updated_at"`

	// Dependency hierarchy fields (industry-aligned: CycloneDX, Snyk, GitHub)
	Depth             int     `json:"depth"`                         // 1 = direct, 2+ = transitive depth
	ParentComponentID *string `json:"parent_component_id,omitempty"` // asset_components.id of parent dependency
	IsDirect          bool    `json:"is_direct"`                     // Convenience: depth == 1
}

// CreateComponentRequest represents the request to create a component.
type CreateComponentRequest struct {
	AssetID        string `json:"asset_id" validate:"required,uuid"`
	Name           string `json:"name" validate:"required,min=1,max=255"`
	Version        string `json:"version" validate:"required,max=100"`
	Ecosystem      string `json:"ecosystem" validate:"required"`
	PackageManager string `json:"package_manager" validate:"max=50"`
	Namespace      string `json:"namespace" validate:"max=255"`
	ManifestFile   string `json:"manifest_file" validate:"max=255"`
	ManifestPath   string `json:"manifest_path" validate:"max=500"`
	DependencyType string `json:"dependency_type" validate:"omitempty"`
	License        string `json:"license" validate:"max=100"`
}

// UpdateComponentRequest represents the request to update a component.
type UpdateComponentRequest struct {
	Version            *string `json:"version" validate:"omitempty,max=100"`
	PackageManager     *string `json:"package_manager" validate:"omitempty,max=50"`
	Namespace          *string `json:"namespace" validate:"omitempty,max=255"`
	ManifestFile       *string `json:"manifest_file" validate:"omitempty,max=255"`
	ManifestPath       *string `json:"manifest_path" validate:"omitempty,max=500"`
	DependencyType     *string `json:"dependency_type" validate:"omitempty"`
	License            *string `json:"license" validate:"omitempty,max=100"`
	Status             *string `json:"status" validate:"omitempty"`
	VulnerabilityCount *int    `json:"vulnerability_count" validate:"omitempty,min=0"`
}

// toComponentResponse converts a domain component to API response (Global view).
func toComponentResponse(c *component.Component) ComponentResponse {
	// Extract metadata fields
	meta := c.Metadata()
	pm, _ := meta["package_manager"].(string)
	ns, _ := meta["namespace"].(string)

	return ComponentResponse{
		ID:                 c.ID().String(),
		TenantID:           "", // Global
		AssetID:            "", // Global
		Name:               c.Name(),
		Version:            c.Version(),
		Ecosystem:          c.Ecosystem().String(),
		PackageManager:     pm,
		Namespace:          ns,
		ManifestFile:       "", // Contextual
		ManifestPath:       "", // Contextual
		DependencyType:     "", // Contextual
		License:            c.License(),
		PURL:               c.PURL(),
		VulnerabilityCount: c.VulnerabilityCount(),
		Status:             "", // Contextual/Calculated?
		Metadata:           c.Metadata(),
		CreatedAt:          c.CreatedAt(),
		UpdatedAt:          c.UpdatedAt(),
	}
}

// handleValidationError converts validation errors to API errors and writes response.
func (h *ComponentHandler) handleValidationError(w http.ResponseWriter, err error) {
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

// handleServiceError converts service errors to API errors and writes response.
func (h *ComponentHandler) handleServiceError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, shared.ErrNotFound):
		apierror.NotFound("Component").WriteJSON(w)
	case errors.Is(err, shared.ErrAlreadyExists):
		apierror.Conflict("Component already exists").WriteJSON(w)
	case errors.Is(err, shared.ErrValidation):
		apierror.BadRequest(err.Error()).WriteJSON(w)
	default:
		h.logger.Error("service error", "error", err)
		apierror.InternalError(err).WriteJSON(w)
	}
}

// List handles GET /api/v1/components
// @Summary      List components
// @Description  Retrieves a paginated list of components for the current tenant
// @Tags         Components
// @Produce      json
// @Security     BearerAuth
// @Param        asset_id           query     string  false  "Filter by asset ID"
// @Param        name               query     string  false  "Filter by name"
// @Param        ecosystems         query     string  false  "Filter by ecosystems (comma-separated)"
// @Param        statuses           query     string  false  "Filter by statuses (comma-separated)"
// @Param        dependency_types   query     string  false  "Filter by dependency types"
// @Param        has_vulnerabilities query    bool    false  "Filter by has vulnerabilities"
// @Param        licenses           query     string  false  "Filter by licenses (comma-separated)"
// @Param        page               query     int     false  "Page number"  default(1)
// @Param        per_page           query     int     false  "Items per page"  default(20)
// @Success      200  {object}  map[string]interface{}
// @Failure      400  {object}  map[string]string
// @Failure      401  {object}  map[string]string
// @Router       /components [get]
func (h *ComponentHandler) List(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())

	query := r.URL.Query()

	hasVulnerabilities := parseQueryBool(query.Get("has_vulnerabilities"))

	input := app.ListComponentsInput{
		TenantID:           tenantID,
		AssetID:            query.Get("asset_id"),
		Name:               query.Get("name"),
		Ecosystems:         parseQueryArray(query.Get("ecosystems")),
		Statuses:           parseQueryArray(query.Get("statuses")),
		DependencyTypes:    parseQueryArray(query.Get("dependency_types")),
		HasVulnerabilities: hasVulnerabilities,
		Licenses:           parseQueryArray(query.Get("licenses")),
		Page:               parseQueryInt(query.Get("page"), 1),
		PerPage:            parseQueryInt(query.Get("per_page"), 20),
	}

	if err := h.validator.Validate(input); err != nil {
		h.handleValidationError(w, err)
		return
	}

	result, err := h.service.ListComponents(r.Context(), input)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	data := make([]ComponentResponse, len(result.Data))
	for i, c := range result.Data {
		data[i] = toComponentResponse(c)
	}

	response := ListResponse[ComponentResponse]{
		Data:       data,
		Total:      result.Total,
		Page:       result.Page,
		PerPage:    result.PerPage,
		TotalPages: result.TotalPages,
		Links:      NewPaginationLinks(r, result.Page, result.PerPage, result.TotalPages),
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(response)
}

// GetStats handles GET /api/v1/components/stats
// @Summary      Get component statistics
// @Description  Retrieves aggregated component statistics for the tenant
// @Tags         Components
// @Produce      json
// @Security     BearerAuth
// @Success      200  {object}  component.ComponentStats
// @Failure      400  {object}  map[string]string
// @Failure      401  {object}  map[string]string
// @Router       /components/stats [get]
func (h *ComponentHandler) GetStats(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())

	stats, err := h.service.GetComponentStats(r.Context(), tenantID)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(stats)
}

// GetEcosystemStats handles GET /api/v1/components/ecosystems
// @Summary      Get ecosystem statistics
// @Description  Retrieves per-ecosystem statistics for the tenant
// @Tags         Components
// @Produce      json
// @Security     BearerAuth
// @Success      200  {array}   component.EcosystemStats
// @Failure      400  {object}  map[string]string
// @Failure      401  {object}  map[string]string
// @Router       /components/ecosystems [get]
func (h *ComponentHandler) GetEcosystemStats(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())

	stats, err := h.service.GetEcosystemStats(r.Context(), tenantID)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	// Return empty array instead of null
	if stats == nil {
		stats = []component.EcosystemStats{}
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(stats)
}

// GetVulnerableComponents handles GET /api/v1/components/vulnerable
// @Summary      Get vulnerable components
// @Description  Retrieves components with vulnerability details for the tenant
// @Tags         Components
// @Produce      json
// @Security     BearerAuth
// @Param        limit  query     int  false  "Limit results"  default(10)
// @Success      200  {array}   component.VulnerableComponent
// @Failure      400  {object}  map[string]string
// @Failure      401  {object}  map[string]string
// @Router       /components/vulnerable [get]
func (h *ComponentHandler) GetVulnerableComponents(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())

	limit := parseQueryInt(r.URL.Query().Get("limit"), 10)

	components, err := h.service.GetVulnerableComponents(r.Context(), tenantID, limit)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	// Return empty array instead of null
	if components == nil {
		components = []component.VulnerableComponent{}
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(components)
}

// GetLicenseStats handles GET /api/v1/components/licenses
// @Summary      Get license statistics
// @Description  Retrieves license distribution statistics for the tenant
// @Tags         Components
// @Produce      json
// @Security     BearerAuth
// @Success      200  {array}   component.LicenseStats
// @Failure      401  {object}  map[string]string
// @Router       /components/licenses [get]
func (h *ComponentHandler) GetLicenseStats(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())

	stats, err := h.service.GetLicenseStats(r.Context(), tenantID)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	// Return empty array instead of null
	if stats == nil {
		stats = []component.LicenseStats{}
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(stats)
}

// Create handles POST /api/v1/components
// @Summary      Create component
// @Description  Creates a new component
// @Tags         Components
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        request  body      CreateComponentRequest  true  "Component data"
// @Success      201  {object}  ComponentResponse
// @Failure      400  {object}  map[string]string
// @Failure      401  {object}  map[string]string
// @Failure      409  {object}  map[string]string
// @Router       /components [post]
func (h *ComponentHandler) Create(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())

	var req CreateComponentRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}

	if err := h.validator.Validate(req); err != nil {
		h.handleValidationError(w, err)
		return
	}

	input := app.CreateComponentInput{
		TenantID:       tenantID,
		AssetID:        req.AssetID,
		Name:           req.Name,
		Version:        req.Version,
		Ecosystem:      req.Ecosystem,
		PackageManager: req.PackageManager,
		Namespace:      req.Namespace,
		ManifestFile:   req.ManifestFile,
		ManifestPath:   req.ManifestPath,
		DependencyType: req.DependencyType,
		License:        req.License,
	}

	c, err := h.service.CreateComponent(r.Context(), input)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(toComponentResponse(c))
}

// Get handles GET /api/v1/components/{id}
// @Summary      Get component
// @Description  Retrieves a component by ID
// @Tags         Components
// @Produce      json
// @Security     BearerAuth
// @Param        id   path      string  true  "Component ID"
// @Success      200  {object}  ComponentResponse
// @Failure      400  {object}  map[string]string
// @Failure      404  {object}  map[string]string
// @Router       /components/{id} [get]
func (h *ComponentHandler) Get(w http.ResponseWriter, r *http.Request) {
	// Get tenant ID from JWT token
	// tenantID := middleware.MustGetTenantID(r.Context())

	id := r.PathValue("id")
	if id == "" {
		apierror.BadRequest("Component ID is required").WriteJSON(w)
		return
	}

	c, err := h.service.GetComponent(r.Context(), id)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	// Global components are not tenant-scoped currently.
	// We might restrict based on "is this component used by any of my assets", but for now it's a global catalog lookup.

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(toComponentResponse(c))
}

// Update handles PUT /api/v1/components/{id}
// @Summary      Update component
// @Description  Updates a component
// @Tags         Components
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        id       path      string                   true  "Component ID"
// @Param        request  body      UpdateComponentRequest   true  "Component data"
// @Success      200  {object}  ComponentResponse
// @Failure      400  {object}  map[string]string
// @Failure      404  {object}  map[string]string
// @Router       /components/{id} [put]
func (h *ComponentHandler) Update(w http.ResponseWriter, r *http.Request) {
	// Get tenant ID from JWT token
	tenantID := middleware.MustGetTenantID(r.Context())

	id := r.PathValue("id")
	if id == "" {
		apierror.BadRequest("Component ID is required").WriteJSON(w)
		return
	}

	var req UpdateComponentRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}

	if err := h.validator.Validate(req); err != nil {
		h.handleValidationError(w, err)
		return
	}

	input := app.UpdateComponentInput{
		Version:            req.Version,
		PackageManager:     req.PackageManager,
		Namespace:          req.Namespace,
		ManifestFile:       req.ManifestFile,
		ManifestPath:       req.ManifestPath,
		DependencyType:     req.DependencyType,
		License:            req.License,
		Status:             req.Status,
		VulnerabilityCount: req.VulnerabilityCount,
	}

	dep, err := h.service.UpdateComponent(r.Context(), id, tenantID, input)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(toAssetComponentResponse(dep))
}

// Delete handles DELETE /api/v1/components/{id}
// @Summary      Delete component
// @Description  Deletes a component
// @Tags         Components
// @Security     BearerAuth
// @Param        id   path      string  true  "Component ID"
// @Success      204  "No Content"
// @Failure      400  {object}  map[string]string
// @Failure      404  {object}  map[string]string
// @Router       /components/{id} [delete]
func (h *ComponentHandler) Delete(w http.ResponseWriter, r *http.Request) {
	// Get tenant ID from JWT token
	tenantID := middleware.MustGetTenantID(r.Context())

	id := r.PathValue("id")
	if id == "" {
		apierror.BadRequest("Component ID is required").WriteJSON(w)
		return
	}

	if err := h.service.DeleteComponent(r.Context(), id, tenantID); err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// toAssetComponentResponse converts domain AssetDependency to API response.
func toAssetComponentResponse(d *component.AssetDependency) ComponentResponse {
	// Re-use ComponentResponse structure but flatten the linkage info.
	// A bit hacky: we mix dependency properties (Path, Type) into the Component object response.
	// This matches the previous API behavior of returning "Components for an Asset" as a list of components with context.

	c := d.Component()
	if c == nil {
		// Fallback if joined component is missing (should not happen in correct DB state)
		var parentID *string
		if d.ParentComponentID() != nil {
			pid := d.ParentComponentID().String()
			parentID = &pid
		}
		return ComponentResponse{
			ID:                d.ID().String(),
			TenantID:          d.TenantID().String(),
			AssetID:           d.AssetID().String(),
			DependencyType:    d.DependencyType().String(),
			ManifestPath:      d.Path(),
			ManifestFile:      d.ManifestFile(),
			Depth:             d.Depth(),
			ParentComponentID: parentID,
			IsDirect:          d.Depth() == 1,
			CreatedAt:         d.CreatedAt(),
			UpdatedAt:         d.UpdatedAt(),
			Status:            "orphaned",
		}
	}

	// Get parent component ID as string pointer
	var parentID *string
	if d.ParentComponentID() != nil {
		pid := d.ParentComponentID().String()
		parentID = &pid
	}

	return ComponentResponse{
		// IMPORTANT: For "Asset Components", the ID should be the DEPENDENCY ID so simple Update/Delete operations on the UI work targeting the link.
		// However, if the UI navigates to "Global Component Details", it might expect the Global ID.
		// Given the UI is "Asset Components" tab, returning the Link ID is safer for operations.
		ID:       d.ID().String(),
		TenantID: d.TenantID().String(),
		AssetID:  d.AssetID().String(),

		// Component Details
		Name:               c.Name(),
		Version:            c.Version(),
		Ecosystem:          c.Ecosystem().String(),
		PURL:               c.PURL(),
		License:            c.License(),
		VulnerabilityCount: c.VulnerabilityCount(),

		// Contextual Details
		DependencyType: d.DependencyType().String(),
		ManifestPath:   d.Path(),
		ManifestFile:   d.ManifestFile(),

		// Dependency hierarchy (industry-aligned: CycloneDX, Snyk, GitHub)
		Depth:             d.Depth(),
		ParentComponentID: parentID,
		IsDirect:          d.Depth() == 1,

		Status:    "active", // TODO: Map status from global component if exists
		Metadata:  c.Metadata(),
		CreatedAt: d.CreatedAt(), // Use Link creation time
		UpdatedAt: d.UpdatedAt(),
	}
}

// ListByAsset handles GET /api/v1/assets/{id}/components
// @Summary      List asset components
// @Description  Retrieves all components for an asset
// @Tags         Components
// @Produce      json
// @Security     BearerAuth
// @Param        id        path      string  true   "Asset ID"
// @Param        page      query     int     false  "Page number"  default(1)
// @Param        per_page  query     int     false  "Items per page"  default(20)
// @Success      200  {object}  map[string]interface{}
// @Failure      400  {object}  map[string]string
// @Failure      404  {object}  map[string]string
// @Router       /assets/{id}/components [get]
func (h *ComponentHandler) ListByAsset(w http.ResponseWriter, r *http.Request) {
	assetID := r.PathValue("id")
	if assetID == "" {
		apierror.BadRequest("Asset ID is required").WriteJSON(w)
		return
	}

	query := r.URL.Query()
	page := parseQueryInt(query.Get("page"), 1)
	perPage := parseQueryInt(query.Get("per_page"), 20)

	result, err := h.service.ListAssetComponents(r.Context(), assetID, page, perPage)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	data := make([]ComponentResponse, len(result.Data))
	for i, c := range result.Data {
		data[i] = toAssetComponentResponse(c)
	}

	response := ListResponse[ComponentResponse]{
		Data:       data,
		Total:      result.Total,
		Page:       result.Page,
		PerPage:    result.PerPage,
		TotalPages: result.TotalPages,
		Links:      NewPaginationLinks(r, result.Page, result.PerPage, result.TotalPages),
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(response)
}

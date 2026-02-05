package handler

import (
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"strconv"
	"time"

	"github.com/openctemio/api/internal/infra/http/middleware"
	"github.com/openctemio/api/pkg/apierror"
	"github.com/openctemio/api/pkg/domain/asset"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/logger"
	"github.com/openctemio/api/pkg/validator"
)

// AssetServiceHandler handles asset service-related HTTP requests.
type AssetServiceHandler struct {
	repo      asset.AssetServiceRepository
	assetRepo asset.Repository
	validator *validator.Validator
	logger    *logger.Logger
}

// NewAssetServiceHandler creates a new asset service handler.
func NewAssetServiceHandler(repo asset.AssetServiceRepository, assetRepo asset.Repository, v *validator.Validator, log *logger.Logger) *AssetServiceHandler {
	return &AssetServiceHandler{
		repo:      repo,
		assetRepo: assetRepo,
		validator: v,
		logger:    log,
	}
}

// =============================================================================
// Response Types
// =============================================================================

// AssetServiceResponse represents an asset service in API responses.
type AssetServiceResponse struct {
	ID              string     `json:"id"`
	TenantID        string     `json:"tenant_id,omitempty"`
	AssetID         string     `json:"asset_id"`
	Name            string     `json:"name,omitempty"`
	Protocol        string     `json:"protocol"`
	Port            int        `json:"port"`
	ServiceType     string     `json:"service_type"`
	Product         string     `json:"product,omitempty"`
	Version         string     `json:"version,omitempty"`
	Banner          string     `json:"banner,omitempty"`
	CPE             string     `json:"cpe,omitempty"`
	IsPublic        bool       `json:"is_public"`
	Exposure        string     `json:"exposure"`
	TLSEnabled      bool       `json:"tls_enabled"`
	TLSVersion      string     `json:"tls_version,omitempty"`
	DiscoverySource string     `json:"discovery_source,omitempty"`
	DiscoveredAt    *time.Time `json:"discovered_at,omitempty"`
	LastSeenAt      *time.Time `json:"last_seen_at,omitempty"`
	FindingCount    int        `json:"finding_count"`
	RiskScore       int        `json:"risk_score"`
	State           string     `json:"state"`
	StateChangedAt  *time.Time `json:"state_changed_at,omitempty"`
	CreatedAt       time.Time  `json:"created_at"`
	UpdatedAt       time.Time  `json:"updated_at"`
}

// AssetServiceStatsResponse represents service statistics.
type AssetServiceStatsResponse struct {
	TotalServices     int64               `json:"total_services"`
	PublicServices    int64               `json:"public_services"`
	ServiceTypeCounts map[string]int      `json:"service_type_counts"`
	TopPorts          []PortCountResponse `json:"top_ports"`
}

// PortCountResponse represents a port count entry.
type PortCountResponse struct {
	Port  int `json:"port"`
	Count int `json:"count"`
}

// =============================================================================
// Request Types
// =============================================================================

// CreateAssetServiceRequest represents the request to create an asset service.
type CreateAssetServiceRequest struct {
	Name            string `json:"name" validate:"omitempty,max=255"`
	Protocol        string `json:"protocol" validate:"required,oneof=tcp udp"`
	Port            int    `json:"port" validate:"required,min=1,max=65535"`
	ServiceType     string `json:"service_type" validate:"required"`
	Product         string `json:"product" validate:"omitempty,max=255"`
	Version         string `json:"version" validate:"omitempty,max=100"`
	Banner          string `json:"banner" validate:"omitempty,max=4096"`
	CPE             string `json:"cpe" validate:"omitempty,max=500"`
	IsPublic        bool   `json:"is_public"`
	Exposure        string `json:"exposure" validate:"omitempty,oneof=public restricted private"`
	TLSEnabled      bool   `json:"tls_enabled"`
	TLSVersion      string `json:"tls_version" validate:"omitempty,max=20"`
	DiscoverySource string `json:"discovery_source" validate:"omitempty,max=100"`
}

// UpdateAssetServiceRequest represents the request to update an asset service.
type UpdateAssetServiceRequest struct {
	Name       *string `json:"name" validate:"omitempty,max=255"`
	Product    *string `json:"product" validate:"omitempty,max=255"`
	Version    *string `json:"version" validate:"omitempty,max=100"`
	Banner     *string `json:"banner" validate:"omitempty,max=4096"`
	CPE        *string `json:"cpe" validate:"omitempty,max=500"`
	IsPublic   *bool   `json:"is_public"`
	Exposure   *string `json:"exposure" validate:"omitempty,oneof=public restricted private"`
	TLSEnabled *bool   `json:"tls_enabled"`
	TLSVersion *string `json:"tls_version" validate:"omitempty,max=20"`
	State      *string `json:"state" validate:"omitempty,oneof=active inactive filtered"`
}

// =============================================================================
// Handlers
// =============================================================================

// ListByAsset handles GET /api/v1/assets/{id}/services
// @Summary      List services for an asset
// @Description  Retrieves all services discovered on a specific asset
// @Tags         Asset Services
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        id path string true "Asset ID (UUID)"
// @Success      200  {object}  object{data=[]AssetServiceResponse,total=int}
// @Failure      400  {object}  apierror.Error
// @Failure      401  {object}  apierror.Error
// @Failure      404  {object}  apierror.Error
// @Failure      500  {object}  apierror.Error
// @Router       /assets/{id}/services [get]
func (h *AssetServiceHandler) ListByAsset(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	tenantIDStr := middleware.MustGetTenantID(ctx)
	tenantID, err := shared.IDFromString(tenantIDStr)
	if err != nil {
		apierror.Unauthorized("Invalid tenant ID").WriteJSON(w)
		return
	}

	assetIDStr := r.PathValue("id")
	assetID, err := shared.IDFromString(assetIDStr)
	if err != nil {
		apierror.BadRequest("Invalid asset ID").WriteJSON(w)
		return
	}

	// Security: GetByID now enforces tenant isolation internally
	_, err = h.assetRepo.GetByID(ctx, tenantID, assetID)
	if err != nil {
		if errors.Is(err, shared.ErrNotFound) {
			apierror.NotFound("Asset").WriteJSON(w)
			return
		}
		h.logger.Error("failed to verify asset existence", "error", err, "asset_id", assetIDStr)
		apierror.InternalError(err).WriteJSON(w)
		return
	}

	services, err := h.repo.GetByAssetID(ctx, tenantID, assetID)
	if err != nil {
		h.logger.Error("failed to get services by asset", "error", err, "asset_id", assetIDStr)
		apierror.InternalError(err).WriteJSON(w)
		return
	}

	response := make([]AssetServiceResponse, len(services))
	for i, svc := range services {
		response[i] = toAssetServiceResponse(svc)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"data":  response,
		"total": len(response),
	})
}

// Create handles POST /api/v1/assets/{id}/services
// @Summary      Create a service for an asset
// @Description  Creates a new service entry for a specific asset (e.g., discovered port/protocol)
// @Tags         Asset Services
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        id path string true "Asset ID (UUID)"
// @Param        body body CreateAssetServiceRequest true "Service details"
// @Success      201  {object}  AssetServiceResponse
// @Failure      400  {object}  apierror.Error
// @Failure      401  {object}  apierror.Error
// @Failure      404  {object}  apierror.Error
// @Failure      409  {object}  apierror.Error "Service already exists for this port"
// @Failure      500  {object}  apierror.Error
// @Router       /assets/{id}/services [post]
func (h *AssetServiceHandler) Create(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	tenantIDStr := middleware.MustGetTenantID(ctx)
	tenantID, err := shared.IDFromString(tenantIDStr)
	if err != nil {
		apierror.Unauthorized("Invalid tenant ID").WriteJSON(w)
		return
	}

	assetIDStr := r.PathValue("id")
	assetID, err := shared.IDFromString(assetIDStr)
	if err != nil {
		apierror.BadRequest("Invalid asset ID").WriteJSON(w)
		return
	}

	// Security: Verify asset exists and belongs to the tenant (tenant-scoped query)
	_, err = h.assetRepo.GetByID(ctx, tenantID, assetID)
	if err != nil {
		if errors.Is(err, shared.ErrNotFound) {
			apierror.NotFound("Asset").WriteJSON(w)
			return
		}
		h.logger.Error("failed to verify asset existence", "error", err, "asset_id", assetIDStr)
		apierror.InternalError(err).WriteJSON(w)
		return
	}

	var req CreateAssetServiceRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}

	if err := h.validator.Validate(req); err != nil {
		h.handleValidationError(w, err)
		return
	}

	// Create domain entity
	svc, err := asset.NewAssetService(
		tenantID,
		assetID,
		req.Port,
		asset.Protocol(req.Protocol),
		asset.ServiceType(req.ServiceType),
	)
	if err != nil {
		apierror.BadRequest(err.Error()).WriteJSON(w)
		return
	}

	// Set optional fields
	if req.Name != "" {
		svc.SetName(req.Name)
	}
	if req.Product != "" {
		svc.SetProduct(req.Product)
	}
	if req.Version != "" {
		svc.SetVersion(req.Version)
	}
	if req.Banner != "" {
		svc.SetBanner(req.Banner)
	}
	if req.CPE != "" {
		svc.SetCPE(req.CPE)
	}
	if req.IsPublic {
		svc.SetPublic(true)
	}
	if req.Exposure != "" {
		if err := svc.SetExposure(asset.Exposure(req.Exposure)); err != nil {
			apierror.BadRequest(err.Error()).WriteJSON(w)
			return
		}
	}
	if req.TLSEnabled {
		svc.SetTLS(true, req.TLSVersion)
	}
	if req.DiscoverySource != "" {
		now := time.Now().UTC()
		svc.SetDiscoveryInfo(req.DiscoverySource, &now)
	}

	// Calculate initial risk score
	svc.CalculateRiskScore()

	if err := h.repo.Create(ctx, svc); err != nil {
		if errors.Is(err, shared.ErrAlreadyExists) {
			apierror.Conflict("Service already exists for this port").WriteJSON(w)
			return
		}
		h.logger.Error("failed to create service", "error", err)
		apierror.InternalError(err).WriteJSON(w)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(toAssetServiceResponse(svc))
}

// Get handles GET /api/v1/services/{id}
// @Summary      Get a service by ID
// @Description  Retrieves a specific service by its unique identifier
// @Tags         Asset Services
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        id path string true "Service ID (UUID)"
// @Success      200  {object}  AssetServiceResponse
// @Failure      400  {object}  apierror.Error
// @Failure      401  {object}  apierror.Error
// @Failure      404  {object}  apierror.Error
// @Failure      500  {object}  apierror.Error
// @Router       /services/{id} [get]
func (h *AssetServiceHandler) Get(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	tenantIDStr := middleware.MustGetTenantID(ctx)
	tenantID, err := shared.IDFromString(tenantIDStr)
	if err != nil {
		apierror.Unauthorized("Invalid tenant ID").WriteJSON(w)
		return
	}

	serviceIDStr := r.PathValue("id")
	serviceID, err := shared.IDFromString(serviceIDStr)
	if err != nil {
		apierror.BadRequest("Invalid service ID").WriteJSON(w)
		return
	}

	svc, err := h.repo.GetByID(ctx, tenantID, serviceID)
	if err != nil {
		if errors.Is(err, shared.ErrNotFound) {
			apierror.NotFound("Service").WriteJSON(w)
			return
		}
		h.logger.Error("failed to get service", "error", err)
		apierror.InternalError(err).WriteJSON(w)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(toAssetServiceResponse(svc))
}

// Update handles PUT /api/v1/services/{id}
// @Summary      Update a service
// @Description  Updates an existing service's properties
// @Tags         Asset Services
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        id path string true "Service ID (UUID)"
// @Param        body body UpdateAssetServiceRequest true "Updated service details"
// @Success      200  {object}  AssetServiceResponse
// @Failure      400  {object}  apierror.Error
// @Failure      401  {object}  apierror.Error
// @Failure      404  {object}  apierror.Error
// @Failure      500  {object}  apierror.Error
// @Router       /services/{id} [put]
func (h *AssetServiceHandler) Update(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	tenantIDStr := middleware.MustGetTenantID(ctx)
	tenantID, err := shared.IDFromString(tenantIDStr)
	if err != nil {
		apierror.Unauthorized("Invalid tenant ID").WriteJSON(w)
		return
	}

	serviceIDStr := r.PathValue("id")
	serviceID, err := shared.IDFromString(serviceIDStr)
	if err != nil {
		apierror.BadRequest("Invalid service ID").WriteJSON(w)
		return
	}

	var req UpdateAssetServiceRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}

	if err := h.validator.Validate(req); err != nil {
		h.handleValidationError(w, err)
		return
	}

	svc, err := h.repo.GetByID(ctx, tenantID, serviceID)
	if err != nil {
		if errors.Is(err, shared.ErrNotFound) {
			apierror.NotFound("Service").WriteJSON(w)
			return
		}
		h.logger.Error("failed to get service for update", "error", err)
		apierror.InternalError(err).WriteJSON(w)
		return
	}

	// Apply updates
	if req.Name != nil {
		svc.SetName(*req.Name)
	}
	if req.Product != nil {
		svc.SetProduct(*req.Product)
	}
	if req.Version != nil {
		svc.SetVersion(*req.Version)
	}
	if req.Banner != nil {
		svc.SetBanner(*req.Banner)
	}
	if req.CPE != nil {
		svc.SetCPE(*req.CPE)
	}
	if req.IsPublic != nil {
		svc.SetPublic(*req.IsPublic)
	}
	if req.Exposure != nil {
		if err := svc.SetExposure(asset.Exposure(*req.Exposure)); err != nil {
			apierror.BadRequest(err.Error()).WriteJSON(w)
			return
		}
	}
	if req.TLSEnabled != nil {
		tlsVersion := ""
		if req.TLSVersion != nil {
			tlsVersion = *req.TLSVersion
		}
		svc.SetTLS(*req.TLSEnabled, tlsVersion)
	}
	if req.State != nil {
		if err := svc.SetState(asset.ServiceState(*req.State)); err != nil {
			apierror.BadRequest(err.Error()).WriteJSON(w)
			return
		}
	}

	// Recalculate risk score
	svc.CalculateRiskScore()

	if err := h.repo.Update(ctx, svc); err != nil {
		h.logger.Error("failed to update service", "error", err)
		apierror.InternalError(err).WriteJSON(w)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(toAssetServiceResponse(svc))
}

// Delete handles DELETE /api/v1/services/{id}
// @Summary      Delete a service
// @Description  Permanently removes a service entry
// @Tags         Asset Services
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        id path string true "Service ID (UUID)"
// @Success      204  "No Content"
// @Failure      400  {object}  apierror.Error
// @Failure      401  {object}  apierror.Error
// @Failure      404  {object}  apierror.Error
// @Failure      500  {object}  apierror.Error
// @Router       /services/{id} [delete]
func (h *AssetServiceHandler) Delete(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	tenantIDStr := middleware.MustGetTenantID(ctx)
	tenantID, err := shared.IDFromString(tenantIDStr)
	if err != nil {
		apierror.Unauthorized("Invalid tenant ID").WriteJSON(w)
		return
	}

	serviceIDStr := r.PathValue("id")
	serviceID, err := shared.IDFromString(serviceIDStr)
	if err != nil {
		apierror.BadRequest("Invalid service ID").WriteJSON(w)
		return
	}

	if err := h.repo.Delete(ctx, tenantID, serviceID); err != nil {
		if errors.Is(err, shared.ErrNotFound) {
			apierror.NotFound("Service").WriteJSON(w)
			return
		}
		h.logger.Error("failed to delete service", "error", err)
		apierror.InternalError(err).WriteJSON(w)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// List handles GET /api/v1/services
// @Summary      List all services
// @Description  Retrieves a paginated list of all services for the tenant with optional filtering
// @Tags         Asset Services
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        service_type query string false "Filter by service type (e.g., http, ssh, database)"
// @Param        state query string false "Filter by state (active, inactive, filtered)"
// @Param        is_public query boolean false "Filter by public exposure"
// @Param        port query int false "Filter by port number"
// @Param        product query string false "Filter by product name"
// @Param        limit query int false "Maximum results (max 1000)" default(50)
// @Param        offset query int false "Pagination offset" default(0)
// @Param        sort_by query string false "Sort field"
// @Param        sort_order query string false "Sort order (asc, desc)"
// @Success      200  {object}  object{data=[]AssetServiceResponse,total=int,limit=int,offset=int}
// @Failure      400  {object}  apierror.Error
// @Failure      401  {object}  apierror.Error
// @Failure      500  {object}  apierror.Error
// @Router       /services [get]
func (h *AssetServiceHandler) List(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	tenantIDStr := middleware.MustGetTenantID(ctx)
	tenantID, err := shared.IDFromString(tenantIDStr)
	if err != nil {
		apierror.Unauthorized("Invalid tenant ID").WriteJSON(w)
		return
	}

	opts := asset.DefaultListAssetServicesOptions()

	// Parse query params
	if v := r.URL.Query().Get("service_type"); v != "" {
		st := asset.ServiceType(v)
		opts.ServiceType = &st
	}
	if v := r.URL.Query().Get("state"); v != "" {
		s := asset.ServiceState(v)
		opts.State = &s
	}
	if v := r.URL.Query().Get("is_public"); v != "" {
		isPublic := v == queryParamTrue
		opts.IsPublic = &isPublic
	}
	if v := r.URL.Query().Get("port"); v != "" {
		if port, err := strconv.Atoi(v); err == nil {
			opts.Port = &port
		}
	}
	if v := r.URL.Query().Get("product"); v != "" {
		opts.Product = &v
	}
	if v := r.URL.Query().Get("limit"); v != "" {
		if limit, err := strconv.Atoi(v); err == nil && limit > 0 {
			opts.Limit = limit
		}
	}
	// Security: Enforce max limit to prevent DoS via large queries
	const maxLimit = 1000
	if opts.Limit > maxLimit {
		opts.Limit = maxLimit
	}
	if v := r.URL.Query().Get("offset"); v != "" {
		if offset, err := strconv.Atoi(v); err == nil && offset >= 0 {
			opts.Offset = offset
		}
	}
	if v := r.URL.Query().Get("sort_by"); v != "" {
		opts.SortBy = v
	}
	if v := r.URL.Query().Get("sort_order"); v != "" {
		opts.SortOrder = v
	}

	services, total, err := h.repo.List(ctx, tenantID, opts)
	if err != nil {
		h.logger.Error("failed to list services", "error", err)
		apierror.InternalError(err).WriteJSON(w)
		return
	}

	response := make([]AssetServiceResponse, len(services))
	for i, svc := range services {
		response[i] = toAssetServiceResponse(svc)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"data":   response,
		"total":  total,
		"limit":  opts.Limit,
		"offset": opts.Offset,
	})
}

// ListPublic handles GET /api/v1/services/public
// @Summary      List public services
// @Description  Retrieves a paginated list of publicly exposed services
// @Tags         Asset Services
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        limit query int false "Maximum results (max 1000)" default(50)
// @Param        offset query int false "Pagination offset" default(0)
// @Success      200  {object}  object{data=[]AssetServiceResponse,total=int,limit=int,offset=int}
// @Failure      401  {object}  apierror.Error
// @Failure      500  {object}  apierror.Error
// @Router       /services/public [get]
func (h *AssetServiceHandler) ListPublic(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	tenantIDStr := middleware.MustGetTenantID(ctx)
	tenantID, err := shared.IDFromString(tenantIDStr)
	if err != nil {
		apierror.Unauthorized("Invalid tenant ID").WriteJSON(w)
		return
	}

	limit := 50
	offset := 0
	if v := r.URL.Query().Get("limit"); v != "" {
		if l, err := strconv.Atoi(v); err == nil && l > 0 {
			limit = l
		}
	}
	if v := r.URL.Query().Get("offset"); v != "" {
		if o, err := strconv.Atoi(v); err == nil && o >= 0 {
			offset = o
		}
	}
	// Security: Enforce max limit to prevent DoS via large queries
	const maxLimit = 1000
	if limit > maxLimit {
		limit = maxLimit
	}

	services, total, err := h.repo.ListPublic(ctx, tenantID, limit, offset)
	if err != nil {
		h.logger.Error("failed to list public services", "error", err)
		apierror.InternalError(err).WriteJSON(w)
		return
	}

	response := make([]AssetServiceResponse, len(services))
	for i, svc := range services {
		response[i] = toAssetServiceResponse(svc)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"data":   response,
		"total":  total,
		"limit":  limit,
		"offset": offset,
	})
}

// Stats handles GET /api/v1/services/stats
// @Summary      Get service statistics
// @Description  Retrieves aggregate statistics about services including counts by type and top ports
// @Tags         Asset Services
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Success      200  {object}  AssetServiceStatsResponse
// @Failure      401  {object}  apierror.Error
// @Failure      500  {object}  apierror.Error
// @Router       /services/stats [get]
func (h *AssetServiceHandler) Stats(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	tenantIDStr := middleware.MustGetTenantID(ctx)
	tenantID, err := shared.IDFromString(tenantIDStr)
	if err != nil {
		apierror.Unauthorized("Invalid tenant ID").WriteJSON(w)
		return
	}

	total, err := h.repo.CountByTenant(ctx, tenantID)
	if err != nil {
		h.logger.Error("failed to count services", "error", err)
		apierror.InternalError(err).WriteJSON(w)
		return
	}

	publicCount, err := h.repo.CountPublic(ctx, tenantID)
	if err != nil {
		h.logger.Error("failed to count public services", "error", err)
		apierror.InternalError(err).WriteJSON(w)
		return
	}

	typeCounts, err := h.repo.GetServiceTypeCounts(ctx, tenantID)
	if err != nil {
		h.logger.Error("failed to get type counts", "error", err)
		apierror.InternalError(err).WriteJSON(w)
		return
	}

	portCounts, err := h.repo.GetPortCounts(ctx, tenantID, 10)
	if err != nil {
		h.logger.Error("failed to get port counts", "error", err)
		apierror.InternalError(err).WriteJSON(w)
		return
	}

	// Convert type counts to string keys
	typeCountsStr := make(map[string]int)
	for k, v := range typeCounts {
		typeCountsStr[string(k)] = v
	}

	// Convert port counts
	topPorts := make([]PortCountResponse, 0, len(portCounts))
	for port, count := range portCounts {
		topPorts = append(topPorts, PortCountResponse{Port: port, Count: count})
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(AssetServiceStatsResponse{
		TotalServices:     total,
		PublicServices:    publicCount,
		ServiceTypeCounts: typeCountsStr,
		TopPorts:          topPorts,
	})
}

// =============================================================================
// Helper Methods
// =============================================================================

func toAssetServiceResponse(svc *asset.AssetService) AssetServiceResponse {
	return AssetServiceResponse{
		ID:              svc.ID().String(),
		TenantID:        svc.TenantID().String(),
		AssetID:         svc.AssetID().String(),
		Name:            svc.Name(),
		Protocol:        svc.Protocol().String(),
		Port:            svc.Port(),
		ServiceType:     svc.ServiceType().String(),
		Product:         svc.Product(),
		Version:         svc.Version(),
		Banner:          sanitizeBanner(svc.Banner()), // Security: redact sensitive info from banners
		CPE:             svc.CPE(),
		IsPublic:        svc.IsPublic(),
		Exposure:        svc.Exposure().String(),
		TLSEnabled:      svc.TLSEnabled(),
		TLSVersion:      svc.TLSVersion(),
		DiscoverySource: svc.DiscoverySource(),
		DiscoveredAt:    svc.DiscoveredAt(),
		LastSeenAt:      svc.LastSeenAt(),
		FindingCount:    svc.FindingCount(),
		RiskScore:       svc.RiskScore(),
		State:           svc.State().String(),
		StateChangedAt:  svc.StateChangedAt(),
		CreatedAt:       svc.CreatedAt(),
		UpdatedAt:       svc.UpdatedAt(),
	}
}

func (h *AssetServiceHandler) handleValidationError(w http.ResponseWriter, err error) {
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

// sensitivePatterns contains regex patterns for sensitive data that should be redacted from banners.
var sensitivePatterns = []*regexp.Regexp{
	// Internal IP addresses (RFC 1918)
	regexp.MustCompile(`\b10\.\d{1,3}\.\d{1,3}\.\d{1,3}\b`),
	regexp.MustCompile(`\b172\.(1[6-9]|2[0-9]|3[0-1])\.\d{1,3}\.\d{1,3}\b`),
	regexp.MustCompile(`\b192\.168\.\d{1,3}\.\d{1,3}\b`),
	// Email addresses
	regexp.MustCompile(`[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`),
	// File paths that might reveal internal structure
	regexp.MustCompile(`/home/[a-zA-Z0-9_-]+/`),
	regexp.MustCompile(`/var/[a-zA-Z0-9_/-]+`),
	regexp.MustCompile(`C:\\Users\\[a-zA-Z0-9_-]+\\`),
	// Potential credentials or tokens (generic patterns)
	regexp.MustCompile(`(?i)(password|passwd|pwd|secret|token|apikey|api_key|auth)[:=]\s*[^\s]+`),
}

// sanitizeBanner removes potentially sensitive information from service banners.
func sanitizeBanner(banner string) string {
	if banner == "" {
		return banner
	}
	result := banner
	for _, pattern := range sensitivePatterns {
		result = pattern.ReplaceAllString(result, "[REDACTED]")
	}
	return result
}

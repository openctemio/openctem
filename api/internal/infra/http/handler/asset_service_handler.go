package handler

import (
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"time"

	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/apierror"
	"github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/validator"
)

// AssetServiceHandler handles asset service-related HTTP requests.
type AssetServiceHandler struct {
	repo      asset.AssetServiceRepository
	assetRepo asset.Repository
	validator *validator.Validator
	logger    *logger.Logger
	dataScope DataScopeEnforcer
}

// SetDataScope wires the Layer 2 data scope: a scoped member sees and
// changes only services of assets in their scope. Returns h for chaining.
func (h *AssetServiceHandler) SetDataScope(e DataScopeEnforcer) *AssetServiceHandler {
	h.dataScope = e
	return h
}

// assetVisible returns shared.ErrNotFound unless the asset exists in the
// tenant and lies inside the caller's data scope (fail closed).
func (h *AssetServiceHandler) assetVisible(r *http.Request, tenantID, assetID shared.ID) error {
	if _, err := h.assetRepo.GetByID(r.Context(), tenantID, assetID); err != nil {
		return err
	}
	if !assetInDataScope(r.Context(), h.dataScope, tenantID, assetID) {
		return shared.ErrNotFound
	}
	return nil
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
	Technologies    []string   `json:"technologies"`
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

// =============================================================================
// Request Types
// =============================================================================

// CreateAssetServiceRequest represents the request to create an asset service.
type CreateAssetServiceRequest struct {
	Name            string   `json:"name" validate:"omitempty,max=255"`
	Protocol        string   `json:"protocol" validate:"required,oneof=tcp udp"`
	Port            int      `json:"port" validate:"required,min=1,max=65535"`
	ServiceType     string   `json:"service_type" validate:"required"`
	Product         string   `json:"product" validate:"omitempty,max=255"`
	Version         string   `json:"version" validate:"omitempty,max=100"`
	Banner          string   `json:"banner" validate:"omitempty,max=4096"`
	CPE             string   `json:"cpe" validate:"omitempty,max=500"`
	Technologies    []string `json:"technologies" validate:"omitempty,max=50,dive,max=100"`
	IsPublic        bool     `json:"is_public"`
	Exposure        string   `json:"exposure" validate:"omitempty,oneof=public restricted private"`
	TLSEnabled      bool     `json:"tls_enabled"`
	TLSVersion      string   `json:"tls_version" validate:"omitempty,max=20"`
	DiscoverySource string   `json:"discovery_source" validate:"omitempty,max=100"`
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

	// The asset must exist in the tenant and be inside the caller's data
	// scope; both misses answer 404 so the reply never reveals that an
	// out-of-scope asset exists. DataScopeGuard checks the same on the route;
	// this keeps the handler safe wherever it is mounted.
	if err = h.assetVisible(r, tenantID, assetID); err != nil {
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

	// The asset must exist in the tenant and be inside the caller's data
	// scope; both misses answer 404 so the reply never reveals that an
	// out-of-scope asset exists. DataScopeGuard checks the same on the route;
	// this keeps the handler safe wherever it is mounted.
	if err = h.assetVisible(r, tenantID, assetID); err != nil {
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
	if len(req.Technologies) > 0 {
		svc.SetTechnologies(req.Technologies)
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
		Technologies:    svc.Technologies(),
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

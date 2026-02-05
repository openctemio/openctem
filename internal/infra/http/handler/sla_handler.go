package handler

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/openctemio/api/internal/app"
	"github.com/openctemio/api/internal/infra/http/middleware"
	"github.com/openctemio/api/pkg/apierror"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/domain/sla"
	"github.com/openctemio/api/pkg/logger"
	"github.com/openctemio/api/pkg/validator"
)

// SLAHandler handles SLA policy-related HTTP requests.
type SLAHandler struct {
	service   *app.SLAService
	validator *validator.Validator
	logger    *logger.Logger
}

// NewSLAHandler creates a new SLA handler.
func NewSLAHandler(svc *app.SLAService, v *validator.Validator, log *logger.Logger) *SLAHandler {
	return &SLAHandler{
		service:   svc,
		validator: v,
		logger:    log,
	}
}

// SLAPolicyResponse represents an SLA policy in API responses.
type SLAPolicyResponse struct {
	ID                  string         `json:"id"`
	TenantID            string         `json:"tenant_id"`
	AssetID             string         `json:"asset_id,omitempty"`
	Name                string         `json:"name"`
	Description         string         `json:"description,omitempty"`
	IsDefault           bool           `json:"is_default"`
	CriticalDays        int            `json:"critical_days"`
	HighDays            int            `json:"high_days"`
	MediumDays          int            `json:"medium_days"`
	LowDays             int            `json:"low_days"`
	InfoDays            int            `json:"info_days"`
	WarningThresholdPct int            `json:"warning_threshold_pct"`
	EscalationEnabled   bool           `json:"escalation_enabled"`
	EscalationConfig    map[string]any `json:"escalation_config,omitempty"`
	IsActive            bool           `json:"is_active"`
	CreatedAt           time.Time      `json:"created_at"`
	UpdatedAt           time.Time      `json:"updated_at"`
}

// toSLAPolicyResponse converts a domain policy to API response.
func toSLAPolicyResponse(p *sla.Policy) SLAPolicyResponse {
	resp := SLAPolicyResponse{
		ID:                  p.ID().String(),
		TenantID:            p.TenantID().String(),
		Name:                p.Name(),
		Description:         p.Description(),
		IsDefault:           p.IsDefault(),
		CriticalDays:        p.CriticalDays(),
		HighDays:            p.HighDays(),
		MediumDays:          p.MediumDays(),
		LowDays:             p.LowDays(),
		InfoDays:            p.InfoDays(),
		WarningThresholdPct: p.WarningThresholdPct(),
		EscalationEnabled:   p.EscalationEnabled(),
		EscalationConfig:    p.EscalationConfig(),
		IsActive:            p.IsActive(),
		CreatedAt:           p.CreatedAt(),
		UpdatedAt:           p.UpdatedAt(),
	}
	if p.AssetID() != nil {
		resp.AssetID = p.AssetID().String()
	}
	return resp
}

// CreateSLAPolicyRequest represents the request to create an SLA policy.
type CreateSLAPolicyRequest struct {
	AssetID             string         `json:"asset_id" validate:"omitempty,uuid"`
	Name                string         `json:"name" validate:"required,min=1,max=100"`
	Description         string         `json:"description" validate:"max=500"`
	IsDefault           bool           `json:"is_default"`
	CriticalDays        int            `json:"critical_days" validate:"required,min=1,max=365"`
	HighDays            int            `json:"high_days" validate:"required,min=1,max=365"`
	MediumDays          int            `json:"medium_days" validate:"required,min=1,max=365"`
	LowDays             int            `json:"low_days" validate:"required,min=1,max=365"`
	InfoDays            int            `json:"info_days" validate:"required,min=1,max=365"`
	WarningThresholdPct int            `json:"warning_threshold_pct" validate:"min=0,max=100"`
	EscalationEnabled   bool           `json:"escalation_enabled"`
	EscalationConfig    map[string]any `json:"escalation_config"`
}

// UpdateSLAPolicyRequest represents the request to update an SLA policy.
type UpdateSLAPolicyRequest struct {
	Name                *string        `json:"name" validate:"omitempty,min=1,max=100"`
	Description         *string        `json:"description" validate:"omitempty,max=500"`
	IsDefault           *bool          `json:"is_default"`
	CriticalDays        *int           `json:"critical_days" validate:"omitempty,min=1,max=365"`
	HighDays            *int           `json:"high_days" validate:"omitempty,min=1,max=365"`
	MediumDays          *int           `json:"medium_days" validate:"omitempty,min=1,max=365"`
	LowDays             *int           `json:"low_days" validate:"omitempty,min=1,max=365"`
	InfoDays            *int           `json:"info_days" validate:"omitempty,min=1,max=365"`
	WarningThresholdPct *int           `json:"warning_threshold_pct" validate:"omitempty,min=0,max=100"`
	EscalationEnabled   *bool          `json:"escalation_enabled"`
	EscalationConfig    map[string]any `json:"escalation_config"`
	IsActive            *bool          `json:"is_active"`
}

// handleValidationError converts validation errors to API errors.
func (h *SLAHandler) handleValidationError(w http.ResponseWriter, err error) {
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

// handleServiceError converts service errors to API errors.
func (h *SLAHandler) handleServiceError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, shared.ErrNotFound) || errors.Is(err, sla.ErrNotFound):
		apierror.NotFound("SLA Policy").WriteJSON(w)
	case errors.Is(err, shared.ErrAlreadyExists) || errors.Is(err, sla.ErrAlreadyExists):
		apierror.Conflict("SLA Policy already exists").WriteJSON(w)
	case errors.Is(err, shared.ErrValidation):
		apierror.BadRequest(err.Error()).WriteJSON(w)
	default:
		h.logger.Error("service error", "error", err)
		apierror.InternalError(err).WriteJSON(w)
	}
}

// List handles GET /api/v1/sla-policies
// @Summary      List SLA policies
// @Description  Retrieves all SLA policies for the current tenant
// @Tags         SLA Policies
// @Produce      json
// @Security     BearerAuth
// @Success      200  {object}  map[string]interface{}
// @Failure      401  {object}  map[string]string
// @Failure      500  {object}  map[string]string
// @Router       /sla-policies [get]
func (h *SLAHandler) List(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())

	policies, err := h.service.ListTenantPolicies(r.Context(), tenantID)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	data := make([]SLAPolicyResponse, len(policies))
	for i, p := range policies {
		data[i] = toSLAPolicyResponse(p)
	}

	response := struct {
		Data  []SLAPolicyResponse `json:"data"`
		Total int                 `json:"total"`
	}{
		Data:  data,
		Total: len(data),
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(response)
}

// Create handles POST /api/v1/sla-policies
// @Summary      Create SLA policy
// @Description  Creates a new SLA policy for the tenant
// @Tags         SLA Policies
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        request  body      CreateSLAPolicyRequest  true  "SLA Policy data"
// @Success      201  {object}  SLAPolicyResponse
// @Failure      400  {object}  map[string]string
// @Failure      401  {object}  map[string]string
// @Failure      409  {object}  map[string]string
// @Router       /sla-policies [post]
func (h *SLAHandler) Create(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())

	var req CreateSLAPolicyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}

	if err := h.validator.Validate(req); err != nil {
		h.handleValidationError(w, err)
		return
	}

	input := app.CreateSLAPolicyInput{
		TenantID:            tenantID,
		AssetID:             req.AssetID,
		Name:                req.Name,
		Description:         req.Description,
		IsDefault:           req.IsDefault,
		CriticalDays:        req.CriticalDays,
		HighDays:            req.HighDays,
		MediumDays:          req.MediumDays,
		LowDays:             req.LowDays,
		InfoDays:            req.InfoDays,
		WarningThresholdPct: req.WarningThresholdPct,
		EscalationEnabled:   req.EscalationEnabled,
		EscalationConfig:    req.EscalationConfig,
	}

	p, err := h.service.CreateSLAPolicy(r.Context(), input)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(toSLAPolicyResponse(p))
}

// Get handles GET /api/v1/sla-policies/{id}
// @Summary      Get SLA policy
// @Description  Retrieves an SLA policy by ID
// @Tags         SLA Policies
// @Produce      json
// @Security     BearerAuth
// @Param        id   path      string  true  "SLA Policy ID"
// @Success      200  {object}  SLAPolicyResponse
// @Failure      400  {object}  map[string]string
// @Failure      404  {object}  map[string]string
// @Router       /sla-policies/{id} [get]
func (h *SLAHandler) Get(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())
	policyID := r.PathValue("id")
	if policyID == "" {
		apierror.BadRequest("Policy ID is required").WriteJSON(w)
		return
	}

	p, err := h.service.GetSLAPolicy(r.Context(), policyID)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	// IDOR prevention
	if p.TenantID().String() != tenantID {
		apierror.NotFound("SLA Policy").WriteJSON(w)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(toSLAPolicyResponse(p))
}

// Update handles PUT /api/v1/sla-policies/{id}
// @Summary      Update SLA policy
// @Description  Updates an SLA policy
// @Tags         SLA Policies
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        id       path      string                  true  "SLA Policy ID"
// @Param        request  body      UpdateSLAPolicyRequest  true  "SLA Policy data"
// @Success      200  {object}  SLAPolicyResponse
// @Failure      400  {object}  map[string]string
// @Failure      404  {object}  map[string]string
// @Router       /sla-policies/{id} [put]
func (h *SLAHandler) Update(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())
	policyID := r.PathValue("id")
	if policyID == "" {
		apierror.BadRequest("Policy ID is required").WriteJSON(w)
		return
	}

	var req UpdateSLAPolicyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}

	if err := h.validator.Validate(req); err != nil {
		h.handleValidationError(w, err)
		return
	}

	input := app.UpdateSLAPolicyInput{
		Name:                req.Name,
		Description:         req.Description,
		IsDefault:           req.IsDefault,
		CriticalDays:        req.CriticalDays,
		HighDays:            req.HighDays,
		MediumDays:          req.MediumDays,
		LowDays:             req.LowDays,
		InfoDays:            req.InfoDays,
		WarningThresholdPct: req.WarningThresholdPct,
		EscalationEnabled:   req.EscalationEnabled,
		EscalationConfig:    req.EscalationConfig,
		IsActive:            req.IsActive,
	}

	p, err := h.service.UpdateSLAPolicy(r.Context(), policyID, tenantID, input)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(toSLAPolicyResponse(p))
}

// Delete handles DELETE /api/v1/sla-policies/{id}
// @Summary      Delete SLA policy
// @Description  Deletes an SLA policy
// @Tags         SLA Policies
// @Security     BearerAuth
// @Param        id   path      string  true  "SLA Policy ID"
// @Success      204  "No Content"
// @Failure      400  {object}  map[string]string
// @Failure      404  {object}  map[string]string
// @Router       /sla-policies/{id} [delete]
func (h *SLAHandler) Delete(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())
	policyID := r.PathValue("id")
	if policyID == "" {
		apierror.BadRequest("Policy ID is required").WriteJSON(w)
		return
	}

	if err := h.service.DeleteSLAPolicy(r.Context(), policyID, tenantID); err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// GetDefault handles GET /api/v1/sla-policies/default
// @Summary      Get default SLA policy
// @Description  Gets the default SLA policy for the tenant
// @Tags         SLA Policies
// @Produce      json
// @Security     BearerAuth
// @Success      200  {object}  SLAPolicyResponse
// @Failure      404  {object}  map[string]string
// @Router       /sla-policies/default [get]
func (h *SLAHandler) GetDefault(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())

	p, err := h.service.GetTenantDefaultPolicy(r.Context(), tenantID)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(toSLAPolicyResponse(p))
}

// GetByAsset handles GET /api/v1/assets/{id}/sla-policy
// @Summary      Get asset SLA policy
// @Description  Gets the SLA policy for a specific asset (or default if not set)
// @Tags         SLA Policies
// @Produce      json
// @Security     BearerAuth
// @Param        id   path      string  true  "Asset ID"
// @Success      200  {object}  SLAPolicyResponse
// @Failure      400  {object}  map[string]string
// @Failure      404  {object}  map[string]string
// @Router       /assets/{id}/sla-policy [get]
func (h *SLAHandler) GetByAsset(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())
	assetID := r.PathValue("assetId")
	if assetID == "" {
		apierror.BadRequest("Asset ID is required").WriteJSON(w)
		return
	}

	p, err := h.service.GetAssetSLAPolicy(r.Context(), tenantID, assetID)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(toSLAPolicyResponse(p))
}

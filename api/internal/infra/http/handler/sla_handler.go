package handler

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"fmt"
	"strings"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/internal/app/sla"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/apierror"
	auditdom "github.com/openctemio/openctem/api/pkg/domain/audit"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	sladom "github.com/openctemio/openctem/api/pkg/domain/sla"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/validator"
)

// SLAHandler handles SLA policy-related HTTP requests.
type SLAHandler struct {
	configAuditor
	service   *sla.Service
	validator *validator.Validator
	logger    *logger.Logger
}

// NewSLAHandler creates a new SLA handler.
func NewSLAHandler(svc *sla.Service, v *validator.Validator, log *logger.Logger) *SLAHandler {
	return &SLAHandler{
		service:   svc,
		validator: v,
		logger:    log,
	}
}

// SLAPolicyResponse represents an SLA policy in API responses.
type SLAPolicyResponse struct {
	ID           string `json:"id"`
	TenantID     string `json:"tenant_id"`
	AssetID      string `json:"asset_id,omitempty"`
	Name         string `json:"name"`
	Description  string `json:"description,omitempty"`
	IsDefault    bool   `json:"is_default"`
	CriticalDays int    `json:"critical_days"`
	HighDays     int    `json:"high_days"`
	MediumDays   int    `json:"medium_days"`
	LowDays      int    `json:"low_days"`
	InfoDays     int    `json:"info_days"`
	// P0Days..P3Days are the remediation windows per CTEM priority class.
	// They take precedence over the severity windows for every finding that
	// has a priority class.
	P0Days              int  `json:"p0_days"`
	P1Days              int  `json:"p1_days"`
	P2Days              int  `json:"p2_days"`
	P3Days              int  `json:"p3_days"`
	WarningThresholdPct int  `json:"warning_threshold_pct"`
	EscalationEnabled   bool `json:"escalation_enabled"`
	IsActive            bool `json:"is_active"`
	// IsPlatformDefault is true when the tenant has configured no policy
	// and the windows are the platform defaults (ID is then empty).
	IsPlatformDefault bool      `json:"is_platform_default"`
	CreatedAt         time.Time `json:"created_at"`
	UpdatedAt         time.Time `json:"updated_at"`
}

// toSLAPolicyResponse converts a domain policy to API response.
func toSLAPolicyResponse(p *sladom.Policy) SLAPolicyResponse {
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
		P0Days:              p.P0Days(),
		P1Days:              p.P1Days(),
		P2Days:              p.P2Days(),
		P3Days:              p.P3Days(),
		WarningThresholdPct: p.WarningThresholdPct(),
		EscalationEnabled:   p.EscalationEnabled(),
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
	AssetID      string `json:"asset_id" validate:"omitempty,uuid"`
	Name         string `json:"name" validate:"required,min=1,max=100"`
	Description  string `json:"description" validate:"max=500"`
	IsDefault    bool   `json:"is_default"`
	CriticalDays int    `json:"critical_days" validate:"required,min=1,max=365"`
	HighDays     int    `json:"high_days" validate:"required,min=1,max=365"`
	MediumDays   int    `json:"medium_days" validate:"required,min=1,max=365"`
	LowDays      int    `json:"low_days" validate:"required,min=1,max=365"`
	InfoDays     int    `json:"info_days" validate:"min=0,max=365"` // 0 = no SLA for informational findings
	// P0Days..P3Days are optional; an omitted class keeps its default window.
	P0Days              *int  `json:"p0_days" validate:"omitempty,min=1,max=365"`
	P1Days              *int  `json:"p1_days" validate:"omitempty,min=1,max=365"`
	P2Days              *int  `json:"p2_days" validate:"omitempty,min=1,max=365"`
	P3Days              *int  `json:"p3_days" validate:"omitempty,min=1,max=365"`
	WarningThresholdPct int   `json:"warning_threshold_pct" validate:"min=0,max=100"`
	EscalationEnabled   *bool `json:"escalation_enabled"`
}

// UpdateSLAPolicyRequest represents the request to update an SLA policy.
type UpdateSLAPolicyRequest struct {
	Name                *string `json:"name" validate:"omitempty,min=1,max=100"`
	Description         *string `json:"description" validate:"omitempty,max=500"`
	IsDefault           *bool   `json:"is_default"`
	CriticalDays        *int    `json:"critical_days" validate:"omitempty,min=1,max=365"`
	HighDays            *int    `json:"high_days" validate:"omitempty,min=1,max=365"`
	MediumDays          *int    `json:"medium_days" validate:"omitempty,min=1,max=365"`
	LowDays             *int    `json:"low_days" validate:"omitempty,min=1,max=365"`
	InfoDays            *int    `json:"info_days" validate:"omitempty,min=0,max=365"` // 0 = no SLA for informational findings
	P0Days              *int    `json:"p0_days" validate:"omitempty,min=1,max=365"`
	P1Days              *int    `json:"p1_days" validate:"omitempty,min=1,max=365"`
	P2Days              *int    `json:"p2_days" validate:"omitempty,min=1,max=365"`
	P3Days              *int    `json:"p3_days" validate:"omitempty,min=1,max=365"`
	WarningThresholdPct *int    `json:"warning_threshold_pct" validate:"omitempty,min=0,max=100"`
	EscalationEnabled   *bool   `json:"escalation_enabled"`
	IsActive            *bool   `json:"is_active"`
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
	case errors.Is(err, shared.ErrNotFound) || errors.Is(err, sladom.ErrNotFound):
		apierror.NotFound("SLA Policy").WriteJSON(w)
	case errors.Is(err, shared.ErrAlreadyExists) || errors.Is(err, sladom.ErrAlreadyExists):
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

	input := sla.CreatePolicyInput{
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
		P0Days:              req.P0Days,
		P1Days:              req.P1Days,
		P2Days:              req.P2Days,
		P3Days:              req.P3Days,
	}

	p, err := h.service.CreateSLAPolicy(r.Context(), input)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}
	created := toSLAPolicyResponse(p)
	h.recordChange(r, h.logger, auditdom.ActionSLAPolicyCreated, auditdom.ResourceTypeSLAPolicy, created.ID, created.Name,
		nil, created, auditdom.SeverityMedium, fmt.Sprintf("SLA policy %q created", created.Name))

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

	// Tenant scoping is enforced inside the service (GetByTenantAndID); a policy
	// belonging to another tenant returns ErrNotFound → 404.
	p, err := h.service.GetSLAPolicy(r.Context(), tenantID, policyID)
	if err != nil {
		h.handleServiceError(w, err)
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

	input := sla.UpdatePolicyInput{
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
		IsActive:            req.IsActive,
		P0Days:              req.P0Days,
		P1Days:              req.P1Days,
		P2Days:              req.P2Days,
		P3Days:              req.P3Days,
	}

	var before any
	if prev, gerr := h.service.GetSLAPolicy(r.Context(), tenantID, policyID); gerr == nil {
		before = toSLAPolicyResponse(prev)
	}
	p, err := h.service.UpdateSLAPolicy(r.Context(), policyID, tenantID, input)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}
	updated := toSLAPolicyResponse(p)
	h.recordChange(r, h.logger, auditdom.ActionSLAPolicyUpdated, auditdom.ResourceTypeSLAPolicy, updated.ID, updated.Name,
		before, updated, slaChangeSeverity(before, updated), fmt.Sprintf("SLA policy %q updated", updated.Name))

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

	var before SLAPolicyResponse
	if prev, gerr := h.service.GetSLAPolicy(r.Context(), tenantID, policyID); gerr == nil {
		before = toSLAPolicyResponse(prev)
	}
	if err := h.service.DeleteSLAPolicy(r.Context(), policyID, tenantID); err != nil {
		h.handleServiceError(w, err)
		return
	}
	h.recordChange(r, h.logger, auditdom.ActionSLAPolicyDeleted, auditdom.ResourceTypeSLAPolicy, policyID, before.Name,
		before, nil, auditdom.SeverityHigh, fmt.Sprintf("SLA policy %q deleted", before.Name))

	w.WriteHeader(http.StatusNoContent)
}

// GetDefault handles GET /api/v1/sla-policies/default
// @Summary      Get default SLA policy
// @Description  Gets the tenant's default SLA policy. When the tenant has configured none, returns the platform default windows with is_platform_default=true and an empty id.
// @Tags         SLA Policies
// @Produce      json
// @Security     BearerAuth
// @Success      200  {object}  SLAPolicyResponse
// @Router       /sla-policies/default [get]
func (h *SLAHandler) GetDefault(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())

	ep, err := h.service.GetEffectiveTenantPolicy(r.Context(), tenantID)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}
	writeEffectivePolicy(w, ep)
}

// writeEffectivePolicy writes a governing policy, or the platform default
// windows (no id, is_platform_default) when the tenant has configured none.
func writeEffectivePolicy(w http.ResponseWriter, ep *sla.EffectivePolicy) {
	resp := toSLAPolicyResponse(ep.Policy)
	if ep.PlatformDefault {
		resp = SLAPolicyResponse{
			TenantID:            resp.TenantID,
			Name:                resp.Name,
			IsDefault:           true,
			CriticalDays:        resp.CriticalDays,
			HighDays:            resp.HighDays,
			MediumDays:          resp.MediumDays,
			LowDays:             resp.LowDays,
			InfoDays:            resp.InfoDays,
			P0Days:              resp.P0Days,
			P1Days:              resp.P1Days,
			P2Days:              resp.P2Days,
			P3Days:              resp.P3Days,
			WarningThresholdPct: resp.WarningThresholdPct,
			EscalationEnabled:   resp.EscalationEnabled,
			IsActive:            true,
			IsPlatformDefault:   true,
		}
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(resp)
}

// GetByAsset handles GET /api/v1/assets/{id}/sla-policy
// @Summary      Get asset SLA policy
// @Description  Gets the SLA policy that governs an asset: its override, else the tenant default, else the platform default windows (is_platform_default=true, empty id).
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

	ep, err := h.service.GetEffectiveAssetPolicy(r.Context(), tenantID, assetID)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}
	writeEffectivePolicy(w, ep)
}

// slaChangeSeverity is High when any remediation window got longer (findings
// may stay open longer before they breach), Medium otherwise.
func slaChangeSeverity(before any, after SLAPolicyResponse) auditdom.Severity {
	changes := auditapp.DiffChanges(before, after)
	if changes == nil {
		return auditdom.SeverityMedium
	}
	for k, b := range changes.Before {
		if !strings.HasSuffix(k, "_days") {
			continue
		}
		bf, bok := b.(float64)
		af, aok := changes.After[k].(float64)
		if bok && aok && af > bf {
			return auditdom.SeverityHigh
		}
	}
	return auditdom.SeverityMedium
}

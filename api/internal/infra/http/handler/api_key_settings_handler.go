package handler

import (
	"encoding/json"
	"net/http"

	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/apierror"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/tenant"
)

// APIKeySettingsResponse is the organization's API key policy.
type APIKeySettingsResponse struct {
	// MaxLifetimeDays is the longest a new key may live (in force).
	MaxLifetimeDays int `json:"max_lifetime_days"`
	// DefaultMaxLifetimeDays applies to an organization that never chose.
	DefaultMaxLifetimeDays int `json:"default_max_lifetime_days"`
	// CeilingDays is the platform ceiling; the organization may only set less.
	CeilingDays int `json:"ceiling_days"`
}

// UpdateAPIKeySettingsRequest sets the maximum lifetime of new keys.
type UpdateAPIKeySettingsRequest struct {
	// MaxLifetimeDays: 1 to the platform ceiling (365).
	MaxLifetimeDays int `json:"max_lifetime_days" validate:"required,min=1,max=365"`
}

func toAPIKeySettingsResponse(s tenant.APIKeySettings) APIKeySettingsResponse {
	return APIKeySettingsResponse{
		MaxLifetimeDays:        s.EffectiveMaxLifetimeDays(),
		DefaultMaxLifetimeDays: tenant.DefaultAPIKeyMaxLifetimeDays,
		CeilingDays:            tenant.APIKeyLifetimeCeilingDays,
	}
}

// GetAPIKeySettings handles GET /api/v1/organization/settings/api-keys.
// @Summary      Get the API key policy
// @Description  The maximum lifetime of a new API key in this organization (default 90 days), the default and the platform ceiling (365 days). Every member who can read or create API keys, so the key dialog offers only allowed lifetimes.
// @Tags         Tenants
// @Produce      json
// @Success      200     {object}  APIKeySettingsResponse
// @Failure      403     {object}  apierror.Error
// @Security     BearerAuth
// @Router       /organization/settings/api-keys [get]
func (h *TenantHandler) GetAPIKeySettings(w http.ResponseWriter, r *http.Request) {
	tenantID, err := shared.IDFromString(middleware.GetTenantID(r.Context()))
	if err != nil || tenantID.IsZero() {
		apierror.BadRequest("Tenant context required").WriteJSON(w)
		return
	}
	ks, err := h.service.GetAPIKeySettings(r.Context(), tenantID.String())
	if err != nil {
		h.handleServiceError(w, err)
		return
	}
	h.writeSectionETag(w, r, tenantID, tenant.SectionAPIKeys)
	writeJSON(w, http.StatusOK, toAPIKeySettingsResponse(*ks))
}

// UpdateAPIKeySettings handles PUT /api/v1/organization/settings/api-keys.
// @Summary      Set the API key policy
// @Description  Sets the maximum lifetime of new API keys (1 to 365 days). A shorter maximum applies at once; existing keys keep their expiry and are flagged when they outlive it. A longer maximum needs a recent sign-in (403 STEP_UP_REQUIRED), is audited high and every owner and administrator is told. Owners and administrators with settings:write.
// @Tags         Tenants
// @Accept       json
// @Produce      json
// @Param        body    body      UpdateAPIKeySettingsRequest  true  "API key policy"
// @Success      200     {object}  APIKeySettingsResponse
// @Failure      400     {object}  apierror.Error
// @Failure      403     {object}  apierror.Error
// @Security     BearerAuth
// @Router       /organization/settings/api-keys [put]
func (h *TenantHandler) UpdateAPIKeySettings(w http.ResponseWriter, r *http.Request) {
	tenantID, err := shared.IDFromString(middleware.GetTenantID(r.Context()))
	if err != nil || tenantID.IsZero() {
		apierror.BadRequest("Tenant context required").WriteJSON(w)
		return
	}
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<10))
	decoder.DisallowUnknownFields()
	var req UpdateAPIKeySettingsRequest
	if err := decoder.Decode(&req); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}
	if err := h.validator.Validate(req); err != nil {
		apierror.BadRequest("max_lifetime_days must be 1 to 365").WriteJSON(w)
		return
	}
	ks, err := h.service.UpdateAPIKeySettings(settingsWriteCtx(r), tenantID.String(),
		tenant.APIKeySettings{MaxLifetimeDays: req.MaxLifetimeDays}, h.buildAuditContext(r))
	if err != nil {
		h.handleServiceError(w, err)
		return
	}
	h.writeSectionETag(w, r, tenantID, tenant.SectionAPIKeys)
	writeJSON(w, http.StatusOK, toAPIKeySettingsResponse(*ks))
}

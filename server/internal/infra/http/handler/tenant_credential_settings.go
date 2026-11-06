package handler

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/openctemio/openctem/server/internal/infra/http/middleware"
	"github.com/openctemio/openctem/server/pkg/apierror"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
	"github.com/openctemio/openctem/server/pkg/domain/tenant"
)

// Settings > Leaked credentials: whether the organization keeps imported
// leaked secret values (docs/architecture/credential-leaks.md).

// LeakedSecretDefaultSource answers the platform default of leaked secret
// value storage.
type LeakedSecretDefaultSource interface {
	PlatformDefault(ctx context.Context) bool
}

// SetLeakedSecretDefault wires the platform default the credential settings
// page shows (nil: not kept).
func (h *TenantHandler) SetLeakedSecretDefault(src LeakedSecretDefaultSource) {
	h.leakedSecretDefault = src
}

// CredentialSettingsResponse is the organization's choice, the platform
// default and the value in force.
type CredentialSettingsResponse struct {
	// StoreSecretValues is the organization's own choice; absent: the
	// platform default applies.
	StoreSecretValues *bool `json:"store_secret_values,omitempty"`
	// PlatformDefault is what applies without a choice.
	PlatformDefault bool `json:"platform_default"`
	// Effective is the value in force for the next import.
	Effective bool `json:"effective"`
}

func (h *TenantHandler) credentialSettingsResponse(ctx context.Context, cs tenant.CredentialSettings) CredentialSettingsResponse {
	def := h.leakedSecretDefault != nil && h.leakedSecretDefault.PlatformDefault(ctx)
	return CredentialSettingsResponse{StoreSecretValues: cs.StoreSecretValues, PlatformDefault: def,
		Effective: cs.EffectiveStoreSecretValues(def)}
}

// GetCredentialSettings handles GET /api/v1/organization/settings/credentials.
// @Summary      Get leaked credential settings
// @Description  Whether imported leaked secret values (password, token, key) are kept, encrypted, for an audited reveal. When not kept, only the mask, the credential type and the organization's keyed fingerprint are stored. Owners and administrators.
// @Tags         Tenants
// @Produce      json
// @Success      200     {object}  CredentialSettingsResponse
// @Failure      400     {object}  apierror.Error
// @Failure      403     {object}  apierror.Error
// @Security     BearerAuth
// @Router       /organization/settings/credentials [get]
func (h *TenantHandler) GetCredentialSettings(w http.ResponseWriter, r *http.Request) {
	tenantID, err := shared.IDFromString(middleware.GetTenantID(r.Context()))
	if err != nil || tenantID.IsZero() {
		apierror.BadRequest("Tenant context required").WriteJSON(w)
		return
	}
	cs, err := h.service.GetCredentialSettings(r.Context(), tenantID.String())
	if err != nil {
		h.handleServiceError(w, err)
		return
	}
	h.writeSectionETag(w, r, tenantID, tenant.SectionCredentials)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(h.credentialSettingsResponse(r.Context(), *cs))
}

// UpdateCredentialSettings handles PUT /api/v1/organization/settings/credentials.
// @Summary      Update leaked credential settings
// @Description  Sets whether imported leaked secret values are kept (store_secret_values true or false; omit it to follow the platform default). Applies to the next import; values already stored are kept. Owners and administrators. Audited.
// @Tags         Tenants
// @Accept       json
// @Produce      json
// @Param        body    body      tenant.CredentialSettings  true  "Credential settings"
// @Success      200     {object}  CredentialSettingsResponse
// @Failure      400     {object}  apierror.Error
// @Failure      403     {object}  apierror.Error
// @Security     BearerAuth
// @Router       /organization/settings/credentials [put]
func (h *TenantHandler) UpdateCredentialSettings(w http.ResponseWriter, r *http.Request) {
	tenantID, err := shared.IDFromString(middleware.GetTenantID(r.Context()))
	if err != nil || tenantID.IsZero() {
		apierror.BadRequest("Tenant context required").WriteJSON(w)
		return
	}
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	var req tenant.CredentialSettings
	if err := decoder.Decode(&req); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}
	cs, err := h.service.UpdateCredentialSettings(settingsWriteCtx(r), tenantID.String(), req, h.buildAuditContext(r))
	if err != nil {
		h.handleServiceError(w, err)
		return
	}
	h.writeSectionETag(w, r, tenantID, tenant.SectionCredentials)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(h.credentialSettingsResponse(r.Context(), *cs))
}

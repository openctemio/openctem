package handler

// The organization owner's shared sensor opt-out
// (docs/rfcs/RFC-100-shared-sensors.md §5, layer 3).

import (
	"encoding/json"
	"net/http"

	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/apierror"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/tenant"
)

// GetSharedSensorsSettings handles GET /api/v1/organization/settings/shared-sensors.
// @Summary      Get the organization's shared sensor choice
// @Description  Whether the organization opted out of shared sensors (opt_out, default false: use them when the instance offers them). Owner or administrator.
// @Tags         Tenants
// @Produce      json
// @Success      200     {object}  tenant.SharedSensorsSettings
// @Failure      400     {object}  apierror.Error
// @Failure      403     {object}  apierror.Error
// @Security     BearerAuth
// @Router       /organization/settings/shared-sensors [get]
func (h *TenantHandler) GetSharedSensorsSettings(w http.ResponseWriter, r *http.Request) {
	tenantID, err := shared.IDFromString(middleware.GetTenantID(r.Context()))
	if err != nil || tenantID.IsZero() {
		apierror.BadRequest("Tenant context required").WriteJSON(w)
		return
	}
	ss, err := h.service.GetSharedSensorsSettings(r.Context(), tenantID.String())
	if err != nil {
		h.handleServiceError(w, err)
		return
	}
	h.writeSectionETag(w, r, tenantID, tenant.SectionSharedSensors)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(ss)
}

// UpdateSharedSensorsSettings handles PUT /api/v1/organization/settings/shared-sensors.
// @Summary      Update the organization's shared sensor choice
// @Description  Owner only. opt_out true: never send this organization's scans to shared sensors. Audited.
// @Tags         Tenants
// @Accept       json
// @Produce      json
// @Param        body    body      tenant.SharedSensorsSettings  true  "Shared sensor choice"
// @Success      200     {object}  tenant.SharedSensorsSettings
// @Failure      400     {object}  apierror.Error
// @Failure      403     {object}  apierror.Error
// @Security     BearerAuth
// @Router       /organization/settings/shared-sensors [put]
func (h *TenantHandler) UpdateSharedSensorsSettings(w http.ResponseWriter, r *http.Request) {
	tenantID, err := shared.IDFromString(middleware.GetTenantID(r.Context()))
	if err != nil || tenantID.IsZero() {
		apierror.BadRequest("Tenant context required").WriteJSON(w)
		return
	}
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096))
	decoder.DisallowUnknownFields()
	var req tenant.SharedSensorsSettings
	if err := decoder.Decode(&req); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}
	ss, err := h.service.UpdateSharedSensorsSettings(settingsWriteCtx(r), tenantID.String(), req, h.buildAuditContext(r))
	if err != nil {
		h.handleServiceError(w, err)
		return
	}
	h.writeSectionETag(w, r, tenantID, tenant.SectionSharedSensors)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(ss)
}

package handler

// CI settings (docs/rfcs/RFC-051-ci-runner-identity-and-gate.md): whether the
// organization accepts CI results sent with a sensor key.

import (
	"context"
	"encoding/json"
	"net/http"

	cirunapp "github.com/openctemio/openctem/api/internal/app/cirun"
	"github.com/openctemio/openctem/api/pkg/apierror"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// CISettingsService reads and writes a tenant's CI settings.
type CISettingsService interface {
	GetSettings(ctx context.Context, tenantID shared.ID) (cirunapp.Settings, error)
	UpdateSettings(ctx context.Context, tenantID shared.ID, in cirunapp.Settings, a cirunapp.Actor) (cirunapp.Settings, error)
}

// SetSettingsService wires the CI settings endpoints.
func (h *CIAdminHandler) SetSettingsService(svc CISettingsService) { h.settings = svc }

// CISettingsRequest changes the CI settings.
type CISettingsRequest struct {
	// RequireOIDC refuses CI results sent with a sensor key (a CI job must
	// use its provider's OIDC identity).
	RequireOIDC *bool `json:"require_oidc"`
}

// GetSettings handles GET /api/v1/ci/settings
// @Summary      CI settings
// @Description  Whether the organization requires the CI job's OIDC identity for CI results (a CI sensor's key is then refused). On for organizations created since this setting exists.
// @Tags         CI
// @Produce      json
// @Security     BearerAuth
// @Success      200  {object}  cirunapp.Settings
// @Router       /ci/settings [get]
func (h *CIAdminHandler) GetSettings(w http.ResponseWriter, r *http.Request) {
	if h.settings == nil {
		apierror.NotFound("CI settings").WriteJSON(w)
		return
	}
	tenantID, ok := h.tenant(w, r)
	if !ok {
		return
	}
	s, err := h.settings.GetSettings(r.Context(), tenantID)
	if err != nil {
		h.writeErr(w, err, "read CI settings", "CI settings")
		return
	}
	ciWriteJSON(w, http.StatusOK, s)
}

// UpdateSettings handles PUT /api/v1/ci/settings
// @Summary      Change the CI settings
// @Description  Turning require_oidc off lets CI sensors authenticate with a sensor key again (audited at high severity).
// @Tags         CI
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        body body CISettingsRequest true "CI settings"
// @Success      200  {object}  cirunapp.Settings
// @Failure      400  {object}  apierror.Error
// @Router       /ci/settings [put]
func (h *CIAdminHandler) UpdateSettings(w http.ResponseWriter, r *http.Request) {
	if h.settings == nil {
		apierror.NotFound("CI settings").WriteJSON(w)
		return
	}
	tenantID, ok := h.tenant(w, r)
	if !ok {
		return
	}
	limitBody(w, r)
	var req CISettingsRequest
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil || req.RequireOIDC == nil {
		apierror.BadRequest("require_oidc is required").WriteJSON(w)
		return
	}
	s, err := h.settings.UpdateSettings(r.Context(), tenantID, cirunapp.Settings{RequireOIDC: *req.RequireOIDC}, h.actor(r))
	if err != nil {
		h.writeErr(w, err, "change CI settings", "CI settings")
		return
	}
	ciWriteJSON(w, http.StatusOK, s)
}

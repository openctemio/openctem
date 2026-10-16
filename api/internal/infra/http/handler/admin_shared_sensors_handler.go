package handler

// Console routes of shared sensor access (docs/rfcs/RFC-100-shared-sensors.md
// §5): the instance setting and the decision for one organization. Any
// administrator reads; a super admin changes either with a reason and a fresh
// authenticator code (the service writes the critical audit row and emails
// the other administrators). Turning the instance switch on is refused while
// the rollout gate (§11) is closed, before the code is spent.

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/openctemio/openctem/api/internal/app/scanpolicy"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/apierror"
	"github.com/openctemio/openctem/api/pkg/logger"
)

const stepUpPurposeSharedSensors = "shared sensor access change"

// codeSharedSensorsNotReady is the error code of a refused switch-on.
const codeSharedSensorsNotReady apierror.Code = "SHARED_SENSORS_NOT_READY"

// codeNewOrgsChoiceRequired refuses a switch-on without the choice for
// organizations without a decision.
const codeNewOrgsChoiceRequired apierror.Code = "NEW_ORGS_CHOICE_REQUIRED"

// SharedSensorsSettingResponse is the instance shared sensor setting.
type SharedSensorsSettingResponse struct {
	// Enabled is the instance switch (default false).
	Enabled bool `json:"enabled"`
	// NewOrgs: whether an organization without a decision may use shared
	// sensors; null when unset (the default), which refuses such an
	// organization.
	NewOrgs *bool `json:"new_orgs"`
	// Ready is false while shared sensors cannot be used on any deployment
	// yet; the switch cannot be turned on until it is true.
	Ready bool `json:"ready"`
	// Version to send back on PUT (0: nothing stored, the defaults apply).
	Version int `json:"version"`
}

// UpdateSharedSensorsSettingRequest changes the instance setting.
type UpdateSharedSensorsSettingRequest struct {
	Enabled  *bool  `json:"enabled"`
	NewOrgs  *bool  `json:"new_orgs"`
	Version  int    `json:"version"`
	Reason   string `json:"reason"`
	TOTPCode string `json:"totp_code"`
}

// SharedSensorsOrganizationResponse is the decision for one organization.
type SharedSensorsOrganizationResponse struct {
	// Access is the administrator's decision: allow, deny, or "" (the
	// instance default for organizations without a decision applies).
	Access string `json:"access" enums:",allow,deny"`
}

// UpdateSharedSensorsOrganizationRequest sets the decision.
type UpdateSharedSensorsOrganizationRequest struct {
	// Access: allow, deny, or "" to follow the instance default.
	Access   *string `json:"access"`
	Reason   string  `json:"reason"`
	TOTPCode string  `json:"totp_code"`
}

// GetSharedSensors returns the instance setting.
// @Summary      Shared sensors on this instance
// @Description  The instance switch (off by default), whether organizations without a decision may use shared sensors (null until the administrator chooses; null refuses them) and whether shared sensors can be used yet. Any administrator.
// @Tags         Admin System
// @Produce      json
// @Success      200  {object}  SharedSensorsSettingResponse
// @Router       /admin/settings/shared-sensors [get]
func (h *AdminScanPolicyHandler) GetSharedSensors(w http.ResponseWriter, r *http.Request) {
	v, ver, err := h.svc.SharedSensorsSetting(r.Context())
	if err != nil {
		h.logger.Error("read shared sensor setting", "error", logger.SanitizeError(err))
		apierror.InternalServerError("could not read the setting").WriteJSON(w)
		return
	}
	writeJSON(w, http.StatusOK, SharedSensorsSettingResponse{Enabled: v.Enabled, NewOrgs: v.NewOrgs,
		Ready: scanpolicy.SharedSensorsReady(), Version: ver})
}

// UpdateSharedSensors changes the instance setting.
// @Summary      Change the shared sensor setting
// @Description  Super admin with a reason and a fresh authenticator code (route-level step-up). Turning the switch on needs new_orgs true or false in the same request (400 NEW_ORGS_CHOICE_REQUIRED without it); it is refused (409 SHARED_SENSORS_NOT_READY) while shared sensors are not available yet. Audited (critical); the other administrators are emailed.
// @Tags         Admin System
// @Accept       json
// @Produce      json
// @Param        request  body      UpdateSharedSensorsSettingRequest  true  "Setting"
// @Success      200  {object}  SharedSensorsSettingResponse
// @Failure      409  {object}  apierror.Error
// @Router       /admin/settings/shared-sensors [put]
func (h *AdminScanPolicyHandler) UpdateSharedSensors(w http.ResponseWriter, r *http.Request) {
	actor := middleware.GetAdminUser(r.Context())
	if actor == nil {
		apierror.Unauthorized("administrator session required").WriteJSON(w)
		return
	}
	var req UpdateSharedSensorsSettingRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8192)).Decode(&req); err != nil {
		apierror.BadRequest("invalid request body").WriteJSON(w)
		return
	}
	if req.Enabled == nil {
		apierror.BadRequest("enabled must be true or false").WriteJSON(w)
		return
	}
	// Turning the switch on needs an explicit choice for organizations
	// without a decision, in the same action: never an implicit default.
	if *req.Enabled && req.NewOrgs == nil {
		apierror.New(http.StatusBadRequest, codeNewOrgsChoiceRequired,
			"Choose whether organizations without a decision may use shared sensors (new_orgs true or false) when you turn shared sensors on").WriteJSON(w)
		return
	}
	// The switch stays off until the rollout gate opens.
	if *req.Enabled && !scanpolicy.SharedSensorsReady() {
		apierror.New(http.StatusConflict, codeSharedSensorsNotReady, scanpolicy.ReasonSharedSensorsNotReady).WriteJSON(w)
		return
	}
	if !h.stepUpChange(w, r, actor, stepUpPurposeSharedSensors, req.Reason, req.TOTPCode) {
		return
	}
	next := scanpolicy.SharedSensorsSetting{Enabled: *req.Enabled, NewOrgs: req.NewOrgs}
	v, err := h.svc.UpdateSharedSensors(r.Context(), next, req.Version, h.change(r, actor, req.Reason))
	if err != nil {
		h.writeSharedErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, SharedSensorsSettingResponse{Enabled: next.Enabled, NewOrgs: next.NewOrgs,
		Ready: scanpolicy.SharedSensorsReady(), Version: v})
}

// GetOrganizationSharedSensors returns the decision for one organization.
// @Summary      Shared sensor access of an organization
// @Description  The instance administrator's decision for the organization: allow, deny, or empty (the instance default applies). Any administrator.
// @Tags         Admin Tenants
// @Produce      json
// @Param        tenantId  path      string  true  "Organization ID"
// @Success      200  {object}  SharedSensorsOrganizationResponse
// @Failure      404  {object}  apierror.Error
// @Router       /admin/tenants/{tenantId}/shared-sensors [get]
func (h *AdminScanPolicyHandler) GetOrganizationSharedSensors(w http.ResponseWriter, r *http.Request) {
	tid, ok := h.tenantID(w, r)
	if !ok {
		return
	}
	d, err := h.svc.SharedSensorsAccess(r.Context(), tid)
	if err != nil {
		h.writeSharedErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, SharedSensorsOrganizationResponse{Access: d})
}

// UpdateOrganizationSharedSensors sets the decision for one organization.
// @Summary      Change the shared sensor access of an organization
// @Description  Super admin with a reason and a fresh authenticator code: allow, deny, or empty to follow the instance default. A deny wins over the default. Audited (critical); the other administrators are emailed.
// @Tags         Admin Tenants
// @Accept       json
// @Produce      json
// @Param        tenantId  path      string  true  "Organization ID"
// @Param        request   body      UpdateSharedSensorsOrganizationRequest  true  "Decision"
// @Success      200  {object}  SharedSensorsOrganizationResponse
// @Failure      404  {object}  apierror.Error
// @Router       /admin/tenants/{tenantId}/shared-sensors [put]
func (h *AdminScanPolicyHandler) UpdateOrganizationSharedSensors(w http.ResponseWriter, r *http.Request) {
	tid, ok := h.tenantID(w, r)
	if !ok {
		return
	}
	actor := middleware.GetAdminUser(r.Context())
	if actor == nil {
		apierror.Unauthorized("administrator session required").WriteJSON(w)
		return
	}
	var req UpdateSharedSensorsOrganizationRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8192)).Decode(&req); err != nil {
		apierror.BadRequest("invalid request body").WriteJSON(w)
		return
	}
	if req.Access == nil || (*req.Access != "" && *req.Access != scanpolicy.SharedSensorsAllow && *req.Access != scanpolicy.SharedSensorsDeny) {
		apierror.BadRequest("access must be allow, deny or empty").WriteJSON(w)
		return
	}
	if !h.stepUpChange(w, r, actor, stepUpPurposeSharedSensors, req.Reason, req.TOTPCode) {
		return
	}
	if err := h.svc.UpdateSharedSensorsAccess(r.Context(), tid, *req.Access, h.change(r, actor, req.Reason)); err != nil {
		h.writeSharedErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, SharedSensorsOrganizationResponse{Access: *req.Access})
}

func (h *AdminScanPolicyHandler) writeSharedErr(w http.ResponseWriter, err error) {
	if errors.Is(err, scanpolicy.ErrSharedSensorsNotReady) {
		apierror.New(http.StatusConflict, codeSharedSensorsNotReady, scanpolicy.ReasonSharedSensorsNotReady).WriteJSON(w)
		return
	}
	h.writeErr(w, err)
}

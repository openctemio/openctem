package handler

// Console routes of two shared sensor settings
// (docs/rfcs/RFC-100-shared-sensors.md §6, §9): "shared sensors may scan
// internal zones" and the anomaly alert thresholds. Any administrator reads;
// a super admin changes either with a reason and a fresh authenticator code
// (route-level step-up; the service writes the critical audit row and emails
// the other administrators).

import (
	"net/http"

	"github.com/openctemio/openctem/api/internal/app/scanpolicy"
	"github.com/openctemio/openctem/api/pkg/apierror"
	"github.com/openctemio/openctem/api/pkg/logger"
)

const (
	stepUpPurposeInternalZones = "shared sensor internal zones change"
	stepUpPurposeAnomaly       = "shared sensor anomaly thresholds change"
)

// SharedSensorInternalZonesResponse is the internal zones setting.
type SharedSensorInternalZonesResponse struct {
	// Allowed: shared sensors may scan instance scan zones the administrator
	// assigns to organizations. False: public targets only.
	Allowed bool `json:"allowed"`
	// Default is the value while nothing is stored: false on every
	// deployment.
	Default bool `json:"default"`
	// Enforced is false while nothing reads the setting yet (instance scan
	// zones and their signed ranges have not landed): it is stored only.
	Enforced bool `json:"enforced"`
	// Version to send back on PUT (0: nothing stored, the default applies).
	Version int `json:"version"`
}

// UpdateSharedSensorInternalZonesRequest changes the setting.
type UpdateSharedSensorInternalZonesRequest struct {
	Allowed  *bool  `json:"allowed"`
	Version  int    `json:"version"`
	Reason   string `json:"reason"`
	TOTPCode string `json:"totp_code"`
}

// SharedSensorAnomalyResponse is the anomaly thresholds setting.
type SharedSensorAnomalyResponse struct {
	// Per organization per UTC day; 0 turns a signal off.
	DistinctDomainsPerDay int `json:"distinct_domains_per_day"`
	FailuresPerDay        int `json:"failures_per_day"`
	DenyListHitsPerDay    int `json:"deny_list_hits_per_day"`
	// Version to send back on PUT (0: nothing stored, the defaults apply).
	Version int `json:"version"`
}

// UpdateSharedSensorAnomalyRequest changes the thresholds.
type UpdateSharedSensorAnomalyRequest struct {
	DistinctDomainsPerDay *int   `json:"distinct_domains_per_day"`
	FailuresPerDay        *int   `json:"failures_per_day"`
	DenyListHitsPerDay    *int   `json:"deny_list_hits_per_day"`
	Version               int    `json:"version"`
	Reason                string `json:"reason"`
	TOTPCode              string `json:"totp_code"`
}

// GetSharedSensorInternalZones returns the setting.
// @Summary      Shared sensors may scan internal zones
// @Description  Whether shared sensors may scan instance scan zones assigned to organizations (otherwise public targets only). Default off on every deployment. enforced is false while nothing reads the setting yet. Any administrator.
// @Tags         Admin System
// @Produce      json
// @Success      200  {object}  SharedSensorInternalZonesResponse
// @Router       /admin/settings/shared-sensor-internal-zones [get]
func (h *AdminScanPolicyHandler) GetSharedSensorInternalZones(w http.ResponseWriter, r *http.Request) {
	v, ver, err := h.svc.InternalZonesSetting(r.Context())
	if err != nil {
		h.logger.Error("read shared sensor internal zones setting", "error", logger.SanitizeError(err))
		apierror.InternalServerError("could not read the setting").WriteJSON(w)
		return
	}
	writeJSON(w, http.StatusOK, SharedSensorInternalZonesResponse{Allowed: v, Default: h.svc.InternalZonesDefault(),
		Enforced: scanpolicy.InternalZonesEnforced(), Version: ver})
}

// UpdateSharedSensorInternalZones changes the setting.
// @Summary      Change whether shared sensors may scan internal zones
// @Description  Super admin with a reason and a fresh authenticator code (route-level step-up). Turning it on assigns no zone: the administrator still assigns each instance scan zone to organizations. Audited (critical); the other administrators are emailed.
// @Tags         Admin System
// @Accept       json
// @Produce      json
// @Param        request  body      UpdateSharedSensorInternalZonesRequest  true  "Setting"
// @Success      200  {object}  SharedSensorInternalZonesResponse
// @Router       /admin/settings/shared-sensor-internal-zones [put]
func (h *AdminScanPolicyHandler) UpdateSharedSensorInternalZones(w http.ResponseWriter, r *http.Request) {
	var req UpdateSharedSensorInternalZonesRequest
	actor, ok := h.decodeAndStepUp(w, r, stepUpPurposeInternalZones, &req, func() (string, string) { return req.Reason, req.TOTPCode })
	if !ok {
		return
	}
	if req.Allowed == nil {
		apierror.BadRequest("allowed must be true or false").WriteJSON(w)
		return
	}
	v, err := h.svc.UpdateInternalZones(r.Context(), *req.Allowed, req.Version, h.change(r, actor, req.Reason))
	if err != nil {
		h.writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, SharedSensorInternalZonesResponse{Allowed: *req.Allowed, Default: h.svc.InternalZonesDefault(),
		Enforced: scanpolicy.InternalZonesEnforced(), Version: v})
}

// GetSharedSensorAnomaly returns the anomaly thresholds.
// @Summary      Shared sensor anomaly thresholds
// @Description  Per organization per UTC day: distinct registrable domains sent to shared sensors, failed shared jobs, deny-list hits. Reaching one raises one alert that day (metric, admin audit row, email to the administrators). 0 turns a signal off. Any administrator.
// @Tags         Admin System
// @Produce      json
// @Success      200  {object}  SharedSensorAnomalyResponse
// @Router       /admin/settings/shared-sensor-anomaly [get]
func (h *AdminScanPolicyHandler) GetSharedSensorAnomaly(w http.ResponseWriter, r *http.Request) {
	t, ver, err := h.svc.AnomalyThresholdsSetting(r.Context())
	if err != nil {
		h.logger.Error("read shared sensor anomaly thresholds", "error", logger.SanitizeError(err))
		apierror.InternalServerError("could not read the setting").WriteJSON(w)
		return
	}
	writeJSON(w, http.StatusOK, anomalyResponse(t, ver))
}

// UpdateSharedSensorAnomaly changes the anomaly thresholds.
// @Summary      Change the shared sensor anomaly thresholds
// @Description  Super admin with a reason and a fresh authenticator code (route-level step-up). Every threshold is required, between 0 (off) and 1000000. Audited (critical); the other administrators are emailed.
// @Tags         Admin System
// @Accept       json
// @Produce      json
// @Param        request  body      UpdateSharedSensorAnomalyRequest  true  "Thresholds"
// @Success      200  {object}  SharedSensorAnomalyResponse
// @Router       /admin/settings/shared-sensor-anomaly [put]
func (h *AdminScanPolicyHandler) UpdateSharedSensorAnomaly(w http.ResponseWriter, r *http.Request) {
	var req UpdateSharedSensorAnomalyRequest
	actor, ok := h.decodeAndStepUp(w, r, stepUpPurposeAnomaly, &req, func() (string, string) { return req.Reason, req.TOTPCode })
	if !ok {
		return
	}
	if req.DistinctDomainsPerDay == nil || req.FailuresPerDay == nil || req.DenyListHitsPerDay == nil {
		apierror.BadRequest("distinct_domains_per_day, failures_per_day and deny_list_hits_per_day are required").WriteJSON(w)
		return
	}
	t := scanpolicy.AnomalyThresholds{
		DistinctDomainsPerDay: *req.DistinctDomainsPerDay,
		FailuresPerDay:        *req.FailuresPerDay,
		DenyListHitsPerDay:    *req.DenyListHitsPerDay,
	}
	v, err := h.svc.UpdateAnomalyThresholds(r.Context(), t, req.Version, h.change(r, actor, req.Reason))
	if err != nil {
		h.writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, anomalyResponse(t, v))
}

func anomalyResponse(t scanpolicy.AnomalyThresholds, version int) SharedSensorAnomalyResponse {
	return SharedSensorAnomalyResponse{
		DistinctDomainsPerDay: t.DistinctDomainsPerDay,
		FailuresPerDay:        t.FailuresPerDay,
		DenyListHitsPerDay:    t.DenyListHitsPerDay,
		Version:               version,
	}
}

package handler

// Per-sensor grants (docs/rfcs/RFC-052-sensor-pairing-and-authorization.md
// §5): read a sensor's grant, list the profiles, narrow or widen a grant and
// promote or demote the trust level. The route needs sensors:grant:narrow or
// sensors:grant:widen; the service decides which one the change needs.

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"github.com/openctemio/openctem/api/internal/app/sensorgrant"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/apierror"
	"github.com/openctemio/openctem/api/pkg/domain/permission"
	sensordom "github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// SetGrantService wires per-sensor grants; without it the grant routes
// answer 404.
func (h *SensorHandler) SetGrantService(s *sensorgrant.Service) { h.grants = s }

// SensorGrantProfiles is the list of selectable grant profiles.
type SensorGrantProfiles struct {
	Profiles []sensorgrant.ProfileView `json:"profiles"`
}

// UpdateSensorGrantRequest replaces a sensor's grant. With profile set, the
// grant is rebuilt from that profile (zone_ids are the zones a zone-bound
// profile keeps to) and the other dimensions are ignored. A null list means
// "no limit" on that dimension, an empty list "nothing".
type UpdateSensorGrantRequest struct {
	// Version is the version read; a stale one answers 409.
	Version          int      `json:"version"`
	Profile          string   `json:"profile,omitempty"`
	TrustLevel       string   `json:"trust_level,omitempty" enums:"new,trusted"`
	JobTypes         []string `json:"job_types"`
	ZoneIDs          []string `json:"zone_ids"`
	Tools            []string `json:"tools"`
	Capabilities     []string `json:"capabilities"`
	TierCeiling      int      `json:"tier_ceiling" minimum:"0" maximum:"2"`
	TargetNetwork    string   `json:"target_network,omitempty" enums:"any,public,none"`
	TargetCIDRs      []string `json:"target_cidrs"`
	TargetDomains    []string `json:"target_domains"`
	AllowCredentials bool     `json:"allow_credentials"`
	AllowPushIngest  bool     `json:"allow_push_ingest"`
	RemoteActions    []string `json:"remote_actions"`
}

// ListGrantProfiles godoc
// @Summary      List sensor grant profiles
// @Description  The profiles an administrator may choose for a sensor. legacy-broad is never listed.
// @Tags         Sensors
// @Produce      json
// @Success      200  {object}  SensorGrantProfiles
// @Security     BearerAuth
// @Router       /sensors/grant-profiles [get]
func (h *SensorHandler) ListGrantProfiles(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, SensorGrantProfiles{Profiles: sensorgrant.Profiles()})
}

// SensorGrantSummaries lists every sensor's grant profile and trust level.
type SensorGrantSummaries struct {
	Data []sensorgrant.SummaryView `json:"data"`
}

// ListGrantSummaries godoc
// @Summary      List the grant profile and trust level of every sensor
// @Description  For the sensor list: which sensors still have the broad legacy grant and which are New.
// @Tags         Sensors
// @Produce      json
// @Success      200  {object}  SensorGrantSummaries
// @Security     BearerAuth
// @Router       /sensors/grant-summaries [get]
func (h *SensorHandler) ListGrantSummaries(w http.ResponseWriter, r *http.Request) {
	tid, err := shared.IDFromString(middleware.GetTenantID(r.Context()))
	if err != nil {
		apierror.Unauthorized("").WriteJSON(w)
		return
	}
	out := []sensorgrant.SummaryView{}
	if h.grants != nil {
		if out, err = h.grants.Summaries(r.Context(), tid); err != nil {
			h.handleServiceError(w, err)
			return
		}
	}
	writeJSON(w, http.StatusOK, SensorGrantSummaries{Data: out})
}

// GetGrant godoc
// @Summary      Get a sensor's grant
// @Description  What the sensor may do (RFC-052 §5) and what applies now after its trust level (effective).
// @Tags         Sensors
// @Produce      json
// @Param        id   path      string  true  "Sensor ID"
// @Success      200  {object}  sensorgrant.View
// @Failure      404  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /sensors/{id}/grant [get]
func (h *SensorHandler) GetGrant(w http.ResponseWriter, r *http.Request) {
	tid, sid, ok := h.tenantAndSensor(w, r)
	if !ok {
		return
	}
	if h.grants == nil {
		apierror.NotFound("Sensor").WriteJSON(w)
		return
	}
	g, err := h.grants.Get(r.Context(), tid, sid)
	if err != nil {
		h.writeGrantError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, sensorgrant.GrantView(*g))
}

// UpdateGrant godoc
// @Summary      Change a sensor's grant
// @Description  Narrowing (and demoting the trust level) needs sensors:grant:narrow; any widening (and promoting to trusted) needs sensors:grant:widen, is audited at high severity and notifies every administrator. Takes effect on the sensor's next request.
// @Tags         Sensors
// @Accept       json
// @Produce      json
// @Param        id    path      string                    true  "Sensor ID"
// @Param        body  body      UpdateSensorGrantRequest  true  "New grant"
// @Success      200   {object}  sensorgrant.View
// @Failure      400   {object}  apierror.Error
// @Failure      403   {object}  apierror.Error
// @Failure      404   {object}  apierror.Error
// @Failure      409   {object}  apierror.Error
// @Security     BearerAuth
// @Router       /sensors/{id}/grant [put]
func (h *SensorHandler) UpdateGrant(w http.ResponseWriter, r *http.Request) {
	tid, sid, ok := h.tenantAndSensor(w, r)
	if !ok {
		return
	}
	if h.grants == nil {
		apierror.NotFound("Sensor").WriteJSON(w)
		return
	}
	var req UpdateSensorGrantRequest
	dec := json.NewDecoder(io.LimitReader(r.Body, 64<<10))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}
	zones := []shared.ID(nil)
	if req.ZoneIDs != nil {
		zones = make([]shared.ID, 0, len(req.ZoneIDs))
		for _, z := range req.ZoneIDs {
			id, err := shared.IDFromString(z)
			if err != nil {
				apierror.BadRequest("Invalid zone id").WriteJSON(w)
				return
			}
			zones = append(zones, id)
		}
	}
	uid, _ := shared.IDFromString(middleware.GetUserID(r.Context()))
	actx := h.buildAuditContext(r)
	actor := sensorgrant.Actor{
		TenantID: tid, UserID: uid, Email: actx.ActorEmail, IP: actx.ActorIP, UserAgent: actx.UserAgent,
		CanNarrow: middleware.HasPermission(r.Context(), string(permission.SensorsGrantNarrow)),
		CanWiden:  middleware.HasPermission(r.Context(), string(permission.SensorsGrantWiden)),
	}
	g, err := h.grants.Update(r.Context(), actor, sid, sensorgrant.UpdateInput{
		Version: req.Version, Profile: req.Profile, TrustLevel: sensordom.TrustLevel(req.TrustLevel),
		JobTypes: req.JobTypes, ZoneIDs: zones, Tools: req.Tools, Capabilities: req.Capabilities,
		TierCeiling: req.TierCeiling, TargetNetwork: sensordom.TargetNetwork(req.TargetNetwork),
		TargetCIDRs: req.TargetCIDRs, TargetDomains: req.TargetDomains,
		AllowCredentials: req.AllowCredentials, AllowPushIngest: req.AllowPushIngest, RemoteActions: req.RemoteActions,
	})
	if err != nil {
		h.writeGrantError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, sensorgrant.GrantView(*g))
}

func (h *SensorHandler) writeGrantError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, shared.ErrNotFound):
		apierror.NotFound("Sensor").WriteJSON(w)
	case errors.Is(err, sensorgrant.ErrWidenForbidden):
		apierror.Forbidden("Widening a sensor's grant or promoting it needs the sensors:grant:widen permission").WriteJSON(w)
	case errors.Is(err, shared.ErrForbidden):
		apierror.Forbidden("Changing a sensor's grant needs the sensors:grant:narrow permission").WriteJSON(w)
	case errors.Is(err, shared.ErrConflict):
		apierror.Conflict("The sensor's grant changed since it was read; reload and retry").WriteJSON(w)
	case errors.Is(err, shared.ErrValidation):
		apierror.BadRequest(err.Error()).WriteJSON(w)
	default:
		h.handleServiceError(w, err)
	}
}

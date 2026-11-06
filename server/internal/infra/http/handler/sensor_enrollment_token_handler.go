package handler

// Organization enrollment tokens, user plane
// (docs/architecture/sensor-pairing.md, "Enrollment tokens"). The tenant
// and the actor come from the session; a token is shown once, in the answer
// to its creation.

import (
	"encoding/json"
	"io"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/openctemio/openctem/api/internal/app/sensorpairing"
	"github.com/openctemio/openctem/api/pkg/apierror"
	sensordom "github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// CreateEnrollmentTokenRequest is the body of POST /sensor-pairings/enrollment-tokens.
type CreateEnrollmentTokenRequest struct {
	Name string `json:"name"`
	// TTLHours is the lifetime, 1 to 720 hours (default 24).
	TTLHours int `json:"ttl_hours"`
	// MaxUses is how many sensors (distinct keys) may enroll, 1 to 1000 (default 10).
	MaxUses         int               `json:"max_uses"`
	RequireApproval bool              `json:"require_approval"`
	SensorType      string            `json:"sensor_type"`
	GrantProfile    string            `json:"grant_profile"`
	ZoneIDs         []string          `json:"zone_ids"`
	Labels          map[string]string `json:"labels"`
	AllowedCIDRs    []string          `json:"allowed_cidrs"`
}

// EnrollmentTokenList is the answer of GET /sensor-pairings/enrollment-tokens.
type EnrollmentTokenList struct {
	Items []*sensorpairing.EnrollmentTokenView `json:"items"`
}

// PendingPairingList is the answer of GET /sensor-pairings/pending.
type PendingPairingList struct {
	Items []*sensorpairing.View `json:"items"`
}

// ListEnrollmentTokens godoc
// @Summary      List sensor enrollment tokens
// @Description  The organization's enrollment tokens with their uses, expiry, last use and presets. Never the token itself.
// @Tags         sensor-pairing
// @Produce      json
// @Success      200  {object}  EnrollmentTokenList
// @Security     BearerAuth
// @Router       /sensor-pairings/enrollment-tokens [get]
func (h *SensorPairingHandler) ListEnrollmentTokens(w http.ResponseWriter, r *http.Request) {
	a, ok := h.actor(r)
	if !ok {
		apierror.Unauthorized("").WriteJSON(w)
		return
	}
	items, err := h.svc.ListEnrollmentTokens(r.Context(), a)
	if err != nil {
		h.writeUserError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, EnrollmentTokenList{Items: items})
}

// CreateEnrollmentToken godoc
// @Summary      Create a sensor enrollment token
// @Description  A token for unattended installs: a sensor that starts pairing with it joins this organization with the token's zones, grant profile, type and labels, at trust level New, without a fingerprint compare unless require_approval is set. Shown once in this answer; only its keyed hash is stored. Needs a recent sign-in or step-up.
// @Tags         sensor-pairing
// @Accept       json
// @Produce      json
// @Param        body  body      CreateEnrollmentTokenRequest  true  "Token settings"
// @Success      201   {object}  sensorpairing.EnrollmentTokenView
// @Failure      400   {object}  apierror.Error
// @Failure      403   {object}  apierror.Error
// @Security     BearerAuth
// @Router       /sensor-pairings/enrollment-tokens [post]
func (h *SensorPairingHandler) CreateEnrollmentToken(w http.ResponseWriter, r *http.Request) {
	a, ok := h.actor(r)
	if !ok {
		apierror.Unauthorized("").WriteJSON(w)
		return
	}
	var req CreateEnrollmentTokenRequest
	dec := json.NewDecoder(io.LimitReader(r.Body, 16<<10))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}
	if req.TTLHours < 0 || req.TTLHours > int(sensordom.MaxEnrollmentTokenTTL/time.Hour) {
		apierror.BadRequest("ttl_hours must be between 1 and 720").WriteJSON(w)
		return
	}
	zones, err := parseIDs(req.ZoneIDs)
	if err != nil {
		apierror.BadRequest("Invalid zone id").WriteJSON(w)
		return
	}
	v, err := h.svc.CreateEnrollmentToken(r.Context(), a, sensorpairing.CreateEnrollmentTokenInput{
		Name: req.Name, TTL: time.Duration(req.TTLHours) * time.Hour, MaxUses: req.MaxUses,
		RequireApproval: req.RequireApproval, SensorType: sensordom.SensorType(req.SensorType),
		GrantProfile: req.GrantProfile, ZoneIDs: zones, Labels: req.Labels, AllowedCIDRs: req.AllowedCIDRs,
	})
	if err != nil {
		h.writeUserError(w, err)
		return
	}
	// The answer carries the token: never cache it.
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusCreated, v)
}

// RevokeEnrollmentToken godoc
// @Summary      Revoke a sensor enrollment token
// @Description  Stops the token at once. Sensors it already enrolled keep their identity.
// @Tags         sensor-pairing
// @Produce      json
// @Param        id   path      string  true  "Token id"
// @Success      200  {object}  sensorpairing.EnrollmentTokenView
// @Failure      404  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /sensor-pairings/enrollment-tokens/{id}/revoke [post]
func (h *SensorPairingHandler) RevokeEnrollmentToken(w http.ResponseWriter, r *http.Request) {
	a, ok := h.actor(r)
	if !ok {
		apierror.Unauthorized("").WriteJSON(w)
		return
	}
	id, err := shared.IDFromString(chi.URLParam(r, "id"))
	if err != nil {
		apierror.NotFound("Pairing request").WriteJSON(w)
		return
	}
	v, err := h.svc.RevokeEnrollmentToken(r.Context(), a, id)
	if err != nil {
		h.writeUserError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, v)
}

// ListPendingPairings godoc
// @Summary      Sensors waiting for approval
// @Description  The organization's open pairing requests whose sensor connected and waits for an administrator: those started with an enrollment token that requires approval, and expectations a sensor attached to. Approve with POST /sensor-pairings/{id}/approve.
// @Tags         sensor-pairing
// @Produce      json
// @Success      200  {object}  PendingPairingList
// @Security     BearerAuth
// @Router       /sensor-pairings/pending [get]
func (h *SensorPairingHandler) ListPendingPairings(w http.ResponseWriter, r *http.Request) {
	a, ok := h.actor(r)
	if !ok {
		apierror.Unauthorized("").WriteJSON(w)
		return
	}
	items, err := h.svc.ListPending(r.Context(), a)
	if err != nil {
		h.writeUserError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, PendingPairingList{Items: items})
}

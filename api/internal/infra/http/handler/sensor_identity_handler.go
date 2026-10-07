package handler

// Key-bound identity management (docs/rfcs/RFC-052-sensor-pairing-and-authorization.md):
// the organization's identity policy (D-4) and a sensor's signing keys.

import (
	"encoding/json"
	"io"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/apierror"
	"github.com/openctemio/openctem/api/pkg/domain/permission"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/sensorproto/pairing"
)

// SensorIdentityPolicy is the organization's sensor identity policy.
type SensorIdentityPolicy struct {
	// BearerKeysAllowed: new sensors may be created with an API key
	// (octs_). False: pairing (key-bound identity) only.
	BearerKeysAllowed bool `json:"bearer_keys_allowed"`
}

// GetIdentityPolicy godoc
// @Summary      Get the sensor identity policy
// @Tags         Sensors
// @Produce      json
// @Success      200  {object}  SensorIdentityPolicy
// @Security     BearerAuth
// @Router       /sensors/identity-policy [get]
func (h *SensorHandler) GetIdentityPolicy(w http.ResponseWriter, r *http.Request) {
	tid, err := shared.IDFromString(middleware.GetTenantID(r.Context()))
	if err != nil {
		apierror.Unauthorized("").WriteJSON(w)
		return
	}
	allowed, err := h.service.BearerKeysAllowed(r.Context(), tid)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, SensorIdentityPolicy{BearerKeysAllowed: allowed})
}

// SetIdentityPolicy godoc
// @Summary      Set the sensor identity policy
// @Description  Requiring key-bound identity narrows (sensors:grant:narrow); allowing bearer keys again widens (sensors:grant:widen). Audited at high severity.
// @Tags         Sensors
// @Accept       json
// @Produce      json
// @Param        body  body      SensorIdentityPolicy  true  "Policy"
// @Success      200   {object}  SensorIdentityPolicy
// @Failure      403   {object}  apierror.Error
// @Security     BearerAuth
// @Router       /sensors/identity-policy [put]
func (h *SensorHandler) SetIdentityPolicy(w http.ResponseWriter, r *http.Request) {
	tid, err := shared.IDFromString(middleware.GetTenantID(r.Context()))
	if err != nil {
		apierror.Unauthorized("").WriteJSON(w)
		return
	}
	var req SensorIdentityPolicy
	if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&req); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}
	need := permission.SensorsGrantNarrow
	if req.BearerKeysAllowed {
		need = permission.SensorsGrantWiden
	}
	if !middleware.HasPermission(r.Context(), string(need)) {
		apierror.Forbidden("Allowing bearer-key sensors needs the permission to widen sensor grants").WriteJSON(w)
		return
	}
	if err := h.service.SetBearerKeysAllowed(r.Context(), *h.buildAuditContext(r), tid, req.BearerKeysAllowed); err != nil {
		if writeStepUpError(w, err) {
			return
		}
		h.handleServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, req)
}

// SensorSigningKeyResponse is one public key of a key-bound sensor.
type SensorSigningKeyResponse struct {
	ID            string     `json:"id"`
	Fingerprint   string     `json:"fingerprint"`
	Status        string     `json:"status"`
	CreatedAt     time.Time  `json:"created_at"`
	ActivatedAt   *time.Time `json:"activated_at,omitempty"`
	RevokedAt     *time.Time `json:"revoked_at,omitempty"`
	RevokedReason string     `json:"revoked_reason,omitempty"`
	LastUsedAt    *time.Time `json:"last_used_at,omitempty"`
	LastUsedIP    string     `json:"last_used_ip,omitempty"`
}

// ListSigningKeys godoc
// @Summary      List a sensor's signing keys
// @Tags         Sensors
// @Produce      json
// @Param        id   path      string  true  "Sensor ID"
// @Success      200  {array}   SensorSigningKeyResponse
// @Failure      404  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /sensors/{id}/keys [get]
func (h *SensorHandler) ListSigningKeys(w http.ResponseWriter, r *http.Request) {
	tid, sid, ok := h.tenantAndSensor(w, r)
	if !ok {
		return
	}
	keys, err := h.service.ListSigningKeys(r.Context(), tid, sid)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}
	out := make([]SensorSigningKeyResponse, 0, len(keys))
	for _, k := range keys {
		item := SensorSigningKeyResponse{ID: k.ID.String(), Fingerprint: pairing.KeyFingerprint(k.Thumbprint), Status: string(k.Status),
			CreatedAt: k.CreatedAt, ActivatedAt: k.ActivatedAt, RevokedAt: k.RevokedAt, RevokedReason: k.RevokedReason, LastUsedAt: k.LastUsedAt}
		if k.LastUsedIP != nil {
			item.LastUsedIP = k.LastUsedIP.String()
		}
		out = append(out, item)
	}
	writeJSON(w, http.StatusOK, out)
}

// RevokeSigningKey godoc
// @Summary      Revoke one signing key of a sensor
// @Description  Effective on the sensor's next request. The sensor must be re-paired to work again.
// @Tags         Sensors
// @Param        id     path  string  true  "Sensor ID"
// @Param        key_id path  string  true  "Key ID"
// @Success      204
// @Failure      404  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /sensors/{id}/keys/{key_id}/revoke [post]
func (h *SensorHandler) RevokeSigningKey(w http.ResponseWriter, r *http.Request) {
	tid, sid, ok := h.tenantAndSensor(w, r)
	if !ok {
		return
	}
	kid, err := shared.IDFromString(chi.URLParam(r, "key_id"))
	if err != nil {
		apierror.NotFound("Key").WriteJSON(w)
		return
	}
	if err := h.service.RevokeSigningKey(r.Context(), *h.buildAuditContext(r), tid, sid, kid); err != nil {
		h.handleServiceError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *SensorHandler) tenantAndSensor(w http.ResponseWriter, r *http.Request) (shared.ID, shared.ID, bool) {
	tid, err := shared.IDFromString(middleware.GetTenantID(r.Context()))
	if err != nil {
		apierror.Unauthorized("").WriteJSON(w)
		return shared.ID{}, shared.ID{}, false
	}
	sid, err := shared.IDFromString(chi.URLParam(r, "id"))
	if err != nil {
		apierror.NotFound("Sensor").WriteJSON(w)
		return shared.ID{}, shared.ID{}, false
	}
	return tid, sid, true
}

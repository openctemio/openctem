package handler

// Interactive sensor pairing (docs/rfcs/RFC-052-sensor-pairing-and-authorization.md
// §4). Sensor plane: /api/v2/sensor/pairing*, no bearer key, every request
// signed by the key being paired. User plane: /api/v1/sensor-pairings/*.

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	authapp "github.com/openctemio/openctem/api/internal/app/auth"
	"github.com/openctemio/openctem/api/internal/app/sensorpairing"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/apierror"
	sensordom "github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/sensorproto/pairing"
	protov2 "github.com/openctemio/openctem/api/pkg/sensorproto/v2"
	"github.com/openctemio/openctem/api/pkg/sensorsig"
)

// maxPairingBody bounds every pairing request body.
const maxPairingBody = 16 << 10

// PairingNonces spends request nonces (the sensor service's store).
type PairingNonces interface {
	UseNonce(ctx context.Context, keyID, nonce string) error
}

// SensorPairingHandler serves both planes of pairing.
type SensorPairingHandler struct {
	svc    *sensorpairing.Service
	nonces PairingNonces
	log    *logger.Logger
	now    func() time.Time
}

// NewSensorPairingHandler creates the handler.
func NewSensorPairingHandler(svc *sensorpairing.Service, nonces PairingNonces, log *logger.Logger) *SensorPairingHandler {
	return &SensorPairingHandler{svc: svc, nonces: nonces, log: log.With("handler", "sensor-pairing"), now: time.Now}
}

// ---------------------------------------------------------------------------
// Sensor plane
// ---------------------------------------------------------------------------

// verifyWithKey checks the request signature with pub (window, keyid,
// signature, nonce, body digest) and returns the verified body.
func (h *SensorPairingHandler) verifyWithKey(r *http.Request, pub ed25519.PublicKey) ([]byte, error) {
	p, err := sensorsig.Parse(r.Header)
	if err != nil {
		return nil, errSignedRefused
	}
	if p.CheckWindow(h.now()) != nil || p.Verify(r, pub) != nil {
		return nil, errSignedRefused
	}
	if h.nonces.UseNonce(r.Context(), p.Params.KeyID, p.Params.Nonce) != nil {
		return nil, errSignedRefused
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, maxPairingBody+1))
	if err != nil || len(body) > maxPairingBody {
		return nil, errSignedRefused
	}
	if !p.CoversDigest() {
		if len(body) > 0 {
			return nil, errSignedRefused
		}
		return body, nil
	}
	if sensorsig.VerifyContentDigest(r.Header.Get(sensorsig.HeaderContentDigest), body) != nil {
		return nil, errSignedRefused
	}
	return body, nil
}

// keyIDOf is the keyid of the request signature ("" when there is none).
func keyIDOf(r *http.Request) string {
	p, err := sensorsig.Parse(r.Header)
	if err != nil {
		return ""
	}
	return p.Params.KeyID
}

// Start begins a pairing (sensor plane, documented in
// api/openapi/sensor-protocol-v2.yaml). The request is RFC 9421-signed with
// the key being paired; the answer has the same shape whether or not a
// reverse-mode code matched (RFC-052 §4.4).
func (h *SensorPairingHandler) Start(w http.ResponseWriter, r *http.Request) {
	// The key comes from the body, so the body is read first (bounded) and
	// the signature is then verified with that key before anything else.
	raw, err := io.ReadAll(io.LimitReader(r.Body, maxPairingBody+1))
	if err != nil || len(raw) > maxPairingBody {
		protov2.NewProblem(protov2.ProblemInvalidRequest).Write(w)
		return
	}
	var req pairing.StartRequest
	if decodeStrict(raw, &req) != nil {
		protov2.NewProblem(protov2.ProblemInvalidRequest).Write(w)
		return
	}
	pub, err := pairing.DecodeKey(req.PublicKey)
	if err != nil {
		protov2.NewProblem(protov2.ProblemInvalidRequest).Write(w)
		return
	}
	r.Body = io.NopCloser(bytes.NewReader(raw))
	if keyIDOf(r) != sensorsig.Thumbprint(pub) {
		protov2.NewProblem(protov2.ProblemUnauthenticated).Write(w)
		return
	}
	if _, err := h.verifyWithKey(r, pub); err != nil {
		protov2.NewProblem(protov2.ProblemUnauthenticated).Write(w)
		return
	}
	resp, err := h.svc.Start(r.Context(), sensorpairing.StartInput{Request: req, PublicKey: pub, SourceIP: net.ParseIP(getClientIP(r))})
	switch {
	case err == nil:
		writeJSON(w, http.StatusCreated, resp)
	case errors.Is(err, sensorpairing.ErrInvalid):
		protov2.NewProblem(protov2.ProblemInvalidRequest).Write(w)
	case errors.Is(err, sensorpairing.ErrCapacity):
		w.Header().Set("Retry-After", "60")
		protov2.NewProblem(protov2.ProblemUnavailable).Write(w)
	default:
		h.log.Error("start pairing", "error", logger.SanitizeError(err))
		protov2.NewProblem(protov2.ProblemInternal).Write(w)
	}
}

// pairingRequest reads the pairing id, finds the request bound to the
// signing key and verifies the signature. ok is false when a problem was
// written: every mismatch is the same 404.
func (h *SensorPairingHandler) pairingRequest(w http.ResponseWriter, r *http.Request) (shared.ID, string, []byte, bool) {
	id, err := shared.IDFromString(chi.URLParam(r, "pairing_id"))
	kid := keyIDOf(r)
	if err != nil || kid == "" {
		protov2.NewProblem(protov2.ProblemPairingNotFound).Write(w)
		return shared.ID{}, "", nil, false
	}
	pub, err := h.svc.PublicKeyFor(r.Context(), id, kid)
	if err != nil {
		protov2.NewProblem(protov2.ProblemPairingNotFound).Write(w)
		return shared.ID{}, "", nil, false
	}
	body, err := h.verifyWithKey(r, pub)
	if err != nil {
		protov2.NewProblem(protov2.ProblemPairingNotFound).Write(w)
		return shared.ID{}, "", nil, false
	}
	return id, kid, body, true
}

// Reveal stores the sensor nonce (PUT /pairings/{pairing_id}/nonce).
func (h *SensorPairingHandler) Reveal(w http.ResponseWriter, r *http.Request) {
	id, kid, body, ok := h.pairingRequest(w, r)
	if !ok {
		return
	}
	var req pairing.RevealRequest
	if decodeStrict(body, &req) != nil {
		protov2.NewProblem(protov2.ProblemInvalidRequest).Write(w)
		return
	}
	switch err := h.svc.Reveal(r.Context(), id, kid, req); {
	case err == nil:
		w.WriteHeader(http.StatusNoContent)
	case errors.Is(err, sensorpairing.ErrInvalid):
		protov2.NewProblem(protov2.ProblemInvalidRequest).Write(w)
	default:
		protov2.NewProblem(protov2.ProblemPairingNotFound).Write(w)
	}
}

// Status is the sensor's poll (GET /pairings/{pairing_id}).
func (h *SensorPairingHandler) Status(w http.ResponseWriter, r *http.Request) {
	id, kid, _, ok := h.pairingRequest(w, r)
	if !ok {
		return
	}
	resp, err := h.svc.Status(r.Context(), id, kid)
	if err != nil {
		protov2.NewProblem(protov2.ProblemPairingNotFound).Write(w)
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

// Confirm is the sensor's signed acceptance of its identity
// (POST /pairings/{pairing_id}/complete); the key becomes active.
func (h *SensorPairingHandler) Confirm(w http.ResponseWriter, r *http.Request) {
	id, kid, body, ok := h.pairingRequest(w, r)
	if !ok {
		return
	}
	var req pairing.ConfirmRequest
	if decodeStrict(body, &req) != nil {
		protov2.NewProblem(protov2.ProblemInvalidRequest).Write(w)
		return
	}
	resp, err := h.svc.Confirm(r.Context(), id, kid, req)
	switch {
	case err == nil:
		writeJSON(w, http.StatusOK, resp)
	case errors.Is(err, sensorpairing.ErrInvalid):
		protov2.NewProblem(protov2.ProblemInvalidRequest).Write(w)
	default:
		protov2.NewProblem(protov2.ProblemPairingNotFound).Write(w)
	}
}

// PairingKey is the sensor-plane key a pairing route is limited by (the
// pairing id in the path).
func PairingKey(r *http.Request) string { return chi.URLParam(r, "pairing_id") }

// ---------------------------------------------------------------------------
// User plane
// ---------------------------------------------------------------------------

func (h *SensorPairingHandler) actor(r *http.Request) (sensorpairing.Actor, bool) {
	tid, err := shared.IDFromString(middleware.GetTenantID(r.Context()))
	if err != nil {
		return sensorpairing.Actor{}, false
	}
	uid := middleware.GetLocalUserID(r.Context())
	if uid.IsZero() {
		if uid, err = shared.IDFromString(middleware.GetUserID(r.Context())); err != nil {
			return sensorpairing.Actor{}, false
		}
	}
	return sensorpairing.Actor{TenantID: tid, UserID: uid, SessionID: middleware.GetSessionID(r.Context()),
		Email: auditActorEmail(r.Context()), IP: getClientIP(r), UserAgent: r.UserAgent()}, true
}

func (h *SensorPairingHandler) writeUserError(w http.ResponseWriter, err error) {
	if WritePlanLimitError(w, err) {
		return
	}
	switch {
	case errors.Is(err, sensorpairing.ErrNotFound):
		apierror.NotFound("Pairing request").WriteJSON(w)
	case errors.Is(err, sensorpairing.ErrFingerprintRequired):
		apierror.New(http.StatusBadRequest, "FINGERPRINT_NOT_CONFIRMED", "Confirm that the fingerprint shown on the sensor matches before approving").WriteJSON(w)
	case errors.Is(err, authapp.ErrStepUpRequired):
		apierror.New(http.StatusForbidden, "STEP_UP_REQUIRED", "Re-authenticate to approve a sensor").WriteJSON(w)
	case errors.Is(err, authapp.ErrStepUpFailed), errors.Is(err, authapp.ErrAccountLocked):
		apierror.New(http.StatusForbidden, "STEP_UP_FAILED", "Re-authentication failed").WriteJSON(w)
	case errors.Is(err, sensorpairing.ErrLookupLocked):
		apierror.TooManyRequests("Too many failed pairing code lookups; try again later").WriteJSON(w)
	case errors.Is(err, sensorpairing.ErrInvalid), errors.Is(err, shared.ErrValidation):
		apierror.BadRequest("Invalid pairing request").WriteJSON(w)
	case errors.Is(err, sensorpairing.ErrCapacity):
		apierror.ServiceUnavailable("Too many open pairing requests; try again later").WriteJSON(w)
	default:
		h.log.Error("sensor pairing", "error", logger.SanitizeError(err))
		apierror.InternalServerError("pairing failed").WriteJSON(w)
	}
}

// PairingLookupRequest is the body of POST /api/v1/sensor-pairings/lookup.
type PairingLookupRequest struct {
	Code string `json:"code"`
}

// Lookup godoc
// @Summary      Look up a pairing code
// @Description  Returns the open pairing request with this code: the SAS fingerprint, key fingerprint, host facts and source address to compare. One 404 for unknown, expired, used and foreign codes.
// @Tags         sensor-pairing
// @Accept       json
// @Produce      json
// @Param        body  body      PairingLookupRequest  true  "Code shown by the sensor"
// @Success      200   {object}  sensorpairing.View
// @Failure      404   {object}  apierror.Error
// @Failure      429   {object}  apierror.Error
// @Security     BearerAuth
// @Router       /sensor-pairings/lookup [post]
func (h *SensorPairingHandler) Lookup(w http.ResponseWriter, r *http.Request) {
	a, ok := h.actor(r)
	if !ok {
		apierror.Unauthorized("").WriteJSON(w)
		return
	}
	var req PairingLookupRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&req); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}
	v, err := h.svc.Lookup(r.Context(), a, req.Code)
	if err != nil {
		h.writeUserError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, v)
}

// PairingExpectRequest is the body of POST /api/v1/sensor-pairings/expectations.
type PairingExpectRequest struct {
	Name           string   `json:"name"`
	ZoneIDs        []string `json:"zone_ids"`
	GrantProfile   string   `json:"grant_profile"`
	RepairSensorID string   `json:"repair_sensor_id"`
}

// Expect godoc
// @Summary      Expect a sensor (reverse pairing)
// @Description  Returns a single-use code (10 minutes) to run as `openctemio-sensor pair <CODE>` on the host.
// @Tags         sensor-pairing
// @Accept       json
// @Produce      json
// @Param        body  body      PairingExpectRequest  true  "Expected sensor"
// @Success      201   {object}  sensorpairing.View
// @Failure      400   {object}  apierror.Error
// @Security     BearerAuth
// @Router       /sensor-pairings/expectations [post]
func (h *SensorPairingHandler) Expect(w http.ResponseWriter, r *http.Request) {
	a, ok := h.actor(r)
	if !ok {
		apierror.Unauthorized("").WriteJSON(w)
		return
	}
	var req PairingExpectRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 16<<10)).Decode(&req); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}
	in := sensorpairing.ExpectInput{Name: req.Name, Profile: req.GrantProfile}
	var err error
	if in.ZoneIDs, err = parseIDs(req.ZoneIDs); err != nil {
		apierror.BadRequest("Invalid zone id").WriteJSON(w)
		return
	}
	if req.RepairSensorID != "" {
		id, err := shared.IDFromString(req.RepairSensorID)
		if err != nil {
			apierror.BadRequest("Invalid sensor id").WriteJSON(w)
			return
		}
		in.RepairSensorID = &id
	}
	v, err := h.svc.Expect(r.Context(), a, in)
	if err != nil {
		h.writeUserError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, v)
}

// GetExpectation godoc
// @Summary      Get a pairing request of the organization
// @Description  A reverse-mode expectation (once the sensor connected: its SAS fingerprint, host facts and source address), or a request this organization approved or denied.
// @Tags         sensor-pairing
// @Produce      json
// @Param        id   path      string  true  "Pairing id"
// @Success      200  {object}  sensorpairing.View
// @Failure      404  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /sensor-pairings/expectations/{id} [get]
func (h *SensorPairingHandler) GetExpectation(w http.ResponseWriter, r *http.Request) {
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
	v, err := h.svc.GetExpectation(r.Context(), a, id)
	if err != nil {
		h.writeUserError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, v)
}

// PairingApproveRequest is the body of POST /api/v1/sensor-pairings/{id}/approve.
type PairingApproveRequest struct {
	// Code is the code the approver entered (default mode; not needed for
	// an expectation of this organization).
	Code                 string              `json:"code"`
	FingerprintConfirmed bool                `json:"fingerprint_confirmed"`
	StepUp               authapp.StepUpProof `json:"step_up"`
	Name                 string              `json:"name"`
	Type                 string              `json:"type"`
	ZoneIDs              []string            `json:"zone_ids"`
	GrantProfile         string              `json:"grant_profile"`
}

// Approve godoc
// @Summary      Approve a sensor pairing
// @Description  Binds the sensor's key to this organization: a new sensor, or the registration being re-paired (its earlier keys revoked). Needs fingerprint_confirmed=true and step-up re-authentication (TOTP, else password, else a sign-in younger than 10 minutes). Audited at high severity; every administrator is notified.
// @Tags         sensor-pairing
// @Accept       json
// @Produce      json
// @Param        id    path      string                 true  "Pairing id"
// @Param        body  body      PairingApproveRequest  true  "Approval"
// @Success      200   {object}  sensorpairing.View
// @Failure      400   {object}  apierror.Error
// @Failure      403   {object}  apierror.Error
// @Failure      404   {object}  apierror.Error
// @Security     BearerAuth
// @Router       /sensor-pairings/{id}/approve [post]
func (h *SensorPairingHandler) Approve(w http.ResponseWriter, r *http.Request) {
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
	var req PairingApproveRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 16<<10)).Decode(&req); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}
	zones, err := parseIDs(req.ZoneIDs)
	if err != nil {
		apierror.BadRequest("Invalid zone id").WriteJSON(w)
		return
	}
	v, err := h.svc.Approve(r.Context(), a, id, sensorpairing.ApproveInput{
		Code: req.Code, FingerprintConfirmed: req.FingerprintConfirmed, StepUp: req.StepUp, Name: req.Name,
		Type: sensordom.SensorType(req.Type), ZoneIDs: zones, Profile: req.GrantProfile,
	})
	if err != nil {
		h.writeUserError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, v)
}

// Deny godoc
// @Summary      Reject a sensor pairing request
// @Tags         sensor-pairing
// @Param        id  path  string  true  "Pairing id"
// @Success      204
// @Failure      404  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /sensor-pairings/{id}/reject [post]
func (h *SensorPairingHandler) Deny(w http.ResponseWriter, r *http.Request) {
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
	if err := h.svc.Deny(r.Context(), a, id); err != nil {
		h.writeUserError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// UserKey is the per-user limiter key of the user-plane pairing routes.
func UserKey(r *http.Request) string { return middleware.GetUserID(r.Context()) }

func parseIDs(in []string) ([]shared.ID, error) {
	out := make([]shared.ID, 0, len(in))
	for _, s := range in {
		id, err := shared.IDFromString(s)
		if err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, nil
}

package handler

// Console > Shared sensors > Enroll (docs/rfcs/RFC-100-shared-sensors.md
// §7): a super administrator issues a single-use instance enrollment token
// with a reason and a fresh console authenticator code. The token is shown
// once; the service stores its keyed hash and writes the console audit row.

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/openctemio/openctem/api/internal/app/sensorpairing"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/apierror"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

const stepUpPurposeInstanceToken = "shared sensor enrollment token"

// AdminSharedSensorHandler serves shared sensor enrollment in the console.
type AdminSharedSensorHandler struct {
	svc    *sensorpairing.Service
	stepUp StepUpVerifier
	logger *logger.Logger
}

// NewAdminSharedSensorHandler creates the handler. A nil step-up verifier
// refuses every request.
func NewAdminSharedSensorHandler(svc *sensorpairing.Service, stepUp StepUpVerifier, log *logger.Logger) *AdminSharedSensorHandler {
	return &AdminSharedSensorHandler{svc: svc, stepUp: stepUp, logger: log.With("handler", "admin_shared_sensor")}
}

// CreateInstanceEnrollmentTokenRequest asks for a token.
type CreateInstanceEnrollmentTokenRequest struct {
	// Name the shared sensor gets (optional; else its host name).
	Name string `json:"name"`
	// TTLMinutes is the lifetime: 5 to 60, default 60.
	TTLMinutes int    `json:"ttl_minutes"`
	Reason     string `json:"reason"`
	TOTPCode   string `json:"totp_code"`
}

// InstanceEnrollmentTokenResponse carries the token, shown once.
type InstanceEnrollmentTokenResponse struct {
	ID string `json:"id"`
	// Token is the single-use secret for SENSOR_INSTANCE_ENROLLMENT_TOKEN;
	// it is never shown again.
	Token     string    `json:"token"`
	Name      string    `json:"name"`
	ExpiresAt time.Time `json:"expires_at"`
}

// CreateInstanceEnrollmentToken issues a token.
// @Summary      Issue a shared sensor enrollment token
// @Description  Super admin, with a reason and a fresh console authenticator code (totp_code). Returns a single-use token, valid 5 to 60 minutes (default 60), shown once. A sensor started with SENSOR_INSTANCE_ENROLLMENT_TOKEN pairs with its own key and becomes a shared sensor (no organization, least-privilege grant). Audited (high).
// @Tags         Admin System
// @Accept       json
// @Produce      json
// @Param        request  body      CreateInstanceEnrollmentTokenRequest  true  "Token"
// @Success      201  {object}  InstanceEnrollmentTokenResponse
// @Failure      400  {object}  apierror.Error
// @Failure      401  {object}  apierror.Error
// @Failure      403  {object}  apierror.Error
// @Router       /admin/shared-sensors/enrollment-tokens [post]
func (h *AdminSharedSensorHandler) CreateInstanceEnrollmentToken(w http.ResponseWriter, r *http.Request) {
	var req CreateInstanceEnrollmentTokenRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8192))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		apierror.BadRequest("invalid request body").WriteJSON(w)
		return
	}
	reason := strings.TrimSpace(req.Reason)
	if reason == "" || len(reason) > 1000 {
		apierror.BadRequest("a reason (at most 1000 characters) is required").WriteJSON(w)
		return
	}
	if req.TTLMinutes != 0 && (req.TTLMinutes < 5 || req.TTLMinutes > 60) {
		apierror.BadRequest("ttl_minutes must be between 5 and 60").WriteJSON(w)
		return
	}
	if !confirmAdminStepUp(w, r, h.stepUp, req.TOTPCode, stepUpPurposeInstanceToken, h.logger) {
		return
	}
	out, err := h.svc.IssueInstanceToken(r.Context(), sensorpairing.IssueInstanceTokenInput{
		Actor: middleware.GetAdminUser(r.Context()), Name: req.Name, Reason: reason,
		TTL: time.Duration(req.TTLMinutes) * time.Minute, IP: middleware.ClientIP(r), UserAgent: r.UserAgent(),
	})
	switch {
	case err == nil:
	case errors.Is(err, shared.ErrValidation):
		apierror.BadRequest(err.Error()).WriteJSON(w)
		return
	default:
		h.logger.Error("issue shared sensor enrollment token", "error", logger.SanitizeError(err))
		apierror.InternalServerError("could not issue the token").WriteJSON(w)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusCreated, InstanceEnrollmentTokenResponse{ID: out.ID.String(), Token: out.Token, Name: out.Name,
		ExpiresAt: out.ExpiresAt})
}

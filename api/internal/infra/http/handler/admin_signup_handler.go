package handler

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/openctemio/openctem/api/internal/app/signup"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/apierror"
	"github.com/openctemio/openctem/api/pkg/domain/admin"
	signupdom "github.com/openctemio/openctem/api/pkg/domain/signup"
	"github.com/openctemio/openctem/api/pkg/logger"
)

const stepUpPurposeSignupPolicy = "sign-up policy change"

// AdminSignupHandler serves Console > System > Sign-up: who may create an
// organization on this deployment (docs/architecture/user-onboarding.md,
// "Sign-up policy").
type AdminSignupHandler struct {
	svc    *signup.Service
	stepUp StepUpVerifier
	logger *logger.Logger
}

// NewAdminSignupHandler creates the handler.
func NewAdminSignupHandler(svc *signup.Service, stepUp StepUpVerifier, log *logger.Logger) *AdminSignupHandler {
	return &AdminSignupHandler{svc: svc, stepUp: stepUp, logger: log.With("handler", "admin_signup")}
}

// SignupPolicyResponse is the stored policy.
type SignupPolicyResponse struct {
	// Mode: admin_only (only platform administrators create organizations)
	// or self_service (anyone may sign up and create one).
	Mode string `json:"mode"`
	// RequestAccess: people who cannot sign up may ask for an organization.
	RequestAccess bool `json:"request_access"`
	// Version to send back on PUT (optimistic concurrency).
	Version int `json:"version"`
	// Source: environment (seeded from TENANT_CREATION_MODE at first start),
	// console (saved by an administrator) or default (nothing stored).
	Source    string `json:"source"`
	UpdatedAt string `json:"updated_at,omitempty"`
}

// UpdateSignupPolicyRequest changes the policy.
type UpdateSignupPolicyRequest struct {
	Mode          string `json:"mode"`
	RequestAccess bool   `json:"request_access"`
	// Version is the version the administrator read.
	Version int `json:"version"`
	// TOTPCode is a fresh code from the administrator's authenticator.
	TOTPCode string `json:"totp_code"`
}

func toSignupPolicyResponse(st signupdom.State) SignupPolicyResponse {
	resp := SignupPolicyResponse{
		Mode:          string(st.Policy.Mode),
		RequestAccess: st.Policy.RequestAccess,
		Version:       st.Version,
		Source:        string(st.Source),
	}
	if !st.UpdatedAt.IsZero() {
		resp.UpdatedAt = st.UpdatedAt.UTC().Format(time.RFC3339)
	}
	return resp
}

// Get returns the sign-up policy.
// @Summary      Get the sign-up policy
// @Description  Who may create an organization on this deployment. Any administrator.
// @Tags         Admin System
// @Produce      json
// @Success      200  {object}  SignupPolicyResponse
// @Router       /admin/settings/signup [get]
func (h *AdminSignupHandler) Get(w http.ResponseWriter, r *http.Request) {
	st, err := h.svc.Get(r.Context())
	if err != nil {
		h.logger.Error("read sign-up policy", "error", err)
		apierror.InternalServerError("could not read the sign-up policy").WriteJSON(w)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(toSignupPolicyResponse(st))
}

// Update changes the sign-up policy. Super admin, with a fresh authenticator
// code. Existing organizations, users and sessions are not affected. Audited
// (critical); the other administrators are notified.
// @Summary      Change the sign-up policy
// @Description  Super admin with a fresh authenticator code. Sends the version read (409 when it moved on). Audited; other administrators are emailed.
// @Tags         Admin System
// @Accept       json
// @Produce      json
// @Param        request  body      UpdateSignupPolicyRequest  true  "Policy"
// @Success      200  {object}  SignupPolicyResponse
// @Router       /admin/settings/signup [put]
func (h *AdminSignupHandler) Update(w http.ResponseWriter, r *http.Request) {
	actor := middleware.GetAdminUser(r.Context())
	if actor == nil {
		apierror.Unauthorized("administrator session required").WriteJSON(w)
		return
	}
	var req UpdateSignupPolicyRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil {
		apierror.BadRequest("invalid request body").WriteJSON(w)
		return
	}
	policy := signupdom.Policy{Mode: signupdom.Mode(strings.TrimSpace(req.Mode)), RequestAccess: req.RequestAccess}
	if err := policy.Validate(); err != nil {
		apierror.BadRequest("mode must be admin_only or self_service").WriteJSON(w)
		return
	}
	req.TOTPCode = strings.TrimSpace(req.TOTPCode)
	if req.TOTPCode == "" {
		apierror.New(http.StatusUnauthorized, codeStepUpRequired,
			"Enter a code from your authenticator to confirm the change").WriteJSON(w)
		return
	}
	if err := h.stepUp.StepUp(r.Context(), actor, req.TOTPCode, stepUpPurposeSignupPolicy, clientInfo(r)); err != nil {
		switch {
		case errors.Is(err, admin.ErrStepUpUnavailable):
			apierror.New(http.StatusForbidden, codeStepUpUnavailable,
				"Enroll the console authenticator (sign in with your password and TOTP) to confirm this action").WriteJSON(w)
		case errors.Is(err, admin.ErrInvalidMFACode):
			apierror.Unauthorized("Invalid or already used code; wait for your authenticator to show a new one").WriteJSON(w)
		default:
			h.logger.Error("sign-up policy step-up", "error", err)
			apierror.InternalServerError("could not verify the code").WriteJSON(w)
		}
		return
	}

	st, err := h.svc.Update(r.Context(), actor, policy, req.Version, middleware.ClientIP(r), r.UserAgent())
	if err != nil {
		switch {
		case errors.Is(err, signupdom.ErrVersionConflict):
			apierror.Conflict("The sign-up policy was changed by someone else; reload and try again").WriteJSON(w)
		default:
			h.logger.Error("update sign-up policy", "error", err)
			apierror.InternalServerError("could not save the sign-up policy").WriteJSON(w)
		}
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(toSignupPolicyResponse(st))
}

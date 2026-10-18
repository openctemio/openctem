package handler

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/openctemio/openctem/api/internal/app/adminapproval"
	"github.com/openctemio/openctem/api/internal/app/signup"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/apierror"
	"github.com/openctemio/openctem/api/pkg/domain/admin"
	signupdom "github.com/openctemio/openctem/api/pkg/domain/signup"
	"github.com/openctemio/openctem/api/pkg/logger"
)

const stepUpPurposeSignupPolicy = "sign-up policy change"

// AdminSignupHandler serves Console > Settings > Sign-up: who may create an
// organization on this deployment (docs/architecture/user-onboarding.md,
// "Sign-up policy").
type AdminSignupHandler struct {
	svc    *signup.Service
	stepUp StepUpVerifier
	logger *logger.Logger
	// approvals is the four-eyes gate: opening sign-up needs a second
	// super admin.
	approvals approvalGate
}

// WithApprovals wires the four-eyes gate.
func (h *AdminSignupHandler) WithApprovals(g approvalGate) *AdminSignupHandler {
	h.approvals = g
	return h
}

// NewAdminSignupHandler creates the handler.
func NewAdminSignupHandler(svc *signup.Service, stepUp StepUpVerifier, log *logger.Logger) *AdminSignupHandler {
	return &AdminSignupHandler{svc: svc, stepUp: stepUp, logger: log.With("handler", "admin_signup")}
}

// SignupPolicyResponse is the stored policy, the deployment ceiling and the
// policy in force.
type SignupPolicyResponse struct {
	// Mode: admin_only (only platform administrators create organizations)
	// or self_service (anyone may sign up and create one). The stored value.
	Mode string `json:"mode"`
	// Accounts: who may create an account by public sign-up: closed, domain
	// (an organization's verified, joinable domain) or open. The stored value.
	Accounts string `json:"accounts"`
	// MaxAccounts is the widest Accounts value the deployment allows.
	MaxAccounts string `json:"max_accounts"`
	// EffectiveAccounts is the account sign-up in force.
	EffectiveAccounts string `json:"effective_accounts"`
	// RequestAccess: people who cannot sign up may ask for an organization.
	RequestAccess bool `json:"request_access"`
	// Version to send back on PUT (optimistic concurrency).
	Version int `json:"version"`
	// Source: environment (seeded from SIGNUP_MODE at first start), console
	// (saved by an administrator) or default (nothing stored).
	Source    string `json:"source"`
	UpdatedAt string `json:"updated_at,omitempty"`
	// DeploymentMode is SIGNUP_MODE (disabled, domain or open): the ceiling
	// set in the server configuration, which no API can change.
	DeploymentMode string `json:"deployment_mode"`
	// SelfServiceLocked: the deployment does not allow self_service, so the
	// console cannot choose it (PUT answers 409 SIGNUP_LOCKED_BY_DEPLOYMENT).
	SelfServiceLocked bool `json:"self_service_locked"`
	// EffectiveMode is the mode in force: the stored mode clamped to the
	// ceiling (and closed while public sign-up has no working e-mail).
	EffectiveMode string `json:"effective_mode"`
}

// CodeSignupLockedByDeployment is the error code of a console change above
// the deployment's SIGNUP_MODE.
const CodeSignupLockedByDeployment apierror.Code = "SIGNUP_LOCKED_BY_DEPLOYMENT"

func signupLockedError() *apierror.Error {
	return apierror.New(http.StatusConflict, CodeSignupLockedByDeployment,
		"Sign-up is limited by this server's configuration (SIGNUP_MODE). Change the server configuration to allow it.")
}

// UpdateSignupPolicyRequest changes the policy.
type UpdateSignupPolicyRequest struct {
	Mode string `json:"mode"`
	// Accounts: closed, domain or open. Empty follows Mode (open with
	// self_service, closed otherwise).
	Accounts      string `json:"accounts"`
	RequestAccess bool   `json:"request_access"`
	// Version is the version the administrator read.
	Version int `json:"version"`
	// TOTPCode is a fresh code from the administrator's authenticator.
	TOTPCode string `json:"totp_code"`
}

func (h *AdminSignupHandler) toSignupPolicyResponse(st signupdom.State) SignupPolicyResponse {
	ceiling := h.svc.Ceiling()
	effective := h.svc.Effective(st.Policy)
	resp := SignupPolicyResponse{
		Mode:              string(st.Policy.Mode),
		Accounts:          string(st.Policy.AccountSignup()),
		MaxAccounts:       string(ceiling.MaxAccounts()),
		EffectiveAccounts: string(effective.AccountSignup()),
		RequestAccess:     st.Policy.RequestAccess,
		Version:           st.Version,
		Source:            string(st.Source),
		DeploymentMode:    ceiling.String(),
		SelfServiceLocked: !ceiling.Permits(signupdom.Policy{Mode: signupdom.ModeSelfService}),
		EffectiveMode:     string(effective.Mode),
	}
	if !st.UpdatedAt.IsZero() {
		resp.UpdatedAt = st.UpdatedAt.UTC().Format(time.RFC3339)
	}
	return resp
}

// Get returns the sign-up policy.
// @Summary      Get the sign-up policy
// @Description  Who may create an organization on this deployment: the stored policy, the deployment ceiling (SIGNUP_MODE) and the policy in force. Any administrator.
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
	_ = json.NewEncoder(w).Encode(h.toSignupPolicyResponse(st))
}

// Update changes the sign-up policy. Super admin, with a fresh authenticator
// code. Existing organizations, users and sessions are not affected. Audited
// (critical); the other administrators are notified.
// @Summary      Change the sign-up policy
// @Description  Super admin with a fresh authenticator code. Sends the version read (409 when it moved on). self_service needs SIGNUP_MODE=open (409 SIGNUP_LOCKED_BY_DEPLOYMENT otherwise). Audited; other administrators are emailed.
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
	policy := signupdom.Policy{Mode: signupdom.Mode(strings.TrimSpace(req.Mode)),
		Accounts: signupdom.Accounts(strings.TrimSpace(req.Accounts)), RequestAccess: req.RequestAccess}
	if err := policy.Validate(); err != nil {
		apierror.BadRequest("mode must be admin_only or self_service, accounts closed, domain or open, and self_service needs open accounts").WriteJSON(w)
		return
	}
	// Above the ceiling: refused before the authenticator code is spent.
	if !h.svc.Ceiling().Permits(policy) {
		signupLockedError().WriteJSON(w)
		return
	}
	// Opening sign-up wider than the stored policy needs a second super
	// admin. Checked before the authenticator code is spent; a spent
	// approval is handed back when the change then fails.
	var grant *adminapproval.Grant
	cur, err := h.svc.Get(r.Context())
	if err != nil {
		h.logger.Error("read sign-up policy", "error", err)
		apierror.InternalServerError("could not read the sign-up policy").WriteJSON(w)
		return
	}
	if policy.OpensBeyond(cur.Policy) {
		target := "mode=" + string(policy.Mode) + ";accounts=" + string(policy.Accounts)
		var ok bool
		if grant, ok = requireSecondApproval(w, r, h.approvals, actor, admin.ApprovalSignupOpen, target, h.logger); !ok {
			return
		}
	}
	if !confirmAdminStepUp(w, r, h.stepUp, req.TOTPCode, stepUpPurposeSignupPolicy, h.logger) {
		releaseSecondApproval(r, h.approvals, actor, grant)
		return
	}

	st, err := h.svc.Update(r.Context(), actor, policy, req.Version, middleware.ClientIP(r), r.UserAgent())
	if err != nil {
		releaseSecondApproval(r, h.approvals, actor, grant)
		switch {
		case errors.Is(err, signupdom.ErrLockedByDeployment):
			signupLockedError().WriteJSON(w)
		case errors.Is(err, signupdom.ErrVersionConflict):
			apierror.Conflict("The sign-up policy was changed by someone else; reload and try again").WriteJSON(w)
		case errors.Is(err, signup.ErrStartLimitsRequired):
			apierror.Conflict(err.Error()).WriteJSON(w)
		default:
			h.logger.Error("update sign-up policy", "error", err)
			apierror.InternalServerError("could not save the sign-up policy").WriteJSON(w)
		}
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(h.toSignupPolicyResponse(st))
}

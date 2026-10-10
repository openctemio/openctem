package handler

// Console > System > Scope approvals and Organization > Security: the
// platform policy for scope-widening approvals (RFC-054 §12.6). Reads: any
// platform administrator. Changes: super_admin (route) with a fresh
// authenticator code and a reason (here); the service audits (critical) and
// notifies.

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/openctemio/openctem/api/internal/app/scopepolicy"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/apierror"
	"github.com/openctemio/openctem/api/pkg/domain/admin"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/tenant"
	"github.com/openctemio/openctem/api/pkg/logger"
)

const stepUpPurposeScopePolicy = "scope approval policy change"

// AdminScopePolicyHandler serves the scope approval policy in the console.
type AdminScopePolicyHandler struct {
	svc    *scopepolicy.Service
	stepUp StepUpVerifier
	logger *logger.Logger
}

// NewAdminScopePolicyHandler creates the handler.
func NewAdminScopePolicyHandler(svc *scopepolicy.Service, stepUp StepUpVerifier, log *logger.Logger) *AdminScopePolicyHandler {
	return &AdminScopePolicyHandler{svc: svc, stepUp: stepUp, logger: log.With("handler", "admin_scope_policy")}
}

// ScopePolicyDefaultResponse is the platform default.
type ScopePolicyDefaultResponse struct {
	// Mode: required, tenant_controlled or disabled.
	Mode string `json:"mode" enums:"required,tenant_controlled,disabled"`
	// Version to send back on PUT (0: nothing stored, the default applies).
	Version int `json:"version"`
}

// ScopePolicyOrganizationResponse is one organization's policy.
type ScopePolicyOrganizationResponse struct {
	// Override: the organization's own mode, null when it follows the
	// platform default.
	Override *string `json:"override"`
	// Effective: the mode in force; Source: platform_default or
	// organization_override.
	Effective       string `json:"effective" enums:"required,tenant_controlled,disabled"`
	Source          string `json:"source" enums:"platform_default,organization_override"`
	PlatformDefault string `json:"platform_default" enums:"required,tenant_controlled,disabled"`
}

// UpdateScopePolicyDefaultRequest changes the platform default.
type UpdateScopePolicyDefaultRequest struct {
	Mode     string `json:"mode"`
	Version  int    `json:"version"`
	Reason   string `json:"reason"`
	TOTPCode string `json:"totp_code"`
}

// UpdateScopePolicyOrganizationRequest sets or clears an override.
type UpdateScopePolicyOrganizationRequest struct {
	// Mode: required, tenant_controlled, disabled, or null to follow the
	// platform default.
	Mode     *string `json:"mode"`
	Reason   string  `json:"reason"`
	TOTPCode string  `json:"totp_code"`
}

// GetDefault returns the platform default.
// @Summary      Scope approval policy (platform default)
// @Description  How scope-widening approvals work for organizations without an override (RFC-054 §12.6): required (default), tenant_controlled or disabled. Any administrator.
// @Tags         Admin System
// @Produce      json
// @Success      200  {object}  ScopePolicyDefaultResponse
// @Router       /admin/settings/scope-policy [get]
func (h *AdminScopePolicyHandler) GetDefault(w http.ResponseWriter, r *http.Request) {
	m, v, err := h.svc.Default(r.Context())
	if err != nil {
		h.logger.Error("read scope approval policy", "error", logger.SanitizeError(err))
		apierror.InternalServerError("could not read the policy").WriteJSON(w)
		return
	}
	writeJSON(w, http.StatusOK, ScopePolicyDefaultResponse{Mode: string(m), Version: v})
}

// UpdateDefault changes the platform default.
// @Summary      Change the scope approval policy (platform default)
// @Description  Super admin with a fresh authenticator code and a reason. Relaxing approvals never turns scope off: step-up, the dry run, ownership proof, the deny list, audit and notifications stay. Audited (critical); the other administrators are emailed.
// @Tags         Admin System
// @Accept       json
// @Produce      json
// @Param        request  body      UpdateScopePolicyDefaultRequest  true  "Policy"
// @Success      200  {object}  ScopePolicyDefaultResponse
// @Router       /admin/settings/scope-policy [put]
func (h *AdminScopePolicyHandler) UpdateDefault(w http.ResponseWriter, r *http.Request) {
	var req UpdateScopePolicyDefaultRequest
	actor, ok := h.decodeAndStepUp(w, r, &req, func() (string, string) { return req.Reason, req.TOTPCode })
	if !ok {
		return
	}
	mode, err := tenant.ParseScopeApprovalMode(req.Mode)
	if err != nil {
		apierror.BadRequest("mode must be required, tenant_controlled or disabled").WriteJSON(w)
		return
	}
	v, err := h.svc.UpdateDefault(r.Context(), mode, req.Version, h.change(r, actor, req.Reason))
	if err != nil {
		h.writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, ScopePolicyDefaultResponse{Mode: string(mode), Version: v})
}

// GetOrganization returns one organization's policy.
// @Summary      Scope approval policy of an organization
// @Description  The organization's override (null: the platform default) and the mode in force. Any administrator.
// @Tags         Admin Organizations
// @Produce      json
// @Param        tenantId  path  string  true  "Organization ID"
// @Success      200  {object}  ScopePolicyOrganizationResponse
// @Router       /admin/tenants/{tenantId}/scope-policy [get]
func (h *AdminScopePolicyHandler) GetOrganization(w http.ResponseWriter, r *http.Request) {
	tid, ok := h.tenantID(w, r)
	if !ok {
		return
	}
	h.writeOrganization(w, r, tid)
}

// UpdateOrganization sets or clears an organization's override.
// @Summary      Change the scope approval policy of an organization
// @Description  Super admin with a fresh authenticator code and a reason. mode null follows the platform default. Audited (critical); the other administrators are emailed and the organization's administrators told.
// @Tags         Admin Organizations
// @Accept       json
// @Produce      json
// @Param        tenantId  path  string                                true  "Organization ID"
// @Param        request   body  UpdateScopePolicyOrganizationRequest  true  "Policy"
// @Success      200  {object}  ScopePolicyOrganizationResponse
// @Router       /admin/tenants/{tenantId}/scope-policy [put]
func (h *AdminScopePolicyHandler) UpdateOrganization(w http.ResponseWriter, r *http.Request) {
	tid, ok := h.tenantID(w, r)
	if !ok {
		return
	}
	var req UpdateScopePolicyOrganizationRequest
	actor, ok := h.decodeAndStepUp(w, r, &req, func() (string, string) { return req.Reason, req.TOTPCode })
	if !ok {
		return
	}
	var mode *tenant.ScopeApprovalMode
	if req.Mode != nil {
		m, err := tenant.ParseScopeApprovalMode(*req.Mode)
		if err != nil {
			apierror.BadRequest("mode must be required, tenant_controlled, disabled or null").WriteJSON(w)
			return
		}
		mode = &m
	}
	if err := h.svc.UpdateOverride(r.Context(), tid, mode, h.change(r, actor, req.Reason)); err != nil {
		h.writeErr(w, err)
		return
	}
	h.writeOrganization(w, r, tid)
}

func (h *AdminScopePolicyHandler) tenantID(w http.ResponseWriter, r *http.Request) (shared.ID, bool) {
	id, err := shared.IDFromString(chi.URLParam(r, middleware.AdminTenantParam))
	if err != nil {
		apierror.NotFound("Organization").WriteJSON(w)
		return shared.ID{}, false
	}
	return id, true
}

func (h *AdminScopePolicyHandler) writeOrganization(w http.ResponseWriter, r *http.Request, tid shared.ID) {
	def, _, err := h.svc.Default(r.Context())
	if err != nil {
		h.logger.Error("read scope approval policy", "error", logger.SanitizeError(err))
		apierror.InternalServerError("could not read the policy").WriteJSON(w)
		return
	}
	override, err := h.svc.Override(r.Context(), tid)
	if err != nil {
		h.writeErr(w, err)
		return
	}
	eff, src := h.svc.Effective(r.Context(), tid)
	resp := ScopePolicyOrganizationResponse{Effective: string(eff), Source: src, PlatformDefault: string(def)}
	if override != nil {
		s := string(*override)
		resp.Override = &s
	}
	writeJSON(w, http.StatusOK, resp)
}

// decodeAndStepUp reads the body and checks the administrator, the reason
// and a fresh authenticator code. It answers the request when it fails.
func (h *AdminScopePolicyHandler) decodeAndStepUp(w http.ResponseWriter, r *http.Request, dst any, fields func() (string, string)) (*admin.AdminUser, bool) {
	actor := middleware.GetAdminUser(r.Context())
	if actor == nil {
		apierror.Unauthorized("administrator session required").WriteJSON(w)
		return nil, false
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8192)).Decode(dst); err != nil {
		apierror.BadRequest("invalid request body").WriteJSON(w)
		return nil, false
	}
	reason, code := fields()
	if strings.TrimSpace(reason) == "" || len(reason) > 1000 {
		apierror.BadRequest("a reason (at most 1000 characters) is required").WriteJSON(w)
		return nil, false
	}
	code = strings.TrimSpace(code)
	if code == "" {
		apierror.New(http.StatusUnauthorized, codeStepUpRequired,
			"Enter a code from your authenticator to confirm the change").WriteJSON(w)
		return nil, false
	}
	if err := h.stepUp.StepUp(r.Context(), actor, code, stepUpPurposeScopePolicy, clientInfo(r)); err != nil {
		switch {
		case errors.Is(err, admin.ErrStepUpUnavailable):
			apierror.New(http.StatusForbidden, codeStepUpUnavailable,
				"Enroll the console authenticator (sign in with your password and TOTP) to confirm this action").WriteJSON(w)
		case errors.Is(err, admin.ErrInvalidMFACode):
			apierror.Unauthorized("Invalid or already used code; wait for your authenticator to show a new one").WriteJSON(w)
		default:
			h.logger.Error("scope policy step-up", "error", err)
			apierror.InternalServerError("could not verify the code").WriteJSON(w)
		}
		return nil, false
	}
	return actor, true
}

func (h *AdminScopePolicyHandler) change(r *http.Request, actor *admin.AdminUser, reason string) scopepolicy.Change {
	return scopepolicy.Change{Actor: actor, Reason: reason, IP: middleware.ClientIP(r), UserAgent: r.UserAgent()}
}

func (h *AdminScopePolicyHandler) writeErr(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, scopepolicy.ErrVersionConflict):
		apierror.Conflict("The policy was changed by someone else; reload and try again").WriteJSON(w)
	case errors.Is(err, shared.ErrNotFound):
		apierror.NotFound("Organization").WriteJSON(w)
	case errors.Is(err, shared.ErrValidation):
		apierror.BadRequest(err.Error()).WriteJSON(w)
	default:
		h.logger.Error("scope approval policy", "error", logger.SanitizeError(err))
		apierror.InternalServerError("could not save the policy").WriteJSON(w)
	}
}

package handler

// Console > System > Scan approval and Organization > Security: the
// platform policy for scan approval (RFC-073 §5): let the organization
// choose, or force off, on (at least) or strict. Reads: any
// platform administrator. Changes: super_admin (route) with a fresh
// authenticator code and a reason (here); the service audits (critical) and
// notifies.

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/openctemio/openctem/api/internal/app/scanpolicy"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/apierror"
	"github.com/openctemio/openctem/api/pkg/domain/admin"
	"github.com/openctemio/openctem/api/pkg/domain/scangov"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

const stepUpPurposeScanPolicy = "scan approval policy change"

// AdminScanPolicyHandler serves the scan approval policy in the console.
type AdminScanPolicyHandler struct {
	svc    *scanpolicy.Service
	stepUp StepUpVerifier
	logger *logger.Logger
}

// NewAdminScanPolicyHandler creates the handler.
func NewAdminScanPolicyHandler(svc *scanpolicy.Service, stepUp StepUpVerifier, log *logger.Logger) *AdminScanPolicyHandler {
	return &AdminScanPolicyHandler{svc: svc, stepUp: stepUp, logger: log.With("handler", "admin_scan_policy")}
}

// ScanPolicyDefaultResponse is the platform default.
type ScanPolicyDefaultResponse struct {
	// Policy: tenant_controlled (default), off, on or strict.
	Policy string `json:"policy" enums:"tenant_controlled,off,on,strict"`
	// Version to send back on PUT (0: nothing stored, the default applies).
	Version int `json:"version"`
}

// ScanPolicyOrganizationResponse is one organization's policy.
type ScanPolicyOrganizationResponse struct {
	// Override: the organization's own policy, null when it follows the
	// platform default.
	Override *string `json:"override"`
	// Policy: the policy in force; Source: platform_default or
	// organization_override.
	Policy          string `json:"policy" enums:"tenant_controlled,off,on,strict"`
	Source          string `json:"source" enums:"platform_default,organization_override"`
	PlatformDefault string `json:"platform_default" enums:"tenant_controlled,off,on,strict"`
	// EffectiveMode: the organization's scan approval in force (its
	// owner's choice under the policy): off, on or strict.
	EffectiveMode string `json:"effective_mode" enums:"off,on,strict"`
}

// UpdateScanPolicyDefaultRequest changes the platform default.
type UpdateScanPolicyDefaultRequest struct {
	Policy   string `json:"policy"`
	Version  int    `json:"version"`
	Reason   string `json:"reason"`
	TOTPCode string `json:"totp_code"`
}

// UpdateScanPolicyOrganizationRequest sets or clears an override.
type UpdateScanPolicyOrganizationRequest struct {
	// Policy: tenant_controlled, off, on, strict, or null to follow the
	// platform default.
	Policy   *string `json:"policy"`
	Reason   string  `json:"reason"`
	TOTPCode string  `json:"totp_code"`
}

// GetDefault returns the platform default.
// @Summary      Scan approval policy (platform default)
// @Description  Scan approval for organizations without an override (RFC-073 §5): tenant_controlled (default: the organization's owner chooses), off, on (at least) or strict. Any administrator.
// @Tags         Admin System
// @Produce      json
// @Success      200  {object}  ScanPolicyDefaultResponse
// @Router       /admin/settings/scan-approval-policy [get]
func (h *AdminScanPolicyHandler) GetDefault(w http.ResponseWriter, r *http.Request) {
	p, v, err := h.svc.Default(r.Context())
	if err != nil {
		h.logger.Error("read scan approval policy", "error", logger.SanitizeError(err))
		apierror.InternalServerError("could not read the policy").WriteJSON(w)
		return
	}
	writeJSON(w, http.StatusOK, ScanPolicyDefaultResponse{Policy: string(p), Version: v})
}

// UpdateDefault changes the platform default.
// @Summary      Change the scan approval policy (platform default)
// @Description  Super admin with a fresh authenticator code and a reason. Forcing off never turns scope off: step-up, exclusions, ownership proof, the deny list, audit and notifications stay. Audited (critical); the other administrators are emailed.
// @Tags         Admin System
// @Accept       json
// @Produce      json
// @Param        request  body      UpdateScanPolicyDefaultRequest  true  "Policy"
// @Success      200  {object}  ScanPolicyDefaultResponse
// @Router       /admin/settings/scan-approval-policy [put]
func (h *AdminScanPolicyHandler) UpdateDefault(w http.ResponseWriter, r *http.Request) {
	var req UpdateScanPolicyDefaultRequest
	actor, ok := h.decodeAndStepUp(w, r, &req, func() (string, string) { return req.Reason, req.TOTPCode })
	if !ok {
		return
	}
	p, err := scangov.ParsePlatformPolicy(req.Policy)
	if err != nil {
		apierror.BadRequest("policy must be tenant_controlled, off, on or strict").WriteJSON(w)
		return
	}
	v, err := h.svc.UpdateDefault(r.Context(), p, req.Version, h.change(r, actor, req.Reason))
	if err != nil {
		h.writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, ScanPolicyDefaultResponse{Policy: string(p), Version: v})
}

// GetOrganization returns one organization's policy.
// @Summary      Scan approval policy of an organization
// @Description  The organization's override (null: the platform default), the policy in force and the organization's scan approval mode in force. Any administrator.
// @Tags         Admin Organizations
// @Produce      json
// @Param        tenantId  path  string  true  "Organization ID"
// @Success      200  {object}  ScanPolicyOrganizationResponse
// @Router       /admin/tenants/{tenantId}/scan-approval-policy [get]
func (h *AdminScanPolicyHandler) GetOrganization(w http.ResponseWriter, r *http.Request) {
	tid, ok := h.tenantID(w, r)
	if !ok {
		return
	}
	h.writeOrganization(w, r, tid)
}

// UpdateOrganization sets or clears an organization's override.
// @Summary      Change the scan approval policy of an organization
// @Description  Super admin with a fresh authenticator code and a reason. policy null follows the platform default. Audited (critical); the other administrators are emailed and the organization's administrators told.
// @Tags         Admin Organizations
// @Accept       json
// @Produce      json
// @Param        tenantId  path  string                                true  "Organization ID"
// @Param        request   body  UpdateScanPolicyOrganizationRequest  true  "Policy"
// @Success      200  {object}  ScanPolicyOrganizationResponse
// @Router       /admin/tenants/{tenantId}/scan-approval-policy [put]
func (h *AdminScanPolicyHandler) UpdateOrganization(w http.ResponseWriter, r *http.Request) {
	tid, ok := h.tenantID(w, r)
	if !ok {
		return
	}
	var req UpdateScanPolicyOrganizationRequest
	actor, ok := h.decodeAndStepUp(w, r, &req, func() (string, string) { return req.Reason, req.TOTPCode })
	if !ok {
		return
	}
	var pol *scangov.PlatformPolicy
	if req.Policy != nil {
		p, err := scangov.ParsePlatformPolicy(*req.Policy)
		if err != nil {
			apierror.BadRequest("policy must be tenant_controlled, off, on, strict or null").WriteJSON(w)
			return
		}
		pol = &p
	}
	if err := h.svc.UpdateOverride(r.Context(), tid, pol, h.change(r, actor, req.Reason)); err != nil {
		h.writeErr(w, err)
		return
	}
	h.writeOrganization(w, r, tid)
}

func (h *AdminScanPolicyHandler) tenantID(w http.ResponseWriter, r *http.Request) (shared.ID, bool) {
	id, err := shared.IDFromString(chi.URLParam(r, middleware.AdminTenantParam))
	if err != nil {
		apierror.NotFound("Organization").WriteJSON(w)
		return shared.ID{}, false
	}
	return id, true
}

func (h *AdminScanPolicyHandler) writeOrganization(w http.ResponseWriter, r *http.Request, tid shared.ID) {
	def, _, err := h.svc.Default(r.Context())
	if err != nil {
		h.logger.Error("read scan approval policy", "error", logger.SanitizeError(err))
		apierror.InternalServerError("could not read the policy").WriteJSON(w)
		return
	}
	override, err := h.svc.Override(r.Context(), tid)
	if err != nil {
		h.writeErr(w, err)
		return
	}
	pol, src, err := h.svc.Policy(r.Context(), tid)
	if err != nil {
		h.writeErr(w, err)
		return
	}
	mode, _, _, err := h.svc.EffectiveMode(r.Context(), tid)
	if err != nil {
		h.writeErr(w, err)
		return
	}
	resp := ScanPolicyOrganizationResponse{Policy: string(pol), Source: src, PlatformDefault: string(def), EffectiveMode: string(mode)}
	if override != nil {
		s := string(*override)
		resp.Override = &s
	}
	writeJSON(w, http.StatusOK, resp)
}

// decodeAndStepUp reads the body and checks the administrator, the reason
// and a fresh authenticator code. It answers the request when it fails.
func (h *AdminScanPolicyHandler) decodeAndStepUp(w http.ResponseWriter, r *http.Request, dst any, fields func() (string, string)) (*admin.AdminUser, bool) {
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
	if err := h.stepUp.StepUp(r.Context(), actor, code, stepUpPurposeScanPolicy, clientInfo(r)); err != nil {
		switch {
		case errors.Is(err, admin.ErrStepUpUnavailable):
			apierror.New(http.StatusForbidden, codeStepUpUnavailable,
				"Enroll the console authenticator (sign in with your password and TOTP) to confirm this action").WriteJSON(w)
		case errors.Is(err, admin.ErrInvalidMFACode):
			apierror.Unauthorized("Invalid or already used code; wait for your authenticator to show a new one").WriteJSON(w)
		default:
			h.logger.Error("scan policy step-up", "error", err)
			apierror.InternalServerError("could not verify the code").WriteJSON(w)
		}
		return nil, false
	}
	return actor, true
}

func (h *AdminScanPolicyHandler) change(r *http.Request, actor *admin.AdminUser, reason string) scanpolicy.Change {
	return scanpolicy.Change{Actor: actor, Reason: reason, IP: middleware.ClientIP(r), UserAgent: r.UserAgent()}
}

func (h *AdminScanPolicyHandler) writeErr(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, scanpolicy.ErrVersionConflict):
		apierror.Conflict("The policy was changed by someone else; reload and try again").WriteJSON(w)
	case errors.Is(err, shared.ErrNotFound):
		apierror.NotFound("Organization").WriteJSON(w)
	case errors.Is(err, shared.ErrValidation):
		apierror.BadRequest(err.Error()).WriteJSON(w)
	default:
		h.logger.Error("scan approval policy", "error", logger.SanitizeError(err))
		apierror.InternalServerError("could not save the policy").WriteJSON(w)
	}
}

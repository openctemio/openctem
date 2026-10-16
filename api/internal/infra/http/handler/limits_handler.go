package handler

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/openctemio/openctem/api/internal/app/entitlement"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/apierror"
	"github.com/openctemio/openctem/api/pkg/domain/admin"
	"github.com/openctemio/openctem/api/pkg/domain/limits"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

const (
	stepUpPurposeSelfServiceLimits = "self-service default limits change"
	stepUpPurposeFeatureDeny       = "organization feature deny change"
	// codeLimitReached is the error code of an addition refused by a limit.
	codeLimitReached apierror.Code = "LIMIT_REACHED"
)

// LimitsHandler serves per-organization limits and feature denies
// (docs/architecture/limits.md): the instance's self-service defaults
// (Console > System > Limits), one organization's limits and denies
// (Console > Organizations), and the organization's own Usage & limits view.
type LimitsHandler struct {
	svc    *entitlement.Service
	stepUp StepUpVerifier
	logger *logger.Logger
	// portalURL is the hosted service's account page (ACCOUNT_PORTAL_URL).
	portalURL string
}

// SetAccountPortalURL sets the account page linked when a limit applies.
func (h *LimitsHandler) SetAccountPortalURL(u string) { h.portalURL = u }

// NewLimitsHandler creates the handler.
func NewLimitsHandler(svc *entitlement.Service, stepUp StepUpVerifier, log *logger.Logger) *LimitsHandler {
	return &LimitsHandler{svc: svc, stepUp: stepUp, logger: log.With("handler", "limits")}
}

// SelfServiceLimitsResponse is the instance's self-service defaults: only the
// keys that are set (an absent key is unlimited).
type SelfServiceLimitsResponse struct {
	Limits  map[string]int `json:"limits"`
	Keys    []string       `json:"keys"`
	Version int            `json:"version"`
	// Sources are the configured sources of limits beyond the operator
	// ("none" on a self-hosted install).
	Sources []string `json:"sources"`
}

// UpdateSelfServiceLimitsRequest saves the self-service defaults.
type UpdateSelfServiceLimitsRequest struct {
	Limits   map[string]int `json:"limits"`
	Version  int            `json:"version"`
	TOTPCode string         `json:"totp_code"`
}

func (h *LimitsHandler) selfServiceResponse(d limits.Limits, version int) SelfServiceLimitsResponse {
	resp := SelfServiceLimitsResponse{Limits: map[string]int{}, Version: version, Sources: h.svc.SourceNames()}
	for _, k := range limits.Keys {
		resp.Keys = append(resp.Keys, string(k))
		if v, ok := d[k]; ok && v != limits.Unlimited {
			resp.Limits[string(k)] = v
		}
	}
	return resp
}

// GetSelfServiceDefaults returns the self-service defaults (any admin).
// @Summary      Get the default limits of self-service organizations
// @Description  Limits an organization starts with when a person creates it themselves, and the per-person organization cap. Empty: no limits.
// @Tags         Admin System
// @Produce      json
// @Success      200  {object}  SelfServiceLimitsResponse
// @Router       /admin/settings/limits [get]
func (h *LimitsHandler) GetSelfServiceDefaults(w http.ResponseWriter, r *http.Request) {
	d, v, err := h.svc.SelfServiceDefaults(r.Context())
	if err != nil {
		h.logger.Error("read self-service default limits", "error", err)
		apierror.InternalServerError("could not read the default limits").WriteJSON(w)
		return
	}
	writeJSON(w, http.StatusOK, h.selfServiceResponse(d, v))
}

// UpdateSelfServiceDefaults saves the self-service defaults (super admin +
// fresh authenticator code; audited). Existing organizations keep theirs.
// @Summary      Change the default limits of self-service organizations
// @Tags         Admin System
// @Accept       json
// @Produce      json
// @Param        request  body  UpdateSelfServiceLimitsRequest  true  "Defaults"
// @Success      200  {object}  SelfServiceLimitsResponse
// @Router       /admin/settings/limits [put]
func (h *LimitsHandler) UpdateSelfServiceDefaults(w http.ResponseWriter, r *http.Request) {
	actor := middleware.GetAdminUser(r.Context())
	if actor == nil {
		apierror.Unauthorized("administrator session required").WriteJSON(w)
		return
	}
	var req UpdateSelfServiceLimitsRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil {
		apierror.BadRequest("invalid request body").WriteJSON(w)
		return
	}
	d := limits.Limits{}
	for k, v := range req.Limits {
		if v != limits.Unlimited {
			d[limits.Key(k)] = v
		}
	}
	if err := d.Validate(); err != nil {
		apierror.BadRequest("unknown limit, or a value below -1 (unlimited)").WriteJSON(w)
		return
	}
	if !h.confirmStepUp(w, r, actor, req.TOTPCode, stepUpPurposeSelfServiceLimits) {
		return
	}
	v, err := h.svc.UpdateSelfServiceDefaults(r.Context(), actor, d, req.Version, middleware.ClientIP(r), r.UserAgent())
	if err != nil {
		if errors.Is(err, shared.ErrConflict) {
			apierror.Conflict("The default limits were changed by someone else; reload and try again").WriteJSON(w)
			return
		}
		h.logger.Error("save self-service default limits", "error", err)
		apierror.InternalServerError("could not save the default limits").WriteJSON(w)
		return
	}
	writeJSON(w, http.StatusOK, h.selfServiceResponse(d, v))
}

func (h *LimitsHandler) confirmStepUp(w http.ResponseWriter, r *http.Request, _ *admin.AdminUser, code, purpose string) bool {
	return confirmAdminStepUp(w, r, h.stepUp, code, purpose, h.logger)
}

// AdminLimitsResponse is one organization's limits, denies and usage, for a
// platform administrator (with who set each one and why).
type AdminLimitsResponse struct {
	Limits    []limits.Effective          `json:"limits"`
	Denied    []entitlement.DeniedFeature `json:"denied_features"`
	OverLimit bool                        `json:"over_limit"`
	Applies   bool                        `json:"applies"`
}

func (h *LimitsHandler) writeAdminSummary(w http.ResponseWriter, r *http.Request, tenantID shared.ID) {
	sum, err := h.svc.Effective(r.Context(), tenantID)
	if err != nil {
		h.logger.Error("read organization limits", "error", err)
		apierror.InternalServerError("could not read the limits").WriteJSON(w)
		return
	}
	writeJSON(w, http.StatusOK, AdminLimitsResponse{Limits: sum.Limits, Denied: sum.Denied, OverLimit: sum.OverLimit, Applies: sum.Applies})
}

func adminTenantID(w http.ResponseWriter, r *http.Request) (shared.ID, bool) {
	id, err := shared.IDFromString(r.PathValue(middleware.AdminTenantParam))
	if err != nil {
		apierror.BadRequest("invalid organization id").WriteJSON(w)
		return shared.ID{}, false
	}
	return id, true
}

// GetTenantLimits returns an organization's limits, denies, usage and the
// over-limit flag (any admin).
// @Summary      Get an organization's limits and usage (platform admin)
// @Tags         Admin Organizations
// @Produce      json
// @Param        tenantId  path  string  true  "Organization ID"
// @Success      200  {object}  AdminLimitsResponse
// @Router       /admin/tenants/{tenantId}/limits [get]
func (h *LimitsHandler) GetTenantLimits(w http.ResponseWriter, r *http.Request) {
	if id, ok := adminTenantID(w, r); ok {
		h.writeAdminSummary(w, r, id)
	}
}

// SetLimitRequest sets one limit for one organization.
type SetLimitRequest struct {
	Value     int        `json:"value"`
	Reason    string     `json:"reason"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
}

// SetTenantLimit sets one limit for one organization (ops_admin+, audited).
// @Summary      Set a limit for an organization (platform admin)
// @Description  A reason is required; an expiry is optional and must be in the future. -1 is unlimited. Lowering a limit never removes anything: only new additions are refused.
// @Tags         Admin Organizations
// @Accept       json
// @Produce      json
// @Param        tenantId  path  string           true  "Organization ID"
// @Param        key       path  string           true  "Limit key"
// @Param        request   body  SetLimitRequest  true  "Limit"
// @Success      200  {object}  AdminLimitsResponse
// @Router       /admin/tenants/{tenantId}/limits/{key} [put]
func (h *LimitsHandler) SetTenantLimit(w http.ResponseWriter, r *http.Request) {
	actor := middleware.GetAdminUser(r.Context())
	id, ok := adminTenantID(w, r)
	if !ok {
		return
	}
	if actor == nil {
		apierror.Unauthorized("administrator session required").WriteJSON(w)
		return
	}
	var req SetLimitRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 2048)).Decode(&req); err != nil {
		apierror.BadRequest("invalid request body").WriteJSON(w)
		return
	}
	err := h.svc.PutLimit(r.Context(), actor, id, entitlement.LimitInput{
		Key: limits.Key(r.PathValue("key")), Value: req.Value, Reason: req.Reason, ExpiresAt: req.ExpiresAt,
	}, middleware.ClientIP(r), r.UserAgent())
	if err != nil {
		if errors.Is(err, limits.ErrInvalid) {
			apierror.BadRequest("Give a known limit, a value of -1 (unlimited) or more, a reason (up to 500 characters) and, if any, a future expiry").WriteJSON(w)
			return
		}
		h.logger.Error("set organization limit", "error", err)
		apierror.InternalServerError("could not set the limit").WriteJSON(w)
		return
	}
	h.writeAdminSummary(w, r, id)
}

// DeleteTenantLimit removes one limit an administrator set (ops_admin+,
// audited).
// @Summary      Remove a limit of an organization (platform admin)
// @Tags         Admin Organizations
// @Produce      json
// @Param        tenantId  path  string  true  "Organization ID"
// @Param        key       path  string  true  "Limit key"
// @Success      200  {object}  AdminLimitsResponse
// @Router       /admin/tenants/{tenantId}/limits/{key} [delete]
func (h *LimitsHandler) DeleteTenantLimit(w http.ResponseWriter, r *http.Request) {
	actor := middleware.GetAdminUser(r.Context())
	id, ok := adminTenantID(w, r)
	if !ok {
		return
	}
	if actor == nil {
		apierror.Unauthorized("administrator session required").WriteJSON(w)
		return
	}
	if err := h.svc.DeleteLimit(r.Context(), actor, id, limits.Key(r.PathValue("key")), middleware.ClientIP(r), r.UserAgent()); err != nil {
		switch {
		case errors.Is(err, limits.ErrInvalid):
			apierror.BadRequest("unknown limit").WriteJSON(w)
		case errors.Is(err, shared.ErrNotFound):
			apierror.NotFound("Limit").WriteJSON(w)
		default:
			h.logger.Error("delete organization limit", "error", err)
			apierror.InternalServerError("could not remove the limit").WriteJSON(w)
		}
		return
	}
	h.writeAdminSummary(w, r, id)
}

// AdminTenantModulesResponse is one organization's module states.
type AdminTenantModulesResponse struct {
	Modules []entitlement.ModuleEntitlement `json:"modules"`
}

func (h *LimitsHandler) writeTenantModules(w http.ResponseWriter, r *http.Request, tenantID shared.ID) {
	list, err := h.svc.ModuleEntitlements(r.Context(), tenantID)
	if err != nil {
		h.logger.Error("read module entitlements", "error", err)
		apierror.InternalServerError("could not read the modules").WriteJSON(w)
		return
	}
	writeJSON(w, http.StatusOK, AdminTenantModulesResponse{Modules: list})
}

// GetTenantModules returns an organization's module states (any admin).
// @Summary      Get an organization's modules (platform admin)
// @Tags         Admin Organizations
// @Produce      json
// @Param        tenantId  path  string  true  "Organization ID"
// @Success      200  {object}  AdminTenantModulesResponse
// @Router       /admin/tenants/{tenantId}/modules [get]
func (h *LimitsHandler) GetTenantModules(w http.ResponseWriter, r *http.Request) {
	if id, ok := adminTenantID(w, r); ok {
		h.writeTenantModules(w, r, id)
	}
}

// SetFeatureDenyRequest denies one module to one organization.
type SetFeatureDenyRequest struct {
	Reason    string     `json:"reason"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
	// TOTPCode is a fresh code from the administrator's authenticator.
	TOTPCode string `json:"totp_code"`
}

// DeleteFeatureDenyRequest lifts one organization's deny.
type DeleteFeatureDenyRequest struct {
	Reason   string `json:"reason"`
	TOTPCode string `json:"totp_code"`
}

const featureDenyInvalid = "Give a non-core module, a reason (up to 500 characters) and, if any, a future expiry"

// SetModuleDeny denies a module to an organization (ops_admin+ with a fresh
// authenticator code, audited). The organization keeps read access for the
// grace period.
// @Summary      Deny a module to an organization (platform admin)
// @Description  A reason and a fresh authenticator code are required; an expiry is optional and must be in the future. Nothing is deleted: the organization keeps read access and export for the grace period.
// @Tags         Admin Organizations
// @Accept       json
// @Produce      json
// @Param        tenantId   path  string                 true  "Organization ID"
// @Param        module_id  path  string                 true  "Module ID"
// @Param        request    body  SetFeatureDenyRequest  true  "Deny"
// @Success      200  {object}  AdminTenantModulesResponse
// @Router       /admin/tenants/{tenantId}/modules/{module_id}/deny [put]
func (h *LimitsHandler) SetModuleDeny(w http.ResponseWriter, r *http.Request) {
	actor := middleware.GetAdminUser(r.Context())
	id, ok := adminTenantID(w, r)
	if !ok {
		return
	}
	if actor == nil {
		apierror.Unauthorized("administrator session required").WriteJSON(w)
		return
	}
	var req SetFeatureDenyRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 2048)).Decode(&req); err != nil {
		apierror.BadRequest("invalid request body").WriteJSON(w)
		return
	}
	in := entitlement.DenyInput{Feature: r.PathValue("module_id"), Reason: req.Reason, ExpiresAt: req.ExpiresAt}
	if in.Validate(time.Now()) != nil {
		apierror.BadRequest(featureDenyInvalid).WriteJSON(w)
		return
	}
	if !h.confirmStepUp(w, r, actor, req.TOTPCode, stepUpPurposeFeatureDeny) {
		return
	}
	if err := h.svc.PutDeny(r.Context(), actor, id, in, middleware.ClientIP(r), r.UserAgent()); err != nil {
		if errors.Is(err, limits.ErrInvalid) {
			apierror.BadRequest(featureDenyInvalid).WriteJSON(w)
			return
		}
		h.logger.Error("set feature deny", "error", err)
		apierror.InternalServerError("could not deny the module").WriteJSON(w)
		return
	}
	h.writeTenantModules(w, r, id)
}

// DeleteModuleDeny lifts an organization's deny of a module (ops_admin+ with
// a reason and a fresh authenticator code, audited).
// @Summary      Allow a denied module again (platform admin)
// @Tags         Admin Organizations
// @Accept       json
// @Produce      json
// @Param        tenantId   path  string                    true  "Organization ID"
// @Param        module_id  path  string                    true  "Module ID"
// @Param        request    body  DeleteFeatureDenyRequest  true  "Reason and code"
// @Success      200  {object}  AdminTenantModulesResponse
// @Router       /admin/tenants/{tenantId}/modules/{module_id}/deny [delete]
func (h *LimitsHandler) DeleteModuleDeny(w http.ResponseWriter, r *http.Request) {
	actor := middleware.GetAdminUser(r.Context())
	id, ok := adminTenantID(w, r)
	if !ok {
		return
	}
	if actor == nil {
		apierror.Unauthorized("administrator session required").WriteJSON(w)
		return
	}
	var req DeleteFeatureDenyRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 2048)).Decode(&req); err != nil {
		apierror.BadRequest("invalid request body").WriteJSON(w)
		return
	}
	feature := r.PathValue("module_id")
	if !limits.IsFeature(feature) || !entitlement.ValidReason(req.Reason) {
		apierror.BadRequest("Give a non-core module and a reason (up to 500 characters)").WriteJSON(w)
		return
	}
	if !h.confirmStepUp(w, r, actor, req.TOTPCode, stepUpPurposeFeatureDeny) {
		return
	}
	if err := h.svc.DeleteDeny(r.Context(), actor, id, feature, req.Reason, middleware.ClientIP(r), r.UserAgent()); err != nil {
		switch {
		case errors.Is(err, limits.ErrInvalid):
			apierror.BadRequest("unknown module").WriteJSON(w)
		case errors.Is(err, shared.ErrNotFound):
			apierror.NotFound("Module deny").WriteJSON(w)
		default:
			h.logger.Error("delete feature deny", "error", err)
			apierror.InternalServerError("could not allow the module").WriteJSON(w)
		}
		return
	}
	h.writeTenantModules(w, r, id)
}

// OrganizationLimit is one limit that applies to the organization, as its
// own administrators see it (no operator notes).
type OrganizationLimit struct {
	Key       limits.Key `json:"key"`
	Limit     int        `json:"limit"`
	Used      int        `json:"used"`
	OverLimit bool       `json:"over_limit"`
	Uncounted bool       `json:"uncounted,omitempty"`
}

// OrganizationDeniedFeature is one feature not available to the organization.
type OrganizationDeniedFeature struct {
	Feature       string     `json:"feature"`
	ReadOnlyUntil *time.Time `json:"read_only_until,omitempty"`
}

// OrganizationLimitsResponse is what applies to the organization: only the
// limits that are set and the features that are not available. Applies is
// false (and both lists empty) when nothing applies, the default of every
// self-hosted install: the console then shows no Usage & limits page.
type OrganizationLimitsResponse struct {
	Applies   bool                        `json:"applies"`
	OverLimit bool                        `json:"over_limit"`
	Limits    []OrganizationLimit         `json:"limits"`
	Denied    []OrganizationDeniedFeature `json:"denied_features"`
	// AccountPortalURL is the service operator's account page, present only
	// when one is configured and a limit or deny applies.
	AccountPortalURL string `json:"account_portal_url,omitempty"`
}

// GetOwnLimits returns the limits and unavailable features that apply to the
// organization (Settings > Usage & limits; owner or admin). The organization
// comes from the credential.
// @Summary      Get this organization's limits and usage
// @Tags         Tenants
// @Produce      json
// @Success      200  {object}  OrganizationLimitsResponse
// @Router       /organization/limits [get]
func (h *LimitsHandler) GetOwnLimits(w http.ResponseWriter, r *http.Request) {
	id, err := shared.IDFromString(middleware.GetTenantID(r.Context()))
	if err != nil {
		apierror.BadRequest("invalid tenant context").WriteJSON(w)
		return
	}
	sum, err := h.svc.Effective(r.Context(), id)
	if err != nil {
		h.logger.Error("read organization limits", "error", err)
		apierror.InternalServerError("could not read the limits").WriteJSON(w)
		return
	}
	resp := OrganizationLimitsResponse{Applies: sum.Applies, OverLimit: sum.OverLimit,
		Limits: []OrganizationLimit{}, Denied: []OrganizationDeniedFeature{}}
	for _, e := range sum.Limits {
		if e.Limit != limits.Unlimited {
			resp.Limits = append(resp.Limits, OrganizationLimit{Key: e.Key, Limit: e.Limit, Used: e.Used, OverLimit: e.OverLimit, Uncounted: e.Uncounted})
		}
	}
	for _, d := range sum.Denied {
		resp.Denied = append(resp.Denied, OrganizationDeniedFeature{Feature: d.Feature, ReadOnlyUntil: d.ReadOnlyUntil})
	}
	if resp.Applies {
		resp.AccountPortalURL = h.portalURL
	}
	writeJSON(w, http.StatusOK, resp)
}

// WriteLimitError answers an addition refused by a limit: 403 LIMIT_REACHED
// with a message the person can act on.
func WriteLimitError(w http.ResponseWriter, err error) bool {
	var lim *limits.ErrLimitReached
	if !errors.As(err, &lim) {
		return false
	}
	apierror.New(http.StatusForbidden, codeLimitReached, LimitMessage(lim)).WriteJSON(w)
	return true
}

// LimitMessage is the person-facing text of a limit refusal.
func LimitMessage(lim *limits.ErrLimitReached) string {
	label := map[limits.Key]string{
		limits.Seats: "seats", limits.Assets: "assets", limits.Sensors: "sensors", limits.APIKeys: "API keys",
		limits.CITrusts: "CI trust configurations", limits.InvitesPerDay: "invitations a day",
		limits.OrgsPerUser: "organizations per person", limits.Findings: "findings",
		limits.PlatformScansPerDay: "platform scans a day", limits.PlatformScansConcurrent: "concurrent platform scans",
	}[lim.Key]
	if label == "" {
		label = string(lim.Key)
	}
	if lim.Unavailable {
		return "This could not be checked against the organization's limits right now. Try again later."
	}
	return "The limit is " + strconv.Itoa(lim.Limit) + " " + label + "; " + strconv.Itoa(lim.Used) +
		" are in use. Remove some, or ask your administrator for more."
}

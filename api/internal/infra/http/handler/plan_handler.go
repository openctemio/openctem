package handler

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/openctemio/openctem/api/internal/app/entitlement"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/apierror"
	"github.com/openctemio/openctem/api/pkg/domain/admin"
	"github.com/openctemio/openctem/api/pkg/domain/plan"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

const stepUpPurposePlanDefaults = "plan defaults change"

// PlanHandler serves plans and limits: the plan defaults (Console > System >
// Plans), an organization's plan and overrides (Console > Organizations), and
// the organization's own Plan & usage view
// (docs/architecture/plans-and-limits.md).
type PlanHandler struct {
	svc    *entitlement.Service
	stepUp StepUpVerifier
	logger *logger.Logger
}

// NewPlanHandler creates the handler.
func NewPlanHandler(svc *entitlement.Service, stepUp StepUpVerifier, log *logger.Logger) *PlanHandler {
	return &PlanHandler{svc: svc, stepUp: stepUp, logger: log.With("handler", "plan")}
}

// PlanDefaultsResponse is the plan defaults: per plan, per limit key; -1 is
// unlimited.
type PlanDefaultsResponse struct {
	Plans    map[string]map[string]int `json:"plans"`
	Keys     []string                  `json:"keys"`
	Version  int                       `json:"version"`
	Unstored bool                      `json:"builtin"`
}

// UpdatePlanDefaultsRequest saves the plan defaults.
type UpdatePlanDefaultsRequest struct {
	Plans    map[string]map[string]int `json:"plans"`
	Version  int                       `json:"version"`
	TOTPCode string                    `json:"totp_code"`
}

func toPlanDefaultsResponse(d plan.Defaults, version int) PlanDefaultsResponse {
	resp := PlanDefaultsResponse{Plans: map[string]map[string]int{}, Version: version, Unstored: version == 0}
	for _, k := range plan.Keys {
		resp.Keys = append(resp.Keys, string(k))
	}
	for _, p := range plan.All {
		l := d.For(p)
		m := map[string]int{}
		for _, k := range plan.Keys {
			m[string(k)] = l.Get(k)
		}
		resp.Plans[string(p)] = m
	}
	return resp
}

// GetDefaults returns the plan defaults (any admin).
// @Summary      Get the plan defaults
// @Tags         Admin System
// @Produce      json
// @Success      200  {object}  PlanDefaultsResponse
// @Router       /admin/settings/plans [get]
func (h *PlanHandler) GetDefaults(w http.ResponseWriter, r *http.Request) {
	d, v, err := h.svc.Defaults(r.Context())
	if err != nil {
		h.logger.Error("read plan defaults", "error", err)
		apierror.InternalServerError("could not read the plan defaults").WriteJSON(w)
		return
	}
	writeJSON(w, http.StatusOK, toPlanDefaultsResponse(d, v))
}

// UpdateDefaults saves the plan defaults (super admin + fresh authenticator
// code; audited; the other administrators are told).
// @Summary      Change the plan defaults
// @Tags         Admin System
// @Accept       json
// @Produce      json
// @Param        request  body  UpdatePlanDefaultsRequest  true  "Defaults"
// @Success      200  {object}  PlanDefaultsResponse
// @Router       /admin/settings/plans [put]
func (h *PlanHandler) UpdateDefaults(w http.ResponseWriter, r *http.Request) {
	actor := middleware.GetAdminUser(r.Context())
	if actor == nil {
		apierror.Unauthorized("administrator session required").WriteJSON(w)
		return
	}
	var req UpdatePlanDefaultsRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8192)).Decode(&req); err != nil {
		apierror.BadRequest("invalid request body").WriteJSON(w)
		return
	}
	d := plan.Defaults{}
	for p, limits := range req.Plans {
		l := plan.Limits{}
		for k, v := range limits {
			l[plan.Key(k)] = v
		}
		d[plan.Plan(p)] = l
	}
	if err := d.Validate(); err != nil {
		apierror.BadRequest("unknown plan or limit, or a value below -1 (unlimited)").WriteJSON(w)
		return
	}
	if !h.confirmStepUp(w, r, actor, req.TOTPCode, stepUpPurposePlanDefaults) {
		return
	}
	v, err := h.svc.UpdateDefaults(r.Context(), actor, d, req.Version, middleware.ClientIP(r), r.UserAgent())
	if err != nil {
		if errors.Is(err, shared.ErrConflict) {
			apierror.Conflict("The plan defaults were changed by someone else; reload and try again").WriteJSON(w)
			return
		}
		h.logger.Error("save plan defaults", "error", err)
		apierror.InternalServerError("could not save the plan defaults").WriteJSON(w)
		return
	}
	writeJSON(w, http.StatusOK, toPlanDefaultsResponse(d, v))
}

func (h *PlanHandler) confirmStepUp(w http.ResponseWriter, r *http.Request, actor *admin.AdminUser, code, purpose string) bool {
	code = strings.TrimSpace(code)
	if code == "" {
		apierror.New(http.StatusUnauthorized, codeStepUpRequired, "Enter a code from your authenticator to confirm the change").WriteJSON(w)
		return false
	}
	if err := h.stepUp.StepUp(r.Context(), actor, code, purpose, clientInfo(r)); err != nil {
		switch {
		case errors.Is(err, admin.ErrStepUpUnavailable):
			apierror.New(http.StatusForbidden, codeStepUpUnavailable,
				"Enroll the console authenticator (sign in with your password and TOTP) to confirm this action").WriteJSON(w)
		case errors.Is(err, admin.ErrInvalidMFACode):
			apierror.Unauthorized("Invalid or already used code; wait for your authenticator to show a new one").WriteJSON(w)
		default:
			h.logger.Error("plan step-up", "error", err)
			apierror.InternalServerError("could not verify the code").WriteJSON(w)
		}
		return false
	}
	return true
}

// PlanSummaryResponse is an organization's plan, limits and usage.
type PlanSummaryResponse struct {
	Plan      string           `json:"plan"`
	OverLimit bool             `json:"over_limit"`
	Limits    []plan.Effective `json:"limits"`
}

func (h *PlanHandler) writeSummary(w http.ResponseWriter, r *http.Request, tenantID shared.ID) {
	sum, err := h.svc.Effective(r.Context(), tenantID)
	if err != nil {
		h.logger.Error("read plan summary", "error", err)
		apierror.InternalServerError("could not read the plan").WriteJSON(w)
		return
	}
	writeJSON(w, http.StatusOK, PlanSummaryResponse{Plan: string(sum.Plan), OverLimit: sum.OverLimit, Limits: sum.Limits})
}

func adminTenantID(w http.ResponseWriter, r *http.Request) (shared.ID, bool) {
	id, err := shared.IDFromString(r.PathValue(middleware.AdminTenantParam))
	if err != nil {
		apierror.BadRequest("invalid organization id").WriteJSON(w)
		return shared.ID{}, false
	}
	return id, true
}

// GetTenantPlan returns an organization's plan, limits, usage and the
// over-limit flag (any admin).
// @Summary      Get an organization's plan and usage (platform admin)
// @Tags         Admin Organizations
// @Produce      json
// @Param        tenantId  path  string  true  "Organization ID"
// @Success      200  {object}  PlanSummaryResponse
// @Router       /admin/tenants/{tenantId}/plan [get]
func (h *PlanHandler) GetTenantPlan(w http.ResponseWriter, r *http.Request) {
	if id, ok := adminTenantID(w, r); ok {
		h.writeSummary(w, r, id)
	}
}

// SetTenantPlanRequest changes an organization's plan.
type SetTenantPlanRequest struct {
	Plan string `json:"plan"`
}

// SetTenantPlan changes an organization's plan (ops_admin+, audited). Nothing
// is removed when the new plan's limits are lower.
// @Summary      Change an organization's plan (platform admin)
// @Tags         Admin Organizations
// @Accept       json
// @Produce      json
// @Param        tenantId  path  string                true  "Organization ID"
// @Param        request   body  SetTenantPlanRequest  true  "Plan"
// @Success      200  {object}  PlanSummaryResponse
// @Router       /admin/tenants/{tenantId}/plan [put]
func (h *PlanHandler) SetTenantPlan(w http.ResponseWriter, r *http.Request) {
	actor := middleware.GetAdminUser(r.Context())
	id, ok := adminTenantID(w, r)
	if !ok || actor == nil {
		return
	}
	var req SetTenantPlanRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1024)).Decode(&req); err != nil {
		apierror.BadRequest("invalid request body").WriteJSON(w)
		return
	}
	if err := h.svc.ChangeTenantPlan(r.Context(), actor, id, plan.Plan(req.Plan), middleware.ClientIP(r), r.UserAgent()); err != nil {
		if errors.Is(err, plan.ErrInvalid) {
			apierror.BadRequest("plan must be free, pro or enterprise").WriteJSON(w)
			return
		}
		h.logger.Error("set tenant plan", "error", err)
		apierror.InternalServerError("could not change the plan").WriteJSON(w)
		return
	}
	h.writeSummary(w, r, id)
}

// SetPlanOverrideRequest sets one limit for one organization.
type SetPlanOverrideRequest struct {
	Value     int        `json:"value"`
	Reason    string     `json:"reason"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
}

// SetOverride sets one limit for one organization (ops_admin+, audited).
// @Summary      Set a per-organization limit (platform admin)
// @Description  Wins over the plan default. A reason is required; an expiry is optional and must be in the future. -1 is unlimited.
// @Tags         Admin Organizations
// @Accept       json
// @Produce      json
// @Param        tenantId  path  string                  true  "Organization ID"
// @Param        key       path  string                  true  "Limit key"
// @Param        request   body  SetPlanOverrideRequest  true  "Override"
// @Success      200  {object}  PlanSummaryResponse
// @Router       /admin/tenants/{tenantId}/plan/overrides/{key} [put]
func (h *PlanHandler) SetOverride(w http.ResponseWriter, r *http.Request) {
	actor := middleware.GetAdminUser(r.Context())
	id, ok := adminTenantID(w, r)
	if !ok || actor == nil {
		return
	}
	var req SetPlanOverrideRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 2048)).Decode(&req); err != nil {
		apierror.BadRequest("invalid request body").WriteJSON(w)
		return
	}
	err := h.svc.PutOverride(r.Context(), actor, id, entitlement.OverrideInput{
		Key: plan.Key(r.PathValue("key")), Value: req.Value, Reason: req.Reason, ExpiresAt: req.ExpiresAt,
	}, middleware.ClientIP(r), r.UserAgent())
	if err != nil {
		if errors.Is(err, plan.ErrInvalid) {
			apierror.BadRequest("Give a known limit, a value of -1 (unlimited) or more, a reason (up to 500 characters) and, if any, a future expiry").WriteJSON(w)
			return
		}
		h.logger.Error("set plan override", "error", err)
		apierror.InternalServerError("could not set the limit").WriteJSON(w)
		return
	}
	h.writeSummary(w, r, id)
}

// DeleteOverride removes one per-organization limit (ops_admin+, audited).
// @Summary      Remove a per-organization limit (platform admin)
// @Tags         Admin Organizations
// @Produce      json
// @Param        tenantId  path  string  true  "Organization ID"
// @Param        key       path  string  true  "Limit key"
// @Success      200  {object}  PlanSummaryResponse
// @Router       /admin/tenants/{tenantId}/plan/overrides/{key} [delete]
func (h *PlanHandler) DeleteOverride(w http.ResponseWriter, r *http.Request) {
	actor := middleware.GetAdminUser(r.Context())
	id, ok := adminTenantID(w, r)
	if !ok || actor == nil {
		return
	}
	if err := h.svc.DeleteOverride(r.Context(), actor, id, plan.Key(r.PathValue("key")), middleware.ClientIP(r), r.UserAgent()); err != nil {
		switch {
		case errors.Is(err, plan.ErrInvalid):
			apierror.BadRequest("unknown limit").WriteJSON(w)
		case errors.Is(err, shared.ErrNotFound):
			apierror.NotFound("Override").WriteJSON(w)
		default:
			h.logger.Error("delete plan override", "error", err)
			apierror.InternalServerError("could not remove the limit").WriteJSON(w)
		}
		return
	}
	h.writeSummary(w, r, id)
}

// GetOwnPlan returns the organization's own plan and usage (Settings > Plan &
// usage; owner or admin). The organization comes from the credential.
// @Summary      Get this organization's plan and usage
// @Tags         Tenants
// @Produce      json
// @Success      200  {object}  PlanSummaryResponse
// @Router       /organization/plan [get]
func (h *PlanHandler) GetOwnPlan(w http.ResponseWriter, r *http.Request) {
	id, err := shared.IDFromString(middleware.GetTenantID(r.Context()))
	if err != nil {
		apierror.BadRequest("invalid tenant context").WriteJSON(w)
		return
	}
	h.writeSummary(w, r, id)
}

// WritePlanLimitError answers an addition refused by a plan limit: 403
// PLAN_LIMIT with the limit and usage, and a message the person can act on.
func WritePlanLimitError(w http.ResponseWriter, err error) bool {
	var lim *plan.ErrLimitReached
	if !errors.As(err, &lim) {
		return false
	}
	apierror.New(http.StatusForbidden, "PLAN_LIMIT", PlanLimitMessage(lim)).WriteJSON(w)
	return true
}

// PlanLimitMessage is the person-facing text of a plan-limit refusal.
func PlanLimitMessage(lim *plan.ErrLimitReached) string {
	label := map[plan.Key]string{
		plan.Seats: "seats", plan.Assets: "assets", plan.Sensors: "sensors", plan.APIKeys: "API keys",
		plan.CITrusts: "CI trust configurations", plan.InvitesPerDay: "invitations a day",
		plan.FreeTeamsPerUser: "Free organizations per person",
	}[lim.Key]
	if label == "" {
		label = string(lim.Key)
	}
	if lim.Unavailable {
		return "This could not be checked against your plan right now. Try again later."
	}
	return "Your plan allows " + strconv.Itoa(lim.Limit) + " " + label + "; you use " + strconv.Itoa(lim.Used) +
		". Remove some, or ask your administrator for more."
}

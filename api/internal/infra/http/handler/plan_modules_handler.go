package handler

// Module entitlements in the platform console (RFC-064): the plan to module
// map (Console > System > Plans) and one organization's grants and denies
// (Organization > Modules).

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/openctemio/openctem/api/internal/app/entitlement"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/apierror"
	moduledom "github.com/openctemio/openctem/api/pkg/domain/module"
	"github.com/openctemio/openctem/api/pkg/domain/plan"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

const stepUpPurposePlanModules = "plan modules change"

// PlanModuleOption is one module an administrator can include in a plan.
type PlanModuleOption struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Release string `json:"release"`
}

// PlanModulesResponse is the plan to module map: each plan lists module ids,
// or ["*"] for every module.
type PlanModulesResponse struct {
	Plans   map[string][]string `json:"plans"`
	Modules []PlanModuleOption  `json:"modules"`
	Version int                 `json:"version"`
	Builtin bool                `json:"builtin"`
}

// UpdatePlanModulesRequest replaces the plan to module map.
type UpdatePlanModulesRequest struct {
	Plans    map[string][]string `json:"plans"`
	Version  int                 `json:"version"`
	TOTPCode string              `json:"totp_code"`
}

func toPlanModulesResponse(m plan.PlanModules, version int) PlanModulesResponse {
	resp := PlanModulesResponse{Plans: map[string][]string{}, Version: version, Builtin: version == 0}
	for _, p := range plan.All {
		ids := m[p]
		if ids == nil {
			ids = []string{}
		}
		resp.Plans[string(p)] = ids
	}
	for _, d := range moduledom.Registry {
		if d.Core || d.Parent != "" {
			continue
		}
		resp.Modules = append(resp.Modules, PlanModuleOption{ID: d.ID, Name: d.Name, Release: string(d.Release)})
	}
	return resp
}

// GetPlanModules returns the plan to module map (any admin).
// @Summary      Get the modules of each plan (platform admin)
// @Tags         Admin Settings
// @Produce      json
// @Success      200  {object}  PlanModulesResponse
// @Router       /admin/settings/plan-modules [get]
func (h *PlanHandler) GetPlanModules(w http.ResponseWriter, r *http.Request) {
	m, v, err := h.svc.PlanModules(r.Context())
	if err != nil {
		h.logger.Error("read plan modules", "error", err)
		apierror.InternalServerError("could not read the plan modules").WriteJSON(w)
		return
	}
	writeJSON(w, http.StatusOK, toPlanModulesResponse(m, v))
}

// UpdatePlanModules replaces the plan to module map (super admin with a fresh
// authenticator code; audited at critical severity). Organizations keep their
// data; a module leaving a plan becomes unavailable to its organizations.
// @Summary      Change the modules of each plan (platform admin)
// @Tags         Admin Settings
// @Accept       json
// @Produce      json
// @Param        request  body  UpdatePlanModulesRequest  true  "Plan modules"
// @Success      200  {object}  PlanModulesResponse
// @Router       /admin/settings/plan-modules [put]
func (h *PlanHandler) UpdatePlanModules(w http.ResponseWriter, r *http.Request) {
	actor := middleware.GetAdminUser(r.Context())
	if actor == nil {
		apierror.Unauthorized("administrator session required").WriteJSON(w)
		return
	}
	var req UpdatePlanModulesRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16384)).Decode(&req); err != nil {
		apierror.BadRequest("invalid request body").WriteJSON(w)
		return
	}
	m := plan.PlanModules{}
	for p, ids := range req.Plans {
		m[plan.Plan(p)] = ids
	}
	if err := m.Validate(); err != nil {
		apierror.BadRequest(`Each plan lists known, non-core modules, or only "*" for every module`).WriteJSON(w)
		return
	}
	if !h.confirmStepUp(w, r, actor, req.TOTPCode, stepUpPurposePlanModules) {
		return
	}
	v, err := h.svc.UpdatePlanModules(r.Context(), actor, m, req.Version, middleware.ClientIP(r), r.UserAgent())
	if err != nil {
		if errors.Is(err, shared.ErrConflict) {
			apierror.Conflict("The plan modules were changed by someone else; reload and try again").WriteJSON(w)
			return
		}
		h.logger.Error("save plan modules", "error", err)
		apierror.InternalServerError("could not save the plan modules").WriteJSON(w)
		return
	}
	writeJSON(w, http.StatusOK, toPlanModulesResponse(m.Normalized(), v))
}

// AdminTenantModulesResponse is one organization's module entitlements.
type AdminTenantModulesResponse struct {
	Plan    string                          `json:"plan"`
	Modules []entitlement.ModuleEntitlement `json:"modules"`
}

func (h *PlanHandler) writeTenantModules(w http.ResponseWriter, r *http.Request, tenantID shared.ID) {
	p, list, err := h.svc.ModuleEntitlements(r.Context(), tenantID)
	if err != nil {
		h.logger.Error("read module entitlements", "error", err)
		apierror.InternalServerError("could not read the modules").WriteJSON(w)
		return
	}
	writeJSON(w, http.StatusOK, AdminTenantModulesResponse{Plan: string(p), Modules: list})
}

// GetTenantModules returns an organization's module entitlements (any admin).
// @Summary      Get an organization's module entitlements (platform admin)
// @Tags         Admin Organizations
// @Produce      json
// @Param        tenantId  path  string  true  "Organization ID"
// @Success      200  {object}  AdminTenantModulesResponse
// @Router       /admin/tenants/{tenantId}/modules [get]
func (h *PlanHandler) GetTenantModules(w http.ResponseWriter, r *http.Request) {
	if id, ok := adminTenantID(w, r); ok {
		h.writeTenantModules(w, r, id)
	}
}

// SetModuleGrantRequest grants or denies one module to one organization.
type SetModuleGrantRequest struct {
	Kind      string     `json:"kind"`
	Reason    string     `json:"reason"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
}

// SetModuleGrant grants a module beyond the plan (a trial, an add-on) or
// denies one the plan includes (ops_admin+, audited).
// @Summary      Grant or deny a module to an organization (platform admin)
// @Description  kind is grant or deny. A reason is required; an expiry is optional and must be in the future.
// @Tags         Admin Organizations
// @Accept       json
// @Produce      json
// @Param        tenantId  path  string                 true  "Organization ID"
// @Param        module_id  path  string                 true  "Module ID"
// @Param        request   body  SetModuleGrantRequest  true  "Grant"
// @Success      200  {object}  AdminTenantModulesResponse
// @Router       /admin/tenants/{tenantId}/modules/{module_id}/grant [put]
func (h *PlanHandler) SetModuleGrant(w http.ResponseWriter, r *http.Request) {
	actor := middleware.GetAdminUser(r.Context())
	id, ok := adminTenantID(w, r)
	if !ok || actor == nil {
		return
	}
	var req SetModuleGrantRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 2048)).Decode(&req); err != nil {
		apierror.BadRequest("invalid request body").WriteJSON(w)
		return
	}
	err := h.svc.PutModuleGrant(r.Context(), actor, id, entitlement.ModuleGrantInput{
		Module: r.PathValue("module_id"), Kind: plan.GrantKind(req.Kind), Reason: req.Reason, ExpiresAt: req.ExpiresAt,
	}, middleware.ClientIP(r), r.UserAgent())
	if err != nil {
		if errors.Is(err, plan.ErrInvalid) {
			apierror.BadRequest("Give a non-core module, grant or deny, a reason (up to 500 characters) and, if any, a future expiry").WriteJSON(w)
			return
		}
		h.logger.Error("set module grant", "error", err)
		apierror.InternalServerError("could not set the module").WriteJSON(w)
		return
	}
	h.writeTenantModules(w, r, id)
}

// DeleteModuleGrant removes an organization's grant or deny of a module: the
// plan decides again (ops_admin+, audited).
// @Summary      Remove an organization's module grant (platform admin)
// @Tags         Admin Organizations
// @Produce      json
// @Param        tenantId  path  string  true  "Organization ID"
// @Param        module_id  path  string  true  "Module ID"
// @Success      200  {object}  AdminTenantModulesResponse
// @Router       /admin/tenants/{tenantId}/modules/{module_id}/grant [delete]
func (h *PlanHandler) DeleteModuleGrant(w http.ResponseWriter, r *http.Request) {
	actor := middleware.GetAdminUser(r.Context())
	id, ok := adminTenantID(w, r)
	if !ok || actor == nil {
		return
	}
	if err := h.svc.DeleteModuleGrant(r.Context(), actor, id, r.PathValue("module_id"), middleware.ClientIP(r), r.UserAgent()); err != nil {
		switch {
		case errors.Is(err, plan.ErrInvalid):
			apierror.BadRequest("unknown module").WriteJSON(w)
		case errors.Is(err, shared.ErrNotFound):
			apierror.NotFound("Module grant").WriteJSON(w)
		default:
			h.logger.Error("delete module grant", "error", err)
			apierror.InternalServerError("could not remove the module grant").WriteJSON(w)
		}
		return
	}
	h.writeTenantModules(w, r, id)
}

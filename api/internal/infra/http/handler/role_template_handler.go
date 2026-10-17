package handler

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/apierror"
	"github.com/openctemio/openctem/api/pkg/domain/permission"
)

// RoleTemplateResponse is one custom-role template.
type RoleTemplateResponse struct {
	ID string `json:"id"`
	// Version goes up when the template's grants change; roles created from
	// an older version are offered the update.
	Version           int      `json:"version"`
	Name              string   `json:"name"`
	Description       string   `json:"description"`
	Personas          []string `json:"personas"`
	HasFullDataAccess bool     `json:"has_full_data_access"`
	Permissions       []string `json:"permissions"`
	// Summary is what a role made from the template can do: risk, why, and
	// per area.
	Summary permission.Summary `json:"summary"`
}

// RoleTemplateListResponse lists the custom-role templates.
type RoleTemplateListResponse struct {
	Templates []RoleTemplateResponse `json:"templates"`
}

// ListRoleTemplates handles GET /api/v1/roles/templates: the starting points
// for a custom role. Creating a role from one is an ordinary POST /roles, so
// the grant ceiling, the admin-only refusal and the audit apply as usual.
//
// @Summary      List custom-role templates
// @Description  Persona-shaped starting points for a custom role (program lead, analyst, remediation owner, auditor, ...). A template grants nothing; create a role from it with POST /roles.
// @Tags         Roles
// @Produce      json
// @Success      200  {object}  RoleTemplateListResponse
// @Security     BearerAuth
// @Router       /roles/templates [get]
func (h *RoleHandler) ListRoleTemplates(w http.ResponseWriter, _ *http.Request) {
	templates := permission.RoleTemplates()
	resp := RoleTemplateListResponse{Templates: make([]RoleTemplateResponse, 0, len(templates))}
	for _, t := range templates {
		resp.Templates = append(resp.Templates, RoleTemplateResponse{
			ID:                t.ID,
			Version:           t.Version,
			Name:              t.Name,
			Description:       t.Description,
			Personas:          t.Personas,
			HasFullDataAccess: t.HasFullDataAccess,
			Permissions:       permission.ToStrings(t.Permissions),
			Summary:           permission.Summarize(permission.ToStrings(t.Permissions), t.HasFullDataAccess, false),
		})
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

// ApplyRoleTemplateUpdateRequest names the template version the editor
// reviewed.
type ApplyRoleTemplateUpdateRequest struct {
	Version int `json:"version" validate:"required,min=1"`
}

// ApplyRoleTemplateUpdate handles POST /api/v1/roles/{roleId}/template/apply.
//
// @Summary      Apply a role template update
// @Description  Brings a custom role up to its template's current version: adds the permissions the template added and removes those it removed, keeping the role's own edits. Full data access is never changed. Same rules as editing the role: you can only give a role permissions you hold, admin-only permissions are refused, and a role bound to a team needs the owner. version must be the template version you reviewed (409 otherwise). Audited as a role update.
// @Tags         Roles
// @Accept       json
// @Produce      json
// @Param        roleId  path  string  true  "Role ID"
// @Param        body  body  ApplyRoleTemplateUpdateRequest  true  "Reviewed template version"
// @Success      200  {object}  RoleResponse
// @Failure      400  {object}  apierror.Error
// @Failure      403  {object}  apierror.Error
// @Failure      404  {object}  apierror.Error
// @Failure      409  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /roles/{roleId}/template/apply [post]
func (h *RoleHandler) ApplyRoleTemplateUpdate(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var req ApplyRoleTemplateUpdateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}
	if err := h.validator.Validate(req); err != nil {
		h.handleValidationError(w, err)
		return
	}
	ro, err := h.service.ApplyTemplateUpdate(ctx, middleware.MustGetTenantID(ctx), chi.URLParam(r, "roleId"), req.Version, h.buildAuditContext(r))
	if err != nil {
		h.handleServiceError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(toRoleResponse(ro))
}

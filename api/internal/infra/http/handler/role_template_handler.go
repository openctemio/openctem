package handler

import (
	"encoding/json"
	"net/http"

	"github.com/openctemio/openctem/api/pkg/domain/permission"
)

// RoleTemplateResponse is one custom-role template.
type RoleTemplateResponse struct {
	ID                string   `json:"id"`
	Name              string   `json:"name"`
	Description       string   `json:"description"`
	Personas          []string `json:"personas"`
	HasFullDataAccess bool     `json:"has_full_data_access"`
	Permissions       []string `json:"permissions"`
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
			Name:              t.Name,
			Description:       t.Description,
			Personas:          t.Personas,
			HasFullDataAccess: t.HasFullDataAccess,
			Permissions:       permission.ToStrings(t.Permissions),
		})
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

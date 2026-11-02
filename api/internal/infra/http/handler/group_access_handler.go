package handler

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/openctemio/openctem/api/internal/app/accesscontrol"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/apierror"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// TeamPresetResponse is one preset of a team.
type TeamPresetResponse struct {
	TemplateID        string `json:"template_id"`
	RoleID            string `json:"role_id"`
	Name              string `json:"name"`
	VersionTaken      int    `json:"version_taken"`
	CurrentVersion    int    `json:"current_version"`
	UpdateAvailable   bool   `json:"update_available"`
	Privileged        bool   `json:"privileged"`
	HasFullDataAccess bool   `json:"has_full_data_access"`
}

// TeamAccessResponse is the access a team carries.
type TeamAccessResponse struct {
	Presets []TeamPresetResponse `json:"presets"`
	// ScopeMode is "specific" (the team's scope rules and assigned assets)
	// or "all_assets".
	ScopeMode string `json:"scope_mode"`
	// Privileged: the team carries elevated access; only owners change it.
	Privileged bool `json:"privileged"`
	// OtherRoles counts roles bound to the team by hand.
	OtherRoles int `json:"other_roles"`
}

// SetTeamAccessRequest sets the access a team carries.
type SetTeamAccessRequest struct {
	// Presets are role template ids (GET /roles/templates); the team's presets
	// become exactly this list.
	Presets   []string `json:"presets" validate:"max=8,dive,required,max=64"`
	ScopeMode string   `json:"scope_mode" validate:"required,oneof=specific all_assets"`
}

// UpgradeTeamPresetRequest brings a preset to its template's current version.
type UpgradeTeamPresetRequest struct {
	TemplateID string `json:"template_id" validate:"required,max=64"`
	// Version is the template version the editor reviewed.
	Version int `json:"version" validate:"required,min=1"`
}

// UserTeamAccessResponse is one role a person holds through a team.
type UserTeamAccessResponse struct {
	GroupID     string     `json:"group_id"`
	GroupName   string     `json:"group_name"`
	RoleID      string     `json:"role_id"`
	RoleName    string     `json:"role_name"`
	Managed     bool       `json:"managed"`
	TemplateID  string     `json:"template_id,omitempty"`
	Privileged  bool       `json:"privileged"`
	MemberUntil *time.Time `json:"member_until,omitempty"`
}

// UserTeamAccessListResponse lists the roles a person holds through teams.
type UserTeamAccessListResponse struct {
	Data []UserTeamAccessResponse `json:"data"`
}

func toTeamAccessResponse(v *accesscontrol.TeamAccessView) TeamAccessResponse {
	resp := TeamAccessResponse{
		Presets: make([]TeamPresetResponse, 0, len(v.Presets)), ScopeMode: v.ScopeMode,
		Privileged: v.Privileged, OtherRoles: v.OtherRoles,
	}
	for _, p := range v.Presets {
		resp.Presets = append(resp.Presets, TeamPresetResponse(p))
	}
	return resp
}

func writeJSONBody(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

// GetTeamAccess handles GET /api/v1/groups/{groupId}/access
// @Summary Get the access a team carries
// @Description The presets (managed roles made from role templates) and the scope mode every active member inherits.
// @Tags groups
// @Produce json
// @Param groupId path string true "Group ID"
// @Success 200 {object} TeamAccessResponse
// @Failure 404 {object} apierror.Error
// @Security BearerAuth
// @Router /groups/{groupId}/access [get]
func (h *GroupHandler) GetTeamAccess(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	v, err := h.service.GetTeamAccess(ctx, middleware.MustGetTenantID(ctx), chi.URLParam(r, "groupId"))
	if err != nil {
		h.writeBindingError(w, r, err)
		return
	}
	writeJSONBody(w, http.StatusOK, toTeamAccessResponse(v))
}

// SetTeamAccess handles PUT /api/v1/groups/{groupId}/access
// @Summary Set the access a team carries
// @Description Sets the team's presets (role templates; each becomes a managed role of the team) and scope mode. Members inherit both at once and lose them when they leave the team or their membership ends. Owner and admin never come through a team. A team with elevated access (all assets, or a preset above the member level) is set only by an owner with a recent sign-in.
// @Tags groups
// @Accept json
// @Produce json
// @Param groupId path string true "Group ID"
// @Param request body SetTeamAccessRequest true "Access"
// @Success 200 {object} TeamAccessResponse
// @Failure 400 {object} apierror.Error
// @Failure 403 {object} apierror.Error
// @Failure 404 {object} apierror.Error
// @Security BearerAuth
// @Router /groups/{groupId}/access [put]
func (h *GroupHandler) SetTeamAccess(w http.ResponseWriter, r *http.Request) {
	var req SetTeamAccessRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}
	if err := h.validator.Validate(req); err != nil {
		h.handleValidationError(w, err)
		return
	}
	v, err := h.service.SetTeamAccess(r.Context(), accesscontrol.SetTeamAccessInput{
		GroupID: chi.URLParam(r, "groupId"), Presets: req.Presets, ScopeMode: req.ScopeMode,
	}, h.buildAuditContext(r))
	if err != nil {
		h.writeBindingError(w, r, err)
		return
	}
	writeJSONBody(w, http.StatusOK, toTeamAccessResponse(v))
}

// UpgradeTeamPreset handles POST /api/v1/groups/{groupId}/access/upgrade
// @Summary Update a team preset to its template's current version
// @Description Applies the template's newer permissions to the team's managed role. Send the template version you reviewed; a different current version is refused with 409.
// @Tags groups
// @Accept json
// @Produce json
// @Param groupId path string true "Group ID"
// @Param request body UpgradeTeamPresetRequest true "Preset"
// @Success 200 {object} TeamAccessResponse
// @Failure 400 {object} apierror.Error
// @Failure 403 {object} apierror.Error
// @Failure 404 {object} apierror.Error
// @Failure 409 {object} apierror.Error
// @Security BearerAuth
// @Router /groups/{groupId}/access/upgrade [post]
func (h *GroupHandler) UpgradeTeamPreset(w http.ResponseWriter, r *http.Request) {
	var req UpgradeTeamPresetRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}
	if err := h.validator.Validate(req); err != nil {
		h.handleValidationError(w, err)
		return
	}
	v, err := h.service.UpgradeTeamPreset(r.Context(), chi.URLParam(r, "groupId"), req.TemplateID, req.Version, h.buildAuditContext(r))
	if err != nil {
		h.writeBindingError(w, r, err)
		return
	}
	writeJSONBody(w, http.StatusOK, toTeamAccessResponse(v))
}

// ListUserTeamAccess handles GET /api/v1/users/{userId}/team-access
// @Summary List the access a person inherits from teams
// @Description The roles the person holds through the active teams they belong to ("access from team X"), with the team each comes from and the end date of the membership.
// @Tags groups
// @Produce json
// @Param userId path string true "User ID"
// @Success 200 {object} UserTeamAccessListResponse
// @Failure 400 {object} apierror.Error
// @Security BearerAuth
// @Router /users/{userId}/team-access [get]
func (h *GroupHandler) ListUserTeamAccess(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	uid, err := shared.IDFromString(chi.URLParam(r, "userId"))
	if err != nil {
		apierror.BadRequest("Invalid user id").WriteJSON(w)
		return
	}
	views, err := h.service.ListUserTeamAccess(ctx, middleware.MustGetTenantID(ctx), uid)
	if err != nil {
		h.writeBindingError(w, r, err)
		return
	}
	resp := UserTeamAccessListResponse{Data: make([]UserTeamAccessResponse, 0, len(views))}
	for _, v := range views {
		resp.Data = append(resp.Data, UserTeamAccessResponse{
			GroupID: v.Grant.GroupID.String(), GroupName: v.Grant.GroupName,
			RoleID: v.Grant.RoleID.String(), RoleName: v.Grant.RoleName,
			Managed: v.Grant.Managed, TemplateID: v.Grant.TemplateID,
			Privileged: v.Privileged, MemberUntil: v.Grant.MemberUntil,
		})
	}
	writeJSONBody(w, http.StatusOK, resp)
}

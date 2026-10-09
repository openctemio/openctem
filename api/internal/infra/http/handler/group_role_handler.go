package handler

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/apierror"
	"github.com/openctemio/openctem/api/pkg/domain/group"
)

// GroupRoleResponse is a role bound to a team.
type GroupRoleResponse struct {
	RoleID     string    `json:"role_id"`
	Name       string    `json:"name"`
	Privileged bool      `json:"privileged"`
	CreatedBy  string    `json:"created_by,omitempty"`
	CreatedAt  time.Time `json:"created_at"`
}

// GroupRoleListResponse lists the roles bound to a team.
type GroupRoleListResponse struct {
	Data []GroupRoleResponse `json:"data"`
}

// BindGroupRoleRequest binds a custom role to a team.
type BindGroupRoleRequest struct {
	RoleID string `json:"role_id" validate:"required,uuid"`
}

func (h *GroupHandler) writeBindingError(w http.ResponseWriter, err error) {
	if writeStepUpError(w, err) {
		return
	}
	switch {
	case errors.Is(err, group.ErrRoleAlreadyBound):
		apierror.Conflict("The role is already bound to this team").WriteJSON(w)
	case errors.Is(err, group.ErrTooManyBindings):
		apierror.ValidationFailed("A team carries at most 10 roles", nil).WriteJSON(w)
	case errors.Is(err, group.ErrRoleBindingMissing):
		apierror.NotFound("Role binding").WriteJSON(w)
	default:
		h.handleServiceError(w, err)
	}
}

// ListGroupRoles handles GET /api/v1/groups/{groupId}/roles
// @Summary List the roles bound to a team
// @Description Every active member of the team holds these custom roles.
// @Tags groups
// @Produce json
// @Param groupId path string true "Group ID"
// @Success 200 {object} GroupRoleListResponse
// @Failure 404 {object} apierror.Error
// @Security BearerAuth
// @Router /groups/{groupId}/roles [get]
func (h *GroupHandler) ListGroupRoles(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	views, err := h.service.ListGroupRoles(ctx, middleware.MustGetTenantID(ctx), chi.URLParam(r, "groupId"))
	if err != nil {
		h.writeBindingError(w, err)
		return
	}
	resp := GroupRoleListResponse{Data: make([]GroupRoleResponse, 0, len(views))}
	for _, v := range views {
		item := GroupRoleResponse{
			RoleID: v.Binding.RoleID.String(), Name: v.Binding.RoleName,
			Privileged: v.Privileged, CreatedAt: v.Binding.CreatedAt,
		}
		if v.Binding.CreatedBy != nil {
			item.CreatedBy = v.Binding.CreatedBy.String()
		}
		resp.Data = append(resp.Data, item)
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

// BindGroupRole handles POST /api/v1/groups/{groupId}/roles
// @Summary Bind a custom role to a team
// @Description Every active member of the team then holds the role. You can bind only a role you could grant yourself; a privileged role (full data access, member, team, role, key, secret or settings administration) needs the owner and a recent sign-in.
// @Tags groups
// @Accept json
// @Param groupId path string true "Group ID"
// @Param request body BindGroupRoleRequest true "Role"
// @Success 201
// @Failure 400 {object} apierror.Error
// @Failure 403 {object} apierror.Error
// @Failure 404 {object} apierror.Error
// @Failure 409 {object} apierror.Error
// @Security BearerAuth
// @Router /groups/{groupId}/roles [post]
func (h *GroupHandler) BindGroupRole(w http.ResponseWriter, r *http.Request) {
	var req BindGroupRoleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}
	if err := h.validator.Validate(req); err != nil {
		h.handleValidationError(w, err)
		return
	}
	if err := h.service.BindRole(r.Context(), chi.URLParam(r, "groupId"), req.RoleID, h.buildAuditContext(r)); err != nil {
		h.writeBindingError(w, err)
		return
	}
	w.WriteHeader(http.StatusCreated)
}

// UnbindGroupRole handles DELETE /api/v1/groups/{groupId}/roles/{roleId}
// @Summary Remove a role from a team
// @Tags groups
// @Param groupId path string true "Group ID"
// @Param roleId path string true "Role ID"
// @Success 204
// @Failure 403 {object} apierror.Error
// @Failure 404 {object} apierror.Error
// @Security BearerAuth
// @Router /groups/{groupId}/roles/{roleId} [delete]
func (h *GroupHandler) UnbindGroupRole(w http.ResponseWriter, r *http.Request) {
	if err := h.service.UnbindRole(r.Context(), chi.URLParam(r, "groupId"), chi.URLParam(r, "roleId"), h.buildAuditContext(r)); err != nil {
		h.writeBindingError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

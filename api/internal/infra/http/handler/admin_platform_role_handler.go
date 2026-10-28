package handler

// Platform roles in the console (design: RFC-134): the catalog, the built-in roles,
// who holds what, and giving or taking an additional role. Console routes
// only; no tenant route serves any of it.

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/openctemio/openctem/api/internal/app/platformrole"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/apierror"
	"github.com/openctemio/openctem/api/pkg/domain/admin"
	"github.com/openctemio/openctem/api/pkg/domain/platformauthz"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// AdminPlatformRoleHandler serves /api/v1/admin/platform-roles and the role
// routes of an administrator.
type AdminPlatformRoleHandler struct {
	svc *platformrole.Service
	log *logger.Logger
}

// NewAdminPlatformRoleHandler creates the handler.
func NewAdminPlatformRoleHandler(svc *platformrole.Service, log *logger.Logger) *AdminPlatformRoleHandler {
	return &AdminPlatformRoleHandler{svc: svc, log: log.With("handler", "admin_platform_role")}
}

// PlatformPermissionResponse is one catalog entry.
type PlatformPermissionResponse struct {
	Key         string `json:"key"`
	Baseline    bool   `json:"baseline"`
	Description string `json:"description"`
}

// PlatformRoleResponse is one built-in role.
type PlatformRoleResponse struct {
	Key         string   `json:"key"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Base        bool     `json:"base"`
	Tier        string   `json:"tier"`
	Permissions []string `json:"permissions"`
	Holders     int      `json:"holders"`
}

// PlatformRolesResponse is the catalog and the roles.
type PlatformRolesResponse struct {
	Roles       []PlatformRoleResponse       `json:"roles"`
	Permissions []PlatformPermissionResponse `json:"permissions"`
	// NamedOwners counts active platform owners that are not break-glass;
	// OwnersWarning is true below two.
	NamedOwners   int  `json:"named_owners"`
	OwnersWarning bool `json:"owners_warning"`
}

// PlatformRoleAssignmentResponse is one administrator's roles.
type PlatformRoleAssignmentResponse struct {
	AdminID    string   `json:"admin_id"`
	Email      string   `json:"email"`
	Name       string   `json:"name"`
	Active     bool     `json:"active"`
	BreakGlass bool     `json:"break_glass"`
	Roles      []string `json:"roles"`
}

// PlatformRoleChangeRequest gives or takes a role.
type PlatformRoleChangeRequest struct {
	Role   string `json:"role"`
	Reason string `json:"reason"`
}

// Roles lists the catalog and the built-in roles with their holder counts.
//
// @Summary      Platform roles and permissions (platform admin)
// @Description  The platform permission catalog, the built-in platform roles with their permissions and holder counts, and whether fewer than two named platform owners exist. Any console role.
// @Tags         Admin
// @Produce      json
// @Success      200  {object}  PlatformRolesResponse
// @Router       /admin/platform-roles [get]
func (h *AdminPlatformRoleHandler) Roles(w http.ResponseWriter, r *http.Request) {
	as, err := h.svc.List(r.Context())
	if err != nil {
		h.log.Error("list platform roles", "error", err)
		apierror.InternalServerError("could not list platform roles").WriteJSON(w)
		return
	}
	holders := map[platformauthz.RoleKey]int{}
	for _, a := range as {
		if !a.Active {
			continue
		}
		for _, k := range a.Roles {
			holders[k]++
		}
	}
	out := PlatformRolesResponse{Roles: []PlatformRoleResponse{}, Permissions: []PlatformPermissionResponse{}}
	for _, d := range platformauthz.Catalog() {
		out.Permissions = append(out.Permissions, PlatformPermissionResponse{Key: string(d.Key), Baseline: d.Baseline, Description: d.Description})
	}
	for _, role := range platformauthz.BuiltinRoles() {
		ps := make([]string, 0, len(role.Permissions))
		for _, p := range role.Permissions {
			ps = append(ps, string(p))
		}
		out.Roles = append(out.Roles, PlatformRoleResponse{Key: string(role.Key), Name: role.Name, Description: role.Description,
			Base: role.Base, Tier: string(role.Tier), Permissions: ps, Holders: holders[role.Key]})
	}
	out.NamedOwners = platformrole.Owners(as)
	out.OwnersWarning = out.NamedOwners < 2
	writeJSON(w, http.StatusOK, out)
}

// Assignments lists every administrator's platform roles.
//
// @Summary      Who holds which platform role (platform admin)
// @Description  Every administrator with the platform roles held. Needs the administrator roster permission.
// @Tags         Admin
// @Produce      json
// @Success      200  {object}  map[string][]PlatformRoleAssignmentResponse
// @Router       /admin/platform-roles/assignments [get]
func (h *AdminPlatformRoleHandler) Assignments(w http.ResponseWriter, r *http.Request) {
	as, err := h.svc.List(r.Context())
	if err != nil {
		h.log.Error("list platform role assignments", "error", err)
		apierror.InternalServerError("could not list platform role assignments").WriteJSON(w)
		return
	}
	out := make([]PlatformRoleAssignmentResponse, 0, len(as))
	for _, a := range as {
		roles := make([]string, 0, len(a.Roles))
		for _, k := range a.Roles {
			roles = append(roles, string(k))
		}
		out = append(out, PlatformRoleAssignmentResponse{AdminID: a.AdminID.String(), Email: a.Email, Name: a.Name,
			Active: a.Active, BreakGlass: a.BreakGlass, Roles: roles})
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": out})
}

// Assign gives an administrator an additional role.
//
// @Summary      Give a platform role (platform admin)
// @Description  Gives an administrator an additional platform role (operator, support, security_auditor, billing). Platform owner, step-up and a reason; never to yourself, never a role whose permissions you do not hold. Audited and announced.
// @Tags         Admin
// @Accept       json
// @Param        id       path  string                     true  "Administrator ID"
// @Param        request  body  PlatformRoleChangeRequest  true  "Role and reason"
// @Success      204
// @Failure      400  {object}  apierror.Error
// @Failure      403  {object}  apierror.Error
// @Failure      404  {object}  apierror.Error
// @Router       /admin/users/{id}/platform-roles [post]
func (h *AdminPlatformRoleHandler) Assign(w http.ResponseWriter, r *http.Request) {
	h.change(w, r, func(actor *admin.AdminUser, id shared.ID, req PlatformRoleChangeRequest) error {
		return h.svc.Assign(r.Context(), actor, id, platformauthz.RoleKey(req.Role), req.Reason, platformrole.Client{IP: middleware.ClientIP(r), UserAgent: r.UserAgent()})
	})
}

// Revoke takes an additional role from an administrator.
//
// @Summary      Take a platform role (platform admin)
// @Description  Takes an additional platform role from an administrator. Platform owner, step-up and a reason; audited and announced.
// @Tags         Admin
// @Accept       json
// @Param        id       path  string                     true  "Administrator ID"
// @Param        role     path  string                     true  "Role key"
// @Param        request  body  PlatformRoleChangeRequest  true  "Reason"
// @Success      204
// @Failure      400  {object}  apierror.Error
// @Failure      403  {object}  apierror.Error
// @Failure      404  {object}  apierror.Error
// @Router       /admin/users/{id}/platform-roles/{role} [delete]
func (h *AdminPlatformRoleHandler) Revoke(w http.ResponseWriter, r *http.Request) {
	h.change(w, r, func(actor *admin.AdminUser, id shared.ID, req PlatformRoleChangeRequest) error {
		return h.svc.Revoke(r.Context(), actor, id, platformauthz.RoleKey(chi.URLParam(r, "role")), req.Reason, platformrole.Client{IP: middleware.ClientIP(r), UserAgent: r.UserAgent()})
	})
}

func (h *AdminPlatformRoleHandler) change(w http.ResponseWriter, r *http.Request, do func(*admin.AdminUser, shared.ID, PlatformRoleChangeRequest) error) {
	actor := middleware.GetAdminUser(r.Context())
	if actor == nil {
		apierror.Unauthorized("admin authentication required").WriteJSON(w)
		return
	}
	id, err := shared.IDFromString(chi.URLParam(r, "id"))
	if err != nil {
		apierror.BadRequest("invalid administrator id").WriteJSON(w)
		return
	}
	var req PlatformRoleChangeRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil {
		apierror.BadRequest("invalid request body").WriteJSON(w)
		return
	}
	switch err := do(actor, id, req); {
	case err == nil:
		w.WriteHeader(http.StatusNoContent)
	case errors.Is(err, platformrole.ErrSelf):
		apierror.Forbidden("You cannot change your own platform roles.").WriteJSON(w)
	case errors.Is(err, platformrole.ErrAboveOwn):
		apierror.Forbidden("You can give or take only a role whose permissions you hold.").WriteJSON(w)
	case errors.Is(err, platformrole.ErrBaseRole):
		apierror.BadRequest("The owner, admin and read-only roles follow the administrator's role; change it on the administrator.").WriteJSON(w)
	case errors.Is(err, platformrole.ErrUnknownRole):
		apierror.BadRequest("Unknown platform role.").WriteJSON(w)
	case errors.Is(err, platformrole.ErrReason):
		apierror.BadRequest("Give a reason of 10 to 500 characters; it is kept in the audit log.").WriteJSON(w)
	case errors.Is(err, admin.ErrBreakGlassHasRoles):
		apierror.Conflict("A break-glass account holds its base platform role only.").WriteJSON(w)
	case errors.Is(err, platformrole.ErrInactive):
		apierror.Conflict("The administrator is not active.").WriteJSON(w)
	case admin.IsAdminNotFound(err):
		apierror.NotFound("Admin").WriteJSON(w)
	case errors.Is(err, platformrole.ErrAuditUnavailable):
		apierror.ServiceUnavailable("The audit log cannot be written; nothing was changed.").WriteJSON(w)
	default:
		h.log.Error("change platform role", "error", err)
		apierror.InternalServerError("could not change the platform role").WriteJSON(w)
	}
}

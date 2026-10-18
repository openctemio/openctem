package handler

// Console kill switches: suspend an organization, block an account
// (docs/architecture/organization-suspension.md).

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/openctemio/openctem/api/internal/app/orgdeletion"
	"github.com/openctemio/openctem/api/internal/app/platformuser"
	"github.com/openctemio/openctem/api/internal/app/suspension"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/apierror"
	"github.com/openctemio/openctem/api/pkg/domain/admin"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// AdminSuspensionHandler serves the console's suspend / lift (organizations)
// and block / unblock (accounts). Every action needs a reason and a fresh
// authenticator code (route step-up) and writes a critical admin audit row.
type AdminSuspensionHandler struct {
	orgs      *suspension.Service
	deletions *orgdeletion.Service
	users     *platformuser.Service
	logger    *logger.Logger
	// approvals is the four-eyes gate: deleting an organization before its
	// grace period ends needs a second super admin.
	approvals approvalGate
}

// WithApprovals wires the four-eyes gate.
func (h *AdminSuspensionHandler) WithApprovals(g approvalGate) *AdminSuspensionHandler {
	h.approvals = g
	return h
}

// NewAdminSuspensionHandler creates the handler. Either service may be nil;
// its actions then answer 503.
func NewAdminSuspensionHandler(orgs *suspension.Service, users *platformuser.Service, log *logger.Logger) *AdminSuspensionHandler {
	return &AdminSuspensionHandler{orgs: orgs, users: users, logger: log.With("handler", "admin_suspension")}
}

// AdminSuspensionRequest carries the administrator's reason (10 to 500
// characters), kept in the critical admin audit row. Organization members
// never see it.
type AdminSuspensionRequest struct {
	Reason string `json:"reason"`
}

// AdminSuspensionResponse is the state after the action.
type AdminSuspensionResponse struct {
	Status string `json:"status"`
}

func readSuspensionReason(w http.ResponseWriter, r *http.Request) (string, bool) {
	var req AdminSuspensionRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil {
		apierror.BadRequest("invalid request body").WriteJSON(w)
		return "", false
	}
	return req.Reason, true
}

func (h *AdminSuspensionHandler) writeError(w http.ResponseWriter, err error, what string) {
	switch {
	case errors.Is(err, shared.ErrValidation):
		apierror.BadRequest("Give a reason (10 to 500 characters); it is kept in the admin audit log.").WriteJSON(w)
	case errors.Is(err, shared.ErrNotFound):
		apierror.NotFound(what).WriteJSON(w)
	case errors.Is(err, shared.ErrConflict):
		msg := err.Error()
		if i := strings.Index(msg, ": "); i != -1 {
			msg = msg[i+2:]
		}
		apierror.Conflict(strings.ToUpper(msg[:1]) + msg[1:] + ".").WriteJSON(w)
	default:
		h.logger.Error("console suspension action", "resource", what, "error", err)
		apierror.InternalServerError("the action failed").WriteJSON(w)
	}
}

func (h *AdminSuspensionHandler) organization(w http.ResponseWriter, r *http.Request,
	run func(context.Context, *admin.AdminUser, shared.ID, string, suspension.Client) error, done string) {
	id, ok := orgIDParam(r)
	if !ok {
		apierror.BadRequest("invalid organization id").WriteJSON(w)
		return
	}
	reason, ok := readSuspensionReason(w, r)
	if !ok {
		return
	}
	actor := middleware.GetAdminUser(r.Context())
	if actor == nil {
		apierror.Unauthorized("Authentication required").WriteJSON(w)
		return
	}
	if err := run(r.Context(), actor, id, reason, suspension.Client{IP: middleware.ClientIP(r), UserAgent: r.UserAgent()}); err != nil {
		h.writeError(w, err, "organization")
		return
	}
	writeJSON(w, http.StatusOK, AdminSuspensionResponse{Status: done})
}

// SuspendOrganization handles POST /api/v1/admin/tenants/{tenantId}/suspend.
//
// @Summary      Suspend an organization (platform admin)
// @Description  From the next request on, every credential of the organization is refused (sessions, API keys, MCP tokens, sensor keys, SCIM tokens, CI run tokens, inbound webhooks) and its scheduled work is skipped. Nothing is deleted. ops_admin+, reason and step-up required; critical admin audit.
// @Tags         Admin Organizations
// @Accept       json
// @Produce      json
// @Param        tenantId  path  string                  true  "Organization ID"
// @Param        request   body  AdminSuspensionRequest  true  "Reason"
// @Success      200  {object}  AdminSuspensionResponse
// @Failure      400  {object}  apierror.Error
// @Failure      404  {object}  apierror.Error
// @Failure      409  {object}  apierror.Error "Already suspended, or the system organization"
// @Security     BearerAuth
// @Router       /admin/tenants/{tenantId}/suspend [post]
func (h *AdminSuspensionHandler) SuspendOrganization(w http.ResponseWriter, r *http.Request) {
	if h.orgs == nil {
		apierror.ServiceUnavailable("Organization suspension is not available").WriteJSON(w)
		return
	}
	h.organization(w, r, h.orgs.Suspend, "suspended")
}

// UnsuspendOrganization handles POST /api/v1/admin/tenants/{tenantId}/unsuspend.
//
// @Summary      Lift an organization's suspension (platform admin)
// @Description  Every credential of the organization works again as before. ops_admin+, reason and step-up required; critical admin audit.
// @Tags         Admin Organizations
// @Accept       json
// @Produce      json
// @Param        tenantId  path  string                  true  "Organization ID"
// @Param        request   body  AdminSuspensionRequest  true  "Reason"
// @Success      200  {object}  AdminSuspensionResponse
// @Failure      400  {object}  apierror.Error
// @Failure      404  {object}  apierror.Error
// @Failure      409  {object}  apierror.Error "Not suspended"
// @Security     BearerAuth
// @Router       /admin/tenants/{tenantId}/unsuspend [post]
func (h *AdminSuspensionHandler) UnsuspendOrganization(w http.ResponseWriter, r *http.Request) {
	if h.orgs == nil {
		apierror.ServiceUnavailable("Organization suspension is not available").WriteJSON(w)
		return
	}
	h.organization(w, r, h.orgs.Unsuspend, "active")
}

func (h *AdminSuspensionHandler) account(w http.ResponseWriter, r *http.Request,
	run func(context.Context, *admin.AdminUser, shared.ID, string, platformuser.Client) error, done string) {
	id, ok := platformUserID(w, r)
	if !ok {
		return
	}
	reason, ok := readSuspensionReason(w, r)
	if !ok {
		return
	}
	actor := middleware.GetAdminUser(r.Context())
	if actor == nil {
		apierror.Unauthorized("Authentication required").WriteJSON(w)
		return
	}
	if err := run(r.Context(), actor, id, reason, platformuser.Client{IP: middleware.ClientIP(r), UserAgent: r.UserAgent()}); err != nil {
		h.writeError(w, err, "user")
		return
	}
	writeJSON(w, http.StatusOK, AdminSuspensionResponse{Status: done})
}

// BlockUser handles POST /api/v1/admin/platform-users/{user_id}/block.
//
// @Summary      Block an account platform-wide (platform admin)
// @Description  The account cannot sign in to any organization; its sessions end and its API keys and MCP tokens stop working at once. Nothing it made is removed. Refused for platform administrator and erased accounts. ops_admin+, reason and step-up required; critical admin audit.
// @Tags         Admin
// @Accept       json
// @Produce      json
// @Param        user_id  path  string                  true  "User ID"
// @Param        request  body  AdminSuspensionRequest  true  "Reason"
// @Success      200  {object}  AdminSuspensionResponse
// @Failure      400  {object}  apierror.Error
// @Failure      404  {object}  apierror.Error
// @Failure      409  {object}  apierror.Error "Already blocked, a platform administrator, or erased"
// @Security     BearerAuth
// @Router       /admin/platform-users/{user_id}/block [post]
func (h *AdminSuspensionHandler) BlockUser(w http.ResponseWriter, r *http.Request) {
	if h.users == nil {
		apierror.ServiceUnavailable("Account actions are not available").WriteJSON(w)
		return
	}
	h.account(w, r, h.users.Block, "blocked")
}

// UnblockUser handles POST /api/v1/admin/platform-users/{user_id}/unblock.
//
// @Summary      Unblock an account (platform admin)
// @Description  The account may sign in again. ops_admin+, reason and step-up required; critical admin audit.
// @Tags         Admin
// @Accept       json
// @Produce      json
// @Param        user_id  path  string                  true  "User ID"
// @Param        request  body  AdminSuspensionRequest  true  "Reason"
// @Success      200  {object}  AdminSuspensionResponse
// @Failure      400  {object}  apierror.Error
// @Failure      404  {object}  apierror.Error
// @Failure      409  {object}  apierror.Error "Not blocked"
// @Security     BearerAuth
// @Router       /admin/platform-users/{user_id}/unblock [post]
func (h *AdminSuspensionHandler) UnblockUser(w http.ResponseWriter, r *http.Request) {
	if h.users == nil {
		apierror.ServiceUnavailable("Account actions are not available").WriteJSON(w)
		return
	}
	h.account(w, r, h.users.Unblock, "active")
}

// SetOrganizationDeletion wires the console's immediate deletion.
func (h *AdminSuspensionHandler) SetOrganizationDeletion(s *orgdeletion.Service) { h.deletions = s }

// PurgeOrganization handles POST /api/v1/admin/tenants/{tenantId}/purge.
//
// @Summary      Delete an organization now (platform admin)
// @Description  Deletes the organization and everything in it at once, whatever its status (active, suspended or waiting for its deletion). Member accounts are kept. super_admin, reason and a fresh step-up; critical admin audit. Cannot be undone.
// @Tags         Admin Organizations
// @Accept       json
// @Produce      json
// @Param        tenantId  path  string                  true  "Organization ID"
// @Param        request   body  AdminSuspensionRequest  true  "Reason"
// @Success      200  {object}  AdminSuspensionResponse
// @Failure      400  {object}  apierror.Error
// @Failure      404  {object}  apierror.Error
// @Failure      409  {object}  apierror.Error "The system organization"
// @Failure      428  {object}  apierror.Error "SECOND_APPROVAL_REQUIRED: another super admin must approve first"
// @Security     BearerAuth
// @Router       /admin/tenants/{tenantId}/purge [post]
func (h *AdminSuspensionHandler) PurgeOrganization(w http.ResponseWriter, r *http.Request) {
	if h.deletions == nil {
		apierror.ServiceUnavailable("Organization deletion is not available").WriteJSON(w)
		return
	}
	id, ok := orgIDParam(r)
	if !ok {
		apierror.BadRequest("invalid organization id").WriteJSON(w)
		return
	}
	reason, ok := readSuspensionReason(w, r)
	if !ok {
		return
	}
	actor := middleware.GetAdminUser(r.Context())
	if actor == nil {
		apierror.Unauthorized("Authentication required").WriteJSON(w)
		return
	}
	// A second super admin approves the deletion of this organization; checked
	// before anything is deleted, handed back when nothing was.
	grant, ok := requireSecondApproval(w, r, h.approvals, actor, admin.ApprovalOrgPurge, "tenant:"+id.String(), h.logger)
	if !ok {
		return
	}
	err := h.deletions.PurgeNow(r.Context(), actor, id, reason, orgdeletion.Client{IP: middleware.ClientIP(r), UserAgent: r.UserAgent()})
	if err != nil {
		releaseSecondApproval(r, h.approvals, actor, grant)
	}
	switch {
	case err == nil:
		writeJSON(w, http.StatusOK, AdminSuspensionResponse{Status: "deleted"})
	case errors.Is(err, orgdeletion.ErrSystemOrganization):
		apierror.Conflict("The system organization cannot be deleted.").WriteJSON(w)
	default:
		h.writeError(w, err, "organization")
	}
}

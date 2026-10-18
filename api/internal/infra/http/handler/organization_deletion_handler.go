package handler

// Organization deletion with a grace period
// (docs/architecture/organization-deletion.md).

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/internal/app/orgdeletion"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/apierror"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// OrganizationDeletionResponse is the state of an organization after a
// deletion request or its cancellation.
type OrganizationDeletionResponse struct {
	// Status is pending_deletion after a request, active after a cancel.
	Status string `json:"status"`
	// DeletionDueAt is when the organization will be deleted (after a request).
	DeletionDueAt *time.Time `json:"deletion_due_at,omitempty"`
}

// SetDeletionScheduler wires the deletion grace period: DELETE schedules the
// deletion instead of deleting at once.
func (h *TenantHandler) SetDeletionScheduler(s *orgdeletion.Service) { h.deletions = s }

// SetOrganizationDeletion wires the owner's cancel on the sign-in path.
func (h *LocalAuthHandler) SetOrganizationDeletion(s *orgdeletion.Service) { h.deletions = s }

func writeDeletionError(w http.ResponseWriter, err error, log interface {
	Error(msg string, args ...any)
}) {
	switch {
	case errors.Is(err, orgdeletion.ErrNotOwner):
		apierror.Forbidden("Only an owner of the organization can do this.").WriteJSON(w)
	case errors.Is(err, orgdeletion.ErrNotActive):
		apierror.Conflict("The organization is not active: it is already scheduled for deletion or suspended.").WriteJSON(w)
	case errors.Is(err, orgdeletion.ErrNotPending):
		apierror.Conflict("The organization is not scheduled for deletion.").WriteJSON(w)
	case errors.Is(err, orgdeletion.ErrSystemOrganization):
		apierror.Conflict("The system organization cannot be deleted.").WriteJSON(w)
	case errors.Is(err, shared.ErrNotFound):
		apierror.NotFound("organization").WriteJSON(w)
	default:
		log.Error("organization deletion", "error", err)
		apierror.InternalServerError("the action failed").WriteJSON(w)
	}
}

// CancelOrganizationDeletionRequest names the organization whose scheduled
// deletion an owner cancels. The refresh token may come from the body or the
// refresh_token cookie (with the CSRF pair).
type CancelOrganizationDeletionRequest struct {
	TenantID     string `json:"tenant_id"`
	RefreshToken string `json:"refresh_token,omitempty"`
}

// CancelOrganizationDeletion handles POST /api/v1/auth/organization-deletion/cancel.
//
// An organization waiting for deletion is refused to every credential, so no
// tenant token can reach it; an owner cancels from the sign-in page with the
// session's refresh token, like the first-team and onboarding steps. The
// owner is checked against the database; anyone else gets the same 403
// whether or not the organization exists.
//
// @Summary      Cancel an organization's scheduled deletion (owner)
// @Tags         Authentication
// @Accept       json
// @Produce      json
// @Param        request  body  CancelOrganizationDeletionRequest  true  "Organization"
// @Success      200  {object}  OrganizationDeletionResponse
// @Failure      401  {object}  apierror.Error
// @Failure      403  {object}  apierror.Error "Not an owner"
// @Failure      409  {object}  apierror.Error "Not scheduled for deletion"
// @Router       /auth/organization-deletion/cancel [post]
func (h *LocalAuthHandler) CancelOrganizationDeletion(w http.ResponseWriter, r *http.Request) {
	if h.deletions == nil {
		apierror.ServiceUnavailable("Organization deletion is not available").WriteJSON(w)
		return
	}
	var req CancelOrganizationDeletionRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil {
		apierror.BadRequest("invalid request body").WriteJSON(w)
		return
	}
	tenantID, err := shared.IDFromString(req.TenantID)
	if err != nil {
		apierror.BadRequest("tenant_id is required").WriteJSON(w)
		return
	}
	refreshToken, ok := h.refreshTokenFrom(w, r, req.RefreshToken)
	if !ok {
		return
	}
	if refreshToken == "" {
		apierror.Unauthorized("refresh_token is required (in body or cookie)").WriteJSON(w)
		return
	}
	ident, err := h.authService.IdentifyRefreshSession(r.Context(), refreshToken)
	if err != nil || ident == nil || ident.User == nil || !ident.User.IsActive() {
		apierror.Unauthorized("Authentication required").WriteJSON(w)
		return
	}
	actx := auditapp.AuditContext{
		ActorID: ident.User.ID().String(), ActorEmail: ident.User.Email(),
		ActorIP: middleware.ClientIP(r), UserAgent: r.UserAgent(), RequestID: r.Header.Get("X-Request-ID"),
	}
	if err := h.deletions.Cancel(r.Context(), actx, tenantID, ident.User.ID()); err != nil {
		writeDeletionError(w, err, h.logger)
		return
	}
	writeJSON(w, http.StatusOK, OrganizationDeletionResponse{Status: "active"})
}

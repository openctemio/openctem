package handler

// The invitee's side of ownership invitations
// (docs/architecture/organization-ownership-invitations.md): list, accept,
// decline. The account comes from the session only; an invitation is found
// by its id AND the caller's account id, so another account's invitation
// answers 404 whatever the caller knows about it.

import (
	"context"
	"errors"
	"net/http"
	"time"

	auditapp "github.com/openctemio/openctem/server/internal/app/audit"
	authapp "github.com/openctemio/openctem/server/internal/app/auth"
	tenantapp "github.com/openctemio/openctem/server/internal/app/tenant"
	"github.com/openctemio/openctem/server/internal/infra/http/middleware"
	"github.com/openctemio/openctem/server/pkg/apierror"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
	tenantdom "github.com/openctemio/openctem/server/pkg/domain/tenant"
	userdom "github.com/openctemio/openctem/server/pkg/domain/user"
)

// OwnerInvitationOfferResponse is an organization the caller is invited to
// own.
type OwnerInvitationOfferResponse struct {
	ID               string    `json:"id"`
	OrganizationID   string    `json:"organization_id"`
	OrganizationName string    `json:"organization_name"`
	OrganizationSlug string    `json:"organization_slug"`
	InvitedAt        time.Time `json:"invited_at"`
	ExpiresAt        time.Time `json:"expires_at"`
}

// OwnerInvitationListResponse lists the caller's open ownership invitations.
type OwnerInvitationListResponse struct {
	Data []OwnerInvitationOfferResponse `json:"data"`
}

// OwnerInvitationAcceptResponse names the organization the caller now owns.
type OwnerInvitationAcceptResponse struct {
	OrganizationID string `json:"organization_id"`
}

func (h *UserHandler) ownerInvitationActor(w http.ResponseWriter, r *http.Request) (*userdom.User, auditapp.AuditContext, bool) {
	u := middleware.GetLocalUser(r.Context())
	if u == nil {
		apierror.Unauthorized("User not found").WriteJSON(w)
		return nil, auditapp.AuditContext{}, false
	}
	return u, auditapp.AuditContext{ActorID: u.ID().String(), ActorEmail: u.Email(), ActorIP: getClientIP(r),
		UserAgent: r.UserAgent(), RequestID: middleware.GetRequestID(r.Context())}, true
}

func ownerInvitationIDParam(w http.ResponseWriter, r *http.Request) (shared.ID, bool) {
	id, err := shared.IDFromString(r.PathValue("id"))
	if err != nil {
		// Same answer as an unknown invitation.
		apierror.NotFound("invitation").WriteJSON(w)
		return id, false
	}
	return id, true
}

// writeInviteeError maps the invitee-side errors. Every "not yours / used /
// gone" case is the same 404.
func (h *UserHandler) writeInviteeError(w http.ResponseWriter, err error) {
	switch {
	case middleware.WriteStepUpError(w, err, authapp.StepUpWindow):
	case errors.Is(err, tenantdom.ErrOwnerInvitationNotFound):
		apierror.NotFound("invitation").WriteJSON(w)
	case errors.Is(err, tenantdom.ErrOwnerInvitationExpired):
		apierror.BadRequest("This invitation has expired. Ask the platform administrator to send it again.").WriteJSON(w)
	case errors.Is(err, tenantdom.ErrOwnerInviteeEmailUnverified):
		apierror.BadRequest("Verify your email address before accepting.").WriteJSON(w)
	case errors.Is(err, tenantdom.ErrOwnerInviteeNotEligible):
		apierror.Forbidden("This account cannot own an organization.").WriteJSON(w)
	case errors.Is(err, tenantdom.ErrBreakGlassMembership):
		apierror.Forbidden("A break-glass administrator account cannot own an organization.").WriteJSON(w)
	case errors.Is(err, tenantapp.ErrOwnerInvitationsUnavailable):
		apierror.ServiceUnavailable("Ownership invitations are not available").WriteJSON(w)
	default:
		h.logger.Error("ownership invitation", "error", sanitizeLogField(err.Error()))
		apierror.InternalServerError("could not complete the request").WriteJSON(w)
	}
}

// ListMyOwnerInvitations handles GET /api/v1/me/ownership-invitations.
// @Summary      My ownership invitations
// @Description  Organizations a platform administrator created for the caller, waiting for the caller to accept ownership. Only open invitations bound to the caller's own account.
// @Tags         Users
// @Produce      json
// @Success      200  {object}  OwnerInvitationListResponse
// @Router       /me/ownership-invitations [get]
func (h *UserHandler) ListMyOwnerInvitations(w http.ResponseWriter, r *http.Request) {
	u, _, ok := h.ownerInvitationActor(w, r)
	if !ok {
		return
	}
	resp, err := h.MyOwnerInvitationsResponse(r.Context(), u.ID())
	if err != nil {
		h.writeInviteeError(w, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, resp)
}

// MyOwnerInvitationsResponse is the GET /me/ownership-invitations body for
// userID (also carried by the session bootstrap, so the app shell's banner
// needs no request of its own).
func (h *UserHandler) MyOwnerInvitationsResponse(ctx context.Context, userID shared.ID) (*OwnerInvitationListResponse, error) {
	offers, err := h.tenantService.ListMyOwnerInvitations(ctx, userID)
	if err != nil {
		return nil, err
	}
	resp := &OwnerInvitationListResponse{Data: make([]OwnerInvitationOfferResponse, 0, len(offers))}
	for _, o := range offers {
		resp.Data = append(resp.Data, OwnerInvitationOfferResponse{
			ID: o.ID.String(), OrganizationID: o.TenantID.String(), OrganizationName: o.OrganizationName,
			OrganizationSlug: o.OrganizationSlug, InvitedAt: o.CreatedAt, ExpiresAt: o.ExpiresAt,
		})
	}
	return resp, nil
}

// AcceptOwnerInvitation handles POST /api/v1/me/ownership-invitations/{id}/accept.
// @Summary      Accept an ownership invitation
// @Description  Step-up. Makes the caller the owner of the organization. Only the invited account can accept (404 for anyone else, and for a used or canceled invitation); 400 when it expired or until the caller's email address is verified.
// @Tags         Users
// @Produce      json
// @Param        id            path  string  true  "Invitation ID"
// @Success      200  {object}  OwnerInvitationAcceptResponse
// @Failure      404  {object}  apierror.Error
// @Failure      400  {object}  apierror.Error
// @Router       /me/ownership-invitations/{id}/accept [post]
func (h *UserHandler) AcceptOwnerInvitation(w http.ResponseWriter, r *http.Request) {
	u, actx, ok := h.ownerInvitationActor(w, r)
	if !ok {
		return
	}
	id, ok := ownerInvitationIDParam(w, r)
	if !ok {
		return
	}
	inv, err := h.tenantService.AcceptOwnerInvitation(r.Context(), id, u, actx)
	if err != nil {
		h.writeInviteeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, OwnerInvitationAcceptResponse{OrganizationID: inv.TenantID.String()})
}

// DeclineOwnerInvitation handles POST /api/v1/me/ownership-invitations/{id}/decline.
// @Summary      Decline an ownership invitation
// @Description  Only the invited account can decline (404 for anyone else). The organization stays without an owner for the platform administrator to decide.
// @Tags         Users
// @Param        id            path  string  true  "Invitation ID"
// @Success      204
// @Failure      404  {object}  apierror.Error
// @Router       /me/ownership-invitations/{id}/decline [post]
func (h *UserHandler) DeclineOwnerInvitation(w http.ResponseWriter, r *http.Request) {
	u, actx, ok := h.ownerInvitationActor(w, r)
	if !ok {
		return
	}
	id, ok := ownerInvitationIDParam(w, r)
	if !ok {
		return
	}
	if err := h.tenantService.DeclineOwnerInvitation(r.Context(), id, u, actx); err != nil {
		h.writeInviteeError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

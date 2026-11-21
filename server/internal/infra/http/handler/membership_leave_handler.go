package handler

// Leaving an organization from the account space:
// docs/architecture/tenantless-account-space.md ("Memberships").

import (
	"errors"
	"net/http"

	tenantapp "github.com/openctemio/openctem/server/internal/app/tenant"
	"github.com/openctemio/openctem/server/pkg/apierror"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
)

// LeaveMembership takes the caller out of one of their organizations, by its
// id, with the account token: the way out of an organization the person
// cannot open (two-factor authentication not set up, its own sign-in
// required, suspended), where POST /organization/leave (which needs that
// organization's token) is out of reach. The organization is the path's, the
// person is the token's: only the caller's own membership is ever touched,
// and any other id answers the same 404 as a membership that does not exist.
// @Summary      Leave one of my organizations
// @Description  Account route (account or organization token). The same offboarding as leaving from inside the organization (keys revoked, access removed, history kept, audited in that organization). Step-up. 404 when the caller is not a member; 409 for the only owner (transfer ownership or delete the organization first) and for someone who still owns work an administrator must reassign.
// @Tags         Users
// @Param        id        path  string  true  "Organization ID"
// @Success      204
// @Failure      404  {object}  apierror.Error
// @Failure      409  {object}  apierror.Error
// @Router       /me/memberships/{id}/leave [post]
func (h *UserHandler) LeaveMembership(w http.ResponseWriter, r *http.Request) {
	u, actx, ok := h.ownerInvitationActor(w, r)
	if !ok {
		return
	}
	tenantID, err := shared.IDFromString(r.PathValue("id"))
	if err != nil {
		apierror.NotFound("Membership not found").WriteJSON(w)
		return
	}
	err = h.tenantService.LeaveOrganization(r.Context(), tenantID, u.ID(), actx)
	switch {
	case err == nil:
		w.WriteHeader(http.StatusNoContent)
	case errors.Is(err, tenantapp.ErrSoleOwnerCannotLeave):
		apierror.Conflict("You are the only owner. Transfer ownership or delete the organization first.").WriteJSON(w)
	case errors.Is(err, tenantapp.ErrLeaveNeedsReassignment):
		apierror.Conflict("You still own work in this organization. Ask an administrator to offboard you.").WriteJSON(w)
	case errors.Is(err, shared.ErrNotFound):
		apierror.NotFound("Membership not found").WriteJSON(w)
	default:
		h.logger.Error("leave organization from the account space", "error", err)
		apierror.InternalServerError("could not leave the organization").WriteJSON(w)
	}
}

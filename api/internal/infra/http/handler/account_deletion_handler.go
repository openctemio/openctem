package handler

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/openctemio/openctem/api/internal/app/accountdeletion"
	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	tenantapp "github.com/openctemio/openctem/api/internal/app/tenant"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/apierror"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Self-service account deletion and leaving an organization
// (docs/rfcs/RFC-104). Both act on the caller only: the account comes from
// the session, the organization from the credential.

// SetAccountDeletion wires self-service account deletion.
func (h *UserHandler) SetAccountDeletion(svc *accountdeletion.Service) { h.accountDeletion = svc }

// AccountDeletionResponse says when the account will be erased.
type AccountDeletionResponse struct {
	// Scheduled: a deletion is pending.
	Scheduled bool `json:"scheduled"`
	// EraseAfter: when the account's personal data is erased. Signing in
	// before then cancels the deletion.
	EraseAfter string `json:"erase_after,omitempty"`
}

// CodeSoleOwner is the error code of a deletion refused because the person
// is the only owner of one or more organizations.
const CodeSoleOwner apierror.Code = "SOLE_OWNER"

// DeleteMe schedules the deletion of the caller's account.
// @Summary      Delete my account
// @Description  Step-up. Ends every session and revokes the account's API keys at once; signing in again within 14 days cancels; afterwards the account leaves every organization and its personal data is erased. Refused (409 SOLE_OWNER, listing the organizations) while the caller is the only owner of an organization.
// @Tags         Users
// @Produce      json
// @Success      202  {object}  AccountDeletionResponse
// @Router       /me/account [delete]
func (h *UserHandler) DeleteMe(w http.ResponseWriter, r *http.Request) {
	u := middleware.GetLocalUser(r.Context())
	if u == nil {
		apierror.Unauthorized("User not found").WriteJSON(w)
		return
	}
	if h.accountDeletion == nil {
		apierror.ServiceUnavailable("Account deletion is not available").WriteJSON(w)
		return
	}
	actx := auditapp.AuditContext{ActorID: u.ID().String(), ActorEmail: u.Email(), ActorIP: getClientIP(r),
		UserAgent: r.UserAgent(), RequestID: r.Header.Get("X-Request-ID")}
	eraseAfter, err := h.accountDeletion.Request(r.Context(), u.ID(), actx)
	var sole *accountdeletion.SoleOwnerError
	switch {
	case err == nil:
	case errors.As(err, &sole):
		apierror.New(http.StatusConflict, CodeSoleOwner,
			"You are the only owner of an organization. Transfer ownership or delete the organization first.").
			WithDetails(map[string]any{"organizations": sole.Organizations}).WriteJSON(w)
		return
	case errors.Is(err, accountdeletion.ErrPlatformAdmin):
		apierror.Forbidden("A platform administrator account is removed in the admin console").WriteJSON(w)
		return
	default:
		h.logger.Error("schedule account deletion", "error", err)
		apierror.InternalServerError("could not schedule the deletion").WriteJSON(w)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	_ = json.NewEncoder(w).Encode(AccountDeletionResponse{Scheduled: true, EraseAfter: eraseAfter.UTC().Format(time.RFC3339)})
}

// GetMyDeletion says whether the caller's account is scheduled for deletion.
// @Summary      My account deletion
// @Tags         Users
// @Produce      json
// @Success      200  {object}  AccountDeletionResponse
// @Router       /me/account/deletion [get]
func (h *UserHandler) GetMyDeletion(w http.ResponseWriter, r *http.Request) {
	u := middleware.GetLocalUser(r.Context())
	if u == nil {
		apierror.Unauthorized("User not found").WriteJSON(w)
		return
	}
	resp := AccountDeletionResponse{}
	if h.accountDeletion != nil {
		if t, err := h.accountDeletion.Status(r.Context(), u.ID()); err == nil {
			resp = AccountDeletionResponse{Scheduled: true, EraseAfter: t.UTC().Format(time.RFC3339)}
		} else if !errors.Is(err, accountdeletion.ErrNotScheduled) {
			h.logger.Error("read account deletion", "error", err)
			apierror.InternalServerError("could not read the deletion").WriteJSON(w)
			return
		}
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

// LeaveOrganization takes the caller out of the organization of their
// credential.
// @Summary      Leave this organization
// @Description  Any member. The same offboarding an administrator runs (keys revoked, access removed, history kept). Refused for the only owner, and for someone who still owns work an administrator must reassign (409).
// @Tags         Tenants
// @Success      204
// @Router       /organization/leave [post]
func (h *TenantHandler) LeaveOrganization(w http.ResponseWriter, r *http.Request) {
	actx := h.tokenTenantAuditContext(r)
	tenantID, terr := shared.IDFromString(actx.TenantID)
	userID, uerr := shared.IDFromString(actx.ActorID)
	if terr != nil || uerr != nil {
		apierror.Unauthorized("Authentication required").WriteJSON(w)
		return
	}
	err := h.service.LeaveOrganization(r.Context(), tenantID, userID, actx)
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
		h.logger.Error("leave organization", "error", err)
		apierror.InternalServerError("could not leave the organization").WriteJSON(w)
	}
}

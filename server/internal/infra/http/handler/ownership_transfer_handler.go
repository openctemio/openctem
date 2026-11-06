package handler

// Ownership transfer endpoints. Design:
// docs/rfcs/RFC-095-role-templates-and-invitations.md.
//
// Authorization: the routes are on the token-tenant chain under
// /api/v1/organization (the tenant comes from the credential, never the
// path). Starting and canceling need the owner (route gate and service);
// starting and accepting need a recent re-authentication. Reading, accepting
// and declining are open to any member at the route, and the service answers
// 404 unless the caller is the owner or the person asked.

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	tenantapp "github.com/openctemio/openctem/api/internal/app/tenant"
	"github.com/openctemio/openctem/api/pkg/apierror"
	"github.com/openctemio/openctem/api/pkg/domain/tenant"
)

// StartOwnershipTransferRequest asks a member to take ownership.
type StartOwnershipTransferRequest struct {
	// Membership id of the new owner.
	MemberID string `json:"member_id" example:"01929c4e-0000-7000-8000-000000000001"`
	// What the current owner becomes when the transfer is accepted: admin (default), member or viewer.
	PreviousOwnerRole string `json:"previous_owner_role,omitempty" example:"admin"`
	// Confirms that an outside member becomes an internal member on acceptance.
	ConfirmInternal bool `json:"confirm_internal,omitempty"`
}

// ownershipTransferErrorCode maps a transfer error to its stable code.
func ownershipTransferErrorCode(err error) (string, int, bool) {
	switch {
	case errors.Is(err, tenant.ErrOwnershipTransferNotOwner):
		return "OWNERSHIP_NOT_OWNER", http.StatusForbidden, true
	case errors.Is(err, tenant.ErrOwnershipTransferPending):
		return "OWNERSHIP_TRANSFER_PENDING", http.StatusConflict, true
	case errors.Is(err, tenant.ErrOwnershipTransferNotFound):
		return "OWNERSHIP_TRANSFER_NOT_FOUND", http.StatusNotFound, true
	case errors.Is(err, tenant.ErrOwnershipTransferExpired):
		return "OWNERSHIP_TRANSFER_EXPIRED", http.StatusGone, true
	case errors.Is(err, tenant.ErrOwnershipTransferStale):
		return "OWNERSHIP_TRANSFER_VOID", http.StatusConflict, true
	case errors.Is(err, tenant.ErrOwnershipTargetSelf):
		return "OWNERSHIP_TARGET_SELF", http.StatusBadRequest, true
	case errors.Is(err, tenant.ErrOwnershipTargetInactive):
		return "OWNERSHIP_TARGET_INACTIVE", http.StatusBadRequest, true
	case errors.Is(err, tenant.ErrOwnershipTargetService):
		return "OWNERSHIP_TARGET_SERVICE_ACCOUNT", http.StatusBadRequest, true
	case errors.Is(err, tenant.ErrOwnershipTargetNoMFA):
		return "OWNERSHIP_TARGET_NEEDS_MFA", http.StatusBadRequest, true
	case errors.Is(err, tenant.ErrOwnershipTargetManaged):
		return "OWNERSHIP_TARGET_MANAGED", http.StatusBadRequest, true
	case errors.Is(err, tenant.ErrOwnershipTargetNeedsInternal):
		return "OWNERSHIP_TARGET_NEEDS_CONFIRMATION", http.StatusBadRequest, true
	case errors.Is(err, tenant.ErrOwnershipPreviousRole):
		return "OWNERSHIP_PREVIOUS_ROLE_INVALID", http.StatusBadRequest, true
	}
	return "", 0, false
}

func (h *TenantHandler) writeOwnershipError(w http.ResponseWriter, err error) {
	if code, status, ok := ownershipTransferErrorCode(err); ok {
		apierror.New(status, apierror.Code(code), trimSentinelPrefix(err.Error())).WriteJSON(w)
		return
	}
	h.writeLifecycleError(w, err)
}

// trimSentinelPrefix drops the generic "<kind>: " prefix of a wrapped error.
func trimSentinelPrefix(msg string) string {
	if _, rest, ok := strings.Cut(msg, ": "); ok {
		return rest
	}
	return msg
}

func (h *TenantHandler) writeOwnershipTransfer(w http.ResponseWriter, status int, v *tenantapp.OwnershipTransferView) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// GetOwnershipTransfer returns the pending ownership transfer.
// @Summary      Pending ownership transfer
// @Description  The open request, when the caller is the owner who asked or the member asked; JSON null when there is none the caller may see (also for everyone else).
// @Tags         Tenants
// @Produce      json
// @Success      200  {object}  tenantapp.OwnershipTransferView
// @Security     BearerAuth
// @Router       /organization/ownership-transfer [get]
func (h *TenantHandler) GetOwnershipTransfer(w http.ResponseWriter, r *http.Request) {
	actx := h.tokenTenantAuditContext(r)
	v, err := h.service.PendingOwnershipTransfer(r.Context(), actx)
	h.writePendingOwnershipTransfer(w, v, err)
}

// writePendingOwnershipTransfer answers the pending-transfer read. No pending
// transfer is not an error for this read: it answers 200 with JSON null, so a
// page that polls it does not log a failed request.
func (h *TenantHandler) writePendingOwnershipTransfer(w http.ResponseWriter, v *tenantapp.OwnershipTransferView, err error) {
	if errors.Is(err, tenant.ErrOwnershipTransferNotFound) {
		h.writeOwnershipTransfer(w, http.StatusOK, nil)
		return
	}
	if err != nil {
		h.writeOwnershipError(w, err)
		return
	}
	h.writeOwnershipTransfer(w, http.StatusOK, v)
}

// StartOwnershipTransfer asks a member to take ownership.
// @Summary      Start an ownership transfer
// @Description  Owner only, with a recent re-authentication. The new owner must be an active member with two-factor authentication on, not a service account and not managed by another organization; an outside member becomes internal on acceptance (confirm_internal). The member accepts within 72 hours.
// @Tags         Tenants
// @Accept       json
// @Produce      json
// @Param        body  body  StartOwnershipTransferRequest  true  "Transfer"
// @Success      201  {object}  tenantapp.OwnershipTransferView
// @Failure      400  {object}  apierror.Error
// @Failure      403  {object}  apierror.Error
// @Failure      404  {object}  apierror.Error
// @Failure      409  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /organization/ownership-transfer [post]
func (h *TenantHandler) StartOwnershipTransfer(w http.ResponseWriter, r *http.Request) {
	var req StartOwnershipTransferRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<10)).Decode(&req); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}
	actx := h.tokenTenantAuditContext(r)
	if actx.ActorID == "" || actx.TenantID == "" {
		apierror.Unauthorized("Authentication required").WriteJSON(w)
		return
	}
	v, err := h.service.StartOwnershipTransfer(r.Context(), tenantapp.StartOwnershipTransferInput{
		MembershipID:      req.MemberID,
		PreviousOwnerRole: req.PreviousOwnerRole,
		ConfirmInternal:   req.ConfirmInternal,
	}, actx)
	if err != nil {
		h.writeOwnershipError(w, err)
		return
	}
	h.writeOwnershipTransfer(w, http.StatusCreated, v)
}

// CancelOwnershipTransfer withdraws the pending transfer.
// @Summary      Cancel the ownership transfer
// @Description  Owner only. Withdraws the open request; the member is told by email.
// @Tags         Tenants
// @Success      204
// @Failure      403  {object}  apierror.Error
// @Failure      404  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /organization/ownership-transfer [delete]
func (h *TenantHandler) CancelOwnershipTransfer(w http.ResponseWriter, r *http.Request) {
	if err := h.service.CancelOwnershipTransfer(r.Context(), h.tokenTenantAuditContext(r)); err != nil {
		h.writeOwnershipError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// AcceptOwnershipTransfer makes the caller the owner.
// @Summary      Accept the ownership transfer
// @Description  The member asked only, with a recent re-authentication. The caller becomes the owner and the previous owner takes the role they chose, in one transaction.
// @Tags         Tenants
// @Produce      json
// @Success      200  {object}  tenantapp.OwnershipTransferView
// @Failure      400  {object}  apierror.Error
// @Failure      404  {object}  apierror.Error
// @Failure      409  {object}  apierror.Error
// @Failure      410  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /organization/ownership-transfer/approve [post]
func (h *TenantHandler) AcceptOwnershipTransfer(w http.ResponseWriter, r *http.Request) {
	v, err := h.service.AcceptOwnershipTransfer(r.Context(), h.tokenTenantAuditContext(r))
	if err != nil {
		h.writeOwnershipError(w, err)
		return
	}
	h.writeOwnershipTransfer(w, http.StatusOK, v)
}

// DeclineOwnershipTransfer refuses the pending transfer.
// @Summary      Decline the ownership transfer
// @Description  The member asked only. The owner is told by email.
// @Tags         Tenants
// @Success      204
// @Failure      404  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /organization/ownership-transfer/reject [post]
func (h *TenantHandler) DeclineOwnershipTransfer(w http.ResponseWriter, r *http.Request) {
	if err := h.service.DeclineOwnershipTransfer(r.Context(), h.tokenTenantAuditContext(r)); err != nil {
		h.writeOwnershipError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

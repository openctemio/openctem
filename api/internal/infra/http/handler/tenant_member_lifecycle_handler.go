package handler

// Member lifecycle endpoints: access report, offboard, erase personal data.
// Design: docs/rfcs/RFC-050-asset-access-model.md.
//
// Authorization: the routes are on the token-tenant chain under
// /api/v1/organization (the tenant comes from the credential, never the path;
// active membership, permission sync, CSRF), owner/admin only (erase: owner
// only). The service loads the target membership within the caller's tenant
// (404 otherwise) and applies the peer-administrator rule.

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/openctemio/openctem/api/internal/app"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/apierror"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/tenant"
)

// OffboardMemberRequest names who takes over the member's work. Every
// category the member owns something in must be covered.
type OffboardMemberRequest struct {
	// New owner of the member's scans, report schedules and workflows.
	SchedulesTo string `json:"schedules_to,omitempty" example:"01929c4e-0000-7000-8000-000000000001"`
	// New assignee of the member's open findings.
	FindingsTo string `json:"findings_to,omitempty"`
	// Put the open findings back in the queue instead (when findings_to is empty).
	UnassignFindings bool `json:"unassign_findings,omitempty"`
	// New owner of the assets the member owns.
	AssetsTo string `json:"assets_to,omitempty"`
}

// tokenTenantAuditContext is buildAuditContext for the token-tenant chain:
// the tenant comes from the credential.
func (h *TenantHandler) tokenTenantAuditContext(r *http.Request) app.AuditContext {
	actx := h.buildAuditContext(r)
	actx.TenantID = middleware.GetTenantID(r.Context())
	return actx
}

// writeLifecycleError maps the lifecycle errors that carry structured
// details, then defers to the generic mapping.
func (h *TenantHandler) writeLifecycleError(w http.ResponseWriter, err error) {
	if re, ok := tenant.AsReassignmentError(err); ok {
		apierror.Conflict("Reassign the member's schedules, findings and assets before offboarding").
			WithDetails(map[string]any{"code": "reassignment_required", "missing": re.Missing}).
			WriteJSON(w)
		return
	}
	if errors.Is(err, tenant.ErrInvalidReassignTarget) {
		apierror.BadRequest("The new owner must be another active member of the organization").WriteJSON(w)
		return
	}
	if errors.Is(err, shared.ErrNotFound) {
		apierror.NotFound("Member").WriteJSON(w)
		return
	}
	h.handleServiceError(w, err)
}

// GetMemberAccessReport lists what a member holds and owns.
// @Summary      Member access report
// @Description  Everything the member holds in the organization (roles, access groups, API keys, pentest engagements, direct grants, visible assets) and owns (scans, report schedules, workflows, open assigned findings, assets). Drives the offboarding wizard. Owner or administrator.
// @Tags         Tenants
// @Produce      json
// @Param        member_id  path  string  true  "Membership ID"
// @Success      200  {object}  tenant.AccessReport
// @Failure      403  {object}  apierror.Error
// @Failure      404  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /organization/members/{member_id}/access-report [get]
func (h *TenantHandler) GetMemberAccessReport(w http.ResponseWriter, r *http.Request) {
	memberID := chi.URLParam(r, "member_id")
	if memberID == "" {
		apierror.BadRequest("Member ID is required").WriteJSON(w)
		return
	}
	report, err := h.service.GetMemberAccessReport(r.Context(), memberID, h.tokenTenantAuditContext(r))
	if err != nil {
		h.writeLifecycleError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(report)
}

// OffboardMember permanently removes a member's access.
// @Summary      Offboard a member
// @Description  Reassigns the member's owned work (mandatory for every category they own something in) to another active member, revokes their API keys, removes their access groups, grants, engagements, roles and invitations, and keeps the membership as a tombstone so history stays valid. A later invitation starts from zero. 409 reassignment_required lists the categories still without a new owner. Owner or administrator; only the owner offboards an administrator.
// @Tags         Tenants
// @Accept       json
// @Produce      json
// @Param        member_id  path  string                 true   "Membership ID"
// @Param        body       body  OffboardMemberRequest  false  "Who takes over the member's work"
// @Success      200  {object}  tenant.OffboardResult
// @Failure      400  {object}  apierror.Error
// @Failure      403  {object}  apierror.Error
// @Failure      404  {object}  apierror.Error
// @Failure      409  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /organization/members/{member_id}/offboard [post]
func (h *TenantHandler) OffboardMember(w http.ResponseWriter, r *http.Request) {
	memberID := chi.URLParam(r, "member_id")
	if memberID == "" {
		apierror.BadRequest("Member ID is required").WriteJSON(w)
		return
	}
	var req OffboardMemberRequest
	if r.ContentLength != 0 {
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10)).Decode(&req); err != nil {
			apierror.BadRequest("Invalid request body").WriteJSON(w)
			return
		}
	}
	actx := h.tokenTenantAuditContext(r)
	if actx.ActorID == "" || actx.TenantID == "" {
		apierror.Unauthorized("Authentication required").WriteJSON(w)
		return
	}
	result, err := h.service.OffboardMember(r.Context(), memberID, app.OffboardMemberInput{
		SchedulesTo:      req.SchedulesTo,
		FindingsTo:       req.FindingsTo,
		UnassignFindings: req.UnassignFindings,
		AssetsTo:         req.AssetsTo,
	}, actx)
	if err != nil {
		h.writeLifecycleError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(result)
}

// EraseMemberPersonalData anonymises an offboarded person.
// @Summary      Erase an offboarded member's personal data
// @Description  Owner only, after offboarding, and only when the person belongs to no other organization: the name becomes "Deleted user #<hash>", the email a non-deliverable placeholder, and credentials, second factor and federated identity are cleared. Rows and foreign keys stay, so history shows the placeholder.
// @Tags         Tenants
// @Param        member_id  path  string  true  "Membership ID"
// @Success      204
// @Failure      403  {object}  apierror.Error
// @Failure      404  {object}  apierror.Error
// @Failure      409  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /organization/members/{member_id}/erase [post]
func (h *TenantHandler) EraseMemberPersonalData(w http.ResponseWriter, r *http.Request) {
	memberID := chi.URLParam(r, "member_id")
	if memberID == "" {
		apierror.BadRequest("Member ID is required").WriteJSON(w)
		return
	}
	actx := h.tokenTenantAuditContext(r)
	if actx.ActorID == "" || actx.TenantID == "" {
		apierror.Unauthorized("Authentication required").WriteJSON(w)
		return
	}
	if err := h.service.EraseMemberPersonalData(r.Context(), memberID, actx); err != nil {
		h.writeLifecycleError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

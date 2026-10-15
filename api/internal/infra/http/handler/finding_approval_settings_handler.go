package handler

// Finding approval settings and the sole member's self-approval
// (api/docs/architecture/finding-status-lifecycle.md, "Approvals").

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/internal/app/finding"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/apierror"
	auditdom "github.com/openctemio/openctem/api/pkg/domain/audit"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	tenantdom "github.com/openctemio/openctem/api/pkg/domain/tenant"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

// FindingApprovalSettingsService reads and writes the organization's
// finding approval settings (*tenant.TenantService).
type FindingApprovalSettingsService interface {
	GetFindingApprovalSettings(ctx context.Context, tenantID string) (*tenantdom.FindingApprovalSettings, error)
	UpdateFindingApprovalSettings(ctx context.Context, tenantID string, change func(*tenantdom.FindingApprovalSettings) error,
		actx auditapp.AuditContext) (before, after *tenantdom.FindingApprovalSettings, err error)
}

// SetFindingApprovalSettings wires the settings routes (nil: 404).
func (h *VulnerabilityHandler) SetFindingApprovalSettings(svc FindingApprovalSettingsService) {
	h.approvalSettings = svc
}

// SelfApproveRequest is the body of POST /approvals/{id}/self-approve.
type SelfApproveRequest struct {
	Reason string `json:"reason" validate:"required,min=1,max=2000"`
	Code   string `json:"code" validate:"required,min=6,max=8"`
}

// SelfApproveResponse is the approved request; end_shortened tells that the
// acceptance end was brought forward to the self-approval limit.
type SelfApproveResponse struct {
	ApprovalResponse
	EndShortened bool `json:"end_shortened"`
}

// SelfApproveApproval handles POST /approvals/{id}/self-approve: the sole
// active member of the organization, an owner, approves their own request
// with a fresh authenticator code and a reason. Every refusal is audited.
// @Summary      Approve your own request as the sole member
// @Description  The owner of an organization with exactly one active person approves their own pending finding request with a fresh authenticator code and a reason. Refused when another member is active or one was suspended or removed in the last 7 days. An accepted risk is shortened to the self-approval limit. Requires findings:approve.
// @Tags         Findings
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        id    path      string              true  "Approval ID"
// @Param        body  body      SelfApproveRequest  true  "Reason and authenticator code"
// @Success      200   {object}  SelfApproveResponse
// @Failure      403   {object}  map[string]string
// @Failure      404   {object}  map[string]string
// @Router       /approvals/{id}/self-approve [post]
func (h *VulnerabilityHandler) SelfApproveApproval(w http.ResponseWriter, r *http.Request) {
	approvalID := r.PathValue("id")
	var req SelfApproveRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("invalid request body").WriteJSON(w)
		return
	}
	if err := h.validator.Validate(req); err != nil {
		h.handleValidationError(w, err)
		return
	}
	res, err := h.service.SelfApproveSolo(r.Context(), finding.SelfApproveInput{
		TenantID:   middleware.GetTenantID(r.Context()),
		ApprovalID: approvalID,
		UserID:     middleware.GetUserID(r.Context()),
		Reason:     req.Reason,
		Code:       req.Code,
	})
	if err != nil {
		var de *shared.DomainError
		if errors.As(err, &de) && (errors.Is(err, shared.ErrForbidden) || errors.Is(err, vulnerability.ErrSoloApprovalNeedsReason)) {
			h.auditApproval(r, auditapp.NewDeniedEvent(auditdom.ActionFindingApprovalSelfRefused, auditdom.ResourceTypeFindingApproval, approvalID, de.Code).
				WithSeverity(auditdom.SeverityHigh).
				WithMessage("Refused: a sole-member self-approval did not meet its conditions ("+de.Code+")"), nil)
		}
		h.handleServiceError(w, err, "self-approve approval")
		return
	}
	a := res.Approval
	h.auditApproval(r, auditapp.NewSuccessEvent(auditdom.ActionFindingApprovalSelfApproved, auditdom.ResourceTypeFindingApproval, a.ID.String()).
		WithSeverity(auditdom.SeverityHigh).
		WithMetadata("reason", a.SelfApprovalReason).
		WithMetadata("end_shortened", res.EndShortened).
		WithMessage(fmt.Sprintf("The sole member approved their own %s request (authenticator code and reason)", a.RequestedStatus)), a)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(SelfApproveResponse{ApprovalResponse: toApprovalResponse(a), EndShortened: res.EndShortened})
}

// FindingApprovalSettingsResponse is the organization's finding approval
// settings.
type FindingApprovalSettingsResponse struct {
	BackupContactEmail string `json:"backup_contact_email"`
}

func toFindingApprovalSettingsResponse(s *tenantdom.FindingApprovalSettings) FindingApprovalSettingsResponse {
	return FindingApprovalSettingsResponse{BackupContactEmail: s.BackupContactEmail}
}

// GetFindingApprovalSettings handles GET /organization/settings/finding-approvals.
// @Summary      Finding approval settings
// @Description  The organization's finding approval settings. Requires findings:read.
// @Tags         Findings
// @Produce      json
// @Security     BearerAuth
// @Success      200  {object}  FindingApprovalSettingsResponse
// @Router       /organization/settings/finding-approvals [get]
func (h *VulnerabilityHandler) GetFindingApprovalSettings(w http.ResponseWriter, r *http.Request) {
	if h.approvalSettings == nil {
		apierror.NotFound("finding approval settings").WriteJSON(w)
		return
	}
	s, err := h.approvalSettings.GetFindingApprovalSettings(r.Context(), middleware.GetTenantID(r.Context()))
	if err != nil {
		h.handleServiceError(w, err, "finding approval settings")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(toFindingApprovalSettingsResponse(s))
}

// UpdateFindingApprovalSettingsRequest is a partial update: a nil field
// keeps its value.
type UpdateFindingApprovalSettingsRequest struct {
	BackupContactEmail *string `json:"backup_contact_email" validate:"omitempty,max=254"`
}

// UpdateFindingApprovalSettings handles PUT /organization/settings/finding-approvals
// (settings:write and a recent re-authentication). The change is audited
// with the values before and after, and the organization's approvers are
// told.
// @Summary      Change the finding approval settings
// @Description  Partial update of the organization's finding approval settings. Requires settings:write and a recent re-authentication; audited, approvers told.
// @Tags         Findings
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        body  body      UpdateFindingApprovalSettingsRequest  true  "Fields to change"
// @Success      200   {object}  FindingApprovalSettingsResponse
// @Failure      403   {object}  map[string]string
// @Router       /organization/settings/finding-approvals [put]
func (h *VulnerabilityHandler) UpdateFindingApprovalSettings(w http.ResponseWriter, r *http.Request) {
	if h.approvalSettings == nil {
		apierror.NotFound("finding approval settings").WriteJSON(w)
		return
	}
	var req UpdateFindingApprovalSettingsRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("invalid request body").WriteJSON(w)
		return
	}
	if err := h.validator.Validate(req); err != nil {
		h.handleValidationError(w, err)
		return
	}
	tenantID := middleware.GetTenantID(r.Context())
	_, after, err := h.approvalSettings.UpdateFindingApprovalSettings(r.Context(), tenantID, func(s *tenantdom.FindingApprovalSettings) error {
		if req.BackupContactEmail != nil {
			s.BackupContactEmail = *req.BackupContactEmail
		}
		return nil
	}, configAuditContext(r))
	if err != nil {
		h.handleServiceError(w, err, "finding approval settings")
		return
	}
	h.service.NotifyApprovalSettingsChanged(r.Context(), tenantID, middleware.GetUserID(r.Context()),
		"Finding approval settings changed", "An administrator changed how this organization approves finding decisions. Review the change in Settings.")
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(toFindingApprovalSettingsResponse(after))
}

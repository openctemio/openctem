package handler

// Finding severity changes and severity requests
// (docs/architecture/finding-severity-override.md).

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	authapp "github.com/openctemio/openctem/api/internal/app/auth"
	"github.com/openctemio/openctem/api/internal/app/finding"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/apierror"
	"github.com/openctemio/openctem/api/pkg/domain/permission"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

// SeverityOverrideResponse is an analyst's override of a finding's severity.
type SeverityOverrideResponse struct {
	Reason       string `json:"reason"`
	OverriddenBy string `json:"overridden_by,omitempty"`
	OverriddenAt string `json:"overridden_at"`
}

// SeverityRequestResponse is a severity downgrade waiting for approval.
type SeverityRequestResponse struct {
	ID                 string `json:"id"`
	RequestedSeverity  string `json:"requested_severity"`
	PreviousSeverity   string `json:"previous_severity"`
	Restore            bool   `json:"restore"`
	Reason             string `json:"reason"`
	RequestedBy        string `json:"requested_by,omitempty"`
	Status             string `json:"status"`
	Tier               string `json:"tier"`
	RequiredApprovals  int    `json:"required_approvals"`
	ApprovalsCollected int    `json:"approvals_collected"`
	DecideBy           string `json:"decide_by"`
	CreatedAt          string `json:"created_at"`
}

// RejectSeverityRequestRequest carries the reason of a rejection.
type RejectSeverityRequestRequest struct {
	Reason string `json:"reason"`
}

func toSeverityOverrideResponse(f *vulnerability.Finding) *SeverityOverrideResponse {
	o := f.SeverityOverride()
	if o == nil {
		return nil
	}
	out := &SeverityOverrideResponse{Reason: o.Reason, OverriddenAt: o.At.UTC().Format(time.RFC3339)}
	if o.By != nil {
		out.OverriddenBy = o.By.String()
	}
	return out
}

func toSeverityRequestResponse(r *vulnerability.SeverityRequest) *SeverityRequestResponse {
	if r == nil {
		return nil
	}
	out := &SeverityRequestResponse{
		ID: r.ID.String(), RequestedSeverity: r.RequestedSeverity.String(), PreviousSeverity: r.PreviousSeverity.String(),
		Restore: r.Restore, Reason: r.Reason, Status: string(r.Status), Tier: r.Tier,
		RequiredApprovals: r.RequiredApprovals, ApprovalsCollected: r.ApprovalsCollected,
		DecideBy: r.DecideBy.UTC().Format(time.RFC3339), CreatedAt: r.CreatedAt.UTC().Format(time.RFC3339),
	}
	if r.RequestedBy != nil {
		out.RequestedBy = r.RequestedBy.String()
	}
	return out
}

// enrichFindingWithSeverityRequest adds the finding's pending severity
// request (the finding was read under the caller's data scope).
func (h *VulnerabilityHandler) enrichFindingWithSeverityRequest(ctx context.Context, f *vulnerability.Finding, resp *FindingResponse) {
	req, err := h.service.PendingSeverityRequest(ctx, f.TenantID(), f.ID())
	if err != nil {
		h.logger.Warn("read pending severity request", "finding_id", f.ID().String(), "error", err)
		return
	}
	resp.PendingSeverityRequest = toSeverityRequestResponse(req)
}

// writeSeverityResult answers a severity change: 200 with the finding (its
// recomputed priority, SLA deadline and reason) when it applied, 202 with the
// finding and its pending request when it waits for approval.
func (h *VulnerabilityHandler) writeSeverityResult(w http.ResponseWriter, r *http.Request, res *finding.SeverityChangeResult) {
	resp := toFindingResponse(res.Finding)
	if res.Request != nil && res.Request.Status == vulnerability.ApprovalStatusPending {
		resp.PendingSeverityRequest = toSeverityRequestResponse(res.Request)
	} else {
		h.enrichFindingWithSeverityRequest(r.Context(), res.Finding, &resp)
	}
	status := http.StatusOK
	if !res.Applied && resp.PendingSeverityRequest != nil {
		status = http.StatusAccepted
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(resp)
}

// UpdateFindingSeverity handles PATCH /api/v1/findings/{id}/severity
// @Summary      Change a finding's severity
// @Description  Sets the effective severity as an analyst override (or restores the reported severity) with a reason, and recomputes the priority class, its reason and the SLA deadline. A downgrade the organization's approval policy does not let the caller decide alone becomes a pending request (202).
// @Tags         Findings
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        id       path      string                 true  "Finding ID"
// @Param        request  body      UpdateSeverityRequest  true  "Severity change"
// @Success      200  {object}  FindingResponse
// @Success      202  {object}  FindingResponse
// @Failure      400  {object}  map[string]string
// @Failure      404  {object}  map[string]string
// @Failure      409  {object}  map[string]string
// @Router       /findings/{id}/severity [patch]
func (h *VulnerabilityHandler) UpdateFindingSeverity(w http.ResponseWriter, r *http.Request) {
	var req UpdateSeverityRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}
	res, err := h.service.ChangeFindingSeverity(r.Context(), finding.ChangeSeverityInput{
		TenantID:   middleware.MustGetTenantID(r.Context()),
		FindingID:  r.PathValue("id"),
		ActorID:    middleware.GetUserID(r.Context()),
		Severity:   req.Severity,
		Restore:    req.Restore,
		Reason:     req.Reason,
		CanApprove: middleware.HasPermission(r.Context(), permission.FindingsApprove.String()),
		Audit:      h.buildAuditContext(r),
	})
	if err != nil {
		h.handleServiceError(w, err, "Finding")
		return
	}
	h.writeSeverityResult(w, r, res)
}

func (h *VulnerabilityHandler) severityDecisionInput(r *http.Request, note string) finding.DecideSeverityRequestInput {
	return finding.DecideSeverityRequestInput{
		TenantID:  middleware.MustGetTenantID(r.Context()),
		FindingID: r.PathValue("id"),
		RequestID: r.PathValue("request_id"),
		ActorID:   middleware.GetUserID(r.Context()),
		Note:      note,
		Audit:     h.buildAuditContext(r),
	}
}

// ApproveSeverityRequest handles POST /api/v1/findings/{id}/severity-requests/{request_id}/approve
// @Summary      Approve a severity request
// @Description  Records the caller's approval of a pending severity downgrade under the approval policy evaluated now; the last approval needed applies it (200) and recomputes the priority and SLA deadline.
// @Tags         Findings
// @Produce      json
// @Security     BearerAuth
// @Param        id         path  string  true  "Finding ID"
// @Param        request_id  path  string  true  "Severity request ID"
// @Success      200  {object}  FindingResponse
// @Failure      403  {object}  map[string]string
// @Failure      404  {object}  map[string]string
// @Failure      409  {object}  map[string]string
// @Router       /findings/{id}/severity-requests/{request_id}/approve [post]
func (h *VulnerabilityHandler) ApproveSeverityRequest(w http.ResponseWriter, r *http.Request) {
	res, err := h.service.ApproveSeverityRequest(r.Context(), h.severityDecisionInput(r, ""))
	if err != nil {
		if h.writeApprovalRefusal(w, r, r.PathValue("request_id"), err) {
			return
		}
		if middleware.WriteStepUpError(w, err, authapp.StepUpWindow) {
			return
		}
		h.handleServiceError(w, err, "Severity request")
		return
	}
	h.writeSeverityResult(w, r, res)
}

// RejectSeverityRequest handles POST /api/v1/findings/{id}/severity-requests/{request_id}/reject
// @Summary      Reject a severity request
// @Description  Rejects a pending severity downgrade with a reason; the severity stays as it is.
// @Tags         Findings
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        id         path  string                        true  "Finding ID"
// @Param        request_id  path  string                        true  "Severity request ID"
// @Param        request    body  RejectSeverityRequestRequest  true  "Reason"
// @Success      200  {object}  FindingResponse
// @Failure      400  {object}  map[string]string
// @Failure      404  {object}  map[string]string
// @Router       /findings/{id}/severity-requests/{request_id}/reject [post]
func (h *VulnerabilityHandler) RejectSeverityRequest(w http.ResponseWriter, r *http.Request) {
	var req RejectSeverityRequestRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}
	res, err := h.service.RejectSeverityRequest(r.Context(), h.severityDecisionInput(r, req.Reason))
	if err != nil {
		h.handleServiceError(w, err, "Severity request")
		return
	}
	h.writeSeverityResult(w, r, res)
}

// CancelSeverityRequest handles POST /api/v1/findings/{id}/severity-requests/{request_id}/cancel
// @Summary      Withdraw a severity request
// @Description  The requester withdraws their own pending severity downgrade.
// @Tags         Findings
// @Produce      json
// @Security     BearerAuth
// @Param        id         path  string  true  "Finding ID"
// @Param        request_id  path  string  true  "Severity request ID"
// @Success      200  {object}  FindingResponse
// @Failure      403  {object}  map[string]string
// @Failure      404  {object}  map[string]string
// @Router       /findings/{id}/severity-requests/{request_id}/cancel [post]
func (h *VulnerabilityHandler) CancelSeverityRequest(w http.ResponseWriter, r *http.Request) {
	res, err := h.service.CancelSeverityRequest(r.Context(), h.severityDecisionInput(r, ""))
	if err != nil {
		h.handleServiceError(w, err, "Severity request")
		return
	}
	h.writeSeverityResult(w, r, res)
}

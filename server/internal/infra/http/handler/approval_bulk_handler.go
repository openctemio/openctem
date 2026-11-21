package handler

// Deciding many approval requests at once, the sole member's own approval
// of a group exception, and leaving one member out of a group
// (server/docs/architecture/finding-status-lifecycle.md, "Approvals").

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	auditapp "github.com/openctemio/openctem/server/internal/app/audit"
	"github.com/openctemio/openctem/server/internal/app/finding"
	"github.com/openctemio/openctem/server/internal/infra/http/middleware"
	"github.com/openctemio/openctem/server/pkg/apierror"
	"github.com/openctemio/openctem/server/pkg/domain/approvalpolicy"
	auditdom "github.com/openctemio/openctem/server/pkg/domain/audit"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
	"github.com/openctemio/openctem/server/pkg/domain/vulnerability"
	"github.com/openctemio/openctem/server/pkg/logger"
)

// maxBulkApprovalBody bounds the body of a bulk decision (100 ids and a
// reason fit well within it).
const maxBulkApprovalBody = 64 << 10

// BulkApprovalDecisionRequest names the requests and groups to approve
// (together at most 100).
type BulkApprovalDecisionRequest struct {
	ApprovalIDs []string `json:"approval_ids"`
	BatchIDs    []string `json:"batch_ids"`
}

// BulkApprovalRejectRequest names the requests and groups to reject with one
// reason (required, at most 2000 characters).
type BulkApprovalRejectRequest struct {
	ApprovalIDs []string `json:"approval_ids"`
	BatchIDs    []string `json:"batch_ids"`
	Reason      string   `json:"reason"`
}

// Outcomes of one item of a bulk decision.
const (
	bulkOutcomeApproved = "approved"
	bulkOutcomeSigned   = "signed"
	bulkOutcomeRejected = "rejected"
	bulkOutcomeSkipped  = "skipped"
	bulkOutcomeFailed   = "failed"
	// bulkCodeError: an item failed for a reason the caller cannot act on.
	bulkCodeError = "error"
)

// BulkApprovalItemResponse is the outcome of one id.
type BulkApprovalItemResponse struct {
	ID   string `json:"id"`
	Kind string `json:"kind" enums:"approval,batch"`
	// Outcome: approved (applied), signed (one approval of several needed;
	// still pending), rejected, skipped (not_found, not_pending,
	// batch_member) or failed (the code says why).
	Outcome string `json:"outcome" enums:"approved,signed,rejected,skipped,failed"`
	// Code is a stable reason for a skipped or failed item: not_found,
	// not_pending, batch_member, own_request, overdue,
	// approver_not_eligible, no_eligible_approver, step_up_required,
	// forbidden, cannot_decide or error.
	Code    string `json:"code,omitempty"`
	Message string `json:"message,omitempty"`
	// Status is the request's or group's status after the call (decided
	// items only).
	Status string `json:"status,omitempty"`
}

// BulkApprovalDecisionResponse is the outcome of every id and the counts.
type BulkApprovalDecisionResponse struct {
	Results  []BulkApprovalItemResponse `json:"results"`
	Approved int                        `json:"approved"`
	Signed   int                        `json:"signed"`
	Rejected int                        `json:"rejected"`
	Skipped  int                        `json:"skipped"`
	Failed   int                        `json:"failed"`
}

// approvalBulkRefusal names why one item was not decided, in stable codes and
// fixed words (never an internal error's text).
func approvalBulkRefusal(err error) (outcome, code, message string) {
	var stepUp *middleware.StepUpRequiredError
	if ref, ok := approvalpolicy.IsRefusal(err); ok {
		if ref.Code == approvalpolicy.CodeNoEligibleApprover {
			return bulkOutcomeFailed, "no_eligible_approver", "nobody eligible can complete this request (" + ref.Reason + ")"
		}
		return bulkOutcomeFailed, "approver_not_eligible", "the approval policy does not let you decide this (" + ref.Reason + ")"
	}
	switch {
	case errors.Is(err, shared.ErrNotFound):
		return bulkOutcomeSkipped, "not_found", "not found"
	case errors.Is(err, finding.ErrApprovalNotPending), errors.Is(err, vulnerability.ErrBatchNotPending):
		return bulkOutcomeSkipped, "not_pending", "already decided, canceled or expired"
	case errors.Is(err, vulnerability.ErrBatchMember):
		return bulkOutcomeSkipped, "batch_member", "part of a group request; decide the group"
	case errors.Is(err, vulnerability.ErrSelfApproval):
		return bulkOutcomeFailed, "own_request", "you made this request; another person decides it"
	case errors.Is(err, vulnerability.ErrDecisionOverdue):
		return bulkOutcomeFailed, "overdue", "the decision deadline has passed"
	case errors.As(err, &stepUp), errors.Is(err, middleware.ErrStepUpRequired), errors.Is(err, middleware.ErrStepUpUnavailable),
		errors.Is(err, finding.ErrStepUpNotWired):
		return bulkOutcomeFailed, "step_up_required", "confirm your identity and try again"
	case errors.Is(err, shared.ErrForbidden):
		return bulkOutcomeFailed, "forbidden", "you may not decide this"
	case errors.Is(err, shared.ErrValidation), errors.Is(err, shared.ErrConflict):
		return bulkOutcomeFailed, "cannot_decide", "cannot be decided now; open it to see why"
	}
	return bulkOutcomeFailed, bulkCodeError, "could not be decided"
}

func decodeBulkApprovalBody(w http.ResponseWriter, r *http.Request, v any) bool {
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBulkApprovalBody)).Decode(v); err != nil {
		apierror.BadRequest("invalid request body").WriteJSON(w)
		return false
	}
	return true
}

// BulkApproveApprovals handles POST /api/v1/approvals/bulk/approve.
// @Summary      Approve several requests and groups
// @Description  Approves each listed finding request and group exception (together at most 100) through the path of a single approval: the approval policy, four-eyes, eligibility and the data scope are judged per item, and an item that fails never stops the rest. An id of another organization or outside the caller's data scope is reported as skipped/not_found. A decided item is reported as skipped/not_pending, so a replay is safe. Requires findings:approve and a recent re-authentication (one for the whole call).
// @Tags         Findings
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        body  body      BulkApprovalDecisionRequest  true  "Requests and groups"
// @Success      200   {object}  BulkApprovalDecisionResponse
// @Failure      400   {object}  apierror.Error
// @Router       /approvals/bulk/approve [post]
func (h *VulnerabilityHandler) BulkApproveApprovals(w http.ResponseWriter, r *http.Request) {
	var req BulkApprovalDecisionRequest
	if !decodeBulkApprovalBody(w, r, &req) {
		return
	}
	items, err := h.service.BulkApproveApprovals(r.Context(), finding.BulkDecisionInput{
		TenantID: middleware.GetTenantID(r.Context()), UserID: middleware.GetUserID(r.Context()),
		ApprovalIDs: req.ApprovalIDs, BatchIDs: req.BatchIDs,
	})
	if err != nil {
		h.handleServiceError(w, err, "bulk approve")
		return
	}
	writeJSON(w, http.StatusOK, h.bulkDecisionResponse(r, items, false))
}

// BulkRejectApprovals handles POST /api/v1/approvals/bulk/reject.
// @Summary      Reject several requests and groups
// @Description  Rejects each listed finding request and group exception (together at most 100) with one reason, through the path of a single rejection; per-item results as for bulk approve. Requires findings:approve.
// @Tags         Findings
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        body  body      BulkApprovalRejectRequest  true  "Requests, groups and the reason"
// @Success      200   {object}  BulkApprovalDecisionResponse
// @Failure      400   {object}  apierror.Error
// @Router       /approvals/bulk/reject [post]
func (h *VulnerabilityHandler) BulkRejectApprovals(w http.ResponseWriter, r *http.Request) {
	var req BulkApprovalRejectRequest
	if !decodeBulkApprovalBody(w, r, &req) {
		return
	}
	items, err := h.service.BulkRejectApprovals(r.Context(), finding.BulkDecisionInput{
		TenantID: middleware.GetTenantID(r.Context()), UserID: middleware.GetUserID(r.Context()),
		ApprovalIDs: req.ApprovalIDs, BatchIDs: req.BatchIDs, Reason: req.Reason,
	})
	if err != nil {
		h.handleServiceError(w, err, "bulk reject")
		return
	}
	writeJSON(w, http.StatusOK, h.bulkDecisionResponse(r, items, true))
}

// bulkDecisionResponse audits each decided item as its single call would and
// builds the per-item results.
func (h *VulnerabilityHandler) bulkDecisionResponse(r *http.Request, items []finding.BulkDecisionItem, reject bool) BulkApprovalDecisionResponse {
	out := BulkApprovalDecisionResponse{Results: make([]BulkApprovalItemResponse, 0, len(items))}
	for _, it := range items {
		res := BulkApprovalItemResponse{ID: it.ID, Kind: it.Kind}
		if it.Err != nil {
			res.Outcome, res.Code, res.Message = approvalBulkRefusal(it.Err)
			if res.Code == bulkCodeError {
				h.logger.Warn("bulk approval decision", "kind", it.Kind, "error", logger.SanitizeError(it.Err))
			}
			h.auditBulkRefusal(r, it)
		} else {
			res.Outcome, res.Status = h.auditBulkDecision(r, it, reject)
		}
		switch res.Outcome {
		case bulkOutcomeApproved:
			out.Approved++
		case bulkOutcomeSigned:
			out.Signed++
		case bulkOutcomeRejected:
			out.Rejected++
		case bulkOutcomeSkipped:
			out.Skipped++
		default:
			out.Failed++
		}
		out.Results = append(out.Results, res)
	}
	return out
}

// auditBulkDecision records one decided item with the action of its single
// call and answers its outcome and status.
func (h *VulnerabilityHandler) auditBulkDecision(r *http.Request, it finding.BulkDecisionItem, reject bool) (string, string) {
	switch {
	case it.Approval != nil && reject:
		a := it.Approval
		h.auditApproval(r, auditapp.NewSuccessEvent(auditdom.ActionFindingApprovalRejected, auditdom.ResourceTypeFindingApproval, a.ID.String()).
			WithMetadata("bulk", true).
			WithMessage(fmt.Sprintf("Rejected the %s request for a finding (bulk)", a.RequestedStatus)), a)
		return bulkOutcomeRejected, string(a.Status)
	case it.Approval != nil:
		a := it.Approval
		if a.Status == vulnerability.ApprovalStatusPending {
			h.auditApproval(r, auditapp.NewSuccessEvent(auditdom.ActionFindingApprovalSigned, auditdom.ResourceTypeFindingApproval, a.ID.String()).
				WithMetadata("bulk", true).
				WithMetadata("approvals_collected", a.ApprovalsCollected).
				WithMetadata("approvals_required", a.RequiredApprovals).
				WithMessage(fmt.Sprintf("Approved %s for a finding (%d of %d approvals, bulk)", a.RequestedStatus,
					a.ApprovalsCollected, a.RequiredApprovals)), a)
			return bulkOutcomeSigned, string(a.Status)
		}
		h.auditApproval(r, auditapp.NewSuccessEvent(auditdom.ActionFindingApprovalApproved, auditdom.ResourceTypeFindingApproval, a.ID.String()).
			WithMetadata("bulk", true).
			WithMessage(fmt.Sprintf("Approved %s for a finding (bulk)", a.RequestedStatus)), a)
		return bulkOutcomeApproved, string(a.Status)
	case it.Batch != nil:
		h.auditApproval(r, auditapp.NewSuccessEvent(auditdom.ActionFindingApprovalBatchRejected, auditdom.ResourceTypeFindingApproval, it.Batch.ID.String()).
			WithMetadata("batch_id", it.Batch.ID.String()).WithMetadata("bulk", true).WithMessage("Rejected a group exception (bulk)"), nil)
		return bulkOutcomeRejected, string(it.Batch.Status)
	case it.Group != nil:
		d := it.Group
		action, outcome := auditdom.ActionFindingApprovalBatchSigned, bulkOutcomeSigned
		msg := fmt.Sprintf("Approved a group exception (%d of %d approvals, bulk)", d.Batch.ApprovalsCollected, d.Batch.RequiredApprovals)
		if d.Batch.Status == vulnerability.ApprovalStatusApproved {
			action, outcome = auditdom.ActionFindingApprovalBatchApproved, bulkOutcomeApproved
			msg = fmt.Sprintf("Approved a group exception (bulk): %d finding(s) %s, %d canceled (moved), %d end(s) shortened to their cap",
				d.Applied, d.Batch.RequestedStatus, len(d.Canceled), d.Shortened)
		}
		h.auditApproval(r, auditapp.NewSuccessEvent(action, auditdom.ResourceTypeFindingApproval, d.Batch.ID.String()).
			WithMetadata("batch_id", d.Batch.ID.String()).WithMetadata("tier", d.Batch.Tier).WithMetadata("bulk", true).WithMessage(msg), nil)
		return outcome, string(d.Batch.Status)
	}
	return bulkOutcomeFailed, ""
}

// auditBulkRefusal records the refusals a single call records: an attempt
// to approve one's own request, and an approval the policy refused.
func (h *VulnerabilityHandler) auditBulkRefusal(r *http.Request, it finding.BulkDecisionItem) {
	if errors.Is(it.Err, vulnerability.ErrSelfApproval) {
		h.auditApproval(r, auditapp.NewDeniedEvent(auditdom.ActionFindingApprovalSelfRefused, auditdom.ResourceTypeFindingApproval, it.ID,
			"the requester cannot approve their own request").
			WithSeverity(auditdom.SeverityMedium).WithMetadata("bulk", true).
			WithMessage("Refused: the requester tried to approve their own request (bulk)"), nil)
		return
	}
	if ref, ok := approvalpolicy.IsRefusal(it.Err); ok {
		h.auditApproval(r, auditapp.NewDeniedEvent(auditdom.ActionFindingApprovalRefused, auditdom.ResourceTypeFindingApproval, it.ID, ref.Reason).
			WithSeverity(auditdom.SeverityMedium).
			WithMetadata("reason", ref.Reason).WithMetadata("bulk", true).
			WithMessage("Refused by the approval policy ("+ref.Reason+", bulk)"), nil)
	}
}

// SelfApproveApprovalBatch handles POST /api/v1/approvals/batches/{id}/self-approve.
// @Summary      Approve your own group exception as the sole member
// @Description  The owner of an organization with exactly one active person approves their own pending group exception with a fresh authenticator code and a reason; every pending member is applied and marked self-approved. Refused when another member is active or one was suspended or removed in the last 7 days. An accepted risk is approved this way only when the organization's risk acceptance level is high_and_above or off, and each member's end is shortened to its self-approval limit. Requires findings:approve and every member in the caller's data scope.
// @Tags         Findings
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        id    path      string              true  "Group exception ID"
// @Param        body  body      SelfApproveRequest  true  "Reason and authenticator code"
// @Success      200   {object}  ApprovalBatchResponse
// @Failure      403   {object}  apierror.Error
// @Failure      404   {object}  apierror.Error
// @Failure      409   {object}  apierror.Error
// @Router       /approvals/batches/{id}/self-approve [post]
func (h *VulnerabilityHandler) SelfApproveApprovalBatch(w http.ResponseWriter, r *http.Request) {
	tid, id, ok := pathBatchID(w, r)
	if !ok {
		return
	}
	uid, err := shared.IDFromString(middleware.GetUserID(r.Context()))
	if err != nil {
		apierror.Unauthorized("invalid user").WriteJSON(w)
		return
	}
	var req SelfApproveRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10)).Decode(&req); err != nil {
		apierror.BadRequest("invalid request body").WriteJSON(w)
		return
	}
	if err := h.validator.Validate(req); err != nil {
		h.handleValidationError(w, err)
		return
	}
	d, err := h.service.SelfApproveSoloBatch(r.Context(), finding.SelfApproveBatchInput{
		TenantID: tid, BatchID: id, UserID: uid, Reason: req.Reason, Code: req.Code,
	})
	if err != nil {
		var de *shared.DomainError
		if errors.As(err, &de) && (errors.Is(err, shared.ErrForbidden) || errors.Is(err, vulnerability.ErrSoloApprovalNeedsReason)) {
			h.auditApproval(r, auditapp.NewDeniedEvent(auditdom.ActionFindingApprovalSelfRefused, auditdom.ResourceTypeFindingApproval, id.String(), de.Code).
				WithSeverity(auditdom.SeverityHigh).WithMetadata("batch_id", id.String()).
				WithMessage("Refused: a sole-member self-approval of a group exception did not meet its conditions ("+de.Code+")"), nil)
		}
		h.handleServiceError(w, err, "self-approve group exception")
		return
	}
	out := toApprovalBatchResponse(d.Batch)
	applied, shortened := d.Applied, d.Shortened
	out.Applied, out.Shortened = &applied, &shortened
	out.Canceled = make([]string, 0, len(d.Canceled))
	for _, c := range d.Canceled {
		out.Canceled = append(out.Canceled, c.String())
	}
	h.auditApproval(r, auditapp.NewSuccessEvent(auditdom.ActionFindingApprovalBatchSelfApproved, auditdom.ResourceTypeFindingApproval, id.String()).
		WithSeverity(auditdom.SeverityHigh).
		WithMetadata("batch_id", id.String()).
		WithMetadata("reason", req.Reason).
		WithMetadata("applied", d.Applied).
		WithMetadata("canceled", len(d.Canceled)).
		WithMetadata("end_shortened", d.Shortened).
		WithMessage(fmt.Sprintf("The sole member approved their own group exception: %d finding(s) %s (authenticator code and reason)",
			d.Applied, d.Batch.RequestedStatus)), nil)
	writeJSON(w, http.StatusOK, out)
}

// LeaveOutApprovalBatchMember handles
// POST /api/v1/approvals/batches/{id}/items/{finding_id}/reject.
// @Summary      Leave one finding out of a group exception
// @Description  Rejects one pending member of a group exception with a reason; the other members stay pending and the group is decided later as usual. When no pending member is left the group closes as rejected. The requester cannot leave out from their own group (they cancel it instead). Requires findings:approve and every member in the caller's data scope.
// @Tags         Findings
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        id          path  string                      true  "Group exception ID"
// @Param        finding_id  path  string                      true  "Finding ID of the member"
// @Param        body        body  RejectApprovalBatchRequest  true  "Reason"
// @Success      200   {object}  ApprovalBatchResponse
// @Failure      400   {object}  apierror.Error
// @Failure      404   {object}  apierror.Error
// @Failure      409   {object}  apierror.Error
// @Router       /approvals/batches/{id}/items/{finding_id}/reject [post]
func (h *VulnerabilityHandler) LeaveOutApprovalBatchMember(w http.ResponseWriter, r *http.Request) {
	tid, id, ok := pathBatchID(w, r)
	if !ok {
		return
	}
	fid, err := shared.IDFromString(r.PathValue("finding_id"))
	if err != nil {
		apierror.NotFound("group exception member").WriteJSON(w)
		return
	}
	uid, err := shared.IDFromString(middleware.GetUserID(r.Context()))
	if err != nil {
		apierror.Unauthorized("invalid user").WriteJSON(w)
		return
	}
	var req RejectApprovalBatchRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10)).Decode(&req); err != nil {
		apierror.BadRequest("invalid request body").WriteJSON(w)
		return
	}
	b, err := h.service.LeaveOutGroupMember(r.Context(), tid, id, fid, uid, req.Reason)
	if err != nil {
		if errors.Is(err, vulnerability.ErrSelfApproval) {
			h.auditApproval(r, auditapp.NewDeniedEvent(auditdom.ActionFindingApprovalSelfRefused, auditdom.ResourceTypeFindingApproval, id.String(),
				"the requester cannot decide a member of their own group exception").
				WithSeverity(auditdom.SeverityMedium).WithMetadata("batch_id", id.String()).
				WithMessage("Refused: the requester tried to leave a finding out of their own group exception"), nil)
		}
		h.handleServiceError(w, err, "group exception member")
		return
	}
	msg := "Left one finding out of a group exception"
	if b.Status == vulnerability.ApprovalStatusRejected {
		msg += "; no member was left pending, so the group closed as rejected"
	}
	h.auditApproval(r, auditapp.NewSuccessEvent(auditdom.ActionFindingApprovalBatchMemberRejected, auditdom.ResourceTypeFindingApproval, id.String()).
		WithMetadata("batch_id", id.String()).WithMetadata("finding_id", fid.String()).
		WithMetadata("batch_status", string(b.Status)).WithMessage(msg), nil)
	full, members, err := h.service.GetGroupException(r.Context(), tid, id)
	if err != nil {
		writeJSON(w, http.StatusOK, toApprovalBatchResponse(b))
		return
	}
	writeJSON(w, http.StatusOK, h.batchDetailResponse(r, full, members))
}

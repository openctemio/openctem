package handler

// Group-level exceptions (api/docs/rfcs/RFC-111-approval-policy.md §7):
// request and preview on a remediation task, list, read and decide under
// /approvals/batches.

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	authapp "github.com/openctemio/openctem/api/internal/app/auth"
	"github.com/openctemio/openctem/api/internal/app/finding"
	remediationapp "github.com/openctemio/openctem/api/internal/app/remediation"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/apierror"
	auditdom "github.com/openctemio/openctem/api/pkg/domain/audit"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

// TaskExceptionRequest asks for one exception over a task's open findings.
type TaskExceptionRequest struct {
	// RequestedStatus is accepted or false_positive.
	RequestedStatus string `json:"requested_status" enums:"accepted,false_positive"`
	// ClosureReason is the structured reason (closure reason catalog).
	ClosureReason string `json:"closure_reason"`
	// Justification is the note (at least 20 characters for the security
	// and dual tiers).
	Justification string `json:"justification"`
	// ExpiresAt is the requested end of an accepted risk (RFC 3339); each
	// finding ends no later than its own cap.
	ExpiresAt *string `json:"expires_at,omitempty"`
	// Approved lets a group above the bulk ceiling through the abuse guard.
	Approved bool `json:"approved,omitempty"`
}

// GroupExceptionMemberResponse is one finding of a group exception.
type GroupExceptionMemberResponse struct {
	FindingID string  `json:"finding_id"`
	Title     string  `json:"title,omitempty"`
	Severity  string  `json:"severity,omitempty"`
	Tier      string  `json:"tier,omitempty"`
	RiskClass string  `json:"risk_class,omitempty"`
	End       *string `json:"end,omitempty"`
	Shortened bool    `json:"shortened,omitempty"`
	// Skipped says why the finding is left out (not_found, cannot_move,
	// pending_request).
	Skipped string `json:"skipped,omitempty"`
}

// GroupExceptionPreviewResponse is what a group exception would be.
type GroupExceptionPreviewResponse struct {
	Evaluation ApprovalEvaluationResponse     `json:"evaluation"`
	Members    []GroupExceptionMemberResponse `json:"members"`
	Included   int                            `json:"included"`
	Skipped    int                            `json:"skipped"`
}

// ApprovalBatchResponse is a group exception.
type ApprovalBatchResponse struct {
	ID                 string  `json:"id"`
	SourceType         string  `json:"source_type"`
	SourceID           string  `json:"source_id"`
	SourceTitle        string  `json:"source_title,omitempty"`
	RequestedStatus    string  `json:"requested_status"`
	ClosureReason      string  `json:"closure_reason"`
	Justification      string  `json:"justification"`
	ExpiresAt          *string `json:"expires_at,omitempty"`
	RequestedBy        string  `json:"requested_by,omitempty"`
	Tier               string  `json:"tier" enums:"peer,security,dual"`
	RiskClass          string  `json:"risk_class"`
	ApprovalsRequired  int     `json:"approvals_required"`
	ApprovalsCollected int     `json:"approvals_collected"`
	Status             string  `json:"status"`
	DecideBy           string  `json:"decide_by"`
	MemberCount        int     `json:"member_count"`
	DecidedBy          *string `json:"decided_by,omitempty"`
	DecidedAt          *string `json:"decided_at,omitempty"`
	RejectionReason    string  `json:"rejection_reason,omitempty"`
	CreatedAt          string  `json:"created_at"`
	// Members are listed on the read of one exception.
	Members []ApprovalBatchMemberResponse `json:"members,omitempty"`
	// Applied / Canceled / Shortened: what the approval that completed it did.
	Applied   *int     `json:"applied,omitempty"`
	Canceled  []string `json:"canceled,omitempty"`
	Shortened *int     `json:"shortened,omitempty"`
}

// ApprovalBatchMemberResponse is one member request of a group exception.
type ApprovalBatchMemberResponse struct {
	ApprovalID string  `json:"approval_id"`
	FindingID  string  `json:"finding_id"`
	Title      string  `json:"title,omitempty"`
	Severity   string  `json:"severity,omitempty"`
	Status     string  `json:"status"`
	ExpiresAt  *string `json:"expires_at,omitempty"`
}

func toApprovalBatchResponse(b *vulnerability.ApprovalBatch) ApprovalBatchResponse {
	out := ApprovalBatchResponse{
		ID: b.ID.String(), SourceType: b.SourceType, SourceID: b.SourceID.String(), SourceTitle: b.SourceTitle,
		RequestedStatus: string(b.RequestedStatus), ClosureReason: b.ClosureReason.String(), Justification: b.Justification,
		ExpiresAt: rfc3339Ptr(b.ExpiresAt), RequestedBy: b.RequestedBy.StringOrEmpty(), Tier: b.Tier, RiskClass: b.RiskClass,
		ApprovalsRequired: b.RequiredApprovals, ApprovalsCollected: b.ApprovalsCollected, Status: string(b.Status),
		DecideBy: b.DecideBy.UTC().Format(time.RFC3339), MemberCount: b.MemberCount, DecidedAt: rfc3339Ptr(b.DecidedAt),
		RejectionReason: b.RejectionReason, CreatedAt: b.CreatedAt.UTC().Format(time.RFC3339),
	}
	if b.DecidedBy != nil {
		s := b.DecidedBy.String()
		out.DecidedBy = &s
	}
	return out
}

func toGroupPreviewResponse(p *finding.GroupExceptionPreview) GroupExceptionPreviewResponse {
	res := p.Result
	out := GroupExceptionPreviewResponse{
		Evaluation: ApprovalEvaluationResponse{
			Kind: string(res.Kind), Tier: string(res.Tier), Floor: string(res.Floor), RiskClass: string(res.Class),
			ApprovalsRequired: res.Required, Reasons: res.Reasons, SecurityPool: res.SecurityPool,
			SecurityPoolFallback: res.PoolFallback, StepUp: res.StepUp, EligibleApprovers: len(res.Eligible),
			EligibleSecurityPool: len(res.EligiblePool), Satisfiable: res.Satisfiable(), MinNoteLength: res.MinNoteLength,
			MaxAcceptanceDays: int(res.MaxAcceptance / (24 * time.Hour)), DecideWithinDays: int(res.DecideWithin / (24 * time.Hour)),
		},
		Members: make([]GroupExceptionMemberResponse, 0, len(p.Members)), Included: p.Included, Skipped: p.Skipped,
	}
	for _, m := range p.Members {
		out.Members = append(out.Members, GroupExceptionMemberResponse{
			FindingID: m.FindingID.String(), Title: m.Title, Severity: m.Severity, Tier: m.Tier, RiskClass: m.RiskClass,
			End: rfc3339Ptr(m.End), Shortened: m.Shortened, Skipped: m.Skipped,
		})
	}
	return out
}

func (req TaskExceptionRequest) input(tid, taskID shared.ID, actor *shared.ID) (remediationapp.TaskExceptionInput, error) {
	in := remediationapp.TaskExceptionInput{
		TenantID: tid, TaskID: taskID, RequestedStatus: req.RequestedStatus, ClosureReason: req.ClosureReason,
		Justification: req.Justification, Approved: req.Approved,
	}
	if actor != nil {
		in.ActorID = *actor
	}
	if req.ExpiresAt != nil && *req.ExpiresAt != "" {
		t, err := time.Parse(time.RFC3339, *req.ExpiresAt)
		if err != nil {
			return in, fmt.Errorf("%w: expires_at must be RFC 3339", shared.ErrValidation)
		}
		in.ExpiresAt = &t
	}
	if len(req.Justification) > 2000 || len(req.ClosureReason) > 64 {
		return in, fmt.Errorf("%w: justification is at most 2000 characters", shared.ErrValidation)
	}
	return in, nil
}

// PreviewException handles POST /api/v1/remediation/tasks/{task_id}/exception/preview.
// @Summary      Preview an exception on a remediation task
// @Description  How one exception (accepted risk or false positive) over the task's open findings would be decided: the group tier, each finding's tier and end, and the findings left out. Requires findings:remediation:write and findings:write; every finding of the task in the caller's scope.
// @Tags         Remediation
// @Accept       json
// @Produce      json
// @Param        task_id  path  string                true  "Task ID"
// @Param        body     body  TaskExceptionRequest  true  "Exception"
// @Success      200  {object}  GroupExceptionPreviewResponse
// @Router       /remediation/tasks/{task_id}/exception/preview [post]
func (h *RemediationTaskHandler) PreviewException(w http.ResponseWriter, r *http.Request) {
	tid, ok := h.tenant(w, r)
	if !ok {
		return
	}
	id, ok := pathTaskID(w, r)
	if !ok {
		return
	}
	var req TaskExceptionRequest
	if err := decodeTaskBody(w, r, &req); err != nil {
		apierror.BadRequest("invalid request body").WriteJSON(w)
		return
	}
	in, err := req.input(tid, id, callerID(r))
	if err != nil {
		h.handleError(w, err)
		return
	}
	p, err := h.service.PreviewException(r.Context(), in)
	if p == nil && err != nil {
		h.handleError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, toGroupPreviewResponse(p))
}

// RequestException handles POST /api/v1/remediation/tasks/{task_id}/exception.
// @Summary      Request an exception on a remediation task
// @Description  One exception request (accepted risk or false positive) over the task's open findings, decided once under the approval policy; each finding keeps its own end and cap. Requires findings:remediation:write and findings:write; every finding of the task in the caller's scope.
// @Tags         Remediation
// @Accept       json
// @Produce      json
// @Param        task_id  path  string                true  "Task ID"
// @Param        body     body  TaskExceptionRequest  true  "Exception"
// @Success      201  {object}  ApprovalBatchResponse
// @Router       /remediation/tasks/{task_id}/exception [post]
func (h *RemediationTaskHandler) RequestException(w http.ResponseWriter, r *http.Request) {
	tid, ok := h.tenant(w, r)
	if !ok {
		return
	}
	id, ok := pathTaskID(w, r)
	if !ok {
		return
	}
	var req TaskExceptionRequest
	if err := decodeTaskBody(w, r, &req); err != nil {
		apierror.BadRequest("invalid request body").WriteJSON(w)
		return
	}
	in, err := req.input(tid, id, callerID(r))
	if err != nil {
		h.handleError(w, err)
		return
	}
	res, err := h.service.RequestException(r.Context(), in, h.auditContext(r))
	if err != nil {
		h.handleError(w, err)
		return
	}
	out := toApprovalBatchResponse(res.Batch)
	writeJSON(w, http.StatusCreated, out)
}

// ListApprovalBatches handles GET /api/v1/approvals/batches.
// @Summary      List group exceptions
// @Description  The organization's group exceptions the caller may see (every member finding in their data scope), newest first. Requires findings:read.
// @Tags         Findings
// @Produce      json
// @Param        status    query  string  false  "pending, approved, rejected, canceled or expired"
// @Param        page      query  int     false  "Page"
// @Param        per_page  query  int     false  "Per page"
// @Success      200  {object}  map[string]interface{}
// @Router       /approvals/batches [get]
func (h *VulnerabilityHandler) ListApprovalBatches(w http.ResponseWriter, r *http.Request) {
	tid, err := shared.IDFromString(middleware.GetTenantID(r.Context()))
	if err != nil {
		apierror.Unauthorized("invalid tenant").WriteJSON(w)
		return
	}
	paging, ok := listPage(w, r, 20)
	if !ok {
		return
	}
	res, err := h.service.ListGroupExceptions(r.Context(), tid, r.URL.Query().Get("status"), paging)
	if err != nil {
		h.handleServiceError(w, err, "group exceptions")
		return
	}
	items := make([]ApprovalBatchResponse, 0, len(res.Data))
	for _, b := range res.Data {
		items = append(items, toApprovalBatchResponse(b))
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": items, "total": res.Total, "page": res.Page, "per_page": res.PerPage})
}

func pathBatchID(w http.ResponseWriter, r *http.Request) (shared.ID, shared.ID, bool) {
	tid, err := shared.IDFromString(middleware.GetTenantID(r.Context()))
	if err != nil {
		apierror.Unauthorized("invalid tenant").WriteJSON(w)
		return shared.ID{}, shared.ID{}, false
	}
	id, err := shared.IDFromString(r.PathValue("id"))
	if err != nil {
		apierror.NotFound("group exception").WriteJSON(w)
		return shared.ID{}, shared.ID{}, false
	}
	return tid, id, true
}

// GetApprovalBatch handles GET /api/v1/approvals/batches/{id}.
// @Summary      Read a group exception
// @Description  A group exception with its member requests. Requires findings:read and every member finding in the caller's data scope.
// @Tags         Findings
// @Produce      json
// @Param        id  path  string  true  "Group exception ID"
// @Success      200  {object}  ApprovalBatchResponse
// @Router       /approvals/batches/{id} [get]
func (h *VulnerabilityHandler) GetApprovalBatch(w http.ResponseWriter, r *http.Request) {
	tid, id, ok := pathBatchID(w, r)
	if !ok {
		return
	}
	b, members, err := h.service.GetGroupException(r.Context(), tid, id)
	if err != nil {
		h.handleServiceError(w, err, "group exception")
		return
	}
	out := toApprovalBatchResponse(b)
	out.Members = make([]ApprovalBatchMemberResponse, 0, len(members))
	for _, m := range members {
		out.Members = append(out.Members, ApprovalBatchMemberResponse{
			ApprovalID: m.ApprovalID.String(), FindingID: m.FindingID.String(), Title: m.Title, Severity: m.Severity,
			Status: string(m.Status), ExpiresAt: rfc3339Ptr(m.ExpiresAt),
		})
	}
	writeJSON(w, http.StatusOK, out)
}

// ApproveApprovalBatch handles POST /api/v1/approvals/batches/{id}/approve.
// @Summary      Approve a group exception
// @Description  One approval of a group exception under the approval policy evaluated now (the highest member tier). The last required approval applies every member with its own end. Requires findings:approve and every member in the caller's data scope; security and dual tiers need a recent re-authentication.
// @Tags         Findings
// @Produce      json
// @Param        id  path  string  true  "Group exception ID"
// @Success      200  {object}  ApprovalBatchResponse
// @Failure      403  {object}  apierror.Error
// @Failure      409  {object}  apierror.Error
// @Router       /approvals/batches/{id}/approve [post]
func (h *VulnerabilityHandler) ApproveApprovalBatch(w http.ResponseWriter, r *http.Request) {
	tid, id, ok := pathBatchID(w, r)
	if !ok {
		return
	}
	uid, err := shared.IDFromString(middleware.GetUserID(r.Context()))
	if err != nil {
		apierror.Unauthorized("invalid user").WriteJSON(w)
		return
	}
	d, err := h.service.ApproveGroupException(r.Context(), tid, id, uid)
	if err != nil {
		if errors.Is(err, vulnerability.ErrSelfApproval) {
			h.auditApproval(r, auditapp.NewDeniedEvent(auditdom.ActionFindingApprovalSelfRefused, auditdom.ResourceTypeFindingApproval, id.String(),
				"the requester cannot approve their own group exception").
				WithSeverity(auditdom.SeverityMedium).
				WithMessage("Refused: the requester tried to approve their own group exception"), nil)
		}
		if h.writeApprovalRefusal(w, r, id.String(), err) {
			return
		}
		if middleware.WriteStepUpError(w, err, authapp.StepUpWindow) {
			return
		}
		h.handleServiceError(w, err, "group exception")
		return
	}
	out := toApprovalBatchResponse(d.Batch)
	action := auditdom.ActionFindingApprovalBatchSigned
	msg := fmt.Sprintf("Approved a group exception (%d of %d approvals)", d.Batch.ApprovalsCollected, d.Batch.RequiredApprovals)
	if d.Batch.Status == vulnerability.ApprovalStatusApproved {
		action = auditdom.ActionFindingApprovalBatchApproved
		msg = fmt.Sprintf("Approved a group exception: %d finding(s) %s, %d canceled (moved), %d end(s) shortened to their cap",
			d.Applied, d.Batch.RequestedStatus, len(d.Canceled), d.Shortened)
		applied, shortened := d.Applied, d.Shortened
		out.Applied, out.Shortened = &applied, &shortened
		out.Canceled = make([]string, 0, len(d.Canceled))
		for _, c := range d.Canceled {
			out.Canceled = append(out.Canceled, c.String())
		}
	}
	h.auditApproval(r, auditapp.NewSuccessEvent(action, auditdom.ResourceTypeFindingApproval, id.String()).
		WithMetadata("batch_id", id.String()).WithMetadata("tier", d.Batch.Tier).WithMessage(msg), nil)
	writeJSON(w, http.StatusOK, out)
}

// RejectApprovalBatchRequest is the body of a rejection.
type RejectApprovalBatchRequest struct {
	Reason string `json:"reason"`
}

// RejectApprovalBatch handles POST /api/v1/approvals/batches/{id}/reject.
// @Summary      Reject a group exception
// @Description  Rejects a pending group exception and its member requests. Requires findings:approve and every member in the caller's data scope.
// @Tags         Findings
// @Accept       json
// @Produce      json
// @Param        id    path  string                      true  "Group exception ID"
// @Param        body  body  RejectApprovalBatchRequest  true  "Reason"
// @Success      200  {object}  ApprovalBatchResponse
// @Router       /approvals/batches/{id}/reject [post]
func (h *VulnerabilityHandler) RejectApprovalBatch(w http.ResponseWriter, r *http.Request) {
	tid, id, ok := pathBatchID(w, r)
	if !ok {
		return
	}
	uid, err := shared.IDFromString(middleware.GetUserID(r.Context()))
	if err != nil {
		apierror.Unauthorized("invalid user").WriteJSON(w)
		return
	}
	var req RejectApprovalBatchRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10)).Decode(&req); err != nil || len(req.Reason) > 2000 {
		apierror.BadRequest("invalid request body").WriteJSON(w)
		return
	}
	b, err := h.service.RejectGroupException(r.Context(), tid, id, uid, req.Reason)
	if err != nil {
		h.handleServiceError(w, err, "group exception")
		return
	}
	h.auditApproval(r, auditapp.NewSuccessEvent(auditdom.ActionFindingApprovalBatchRejected, auditdom.ResourceTypeFindingApproval, id.String()).
		WithMetadata("batch_id", id.String()).WithMessage("Rejected a group exception"), nil)
	writeJSON(w, http.StatusOK, toApprovalBatchResponse(b))
}

// CancelApprovalBatch handles POST /api/v1/approvals/batches/{id}/cancel.
// @Summary      Cancel a group exception
// @Description  The requester cancels their pending group exception and its member requests. Requires findings:write.
// @Tags         Findings
// @Produce      json
// @Param        id  path  string  true  "Group exception ID"
// @Success      200  {object}  ApprovalBatchResponse
// @Router       /approvals/batches/{id}/cancel [post]
func (h *VulnerabilityHandler) CancelApprovalBatch(w http.ResponseWriter, r *http.Request) {
	tid, id, ok := pathBatchID(w, r)
	if !ok {
		return
	}
	uid, err := shared.IDFromString(middleware.GetUserID(r.Context()))
	if err != nil {
		apierror.Unauthorized("invalid user").WriteJSON(w)
		return
	}
	b, err := h.service.CancelGroupException(r.Context(), tid, id, uid)
	if err != nil {
		h.handleServiceError(w, err, "group exception")
		return
	}
	h.auditApproval(r, auditapp.NewSuccessEvent(auditdom.ActionFindingApprovalBatchCanceled, auditdom.ResourceTypeFindingApproval, id.String()).
		WithMetadata("batch_id", id.String()).WithMessage("Canceled a group exception"), nil)
	writeJSON(w, http.StatusOK, toApprovalBatchResponse(b))
}

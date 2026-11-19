package handler

// Bulk "Dismiss" of findings: preview, apply and undo
// (docs/architecture/findings-bulk-by-filter.md, "Bulk dismiss"). The rules
// live in finding.VulnerabilityService (bulk_dismiss.go); this file parses the
// request, takes the caller's identity and authority from the request's
// authentication only, maps the errors and writes the audit trail.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	auditapp "github.com/openctemio/openctem/server/internal/app/audit"
	authapp "github.com/openctemio/openctem/server/internal/app/auth"
	"github.com/openctemio/openctem/server/internal/app/finding"
	"github.com/openctemio/openctem/server/internal/infra/http/filterquery"
	"github.com/openctemio/openctem/server/internal/infra/http/middleware"
	"github.com/openctemio/openctem/server/pkg/apierror"
	auditdom "github.com/openctemio/openctem/server/pkg/domain/audit"
	"github.com/openctemio/openctem/server/pkg/domain/permission"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
	"github.com/openctemio/openctem/server/pkg/filterspec"
)

// maxBulkDismissBody bounds a bulk dismiss request body (500 ids, a filter
// and a note).
const maxBulkDismissBody = 128 << 10

// bulkFilterSummaryMax caps the filter summary in the group's label.
const bulkFilterSummaryMax = 120

// BulkDismissRequest is a bulk dismiss: finding_ids, or filter with
// expected_count (exactly one of the two).
type BulkDismissRequest struct {
	// FindingIDs are the selected rows (at most 500).
	FindingIDs []string `json:"finding_ids,omitempty"`
	// Filter is the list's filter ("select all matching"; GET /findings
	// params without paging or sort). At most 500 findings.
	Filter FilterValues `json:"filter,omitempty"`
	// ExpectedCount is the total the caller confirmed (filter only); the
	// server recounts in the caller's scope (409 SELECTION_CHANGED).
	ExpectedCount int `json:"expected_count,omitempty"`
	// Status is false_positive (default) or accepted.
	Status string `json:"status,omitempty" enums:"false_positive,accepted"`
	// ClosureReason is required: a false-positive justification or an
	// accepted-risk reason.
	ClosureReason string `json:"closure_reason" enums:"component_not_present,vulnerable_code_not_present,vulnerable_code_not_in_execute_path,vulnerable_code_cannot_be_controlled_by_adversary,inline_mitigations_already_exist,detection_error,test_or_example_code,risk_accepted,compensating_control,wont_fix,no_fix_available"`
	// Note is optional only when every finding is decided alone and none is
	// serious (the preview says note_required and note_min_length).
	Note string `json:"note,omitempty"`
	// ExpiresAt ends an accepted risk (RFC 3339; accepted only).
	ExpiresAt *string `json:"expires_at,omitempty"`
	// IdempotencyKey is required to apply: a retry returns the first
	// request's result (replay: true).
	IdempotencyKey string `json:"idempotency_key,omitempty"`
}

// PreviewBulkDismiss handles POST /api/v1/findings/bulk-dismissals/preview
// @Summary      Preview a bulk dismiss of findings
// @Description  How a bulk Dismiss (false positive, or accepted risk) would split, changing nothing: findings
// @Description  decided now by the caller alone (the organization's level, per finding, as a single request), the
// @Description  ones that go to one approval group, and the skipped ones (not_found, cannot_move, pending_request).
// @Description  Lists hold at most 50 findings each; counts are complete. Out-of-scope or unknown ids are
// @Description  not_found, without titles. same_rule names the tool rule most findings share (suggest: 20 or more).
// @Tags         Findings
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        request  body  BulkDismissRequest  true  "Selection, status, reason and note"
// @Success      200  {object}  finding.BulkDismissResult
// @Failure      400  {object}  apierror.Error
// @Failure      403  {object}  apierror.Error
// @Failure      409  {object}  apierror.Error
// @Failure      422  {object}  apierror.Error
// @Router       /findings/bulk-dismissals/preview [post]
func (h *VulnerabilityHandler) PreviewBulkDismiss(w http.ResponseWriter, r *http.Request) {
	in, ok := h.parseBulkDismiss(w, r, "POST /findings/bulk-dismissals/preview")
	if !ok {
		return
	}
	out, err := h.service.PreviewBulkDismiss(r.Context(), in)
	if err != nil {
		h.writeBulkDismissError(w, err)
		return
	}
	writeJSONOK(w, out)
}

// BulkDismiss handles POST /api/v1/findings/bulk-dismissals
// @Summary      Dismiss findings in bulk
// @Description  Marks up to 500 findings a false positive (default) or accepts their risk. Each finding follows the
// @Description  same approval policy as a single request: the ones the caller may decide alone are applied now
// @Description  (own activity entry with bulk_id and audit row), the others become ONE approval group, the rest is
// @Description  skipped. More than 25 decided alone needs a recent re-authentication (403 STEP_UP_REQUIRED, nothing
// @Description  changed). At most 1,000 decided alone per person per 24 hours; more go to the group
// @Description  (counts.budget_overflow). idempotency_key is required; the same key replays the first result
// @Description  (replay: true), with another request it answers 422 IDEMPOTENCY_KEY_REUSED.
// @Tags         Findings
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        request  body  BulkDismissRequest  true  "Selection, status, reason, note and idempotency key"
// @Success      200  {object}  finding.BulkDismissResult
// @Failure      400  {object}  apierror.Error
// @Failure      403  {object}  apierror.Error
// @Failure      409  {object}  apierror.Error
// @Failure      422  {object}  apierror.Error
// @Router       /findings/bulk-dismissals [post]
func (h *VulnerabilityHandler) BulkDismiss(w http.ResponseWriter, r *http.Request) {
	in, ok := h.parseBulkDismiss(w, r, "POST /findings/bulk-dismissals")
	if !ok {
		return
	}
	out, err := h.service.BulkDismiss(r.Context(), in)
	if err != nil {
		h.writeBulkDismissError(w, err)
		return
	}
	if !out.Replay {
		// The apply outlives a client that leaves; so does its audit trail.
		h.auditBulkDismiss(r.WithContext(context.WithoutCancel(r.Context())), out)
	}
	writeJSONOK(w, out)
}

// UndoBulkDismiss handles POST /api/v1/findings/bulk-dismissals/{id}/reopen
// @Summary      Undo a bulk dismiss
// @Description  Reopens (to confirmed, through the normal status path, note "Undo of bulk dismissal <id>") the
// @Description  findings the caller's bulk dismiss decided alone that are still in the status it set, and cancels
// @Description  its pending approval group. Findings changed since are skipped (changed). Only its creator, within
// @Description  24 hours, once (409 after); anyone else gets 404. Nothing is deleted.
// @Tags         Findings
// @Produce      json
// @Security     BearerAuth
// @Param        id  path  string  true  "Bulk dismissal ID"
// @Success      200  {object}  finding.UndoBulkDismissResult
// @Failure      403  {object}  apierror.Error
// @Failure      404  {object}  apierror.Error
// @Failure      409  {object}  apierror.Error
// @Router       /findings/bulk-dismissals/{id}/reopen [post]
func (h *VulnerabilityHandler) UndoBulkDismiss(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id, err := shared.IDFromString(chi.URLParam(r, "id"))
	tenantID, terr := shared.IDFromString(middleware.GetTenantID(ctx))
	userID, uerr := shared.IDFromString(bulkActorID(r))
	if err != nil || terr != nil || uerr != nil {
		apierror.NotFound("Bulk dismissal").WriteJSON(w)
		return
	}
	out, err := h.service.UndoBulkDismiss(ctx, finding.UndoBulkDismissInput{
		TenantID: tenantID, UserID: userID, BulkID: id,
		HasApprovePermission:  middleware.HasPermission(ctx, string(permission.FindingsApprove)),
		HasVerifyPermission:   middleware.HasPermission(ctx, string(permission.FindingsVerify)),
		HasFixApplyPermission: middleware.HasPermission(ctx, string(permission.FindingsFixApply)),
	})
	if err != nil {
		h.writeBulkDismissError(w, err)
		return
	}
	recordConfigAudit(ctx, h.auditService, h.logger, configAuditContext(r),
		auditapp.NewSuccessEvent(auditdom.ActionFindingsBulkDismissUndone, auditdom.ResourceTypeFindingBulkDismissal, out.BulkID).
			WithMetadata("bulk_id", out.BulkID).
			WithMetadata("reopened", len(out.Reopened)).
			WithMetadata("skipped", len(out.Skipped)).
			WithMetadata("group_canceled", out.GroupCanceled).
			WithMessage(fmt.Sprintf("Undid a bulk dismissal: %d findings reopened, %d left as they are", len(out.Reopened), len(out.Skipped))))
	writeJSONOK(w, out)
}

func writeJSONOK(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(v)
}

// bulkActorID is the acting person, by the same id every approve, reject and
// leave-out path compares with (middleware.GetUserID), so the requester of a
// group is never a different identity from the one that decides on it.
func bulkActorID(r *http.Request) string {
	return middleware.GetUserID(r.Context())
}

// parseBulkDismiss reads and checks the request and builds the service
// input; it answers the error itself when it fails.
func (h *VulnerabilityHandler) parseBulkDismiss(w http.ResponseWriter, r *http.Request, routeName string) (finding.BulkDismissInput, bool) {
	var in finding.BulkDismissInput
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBulkDismissBody))
	if err != nil {
		apierror.BadRequest("Request body is too large or unreadable").WriteJSON(w)
		return in, false
	}
	var req BulkDismissRequest
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		apierror.BadRequest("Invalid request body: unknown field, or a value of the wrong type").WriteJSON(w)
		return in, false
	}
	byFilter := req.Filter != nil
	if byFilter == (len(req.FindingIDs) > 0) {
		apierror.ValidationFailed("send finding_ids or filter (with expected_count), not both", nil).WriteJSON(w)
		return in, false
	}
	if len(req.FindingIDs) > finding.MaxBulkDismiss {
		writeBulkDismissTooLarge(w, &finding.BulkDismissTooLargeError{Count: len(req.FindingIDs)})
		return in, false
	}
	if len(req.IdempotencyKey) > 128 || len([]rune(req.Note)) > 2000 || len(req.ClosureReason) > 64 || len(req.Status) > 32 {
		apierror.ValidationFailed("idempotency_key (128), note (2000), closure_reason (64) or status is too long", nil).WriteJSON(w)
		return in, false
	}
	ctx := r.Context()
	tenantID, terr := shared.IDFromString(middleware.GetTenantID(ctx))
	userID, uerr := shared.IDFromString(bulkActorID(r))
	if terr != nil || uerr != nil {
		apierror.Forbidden("A bulk dismiss needs a signed-in user").WriteJSON(w)
		return in, false
	}
	in = finding.BulkDismissInput{
		TenantID: tenantID, UserID: userID, Status: req.Status, ClosureReason: req.ClosureReason, Note: req.Note,
		IdempotencyKey: strings.TrimSpace(req.IdempotencyKey),
		// Who may decide alone comes from the request's authentication only:
		// a person's own session holding findings:approve. A delegated
		// credential (API key, MCP token) never decides alone.
		CanApprove:   requesterMayDecideAlone(ctx),
		ByAutomation: middleware.IsDelegatedCredential(ctx),
	}
	if req.ExpiresAt != nil {
		t, err := time.Parse(time.RFC3339, *req.ExpiresAt)
		if err != nil {
			apierror.ValidationFailed("expires_at must be an RFC 3339 time", nil).WriteJSON(w)
			return in, false
		}
		in.ExpiresAt = &t
	}
	if byFilter {
		if req.ExpectedCount < 1 || req.ExpectedCount > finding.MaxBulkByFilter {
			apierror.ValidationFailed("expected_count must be between 1 and 10000", nil).WriteJSON(w)
			return in, false
		}
		spec, ok := h.bulkSelectionSpec(w, r, req.Filter, routeName)
		if !ok {
			return in, false
		}
		caller := filterCaller(r)
		caller.UserID = userID.String()
		in.Spec, in.Caller, in.ExpectedCount = spec, caller, req.ExpectedCount
		in.FilterHash, in.FilterSummary = filterHash(req.Filter), filterSummary(req.Filter)
	} else {
		in.FindingIDs = make([]shared.ID, 0, len(req.FindingIDs))
		for _, s := range req.FindingIDs {
			id, err := shared.IDFromString(s)
			if err != nil {
				apierror.ValidationFailed("finding_ids must be finding ids", nil).WriteJSON(w)
				return in, false
			}
			in.FindingIDs = append(in.FindingIDs, id)
		}
	}
	in.RequestHash = bulkDismissHash(req)
	return in, true
}

// bulkDismissHash identifies a request for idempotency: every field that
// changes what it does (ids sorted; json.Marshal sorts map keys).
func bulkDismissHash(req BulkDismissRequest) string {
	ids := append([]string(nil), req.FindingIDs...)
	for i := range ids {
		ids[i] = strings.ToLower(strings.TrimSpace(ids[i]))
	}
	sort.Strings(ids)
	b, _ := json.Marshal(BulkDismissRequest{
		FindingIDs: ids, Filter: req.Filter, ExpectedCount: req.ExpectedCount, Status: req.Status,
		ClosureReason: req.ClosureReason, Note: req.Note, ExpiresAt: req.ExpiresAt,
	})
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// filterHash identifies a filter in the audit trail.
func filterHash(f FilterValues) string {
	b, _ := json.Marshal(f)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// filterSummary is a short plain-text form of a filter for the group's
// label ("severity=high,critical; tool_name=semgrep").
func filterSummary(f FilterValues) string {
	keys := make([]string, 0, len(f))
	for k := range f {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, k+"="+strings.Join(f[k], ","))
	}
	out := strings.Join(parts, "; ")
	if r := []rune(out); len(r) > bulkFilterSummaryMax {
		out = string(r[:bulkFilterSummaryMax-1]) + "…"
	}
	return out
}

func writeBulkDismissTooLarge(w http.ResponseWriter, e *finding.BulkDismissTooLargeError) {
	apierror.FromCode(apierror.CodeBulkDismissTooLarge).
		WithDetails(map[string]any{paramCount: e.Count, paramMax: finding.MaxBulkDismiss}).
		WithParams(apierror.Params{paramCount: strconv.Itoa(e.Count), paramMax: strconv.Itoa(finding.MaxBulkDismiss)}).WriteJSON(w)
}

func (h *VulnerabilityHandler) writeBulkDismissError(w http.ResponseWriter, err error) {
	var tooLarge *finding.BulkDismissTooLargeError
	var changed *finding.SelectionChangedError
	switch {
	case errors.As(err, &tooLarge):
		writeBulkDismissTooLarge(w, tooLarge)
	case errors.As(err, &changed):
		apierror.FromCode(apierror.CodeSelectionChanged).
			WithDetails(map[string]any{paramCount: changed.Count}).
			WithParams(apierror.Params{paramCount: strconv.Itoa(changed.Count)}).WriteJSON(w)
	case errors.Is(err, finding.ErrIdempotencyMismatch):
		apierror.FromCode(apierror.CodeIdempotencyKeyReused).WriteJSON(w)
	case middleware.WriteStepUpError(w, err, authapp.StepUpWindow):
	case errors.Is(err, finding.ErrBulkDismissNotFound):
		apierror.NotFound("Bulk dismissal").WriteJSON(w)
	default:
		if _, isFilter := filterspec.AsError(err); isFilter {
			filterquery.WriteError(w, err)
			return
		}
		h.handleServiceError(w, err, "Finding")
	}
}

// auditBulkDismiss writes the audit rows of an applied bulk dismiss: one
// per decision made alone (as a single request writes), and one for the
// bulk (high severity when more than 100 were decided alone).
func (h *VulnerabilityHandler) auditBulkDismiss(r *http.Request, out *finding.BulkDismissResult) {
	for _, a := range out.Applied {
		h.auditApproval(r, auditapp.NewSuccessEvent(auditdom.ActionFindingApprovalSinglePerson, auditdom.ResourceTypeFindingApproval, a.ID.String()).
			WithMetadata("closure_reason", a.ClosureReason.String()).
			WithMetadata("bulk_id", out.BulkID).
			WithMessage("Dismissed a finding alone in a bulk dismiss: the organization's level does not require a second person for it"), a)
	}
	ev := auditapp.NewSuccessEvent(auditdom.ActionFindingsBulkDismissed, auditdom.ResourceTypeFindingBulkDismissal, out.BulkID).
		WithMetadata("bulk_id", out.BulkID).
		WithMetadata("status", out.Status).
		WithMetadata("decided", out.Counts.Decided).
		WithMetadata("grouped", out.Counts.Grouped).
		WithMetadata("skipped", out.Counts.Skipped).
		WithMetadata("budget_overflow", out.Counts.BudgetOverflow).
		WithMessage(fmt.Sprintf("Dismissed findings in bulk: %d decided alone, %d sent for approval, %d skipped",
			out.Counts.Decided, out.Counts.Grouped, out.Counts.Skipped))
	if out.FilterHash != "" {
		ev = ev.WithMetadata("filter_hash", out.FilterHash)
	}
	if out.SourceLabel != "" {
		ev = ev.WithMetadata("source_label", out.SourceLabel)
	}
	if out.Grouped != nil && out.Grouped.BatchID != "" {
		ev = ev.WithMetadata("batch_id", out.Grouped.BatchID)
	}
	if out.Counts.Decided > finding.BulkDismissNoticeAbove {
		ev = ev.WithSeverity(auditdom.SeverityHigh)
	}
	recordConfigAudit(r.Context(), h.auditService, h.logger, configAuditContext(r), ev)
}

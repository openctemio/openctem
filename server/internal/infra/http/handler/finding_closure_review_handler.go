package handler

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/openctemio/openctem/api/internal/app/finding"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/apierror"
)

// Ready to close and Recently auto-closed
// (docs/architecture/finding-verification-plan.md, "Ready to close").

// ClosureProposalResponse is one pending proposal and the finding it would
// close.
type ClosureProposalResponse struct {
	ID           string         `json:"id"`
	FindingID    string         `json:"finding_id"`
	Method       string         `json:"method"`
	Evidence     map[string]any `json:"evidence"`
	ProposedAt   time.Time      `json:"proposed_at"`
	EvidenceAt   time.Time      `json:"evidence_at"`
	FindingTitle string         `json:"finding_title"`
	Severity     string         `json:"severity"`
	Status       string         `json:"status"`
	ToolName     string         `json:"tool_name,omitempty"`
	AssetID      string         `json:"asset_id,omitempty"`
	AssetName    string         `json:"asset_name,omitempty"`
	// Tier is standard, high or critical (critical: severity critical, P0 or KEV).
	Tier string `json:"tier"`
}

// AutoClosedFindingResponse is one finding the platform closed by itself in
// the last seven days.
type AutoClosedFindingResponse struct {
	FindingID    string         `json:"finding_id"`
	FindingTitle string         `json:"finding_title"`
	Severity     string         `json:"severity"`
	ToolName     string         `json:"tool_name,omitempty"`
	AssetID      string         `json:"asset_id,omitempty"`
	AssetName    string         `json:"asset_name,omitempty"`
	Verification string         `json:"verification"`
	ResolvedAt   time.Time      `json:"resolved_at"`
	Evidence     map[string]any `json:"evidence"`
}

// DecideClosureProposalsRequest confirms or dismisses proposals.
type DecideClosureProposalsRequest struct {
	ProposalIDs []string `json:"proposal_ids"`
	// Decision is confirm or dismiss.
	Decision string `json:"decision"`
	// Reason (dismiss only): still_present_manual_check, scan_not_trustworthy,
	// wrong_asset or other (other needs a note).
	Reason string `json:"reason,omitempty"`
	Note   string `json:"note,omitempty"`
}

// DecideClosureProposalsResponse says what was decided.
type DecideClosureProposalsResponse struct {
	Applied []string `json:"applied"`
	// Skipped maps a proposal id to not_found or not_eligible.
	Skipped map[string]string `json:"skipped"`
	// FindingIDs are the findings closed (confirm) or kept open (dismiss).
	FindingIDs []string `json:"finding_ids"`
}

// ReopenNotFixedRequest is the optional note of a "Reopen: not fixed".
type ReopenNotFixedRequest struct {
	Note string `json:"note,omitempty"`
}

// ListClosureProposals handles GET /api/v1/findings/closure/proposals.
// @Summary      List Ready to close proposals
// @Description  Pending proposals to close a finding (the organization's closing mode or the tier rule sent the close to a person), in the caller's data scope, critical first. A proposal whose finding was seen again or left the open statuses is not listed.
// @Tags         Findings
// @Produce      json
// @Param        page      query     int  false  "Page"
// @Param        per_page  query     int  false  "Per page (max 100)"
// @Success      200  {object}  ListResponse[ClosureProposalResponse]
// @Failure      400  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /findings/closure/proposals [get]
func (h *VulnerabilityHandler) ListClosureProposals(w http.ResponseWriter, r *http.Request) {
	paging, ok := listPageMax(w, r, 50, 100)
	if !ok {
		return
	}
	res, err := h.service.ListClosureProposals(r.Context(), middleware.GetTenantID(r.Context()), paging)
	if err != nil {
		h.handleServiceError(w, err, "closure proposals")
		return
	}
	items := make([]ClosureProposalResponse, 0, len(res.Data))
	for _, p := range res.Data {
		item := ClosureProposalResponse{
			ID: p.ID.String(), FindingID: p.FindingID.String(), Method: string(p.Method), Evidence: p.Evidence,
			ProposedAt: p.ProposedAt, EvidenceAt: p.EvidenceAt, FindingTitle: p.Title, Severity: string(p.Severity),
			Status: string(p.Status), ToolName: p.ToolName, AssetName: p.AssetName, Tier: string(p.Tier),
		}
		if item.Evidence == nil {
			item.Evidence = map[string]any{}
		}
		if !p.AssetID.IsZero() {
			item.AssetID = p.AssetID.String()
		}
		items = append(items, item)
	}
	writeJSON(w, http.StatusOK, ListResponse[ClosureProposalResponse]{
		Data: items, Total: res.Total, Page: res.Page, PerPage: res.PerPage, TotalPages: res.TotalPages,
	})
}

// DecideClosureProposals handles POST /api/v1/findings/closure/proposals/decide.
// @Summary      Confirm or dismiss Ready to close proposals
// @Description  confirm closes each finding as fixed, verified by the proposal's method, after re-checking that it is still open and was not seen after the evidence; dismiss keeps it open with a reason. Up to 200 proposals; every confirm needs a recent re-authentication (403 STEP_UP_REQUIRED). Proposals outside the caller's data scope are skipped as not_found. Audited.
// @Tags         Findings
// @Accept       json
// @Produce      json
// @Param        body  body      DecideClosureProposalsRequest  true  "Decision"
// @Success      200   {object}  DecideClosureProposalsResponse
// @Failure      400   {object}  apierror.Error
// @Failure      403   {object}  apierror.Error
// @Security     BearerAuth
// @Router       /findings/closure/proposals/decide [post]
func (h *VulnerabilityHandler) DecideClosureProposals(w http.ResponseWriter, r *http.Request) {
	var req DecideClosureProposalsRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}
	res, err := h.service.DecideClosureProposals(r.Context(), finding.DecideClosureInput{
		TenantID: middleware.GetTenantID(r.Context()), ActorID: middleware.GetUserID(r.Context()),
		ActorName: middleware.GetUsername(r.Context()), ProposalIDs: req.ProposalIDs,
		Decision: finding.ClosureDecisionKind(req.Decision), Reason: req.Reason, Note: req.Note,
	})
	if err != nil {
		h.handleServiceError(w, err, "closure proposals")
		return
	}
	out := DecideClosureProposalsResponse{
		Applied: make([]string, 0, len(res.Applied)), Skipped: make(map[string]string, len(res.Skipped)),
		FindingIDs: make([]string, 0, len(res.Findings)),
	}
	for _, id := range res.Applied {
		out.Applied = append(out.Applied, id.String())
	}
	for id, why := range res.Skipped {
		out.Skipped[id.String()] = why
	}
	for _, id := range res.Findings {
		out.FindingIDs = append(out.FindingIDs, id.String())
	}
	writeJSON(w, http.StatusOK, out)
}

// ListRecentlyAutoClosed handles GET /api/v1/findings/closure/auto-closed.
// @Summary      List findings closed automatically in the last seven days
// @Description  Findings the platform closed by itself (no person) in the last seven days and still closed, newest first, in the caller's data scope, with the evidence of the close (scanner, scan, profile).
// @Tags         Findings
// @Produce      json
// @Param        page      query     int  false  "Page"
// @Param        per_page  query     int  false  "Per page (max 100)"
// @Success      200  {object}  ListResponse[AutoClosedFindingResponse]
// @Failure      400  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /findings/closure/auto-closed [get]
func (h *VulnerabilityHandler) ListRecentlyAutoClosed(w http.ResponseWriter, r *http.Request) {
	paging, ok := listPageMax(w, r, 50, 100)
	if !ok {
		return
	}
	res, err := h.service.ListRecentlyAutoClosed(r.Context(), middleware.GetTenantID(r.Context()), paging)
	if err != nil {
		h.handleServiceError(w, err, "auto-closed findings")
		return
	}
	items := make([]AutoClosedFindingResponse, 0, len(res.Data))
	for _, f := range res.Data {
		item := AutoClosedFindingResponse{
			FindingID: f.FindingID.String(), FindingTitle: f.Title, Severity: string(f.Severity), ToolName: f.ToolName,
			AssetName: f.AssetName, Verification: f.Verification, ResolvedAt: f.ResolvedAt, Evidence: f.Evidence,
		}
		if item.Evidence == nil {
			item.Evidence = map[string]any{}
		}
		if !f.AssetID.IsZero() {
			item.AssetID = f.AssetID.String()
		}
		items = append(items, item)
	}
	writeJSON(w, http.StatusOK, ListResponse[AutoClosedFindingResponse]{
		Data: items, Total: res.Total, Page: res.Page, PerPage: res.PerPage, TotalPages: res.TotalPages,
	})
}

// ReopenAutoClosedNotFixed handles POST /api/v1/findings/{id}/reopen.
// @Summary      Reopen a finding closed automatically: not fixed
// @Description  Reopens (as confirmed) a finding the platform closed by itself in the last seven days, recording that the close was wrong. Not counted as a regression. 404 when the finding is not such a finding in the caller's data scope. Audited.
// @Tags         Findings
// @Accept       json
// @Param        id    path  string                 true   "Finding ID"
// @Param        body  body  ReopenNotFixedRequest  false  "Note"
// @Success      204
// @Failure      404  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /findings/{id}/reopen [post]
func (h *VulnerabilityHandler) ReopenAutoClosedNotFixed(w http.ResponseWriter, r *http.Request) {
	var req ReopenNotFixedRequest
	if r.ContentLength != 0 {
		dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&req); err != nil {
			apierror.BadRequest("Invalid request body").WriteJSON(w)
			return
		}
	}
	ctx := r.Context()
	if err := h.service.ReopenAutoClosedNotFixed(ctx, middleware.GetTenantID(ctx), chi.URLParam(r, "id"),
		middleware.GetUserID(ctx), middleware.GetUsername(ctx), req.Note); err != nil {
		h.handleServiceError(w, err, "finding")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

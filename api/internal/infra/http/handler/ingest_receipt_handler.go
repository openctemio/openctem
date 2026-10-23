package handler

// Receipts of uploads and sensor runs (docs/rfcs/RFC-122-ingest-receipts.md).
//
// A receipt's counts are organization-wide: a run that covered assets outside
// a restricted member's data scope counts findings that member cannot see. A
// caller with the organization view (unrestricted data scope, or
// dashboards:org:view) reads every receipt; anyone else reads only the
// receipts they started (their own uploads, which ran under their scope);
// another receipt is 404. The per-finding actions are filtered by the
// caller's data scope and the pentest visibility rule for everyone.

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/openctemio/openctem/api/internal/app/datascope"
	"github.com/openctemio/openctem/api/internal/app/findingimport"
	"github.com/openctemio/openctem/api/internal/app/ingestqueue"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/apierror"
	"github.com/openctemio/openctem/api/pkg/domain/ingestreceipt"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/filterspec"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/pagination"
)

// IngestReceiptReader reads receipts (postgres.IngestReceiptRepository).
type IngestReceiptReader interface {
	Get(ctx context.Context, tenantID, id shared.ID) (*ingestreceipt.Receipt, error)
	List(ctx context.Context, tenantID shared.ID, f ingestreceipt.Filter, p pagination.Pagination) ([]*ingestreceipt.Receipt, int64, error)
	ActionCountsBySeverity(ctx context.Context, tenantID, receiptID shared.ID, scope *shared.DataScope) (map[string]map[string]int, error)
	ListActions(ctx context.Context, tenantID, receiptID shared.ID, action ingestreceipt.Action, scope *shared.DataScope, p pagination.Pagination) ([]ingestreceipt.ActionRow, int64, error)
	FindingActions(ctx context.Context, tenantID, findingID shared.ID, limit int) ([]ingestreceipt.FindingAction, error)
}

// maxFindingReceipts bounds the receipts listed for one finding.
const maxFindingReceipts = 20

// IngestReceiptHandler serves the receipt reads.
type IngestReceiptHandler struct {
	repo   IngestReceiptReader
	scope  *datascope.Enforcer
	logger *logger.Logger
	// imports reads the per-file results of a committed upload the ingest
	// worker imported (nil: the result read answers 404).
	imports ImportResults
}

// ImportResults reads a committed upload's state (findingimport.Service).
type ImportResults interface {
	UploadResult(ctx context.Context, tenantID, receiptID shared.ID, wait time.Duration) (*findingimport.UploadState, error)
}

// SetImportResults wires the result read of committed uploads.
func (h *IngestReceiptHandler) SetImportResults(r ImportResults) { h.imports = r }

// NewIngestReceiptHandler creates the handler.
func NewIngestReceiptHandler(repo IngestReceiptReader, scope *datascope.Enforcer, log *logger.Logger) *IngestReceiptHandler {
	return &IngestReceiptHandler{repo: repo, scope: scope, logger: log.With("handler", "ingest_receipt")}
}

// ReceiptSource names what a receipt counts.
type ReceiptSource struct {
	Kind string `json:"kind"`
	Ref  string `json:"ref"`
}

// ReceiptCoverage says whether the source proved coverage of a scope.
type ReceiptCoverage struct {
	// Type is partial or full; only full can close findings.
	Type string `json:"type"`
	// Note is the coverage decision: resolved, held or dry_run.
	Note string `json:"note,omitempty"`
}

// ReceiptCounts is what the source did to the findings.
type ReceiptCounts struct {
	Created     int `json:"created"`
	Updated     int `json:"updated"`
	Reactivated int `json:"reactivated"`
	Closed      int `json:"closed"`
	// Untouched is null when no scope was declared.
	Untouched  *int `json:"untouched"`
	Skipped    int  `json:"skipped"`
	Failed     int  `json:"failed"`
	Suppressed int  `json:"suppressed"`
}

// ReceiptError is one problem: an index and a fixed code.
type ReceiptError struct {
	Index int    `json:"index"`
	Code  string `json:"code"`
}

// ReceiptResponse is one receipt.
type ReceiptResponse struct {
	ID          string          `json:"id"`
	Status      string          `json:"status"`
	Source      ReceiptSource   `json:"source"`
	Tool        string          `json:"tool,omitempty"`
	Format      string          `json:"format,omitempty"`
	Coverage    ReceiptCoverage `json:"coverage"`
	Counts      ReceiptCounts   `json:"counts"`
	Reports     int             `json:"reports"`
	Received    int             `json:"received"`
	Assets      ReceiptAssets   `json:"assets"`
	CreatedBy   string          `json:"created_by,omitempty"`
	Errors      []ReceiptError  `json:"errors"`
	Truncated   bool            `json:"actions_truncated"`
	StartedAt   time.Time       `json:"started_at"`
	UpdatedAt   time.Time       `json:"updated_at"`
	FinishedAt  *time.Time      `json:"finished_at,omitempty"`
	Components  int             `json:"components,omitempty"`
	Statements  int             `json:"statements,omitempty"`
	VEXStored   int             `json:"vex_stored,omitempty"`
	VEXRequests int             `json:"vex_requested,omitempty"`
	// BySeverity (detail only) counts the actions per action and finding
	// severity, over the findings the caller may see.
	BySeverity map[string]map[string]int `json:"by_severity,omitempty"`
}

// ReceiptAssets counts the assets the source created and updated.
type ReceiptAssets struct {
	Created int `json:"created"`
	Updated int `json:"updated"`
}

// ReceiptActionResponse is one finding a receipt acted on.
type ReceiptActionResponse struct {
	FindingID string    `json:"finding_id"`
	Action    string    `json:"action"`
	Title     string    `json:"title"`
	Severity  string    `json:"severity"`
	At        time.Time `json:"at"`
}

// FindingReceiptResponse is one receipt that acted on a finding.
type FindingReceiptResponse struct {
	ReceiptID string        `json:"receipt_id"`
	Source    ReceiptSource `json:"source"`
	Tool      string        `json:"tool,omitempty"`
	Action    string        `json:"action"`
	At        time.Time     `json:"at"`
}

// FindingReceiptsResponse lists the receipts of one finding.
type FindingReceiptsResponse struct {
	Data []FindingReceiptResponse `json:"data"`
}

func toReceiptResponse(rec *ingestreceipt.Receipt) ReceiptResponse {
	out := ReceiptResponse{
		ID: rec.ID.String(), Status: rec.Status, Source: ReceiptSource{Kind: string(rec.SourceKind), Ref: rec.SourceRef},
		Tool: rec.ToolName, Format: rec.Format, Coverage: ReceiptCoverage{Type: rec.Coverage, Note: rec.CoverageNote},
		Counts: ReceiptCounts{Created: rec.Counts.Created, Updated: rec.Counts.StillDetected, Reactivated: rec.Counts.Reopened,
			Closed: rec.Counts.Closed, Untouched: rec.Counts.Untouched, Skipped: rec.Counts.Skipped, Failed: rec.Counts.Failed,
			Suppressed: rec.Counts.Suppressed},
		Reports: rec.Reports, Received: rec.Received, Assets: ReceiptAssets{Created: rec.AssetsCreated, Updated: rec.AssetsUpdated},
		Errors: make([]ReceiptError, 0, len(rec.Errors)), Truncated: rec.ActionsTruncated, StartedAt: rec.CreatedAt,
		UpdatedAt: rec.UpdatedAt, FinishedAt: rec.FinishedAt, Components: rec.Components, Statements: rec.Statements,
		VEXStored: rec.VEXStored, VEXRequests: rec.VEXRequested,
	}
	if rec.ActorUserID != nil {
		out.CreatedBy = rec.ActorUserID.String()
	}
	for _, e := range rec.Errors {
		out.Errors = append(out.Errors, ReceiptError{Index: e.Index, Code: e.Code})
	}
	return out
}

// viewer is who reads receipts: the tenant, the caller's data scope (nil:
// unrestricted) and whether they see the organization's receipts.
type viewer struct {
	tenant  shared.ID
	scope   *shared.DataScope
	orgView bool
	userID  shared.ID
}

// viewerOf resolves the caller. It fails closed: an unresolvable scope is
// an error, never an organization view.
func (h *IngestReceiptHandler) viewerOf(r *http.Request) (viewer, error) {
	tid, err := shared.IDFromString(middleware.MustGetTenantID(r.Context()))
	if err != nil {
		return viewer{}, shared.ErrValidation
	}
	scope, orgWide, err := h.scope.ViewerScope(r.Context(), tid)
	if err != nil {
		return viewer{}, err
	}
	v := viewer{tenant: tid, orgView: scope == nil || orgWide}
	if !orgWide {
		v.scope = scope
	} else if s, err := h.scope.ResolveStrict(r.Context(), tid); err == nil {
		// An organization viewer still reads per-finding rows in their own
		// scope only.
		v.scope = s
	} else {
		return viewer{}, err
	}
	v.userID, _ = shared.IDFromString(middleware.GetUserID(r.Context()))
	return v, nil
}

// visible reports whether the viewer may read the receipt.
func (v viewer) visible(rec *ingestreceipt.Receipt) bool {
	if v.orgView {
		return true
	}
	return rec.ActorUserID != nil && !v.userID.IsZero() && *rec.ActorUserID == v.userID
}

// receiptListParams are the parameters GET /findings/imports accepts.
var receiptListParams = map[string]bool{"source_kind": true, "source_ref": true, "page": true, "per_page": true}

// receiptActionParams are the parameters GET /findings/imports/{id}/actions accepts.
var receiptActionParams = map[string]bool{"action": true, "page": true, "per_page": true}

// strictParams refuses a parameter the endpoint does not know with 400
// INVALID_FILTER (a misspelled filter must not widen the result), and parses
// page and per_page (per_page capped at 100).
func strictParams(w http.ResponseWriter, r *http.Request, known map[string]bool) (pagination.Pagination, bool) {
	q := r.URL.Query()
	var details []filterspec.Detail
	for name := range q {
		if !known[name] {
			details = append(details, filterspec.Detail{Param: filterspec.SafeName(name), Reason: "unknown parameter"})
		}
	}
	page, perPage := 1, 20
	for _, p := range []struct {
		name string
		dst  *int
	}{{"page", &page}, {"per_page", &perPage}} {
		if s := q.Get(p.name); s != "" {
			n, err := strconv.Atoi(s)
			if err != nil || n < 1 {
				details = append(details, filterspec.Detail{Param: p.name, Reason: "must be a positive integer"})
				continue
			}
			*p.dst = n
		}
	}
	if len(details) > 0 {
		(&filterspec.Error{Details: details}).APIError().WriteJSON(w)
		return pagination.Pagination{}, false
	}
	return pagination.New(page, perPage), true
}

func (h *IngestReceiptHandler) writeViewerError(w http.ResponseWriter, err error) {
	if errors.Is(err, shared.ErrValidation) {
		apierror.BadRequest("invalid tenant").WriteJSON(w)
		return
	}
	h.logger.Error("receipts: resolve data scope", "error", err)
	apierror.InternalServerError("could not read receipts").WriteJSON(w)
}

// List handles GET /api/v1/findings/imports.
//
// @Summary      List import and run receipts
// @Description  Receipts of uploads and sensor runs, newest first: what each did to the organization's findings (created, updated = still detected, reactivated, closed, untouched, skipped, failed). A caller without the organization view (unrestricted data scope or dashboards:org:view) sees only the uploads they made. Unknown parameters are refused (400 INVALID_FILTER); per_page is capped at 100.
// @Tags         Findings
// @Produce      json
// @Param        source_kind  query  string  false  "upload, scan_run, command, ci_run, connector or sensor"
// @Param        source_ref   query  string  false  "The run, command or connector run id (an upload's receipt id)"
// @Param        page         query  int     false  "Page (from 1)"
// @Param        per_page     query  int     false  "Page size (at most 100)"
// @Success      200  {object}  ListResponse[ReceiptResponse]
// @Failure      400  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /findings/imports [get]
func (h *IngestReceiptHandler) List(w http.ResponseWriter, r *http.Request) {
	p, ok := strictParams(w, r, receiptListParams)
	if !ok {
		return
	}
	v, err := h.viewerOf(r)
	if err != nil {
		h.writeViewerError(w, err)
		return
	}
	q := r.URL.Query()
	f := ingestreceipt.Filter{SourceKind: ingestreceipt.SourceKind(q.Get("source_kind")), SourceRef: q.Get("source_ref")}
	if f.SourceKind != "" && !f.SourceKind.IsValid() {
		(&filterspec.Error{Details: []filterspec.Detail{{Param: "source_kind", Reason: "must be upload, scan_run, command, ci_run, connector or sensor"}}}).APIError().WriteJSON(w)
		return
	}
	if len(f.SourceRef) > 128 {
		(&filterspec.Error{Details: []filterspec.Detail{{Param: "source_ref", Reason: "at most 128 characters"}}}).APIError().WriteJSON(w)
		return
	}
	if !v.orgView {
		// Only the caller's own uploads; a caller with no user (a key
		// without one) matches nothing.
		uid := v.userID
		f.ActorUserID = &uid
	}
	recs, total, err := h.repo.List(r.Context(), v.tenant, f, p)
	if err != nil {
		h.logger.Error("receipts: list", "error", err)
		apierror.InternalServerError("could not read receipts").WriteJSON(w)
		return
	}
	data := make([]ReceiptResponse, 0, len(recs))
	for _, rec := range recs {
		data = append(data, toReceiptResponse(rec))
	}
	res := pagination.NewResult(data, total, p)
	writeJSON(w, http.StatusOK, ListResponse[ReceiptResponse]{Data: res.Data, Total: res.Total, Page: res.Page,
		PerPage: res.PerPage, TotalPages: res.TotalPages})
}

// loadVisible reads the receipt named in the path if the viewer may see it.
func (h *IngestReceiptHandler) loadVisible(w http.ResponseWriter, r *http.Request) (viewer, *ingestreceipt.Receipt, bool) {
	v, err := h.viewerOf(r)
	if err != nil {
		h.writeViewerError(w, err)
		return viewer{}, nil, false
	}
	id, err := shared.IDFromString(chi.URLParam(r, "id"))
	if err != nil {
		apierror.NotFound("Receipt").WriteJSON(w)
		return viewer{}, nil, false
	}
	rec, err := h.repo.Get(r.Context(), v.tenant, id)
	if errors.Is(err, shared.ErrNotFound) || (err == nil && !v.visible(rec)) {
		apierror.NotFound("Receipt").WriteJSON(w)
		return viewer{}, nil, false
	}
	if err != nil {
		h.logger.Error("receipts: get", "error", err)
		apierror.InternalServerError("could not read the receipt").WriteJSON(w)
		return viewer{}, nil, false
	}
	return v, rec, true
}

// Get handles GET /api/v1/findings/imports/{id}.
//
// @Summary      Get an import or run receipt
// @Description  One receipt, with its actions counted per action and finding severity over the findings the caller may see. Another tenant's receipt, and another member's receipt for a caller without the organization view, is 404.
// @Tags         Findings
// @Produce      json
// @Param        id   path  string  true  "Receipt id"
// @Success      200  {object}  ReceiptResponse
// @Failure      404  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /findings/imports/{id} [get]
func (h *IngestReceiptHandler) Get(w http.ResponseWriter, r *http.Request) {
	if len(r.URL.Query()) > 0 {
		if _, ok := strictParams(w, r, map[string]bool{}); !ok {
			return
		}
	}
	v, rec, ok := h.loadVisible(w, r)
	if !ok {
		return
	}
	by, err := h.repo.ActionCountsBySeverity(h.scope.WithFindingViewer(r.Context()), v.tenant, rec.ID, v.scope)
	if err != nil {
		h.logger.Error("receipts: counts by severity", "error", err)
		apierror.InternalServerError("could not read the receipt").WriteJSON(w)
		return
	}
	out := toReceiptResponse(rec)
	out.BySeverity = by
	writeJSON(w, http.StatusOK, out)
}

// Actions handles GET /api/v1/findings/imports/{id}/actions.
//
// @Summary      List what a receipt did to each finding
// @Description  The findings a receipt created, saw again (still_detected), reopened or closed, newest first, limited to the findings the caller may see. Unknown parameters are refused (400 INVALID_FILTER); per_page is capped at 100.
// @Tags         Findings
// @Produce      json
// @Param        id        path   string  true   "Receipt id"
// @Param        action    query  string  false  "created, still_detected, reopened or closed"
// @Param        page      query  int     false  "Page (from 1)"
// @Param        per_page  query  int     false  "Page size (at most 100)"
// @Success      200  {object}  ListResponse[ReceiptActionResponse]
// @Failure      400  {object}  apierror.Error
// @Failure      404  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /findings/imports/{id}/actions [get]
func (h *IngestReceiptHandler) Actions(w http.ResponseWriter, r *http.Request) {
	p, ok := strictParams(w, r, receiptActionParams)
	if !ok {
		return
	}
	action := ingestreceipt.Action(r.URL.Query().Get("action"))
	if action != "" && !action.IsValid() {
		(&filterspec.Error{Details: []filterspec.Detail{{Param: "action", Reason: "must be created, still_detected, reopened or closed"}}}).APIError().WriteJSON(w)
		return
	}
	v, rec, ok := h.loadVisible(w, r)
	if !ok {
		return
	}
	rows, total, err := h.repo.ListActions(h.scope.WithFindingViewer(r.Context()), v.tenant, rec.ID, action, v.scope, p)
	if err != nil {
		h.logger.Error("receipts: actions", "error", err)
		apierror.InternalServerError("could not read the receipt").WriteJSON(w)
		return
	}
	data := make([]ReceiptActionResponse, 0, len(rows))
	for _, row := range rows {
		data = append(data, ReceiptActionResponse{FindingID: row.FindingID.String(), Action: string(row.Action),
			Title: row.Title, Severity: row.Severity, At: row.At})
	}
	res := pagination.NewResult(data, total, p)
	writeJSON(w, http.StatusOK, ListResponse[ReceiptActionResponse]{Data: res.Data, Total: res.Total, Page: res.Page,
		PerPage: res.PerPage, TotalPages: res.TotalPages})
}

// FindingReceipts handles GET /api/v1/findings/{id}/imports.
//
// @Summary      List the receipts that acted on a finding
// @Description  The newest uploads and runs (at most 20) that created, saw again, reopened or closed the finding: the receipt id, its source, tool, the action and when. Out of the caller's data scope: 404.
// @Tags         Findings
// @Produce      json
// @Param        id   path  string  true  "Finding id"
// @Success      200  {object}  FindingReceiptsResponse
// @Failure      404  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /findings/{id}/imports [get]
func (h *IngestReceiptHandler) FindingReceipts(w http.ResponseWriter, r *http.Request) {
	tid, err := shared.IDFromString(middleware.MustGetTenantID(r.Context()))
	if err != nil {
		apierror.BadRequest("invalid tenant").WriteJSON(w)
		return
	}
	fid, err := shared.IDFromString(chi.URLParam(r, "id"))
	if err != nil {
		apierror.NotFound("Finding").WriteJSON(w)
		return
	}
	if err := h.scope.AssertFinding(r.Context(), tid, fid); err != nil {
		apierror.NotFound("Finding").WriteJSON(w)
		return
	}
	rows, err := h.repo.FindingActions(r.Context(), tid, fid, maxFindingReceipts)
	if err != nil {
		h.logger.Error("receipts: finding receipts", "error", err)
		apierror.InternalServerError("could not read the finding's receipts").WriteJSON(w)
		return
	}
	out := FindingReceiptsResponse{Data: make([]FindingReceiptResponse, 0, len(rows))}
	for _, fa := range rows {
		out.Data = append(out.Data, FindingReceiptResponse{ReceiptID: fa.ReceiptID.String(),
			Source: ReceiptSource{Kind: string(fa.SourceKind), Ref: fa.SourceRef}, Tool: fa.ToolName,
			Action: string(fa.Action), At: fa.At})
	}
	writeJSON(w, http.StatusOK, out)
}

// Result handles GET /api/v1/findings/imports/{id}/result.
//
// @Summary      Per-file results of a committed upload
// @Description  A committed upload is imported by the ingest worker. This read answers its state (queued, processing, applied or failed with a fixed error_code) and, once applied, the per-file results the upload used to answer with, and its receipt. wait=N (seconds, at most 10) waits for the import to finish first. Visible to the same callers as the receipt (another member's upload is 404 without the organization view).
// @Tags         Findings
// @Produce      json
// @Param        id    path   string  true   "Receipt id"
// @Param        wait  query  int     false  "Seconds to wait for the import to finish (at most 10)"
// @Success      200  {object}  FindingImportResponse
// @Failure      400  {object}  apierror.Error
// @Failure      404  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /findings/imports/{id}/result [get]
func (h *IngestReceiptHandler) Result(w http.ResponseWriter, r *http.Request) {
	if _, ok := strictParams(w, r, map[string]bool{"wait": true}); !ok {
		return
	}
	v, rec, ok := h.loadVisible(w, r)
	if !ok {
		return
	}
	if h.imports == nil || rec.SourceKind != ingestreceipt.SourceUpload {
		apierror.NotFound("Import result").WriteJSON(w)
		return
	}
	st, err := h.imports.UploadResult(r.Context(), v.tenant, rec.ID, ingestqueue.ClampWait(r.URL.Query().Get("wait")))
	if errors.Is(err, shared.ErrNotFound) {
		// An upload imported before uploads were queued has no job: its
		// receipt is all there is.
		rr := toReceiptResponse(rec)
		writeJSON(w, http.StatusOK, FindingImportResponse{ReceiptID: rec.ID.String(), Status: string(ingestqueue.StatusApplied),
			Receipt: &rr, Files: []ImportFileResponse{}})
		return
	}
	if err != nil {
		h.logger.Error("receipts: import result", "error", err)
		apierror.InternalServerError("could not read the import").WriteJSON(w)
		return
	}
	out := FindingImportResponse{ReceiptID: rec.ID.String(), Status: string(st.Status), ErrorCode: st.ErrorCode,
		Files: make([]ImportFileResponse, 0, len(st.Files))}
	for i := range st.Files {
		out.Files = append(out.Files, toImportFileResponse(&st.Files[i]))
	}
	// The receipt as it stands after the wait.
	if fresh, err := h.repo.Get(r.Context(), v.tenant, rec.ID); err == nil {
		rec = fresh
	}
	rr := toReceiptResponse(rec)
	out.Receipt = &rr
	writeJSON(w, http.StatusOK, out)
}

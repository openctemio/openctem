package handler

import (
	"context"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/openctemio/ctis"
	"github.com/openctemio/ctis/importer"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/internal/app/datascope"
	"github.com/openctemio/openctem/api/internal/app/findingimport"
	"github.com/openctemio/openctem/api/internal/app/ingest"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/apierror"
	auditdom "github.com/openctemio/openctem/api/pkg/domain/audit"
	"github.com/openctemio/openctem/api/pkg/domain/permission"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// Upload limits of POST /findings/import.
const (
	// MaxFindingImportBody bounds the whole multipart body.
	MaxFindingImportBody = 110 << 20
	// maxImportKB bounds the Qualys KnowledgeBase companion (read into
	// memory: the parser needs it before the detections).
	maxImportKB = 64 << 20
	// maxImportFiles bounds the file parts of one request.
	maxImportFiles = 10
	// findingImportTimeout bounds the work of one request.
	findingImportTimeout = 10 * time.Minute
	// maxAuditedImportIDs bounds the finding ids an audit record lists.
	maxAuditedImportIDs = 100
)

// FindingImportHandler serves POST /api/v1/findings/import.
type FindingImportHandler struct {
	svc *findingimport.Service
	// actorOf resolves the uploader's data scope: nil is unrestricted.
	actorOf func(ctx context.Context, tenantID shared.ID) (ingest.ActorScope, error)
	audit   *auditapp.AuditService
	logger  *logger.Logger
	// tempDir is where an uploaded archive is spooled ("" = os.TempDir()).
	tempDir string
	// maxBody bounds the request body (0 = MaxFindingImportBody).
	maxBody int64
}

// NewFindingImportHandler creates the handler. Without a data scope
// enforcer every upload is refused (fail closed).
func NewFindingImportHandler(svc *findingimport.Service, ds *datascope.Enforcer, audit *auditapp.AuditService, log *logger.Logger) *FindingImportHandler {
	h := &FindingImportHandler{svc: svc, audit: audit, logger: log}
	if ds != nil {
		h.actorOf = func(ctx context.Context, tenantID shared.ID) (ingest.ActorScope, error) {
			scope, err := ds.Resolve(ctx, tenantID)
			if err != nil || scope == nil {
				return nil, err
			}
			return uploaderScope{enforcer: ds, scope: scope}, nil
		}
	}
	return h
}

// uploaderScope is the data scope of a person uploading a report, as the
// ingest service consumes it.
type uploaderScope struct {
	enforcer *datascope.Enforcer
	scope    *shared.DataScope
}

func (u uploaderScope) AssetsInScope(ctx context.Context, ids []shared.ID) ([]shared.ID, error) {
	admit, err := u.enforcer.Filter(ctx, u.scope, ids)
	if err != nil {
		return nil, err
	}
	out := make([]shared.ID, 0, len(ids))
	for _, id := range ids {
		if admit(id) {
			out = append(out, id)
		}
	}
	return out, nil
}

// SetActorResolver replaces how the uploader's data scope is resolved (nil
// result = unrestricted). The constructor wires the data scope enforcer;
// tests and embedders without one use this.
func (h *FindingImportHandler) SetActorResolver(fn func(ctx context.Context, tenantID shared.ID) (ingest.ActorScope, error)) {
	h.actorOf = fn
}

// FindingImportResponse is the result of an import or a preview.
type FindingImportResponse struct {
	SessionID string `json:"session_id"`
	DryRun    bool   `json:"dry_run"`
	// How VEX documents act: off (stored only), dry_run (counted), enforce
	// (not_affected closes findings).
	VEXMode string `json:"vex_mode"`
	// Whether a not_affected statement of this upload may close findings
	// (enforce mode and the uploader holds findings:approve).
	VEXCanClose      bool                 `json:"vex_can_close"`
	Files            []ImportFileResponse `json:"files"`
	SupportedFormats []string             `json:"supported_formats"`
}

// ImportFileResponse is the outcome of one file.
type ImportFileResponse struct {
	// ImportID is the record of a committed file: the producer of the
	// findings (scan_id) and assets (import_id) it wrote. Empty in a preview.
	ImportID string               `json:"import_id,omitempty"`
	Name     string               `json:"name"`
	Format   string               `json:"format,omitempty"`
	Error    *ImportFileError     `json:"error,omitempty"`
	Stats    ImportStats          `json:"stats"`
	Issues   []ImportIssue        `json:"issues,omitempty"`
	Unmapped []string             `json:"unmapped,omitempty"`
	VEX      *ImportVEXSummary    `json:"vex,omitempty"`
	Ingest   *ImportIngestSummary `json:"ingest,omitempty"`
}

// ImportFileError is why a file could not be imported.
type ImportFileError struct {
	Kind    string `json:"kind"`
	Message string `json:"message"`
	Line    int    `json:"line,omitempty"`
	Column  int    `json:"column,omitempty"`
}

// ImportStats counts what a file held.
type ImportStats struct {
	Records    int            `json:"records"`
	Assets     int            `json:"assets"`
	Findings   int            `json:"findings"`
	Components int            `json:"components"`
	Statements int            `json:"statements"`
	Skipped    int            `json:"skipped"`
	BySeverity map[string]int `json:"by_severity,omitempty"`
}

// ImportIssue is a problem at a place in a file.
type ImportIssue struct {
	Line    int    `json:"line,omitempty"`
	Column  int    `json:"column,omitempty"`
	Path    string `json:"path,omitempty"`
	Message string `json:"message"`
}

// ImportVEXSummary is what the VEX statements of a file did or would do.
type ImportVEXSummary struct {
	Statements  int    `json:"statements"`
	Unmatchable int    `json:"unmatchable"`
	Matched     int    `json:"matched"`
	Stored      int    `json:"stored"`
	Closed      int    `json:"closed"`
	WouldClose  int    `json:"would_close"`
	Mode        string `json:"mode"`
}

// ImportIngestSummary is what the ingest of a file changed.
type ImportIngestSummary struct {
	AssetsCreated           int      `json:"assets_created"`
	AssetsUpdated           int      `json:"assets_updated"`
	AssetsSkippedOutOfScope int      `json:"assets_skipped_out_of_scope"`
	FindingsCreated         int      `json:"findings_created"`
	FindingsUpdated         int      `json:"findings_updated"`
	FindingsSkipped         int      `json:"findings_skipped"`
	ComponentsCreated       int      `json:"components_created"`
	ComponentsUpdated       int      `json:"components_updated"`
	Errors                  []string `json:"errors,omitempty"`
}

// Import handles POST /api/v1/findings/import.
//
// @Summary      Import results from another tool
// @Description  Multipart upload of an exported file (Nessus .nessus, Qualys detection XML with an optional KnowledgeBase part, CycloneDX, SPDX, OSV results, CSAF, OpenVEX, DefectDojo Generic Findings JSON) or a ZIP of them. The format is detected from the content. With dry_run=true the files are only parsed and counted. The import runs with the uploader's rights: findings land only on assets in the uploader's data scope, nothing is auto-resolved, and a VEX not_affected statement closes findings only under INGEST_VEX=enforce for an uploader holding findings:approve. Send the knowledge_base part before the file part.
// @Tags         Findings
// @Accept       multipart/form-data
// @Produce      json
// @Param        file            formData  file    true   "Exported file or ZIP archive"
// @Param        knowledge_base  formData  file    false  "Qualys KnowledgeBase XML (before file)"
// @Param        dry_run         query     bool    false  "Parse and count only"
// @Param        format          query     string  false  "Force the format of a single file"
// @Param        min_severity    query     string  false  "Drop findings below: info, low, medium, high, critical"
// @Success      200  {object}  FindingImportResponse
// @Failure      400  {object}  apierror.Error
// @Failure      413  {object}  apierror.Error
// @Failure      429  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /findings/import [post]
func (h *FindingImportHandler) Import(w http.ResponseWriter, r *http.Request) {
	tid, err := shared.IDFromString(middleware.MustGetTenantID(r.Context()))
	if err != nil {
		apierror.BadRequest("invalid tenant").WriteJSON(w)
		return
	}
	if h.actorOf == nil || h.svc == nil {
		h.logger.Error("finding import refused: not configured")
		apierror.InternalServerError("import failed").WriteJSON(w)
		return
	}
	actor, err := h.actorOf(r.Context(), tid)
	if err != nil {
		h.logger.Error("finding import: resolve data scope", "error", err)
		apierror.InternalServerError("import failed").WriteJSON(w)
		return
	}

	q := r.URL.Query()
	req := findingimport.Request{
		TenantID:   tid,
		DryRun:     parseBool(q.Get("dry_run")),
		CanApprove: middleware.HasPermission(r.Context(), permission.FindingsApprove.String()),
		SessionID:  shared.NewID().String(),
	}
	req.Actor = actor
	if uid, err := shared.IDFromString(middleware.GetUserID(r.Context())); err == nil {
		req.ActorUserID = &uid
	}
	if f := strings.TrimSpace(q.Get("format")); f != "" {
		if !importer.Format(f).IsValid() {
			apierror.BadRequest("unknown format; supported: " + strings.Join(supportedFormats(), ", ")).WriteJSON(w)
			return
		}
		req.Format = importer.Format(f)
	}
	if s := strings.TrimSpace(q.Get("min_severity")); s != "" {
		sev := ctis.Severity(strings.ToLower(s))
		if !sev.IsValid() {
			apierror.BadRequest("min_severity must be one of info, low, medium, high, critical").WriteJSON(w)
			return
		}
		req.MinSeverity = sev
	}

	maxBody := h.maxBody
	if maxBody <= 0 {
		maxBody = MaxFindingImportBody
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxBody)
	mr, err := r.MultipartReader()
	if err != nil {
		apierror.BadRequest("send the file as multipart/form-data").WriteJSON(w)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), findingImportTimeout)
	defer cancel()

	resp := FindingImportResponse{
		SessionID:        req.SessionID,
		DryRun:           req.DryRun,
		VEXMode:          string(h.svc.VEXMode()),
		VEXCanClose:      string(h.svc.VEXMode()) == "enforce" && req.CanApprove,
		SupportedFormats: supportedFormats(),
	}
	var kb []byte
	var results []findingimport.FileResult
	files := 0
	for {
		part, err := mr.NextPart()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			writeBodyError(w, err)
			return
		}
		switch part.FormName() {
		case "knowledge_base":
			kb, err = io.ReadAll(io.LimitReader(part, maxImportKB+1))
			if err != nil {
				writeBodyError(w, err)
				return
			}
			if len(kb) > maxImportKB {
				apierror.New(http.StatusRequestEntityTooLarge, "PAYLOAD_TOO_LARGE", "the knowledge base is too large").WriteJSON(w)
				return
			}
		case "file":
			files++
			if files > maxImportFiles {
				apierror.BadRequest(fmt.Sprintf("at most %d files per request", maxImportFiles)).WriteJSON(w)
				return
			}
			out, status, apiErr := h.importPart(ctx, req, part, kb, len(results))
			if apiErr != nil {
				apiErr.WriteJSON(w)
				return
			}
			if status != 0 {
				// A single file that could not be read is the request's
				// error: 400 (or 413) with the details of the file.
				writeFileError(w, status, out[0])
				return
			}
			results = append(results, out...)
		default:
			// Unknown parts are drained, never stored.
			if _, err := io.Copy(io.Discard, part); err != nil {
				writeBodyError(w, err)
				return
			}
		}
		_ = part.Close()
	}
	if files == 0 {
		apierror.BadRequest("no file part in the upload").WriteJSON(w)
		return
	}
	for i := range results {
		resp.Files = append(resp.Files, toImportFileResponse(&results[i]))
	}
	h.auditImport(r, req, results)

	writeJSON(w, http.StatusOK, resp)
}

// importPart imports one file part through findingimport (the one entry
// point that detects and converts an upload). For a single file that cannot
// be read, or an upload refused as a whole, it returns the HTTP status the
// request fails with and the file to describe.
func (h *FindingImportHandler) importPart(ctx context.Context, req findingimport.Request, part *multipart.Part,
	kb []byte, index int) ([]findingimport.FileResult, int, *apierror.Error) {
	name := findingimport.SafeName(part.FileName())
	tr := &readErrTracker{r: part}
	up := findingimport.Upload{
		Name:           name,
		Body:           tr,
		KnowledgeBase:  kb,
		ReportIDPrefix: fmt.Sprintf("%s-%d", req.SessionID, index),
		TempDir:        h.tempDir,
	}
	results, archive, refused := h.svc.ImportUpload(ctx, req, up)
	var mbe *http.MaxBytesError
	if errors.As(tr.err, &mbe) {
		return nil, 0, bodyError(mbe)
	}
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return nil, 0, apierror.ServiceUnavailable("the import took too long")
	}
	if refused != nil {
		if refused.Kind == findingimport.KindReadFailed {
			return nil, 0, apierror.BadRequest("the upload could not be read")
		}
		return []findingimport.FileResult{{Name: name, Error: refused}}, statusOf(refused), nil
	}
	if !archive && len(results) == 1 && results[0].Error != nil && results[0].Format == "" {
		return results, statusOf(results[0].Error), nil
	}
	return results, 0, nil
}

// statusOf is the HTTP status of a refused upload.
func statusOf(fe *findingimport.FileError) int {
	if fe.Kind == findingimport.KindTooLarge {
		return http.StatusRequestEntityTooLarge
	}
	return http.StatusBadRequest
}

// readErrTracker remembers the last read error of the upload, so a body
// over the limit is answered 413 even when the parser saw it as a read
// failure.
type readErrTracker struct {
	r   io.Reader
	err error
}

func (t *readErrTracker) Read(p []byte) (int, error) {
	n, err := t.r.Read(p)
	if err != nil && !errors.Is(err, io.EOF) {
		t.err = err
	}
	return n, err
}

// bodyError maps an error reading the request body.
func bodyError(err error) *apierror.Error {
	var mbe *http.MaxBytesError
	if errors.As(err, &mbe) {
		return apierror.New(http.StatusRequestEntityTooLarge, "PAYLOAD_TOO_LARGE",
			fmt.Sprintf("the upload is larger than %d MiB", MaxFindingImportBody>>20))
	}
	return apierror.BadRequest("the upload could not be read")
}

func writeBodyError(w http.ResponseWriter, err error) { bodyError(err).WriteJSON(w) }

// writeFileError answers a single unreadable file with its details.
func writeFileError(w http.ResponseWriter, status int, fr findingimport.FileResult) {
	code := apierror.CodeBadRequest
	if status == http.StatusRequestEntityTooLarge {
		code = "PAYLOAD_TOO_LARGE"
	}
	msg := "the file could not be imported"
	if fr.Error != nil {
		msg = fr.Error.Message
	}
	apierror.New(status, code, msg).WithDetails(toImportFileResponse(&fr)).WriteJSON(w)
}

func supportedFormats() []string {
	all := importer.AllFormats()
	out := make([]string, 0, len(all))
	for _, f := range all {
		out = append(out, string(f))
	}
	return out
}

func toImportFileResponse(fr *findingimport.FileResult) ImportFileResponse {
	out := ImportFileResponse{
		ImportID: fr.ImportID,
		Name:     fr.Name,
		Format:   string(fr.Format),
		Unmapped: fr.Unmapped,
		Stats: ImportStats{
			Records: fr.Stats.Records, Assets: fr.Stats.Assets, Findings: fr.Stats.Findings,
			Components: fr.Stats.Components, Statements: fr.Stats.Statements, Skipped: fr.Stats.Skipped,
		},
	}
	if len(fr.Stats.BySeverity) > 0 {
		out.Stats.BySeverity = make(map[string]int, len(fr.Stats.BySeverity))
		for k, v := range fr.Stats.BySeverity {
			out.Stats.BySeverity[string(k)] = v
		}
	}
	if fr.Error != nil {
		out.Error = &ImportFileError{Kind: fr.Error.Kind, Message: fr.Error.Message, Line: fr.Error.Line, Column: fr.Error.Column}
	}
	for _, is := range fr.Issues {
		out.Issues = append(out.Issues, ImportIssue{Line: is.Line, Column: is.Column, Path: is.Path, Message: is.Message})
	}
	if v := fr.VEX; v != nil {
		out.VEX = &ImportVEXSummary{Statements: v.Statements, Unmatchable: v.Unmatchable, Matched: v.Matched,
			Stored: v.Stored, Closed: v.Closed, WouldClose: v.WouldClose, Mode: v.Mode}
	}
	if o := fr.Ingest; o != nil {
		out.Ingest = &ImportIngestSummary{
			AssetsCreated: o.AssetsCreated, AssetsUpdated: o.AssetsUpdated, AssetsSkippedOutOfScope: o.AssetsSkippedOutOfScope,
			FindingsCreated: o.FindingsCreated, FindingsUpdated: o.FindingsUpdated, FindingsSkipped: o.FindingsSkipped,
			ComponentsCreated: o.ComponentsCreated, ComponentsUpdated: o.ComponentsUpdated, Errors: o.Errors,
		}
	}
	return out
}

// auditImport records the import (or the preview): counts, formats and file
// names, never file content. A VEX document that closed findings, or would
// have, gets its own record listing them.
func (h *FindingImportHandler) auditImport(r *http.Request, req findingimport.Request, results []findingimport.FileResult) {
	if h.audit == nil {
		return
	}
	actx := auditapp.AuditContext{
		TenantID:   req.TenantID.String(),
		ActorID:    middleware.GetUserID(r.Context()),
		ActorEmail: auditActorEmail(r.Context()),
		ActorIP:    getClientIP(r),
		UserAgent:  r.UserAgent(),
		RequestID:  r.Header.Get("X-Request-ID"),
	}
	importIDs := make([]string, 0, len(results))
	names := make([]string, 0, len(results))
	formats := make([]string, 0, len(results))
	var assetsC, assetsU, skipped, findC, findU, failed, vexStored, vexClosed, vexWould int
	var vexIDs []string
	for i := range results {
		fr := &results[i]
		names = append(names, fr.Name)
		if fr.ImportID != "" {
			importIDs = append(importIDs, fr.ImportID)
		}
		formats = append(formats, string(fr.Format))
		if fr.Error != nil {
			failed++
		}
		if o := fr.Ingest; o != nil {
			assetsC += o.AssetsCreated
			assetsU += o.AssetsUpdated
			skipped += o.AssetsSkippedOutOfScope
			findC += o.FindingsCreated
			findU += o.FindingsUpdated
		}
		if v := fr.VEX; v != nil {
			vexStored += v.Stored
			vexClosed += v.Closed
			vexWould += v.WouldClose
			for _, id := range v.FindingIDs {
				if len(vexIDs) < maxAuditedImportIDs {
					vexIDs = append(vexIDs, id.String())
				}
			}
		}
	}
	msg := "Findings imported from files"
	if req.DryRun {
		msg = "Finding import previewed"
	}
	event := auditapp.NewSuccessEvent(auditdom.ActionAssetImported, auditdom.ResourceTypeFinding, req.SessionID).
		WithMessage(msg).
		WithSeverity(auditdom.SeverityForAction(auditdom.ActionAssetImported)).
		WithMetadata("source", "finding_import").
		WithMetadata("dry_run", req.DryRun).
		WithMetadata("restricted_uploader", req.Actor != nil).
		WithMetadata("import_ids", importIDs).
		WithMetadata("files", names).
		WithMetadata("formats", formats).
		WithMetadata("files_failed", failed).
		WithMetadata("assets_created", assetsC).
		WithMetadata("assets_updated", assetsU).
		WithMetadata("assets_skipped_out_of_scope", skipped).
		WithMetadata("findings_created", findC).
		WithMetadata("findings_updated", findU).
		WithMetadata("vex_stored", vexStored).
		WithMetadata("vex_closed", vexClosed).
		WithMetadata("vex_would_close", vexWould)
	_ = h.audit.LogEvent(r.Context(), actx, event)

	if len(vexIDs) > 0 && !req.DryRun {
		action := auditdom.ActionIngestVEXDryRun
		if vexClosed > 0 {
			action = auditdom.ActionIngestVEXApplied
		}
		ve := auditapp.NewSuccessEvent(action, auditdom.ResourceTypeIngest, req.SessionID).
			WithMessage("VEX not_affected from an imported document").
			WithSeverity(auditdom.SeverityForAction(action)).
			WithMetadata("source", "finding_import").
			WithMetadata("import_ids", importIDs).
			WithMetadata("mode", string(h.svc.VEXMode())).
			WithMetadata("closed", vexClosed).
			WithMetadata("would_close", vexWould).
			WithMetadata("finding_ids", vexIDs).
			WithMetadata("finding_ids_truncated", vexClosed+vexWould > len(vexIDs))
		_ = h.audit.LogEvent(r.Context(), actx, ve)
	}
}

// parseBool is strconv.ParseBool that treats an error as false.
func parseBool(s string) bool {
	b, _ := strconv.ParseBool(s)
	return b
}

package handler

import (
	"context"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
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
	"github.com/openctemio/openctem/api/pkg/domain/idempotency"
	"github.com/openctemio/openctem/api/pkg/domain/permission"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// Upload limits of POST /findings/imports.
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

// FindingImportHandler serves POST /api/v1/findings/imports.
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
	// receipts reads the upload's receipt for the response; idem is the
	// durable Idempotency-Key store (nil: a request with a key is refused).
	receipts IngestReceiptReader
	idem     idempotency.Store
}

// SetReceiptStores wires the receipt reader and the Idempotency-Key store.
func (h *FindingImportHandler) SetReceiptStores(receipts IngestReceiptReader, idem idempotency.Store) {
	h.receipts, h.idem = receipts, idem
}

// NewFindingImportHandler creates the handler. Without a data scope
// enforcer every upload is refused (fail closed).
func NewFindingImportHandler(svc *findingimport.Service, ds *datascope.Enforcer, audit *auditapp.AuditService, log *logger.Logger) *FindingImportHandler {
	h := &FindingImportHandler{svc: svc, audit: audit, logger: log}
	if ds != nil {
		h.actorOf = func(ctx context.Context, tenantID shared.ID) (ingest.ActorScope, error) {
			scope, err := ds.Resolve(ctx, tenantID)
			if err != nil || !scope.Restricted() {
				// An unrestricted uploader may create assets; hiding private
				// program assets is about reading, not importing.
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
	// Receipt is what the upload did to the organization's findings (absent
	// in a preview).
	Receipt   *ReceiptResponse `json:"receipt,omitempty"`
	SessionID string           `json:"session_id"`
	// ReceiptID is the upload's receipt (empty in a preview): what the
	// upload did to the organization's findings.
	ReceiptID string `json:"receipt_id,omitempty"`
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
	Requested   int    `json:"requested"`
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

// Import handles POST /api/v1/findings/imports.
//
// @Summary      Import results from another tool
// @Description  Multipart upload of an exported file (Nessus .nessus, Qualys detection XML with an optional KnowledgeBase part, CycloneDX, SPDX, OSV results, CSAF, OpenVEX, DefectDojo Generic Findings JSON) or a ZIP of them. The format is detected from the content. A committed upload answers 201 with Location and its receipt (what it did to the organization's findings); with dry_run=true the files are only parsed and counted (200). The import runs with the uploader's rights: findings land only on assets in the uploader's data scope, nothing is closed unless the upload declares coverage=full for explicit asset_id values (then the open findings of each file's tool on those assets that the upload did not report are closed, with the same guards as a covered scan), and a VEX not_affected statement only requests a false positive (a pending request that a second person decides under the approval policy), and only under INGEST_VEX=enforce for an uploader holding findings:approve. Send the knowledge_base part before the file part. An Idempotency-Key header (1-128 printable ASCII) makes a retry of the same files return the first answer (Idempotent-Replayed: true); the same key with other files is 422, while the first request runs 409, and when the key store is unavailable 503 (nothing imported).
// @Tags         Findings
// @Accept       multipart/form-data
// @Produce      json
// @Param        file             formData  file    true   "Exported file or ZIP archive"
// @Param        knowledge_base   formData  file    false  "Qualys KnowledgeBase XML (before file)"
// @Param        dry_run          query     bool    false  "Parse and count only"
// @Param        format           query     string  false  "Force the format of a single file"
// @Param        min_severity     query     string  false  "Drop findings below: info, low, medium, high, critical"
// @Param        coverage         query     string  false  "partial (default, closes nothing) or full: the upload is a complete scan of the asset_id assets by each file's tool, and their open findings of that tool it does not report are closed (needs findings:status)"
// @Param        asset_id         query     []string  false  "With coverage=full: 1 to 100 asset ids in the uploader's data scope"  collectionFormat(multi)
// @Param        Idempotency-Key  header    string  false  "Makes a retry of the same upload return the first answer"
// @Success      200  {object}  FindingImportResponse  "Preview"
// @Success      201  {object}  FindingImportResponse  "Committed, with the receipt"
// @Failure      400  {object}  apierror.Error
// @Failure      409  {object}  apierror.Error
// @Failure      413  {object}  apierror.Error
// @Failure      422  {object}  apierror.Error
// @Failure      429  {object}  apierror.Error
// @Failure      503  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /findings/imports [post]
func (h *FindingImportHandler) Import(w http.ResponseWriter, r *http.Request) { //nolint:cyclop,gocognit // one upload flow: params, key, parts, receipt
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

	if apiErr := h.parseCoverage(r, &req); apiErr != nil {
		apiErr.WriteJSON(w)
		return
	}

	maxBody := h.maxBody
	if maxBody <= 0 {
		maxBody = MaxFindingImportBody
	}

	// Idempotency-Key (a preview writes nothing and ignores it).
	claim, hasher, handled := h.claimKey(w, r, tid, q, maxBody, req.DryRun)
	if handled {
		return
	}
	completed := false
	if claim != nil {
		defer func() {
			if !completed {
				if err := h.idem.Release(context.WithoutCancel(r.Context()), claim); err != nil {
					h.logger.Warn("finding import: release idempotency key", "error", logger.SanitizeError(err))
				}
			}
		}()
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
	finished := false
	// The receipt is finished on every way out once it exists: a request
	// refused halfway still says what its earlier files wrote.
	defer func() {
		if !req.ReceiptID.IsZero() && !finished {
			h.svc.FinishUpload(context.WithoutCancel(ctx), req, results, false)
		}
	}()
	// hashed wraps a part for the request fingerprint when a key is used.
	hashed := func(p *multipart.Part) (io.Reader, func() error) {
		if hasher == nil {
			return p, func() error { return nil }
		}
		pr := hasher.part(p.FormName(), p)
		return pr, pr.done
	}
	for {
		part, err := mr.NextPart()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			writeBodyError(w, err)
			return
		}
		body, done := hashed(part)
		switch part.FormName() {
		case "knowledge_base":
			kb, err = io.ReadAll(io.LimitReader(body, maxImportKB+1))
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
			if !req.DryRun && req.ReceiptID.IsZero() {
				id, err := h.svc.BeginUpload(ctx, req, findingimport.SafeName(part.FileName()))
				if err != nil {
					apierror.InternalServerError("import failed").WriteJSON(w)
					return
				}
				req.ReceiptID = id
				resp.ReceiptID = id.String()
			}
			out, status, apiErr := h.importPart(ctx, req, part, body, kb, len(results))
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
		}
		// Unknown parts are drained, never stored; every part is read to
		// its end for the fingerprint.
		if err := done(); err != nil {
			writeBodyError(w, err)
			return
		}
		if hasher == nil && part.FormName() != "file" && part.FormName() != "knowledge_base" {
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

	if req.DryRun {
		writeJSON(w, http.StatusOK, resp)
		return
	}
	h.svc.FinishUpload(context.WithoutCancel(ctx), req, results, true)
	finished = true
	if h.receipts != nil {
		if rec, err := h.receipts.Get(context.WithoutCancel(ctx), tid, req.ReceiptID); err == nil {
			rr := toReceiptResponse(rec)
			resp.Receipt = &rr
		} else {
			h.logger.Warn("finding import: read receipt", "error", err)
		}
	}
	body, err := storableResponse(resp)
	if err != nil {
		apierror.InternalServerError("import failed").WriteJSON(w)
		return
	}
	if claim != nil {
		rid := req.ReceiptID
		if err := h.idem.Complete(context.WithoutCancel(ctx), claim, hasher.sum(), http.StatusCreated, body, &rid); err != nil {
			// The upload is stored; the key stays pending until it expires,
			// so a retry meanwhile is refused (409) rather than imported
			// again.
			h.logger.Error("finding import: store idempotent answer", "error", logger.SanitizeError(err))
		}
		completed = true
	}
	w.Header().Set("Location", "/api/v1/findings/imports/"+req.ReceiptID.String())
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_, _ = w.Write(body)
}

// claimKey claims the request's Idempotency-Key. handled is true when the
// answer was written: a bad key (400), the store down (503, fail closed), a
// key in flight (409) or reused (422), or a replay of the stored answer.
// Without a key (or in a preview) claim and hasher are nil.
func (h *FindingImportHandler) claimKey(w http.ResponseWriter, r *http.Request, tid shared.ID, q url.Values, maxBody int64,
	dryRun bool) (*idempotency.Claim, *requestHasher, bool) {
	key := r.Header.Get(idempotency.Header)
	if key == "" || dryRun {
		return nil, nil, false
	}
	scope, err := idempotency.NewScope(tid, importPrincipal(r), findingImportRoute, key)
	if err != nil {
		apierror.BadRequest(err.Error()).WriteJSON(w)
		return nil, nil, true
	}
	if h.idem == nil {
		h.logger.Error("finding import: Idempotency-Key sent but no key store is wired")
		storeUnavailable(w)
		return nil, nil, true
	}
	c, existing, err := h.idem.Claim(r.Context(), scope, findingImportTimeout+5*time.Minute)
	if err != nil {
		h.logger.Error("finding import: idempotency store", "error", logger.SanitizeError(err))
		storeUnavailable(w)
		return nil, nil, true
	}
	if existing == nil {
		return c, newRequestHasher(q), false
	}
	if existing.State != idempotency.StateDone {
		writeIdempotencyRefusal(w, true)
		return nil, nil, true
	}
	fp, err := fingerprintRequest(r, maxBody, w)
	switch {
	case err != nil:
		writeBodyError(w, err)
	case fp != existing.RequestSHA256:
		writeIdempotencyRefusal(w, false)
	default:
		replay(w, existing)
	}
	return nil, nil, true
}

// parseCoverage reads coverage=full and its asset_id values. Declaring full
// coverage closes findings, so it needs findings:status, and every asset
// must be the organization's and in the uploader's scope (one answer for a
// missing and a hidden asset).
func (h *FindingImportHandler) parseCoverage(r *http.Request, req *findingimport.Request) *apierror.Error {
	q := r.URL.Query()
	switch c := q.Get("coverage"); c {
	case "", "partial":
	case "full":
		req.Coverage.Full = true
	default:
		return apierror.BadRequest("coverage must be partial or full")
	}
	raw := q["asset_id"]
	if len(raw) > findingimport.MaxCoverageAssets {
		return apierror.BadRequest(findingimport.ErrCoverageScope.Error())
	}
	for _, v := range raw {
		id, err := shared.IDFromString(v)
		if err != nil {
			return apierror.BadRequest(findingimport.ErrCoverageScope.Error())
		}
		req.Coverage.AssetIDs = append(req.Coverage.AssetIDs, id)
	}
	if req.Coverage.Full && !middleware.HasPermission(r.Context(), permission.FindingsStatus.String()) {
		return apierror.Forbidden("coverage=full closes findings and needs " + permission.FindingsStatus.String())
	}
	if err := h.svc.CheckCoverage(r.Context(), *req); err != nil {
		switch {
		case errors.Is(err, findingimport.ErrCoverageScope):
			return apierror.BadRequest(err.Error())
		case errors.Is(err, findingimport.ErrCoverageUnsupported):
			return apierror.New(http.StatusNotImplemented, "NOT_IMPLEMENTED", err.Error())
		default:
			h.logger.Error("finding import: check coverage", "error", err)
			return apierror.InternalServerError("import failed")
		}
	}
	return nil
}

// importPrincipal is who an Idempotency-Key belongs to: the API key, or the
// user, behind the request.
func importPrincipal(r *http.Request) string {
	if k := middleware.GetAPIKeyID(r.Context()); k != "" {
		return "key:" + k
	}
	return "user:" + middleware.GetUserID(r.Context())
}

// importPart imports one file part through findingimport (the one entry
// point that detects and converts an upload). For a single file that cannot
// be read, or an upload refused as a whole, it returns the HTTP status the
// request fails with and the file to describe.
func (h *FindingImportHandler) importPart(ctx context.Context, req findingimport.Request, part *multipart.Part,
	body io.Reader, kb []byte, index int) ([]findingimport.FileResult, int, *apierror.Error) {
	name := findingimport.SafeName(part.FileName())
	tr := &readErrTracker{r: body}
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
			Stored: v.Stored, Requested: v.Requested, WouldClose: v.WouldClose, Mode: v.Mode}
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
	var assetsC, assetsU, skipped, findC, findU, failed, vexStored, vexRequested, vexWould int
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
			vexRequested += v.Requested
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
		WithMetadata("vex_requested", vexRequested).
		WithMetadata("vex_would_close", vexWould)
	_ = h.audit.LogEvent(r.Context(), actx, event)

	if len(vexIDs) > 0 && !req.DryRun {
		action := auditdom.ActionIngestVEXDryRun
		if vexRequested > 0 {
			action = auditdom.ActionIngestVEXApplied
		}
		ve := auditapp.NewSuccessEvent(action, auditdom.ResourceTypeIngest, req.SessionID).
			WithMessage("VEX not_affected from an imported document").
			WithSeverity(auditdom.SeverityForAction(action)).
			WithMetadata("source", "finding_import").
			WithMetadata("import_ids", importIDs).
			WithMetadata("mode", string(h.svc.VEXMode())).
			WithMetadata("requested", vexRequested).
			WithMetadata("would_close", vexWould).
			WithMetadata("finding_ids", vexIDs).
			WithMetadata("finding_ids_truncated", vexRequested+vexWould > len(vexIDs))
		_ = h.audit.LogEvent(r.Context(), actx, ve)
	}
}

// parseBool is strconv.ParseBool that treats an error as false.
func parseBool(s string) bool {
	b, _ := strconv.ParseBool(s)
	return b
}

package handler

// CI runner endpoints (docs/rfcs/RFC-051-ci-runner-identity-and-gate.md):
// the OIDC token exchange and the run-token routes a pipeline calls. Never
// logs a token: neither the CI provider's nor the run's.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"strings"
	"time"

	"github.com/openctemio/ctis"
	"github.com/openctemio/ctis/importer"

	cirunapp "github.com/openctemio/openctem/api/internal/app/cirun"
	"github.com/openctemio/openctem/api/internal/app/findingimport"
	"github.com/openctemio/openctem/api/internal/app/ingest"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/apierror"
	"github.com/openctemio/openctem/api/pkg/domain/cirun"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// CIRunService is what the CI runner endpoints need.
type CIRunService interface {
	Exchange(ctx context.Context, in cirunapp.ExchangeInput) (*cirunapp.ExchangeOutput, error)
	Authenticate(ctx context.Context, token string) (*cirun.Run, error)
	UploadReport(ctx context.Context, run *cirun.Run, report *ctis.Report) (*ingest.Output, error)
	UploadImported(ctx context.Context, run *cirun.Run, report *ctis.Report) (*ingest.Output, int, error)
	BaselineDiff(ctx context.Context, run *cirun.Run, fingerprints []string) (*cirunapp.BaselineDiffOutput, error)
	Evaluate(ctx context.Context, run *cirun.Run, in cirunapp.EvaluateInput) (*cirunapp.Verdict, error)
}

// CIRunnerHandler serves the pipeline side of CI runs.
type CIRunnerHandler struct {
	svc    CIRunService
	logger *logger.Logger
	// vex applies the VEX statements of an uploaded VEX document; nil
	// refuses VEX documents.
	vex CIVEXApplier
}

// CIVEXApplier applies converted VEX statements (findingimport.Service).
type CIVEXApplier interface {
	ApplyVEXStatements(ctx context.Context, req findingimport.Request, stmts []importer.VEXStatement) (*findingimport.VEXSummary, error)
}

// SetVEXApplier wires VEX documents uploaded by a run.
func (h *CIRunnerHandler) SetVEXApplier(v CIVEXApplier) { h.vex = v }

// NewCIRunnerHandler creates the handler.
func NewCIRunnerHandler(svc CIRunService, log *logger.Logger) *CIRunnerHandler {
	return &CIRunnerHandler{svc: svc, logger: log.With("handler", "ci_runner")}
}

type ciRunContextKey struct{}

// CIRunFromContext returns the run AuthenticateRun resolved.
func CIRunFromContext(ctx context.Context) *cirun.Run {
	run, _ := ctx.Value(ciRunContextKey{}).(*cirun.Run)
	return run
}

// maxExchangeBody bounds the exchange request (an OIDC token is a few KB).
const maxExchangeBody = 32 << 10

// CIExchangeRequest is a CI job's token exchange request.
type CIExchangeRequest struct {
	// TenantID is the organization whose trust configurations decide.
	TenantID string `json:"tenant_id"`
	// IDToken is the CI provider's OIDC token for the job.
	IDToken string `json:"id_token"`
	// RunID, optional, asks for a fresh token for a run this pipeline run
	// already holds (same repository, commit and pipeline run; not yet
	// evaluated).
	RunID string `json:"run_id,omitempty"`
	// Aggregate, optional, joins the run every capability job of the same
	// pipeline run reports into (opening it for the first job); each job
	// gets its own token for it, and one final job asks for the verdict.
	Aggregate bool `json:"aggregate,omitempty"`
}

// CIExchangeResponse is a run and its upload token (shown once).
type CIExchangeResponse struct {
	RunID             string    `json:"run_id"`
	Token             string    `json:"token"`
	TokenType         string    `json:"token_type"`
	ExpiresAt         time.Time `json:"expires_at"`
	ExpiresIn         int       `json:"expires_in"`
	Repository        string    `json:"repository"`
	RepositoryAssetID string    `json:"repository_asset_id"`
	Branch            string    `json:"branch,omitempty"`
	CommitSHA         string    `json:"commit_sha,omitempty"`
	PullRequest       string    `json:"pull_request,omitempty"`
	DefaultBranch     string    `json:"default_branch,omitempty"`
	IsDefaultBranch   bool      `json:"is_default_branch"`
	// Aggregate: the token belongs to the aggregate run of the pipeline run.
	Aggregate bool `json:"aggregate"`
}

// Exchange handles POST /api/v1/ci/oidc/exchange
// @Summary      Exchange a CI OIDC token for a run upload token
// @Description  A GitHub Actions or GitLab CI job presents its OIDC token. When one of the organization's CI trust configurations admits it (issuer, audience, repository, ref, environment and event rules; fork pull requests refused by default), the platform creates a CI run on the repository asset and returns a run upload token that expires within 15 minutes. Each OIDC token can be exchanged once. With aggregate true, the jobs of one pipeline run (same pipeline, provider run id, attempt and commit, from the verified token) share one run, each with its own token, and one final job evaluates it. Every refusal answers the same 401.
// @Tags         CI
// @Accept       json
// @Produce      json
// @Param        body body CIExchangeRequest true "Tenant and OIDC token"
// @Success      201  {object}  CIExchangeResponse
// @Failure      400  {object}  apierror.Error
// @Failure      401  {object}  apierror.Error
// @Failure      403  {object}  apierror.Error "RUNNER_OUTDATED: the runner reports a version below the minimum supported one"
// @Failure      429  {object}  apierror.Error
// @Router       /ci/oidc/exchange [post]
func (h *CIRunnerHandler) Exchange(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	r.Body = http.MaxBytesReader(w, r.Body, maxExchangeBody)
	var req CIExchangeRequest
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil || req.IDToken == "" || req.TenantID == "" {
		apierror.BadRequest("tenant_id and id_token are required").WriteJSON(w)
		return
	}
	out, err := h.svc.Exchange(r.Context(), cirunapp.ExchangeInput{TenantID: req.TenantID, IDToken: req.IDToken,
		RunID: req.RunID, Aggregate: req.Aggregate, ClientIP: getClientIP(r), UserAgent: r.UserAgent()})
	if err != nil {
		if errors.Is(err, cirunapp.ErrExchangeRefused) {
			apierror.Unauthorized("The CI token was not accepted").WriteJSON(w)
			return
		}
		if errors.Is(err, cirunapp.ErrRunnerOutdated) {
			apierror.New(http.StatusForbidden, "RUNNER_OUTDATED",
				"This CI runner is older than the minimum supported version; update the sensor image").WriteJSON(w)
			return
		}
		h.logger.Error("ci token exchange failed", "error", logger.SanitizeError(err))
		apierror.InternalServerError("token exchange failed").WriteJSON(w)
		return
	}
	run := out.Run
	resp := CIExchangeResponse{RunID: run.ID.String(), Token: out.Token, TokenType: "Bearer", ExpiresAt: out.ExpiresAt,
		ExpiresIn: int(time.Until(out.ExpiresAt).Seconds()), Repository: run.Repository,
		RepositoryAssetID: run.RepositoryAssetID.String(), Branch: run.Branch, CommitSHA: run.CommitSHA,
		PullRequest: run.PullRequest, DefaultBranch: run.DefaultBranch, IsDefaultBranch: run.IsDefaultBranch,
		Aggregate: run.Aggregate}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(resp)
}

// AuthenticateRun authenticates a run upload token (Authorization: Bearer
// octci_...) and requires the {id} path parameter to be that run. Any
// failure is the same 401; a token for another run is a 404.
func (h *CIRunnerHandler) AuthenticateRun(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		token, ok := strings.CutPrefix(auth, "Bearer ")
		if !ok || !cirun.LooksLikeToken(token) {
			apierror.Unauthorized("A CI run token is required").WriteJSON(w)
			return
		}
		run, err := h.svc.Authenticate(r.Context(), token)
		if err != nil {
			if !errors.Is(err, shared.ErrNotFound) {
				h.logger.Error("ci run token lookup failed", "error", logger.SanitizeError(err))
			}
			apierror.Unauthorized("Invalid or expired CI run token").WriteJSON(w)
			return
		}
		if id := r.PathValue("id"); id != "" && id != run.ID.String() {
			apierror.NotFound("CI run").WriteJSON(w)
			return
		}
		ctx := context.WithValue(r.Context(), ciRunContextKey{}, run)
		// The tenant-keyed rate limiters and concurrency caps read it.
		ctx = context.WithValue(ctx, middleware.TenantIDKey, run.TenantID.String())
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// UploadResults handles POST /api/v1/ci/runs/{id}/results
// @Summary      Upload a CI run's results
// @Description  A CTIS report from the run, or a file a tool wrote in a format the importers read (SARIF, an SBOM, OSV results, ...; detected from the content, a ZIP of them too). It may name only the run's repository (an exported file's findings on any other asset are dropped and counted); the branch, commit and pull request come from the verified OIDC token, not from the report. Findings are recorded for the run's gate verdict.
// @Tags         CI
// @Accept       json
// @Produce      json
// @Param        id   path string true "Run ID"
// @Param        body body CTISIngestRequest true "CTIS report"
// @Success      201  {object}  IngestResponse
// @Failure      400  {object}  apierror.Error
// @Failure      401  {object}  apierror.Error
// @Failure      404  {object}  apierror.Error
// @Failure      409  {object}  apierror.Error
// @Security     CIRunToken
// @Router       /ci/runs/{id}/results [post]
func (h *CIRunnerHandler) UploadResults(w http.ResponseWriter, r *http.Request) {
	run := CIRunFromContext(r.Context())
	if run == nil {
		apierror.Unauthorized("A CI run token is required").WriteJSON(w)
		return
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		apierror.BadRequest("Failed to read request body").WriteJSON(w)
		return
	}
	if isToolExport(body, r.Header.Get("Content-Type")) {
		h.uploadExport(w, r, run, body)
		return
	}
	report, ok := decodeCTISReport(body)
	if !ok {
		apierror.BadRequest("Invalid JSON request body").WriteJSON(w)
		return
	}
	out, err := h.svc.UploadReport(r.Context(), run, report)
	if err != nil {
		h.writeErr(w, "upload CI results", err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(newIngestResponse(out))
}

// decodeCTISReport accepts {"report": {...}} or a bare report, refusing
// fields outside the contract.
func decodeCTISReport(body []byte) (*ctis.Report, bool) {
	var req CTISIngestRequest
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err == nil && req.Report.Version != "" {
		return &req.Report, true
	}
	var report ctis.Report
	dec = json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&report); err != nil {
		return nil, false
	}
	if report.Version == "" {
		report.Version = "1.0"
	}
	return &report, true
}

// CIBaselineDiffRequest lists finding fingerprints to compare.
type CIBaselineDiffRequest struct {
	Fingerprints []string `json:"fingerprints"`
}

// BaselineDiff handles POST /api/v1/ci/runs/{id}/baseline-diff
// @Summary      Compare a CI run's fingerprints with the default branch
// @Description  Splits fingerprints into new and already open on the repository's default branch, for inline comments on new findings. The repository and branch are the run's.
// @Tags         CI
// @Accept       json
// @Produce      json
// @Param        id   path string true "Run ID"
// @Param        body body CIBaselineDiffRequest true "Fingerprints"
// @Success      200  {object}  cirunapp.BaselineDiffOutput
// @Failure      400  {object}  apierror.Error
// @Failure      401  {object}  apierror.Error
// @Security     CIRunToken
// @Router       /ci/runs/{id}/baseline-diff [post]
func (h *CIRunnerHandler) BaselineDiff(w http.ResponseWriter, r *http.Request) {
	run := CIRunFromContext(r.Context())
	if run == nil {
		apierror.Unauthorized("A CI run token is required").WriteJSON(w)
		return
	}
	limitBody(w, r)
	var req CIBaselineDiffRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}
	out, err := h.svc.BaselineDiff(r.Context(), run, req.Fingerprints)
	if err != nil {
		h.writeErr(w, "baseline diff", err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(out)
}

// CIEvaluateRequest is what the runner reports about its own run.
type CIEvaluateRequest struct {
	// ScanFailures counts scanners that failed to run or whose output could
	// not be parsed. Any failure fails the gate.
	ScanFailures int `json:"scan_failures"`
}

// Evaluate handles POST /api/v1/ci/runs/{id}/evaluate
// @Summary      Gate verdict for a CI run
// @Description  Judges the run's findings against the gate policy (repository, else business unit, else organization, else the built-in default): severity threshold, KEV, EPSS, new findings only compared with the default branch by default. Accepted risk, false positives and suppressions are honored; a committed secret always fails; a scan failure fails. An active break-glass for the commit lets a failing run pass (audited). Returns pass or fail with reasons and links.
// @Tags         CI
// @Accept       json
// @Produce      json
// @Param        id   path string true "Run ID"
// @Param        body body CIEvaluateRequest false "Runner status"
// @Success      200  {object}  cirunapp.Verdict
// @Failure      401  {object}  apierror.Error
// @Failure      404  {object}  apierror.Error
// @Security     CIRunToken
// @Router       /ci/runs/{id}/evaluate [post]
func (h *CIRunnerHandler) Evaluate(w http.ResponseWriter, r *http.Request) {
	run := CIRunFromContext(r.Context())
	if run == nil {
		apierror.Unauthorized("A CI run token is required").WriteJSON(w)
		return
	}
	limitBody(w, r)
	var req CIEvaluateRequest
	if r.ContentLength != 0 {
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil && !errors.Is(err, io.EOF) {
			apierror.BadRequest("Invalid request body").WriteJSON(w)
			return
		}
	}
	v, err := h.svc.Evaluate(r.Context(), run, cirunapp.EvaluateInput{ScanFailures: req.ScanFailures,
		ClientIP: getClientIP(r), UserAgent: r.UserAgent()})
	if err != nil {
		h.writeErr(w, "evaluate CI run", err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func (h *CIRunnerHandler) writeErr(w http.ResponseWriter, what string, err error) {
	var de *shared.DomainError
	switch {
	case errors.Is(err, cirunapp.ErrReportOutOfScope):
		apierror.New(http.StatusBadRequest, "REPORT_OUT_OF_SCOPE", "A CI run may report only on its own repository.").WriteJSON(w)
	case errors.As(err, &de) && de.Code == ingest.CodePayloadTooLarge:
		apierror.New(http.StatusRequestEntityTooLarge, "PAYLOAD_TOO_LARGE", de.Message).WriteJSON(w)
	case errors.Is(err, shared.ErrValidation):
		apierror.BadRequest("Invalid request: " + sanitizeLogField(err.Error())).WriteJSON(w)
	case errors.Is(err, shared.ErrConflict):
		apierror.Conflict(sanitizeLogField(err.Error())).WriteJSON(w)
	case errors.Is(err, shared.ErrNotFound):
		apierror.NotFound("CI run").WriteJSON(w)
	default:
		h.logger.Error(what+" failed", "error", logger.SanitizeError(err))
		apierror.InternalServerError(what + " failed").WriteJSON(w)
	}
}

// isToolExport reports whether a run's upload is a file a tool wrote rather
// than a CTIS report: an archive, or a format the importers detect. A JSON
// document that is a CTIS report (it has "version" or "report") stays on the
// CTIS path even when a detector would also accept it.
func isToolExport(body []byte, contentType string) bool {
	if mt, _, _ := mime.ParseMediaType(contentType); mt == "application/sarif+json" {
		return true
	}
	head := body
	if len(head) > importer.SniffLen {
		head = head[:importer.SniffLen]
	}
	if importer.IsZip(head) {
		return true
	}
	if _, ok := importer.Detect(head); !ok {
		return false
	}
	// A CTIS report (bare or as {"report": ...}) has a version and a
	// metadata object; tool formats that also have a "version" (SARIF,
	// semgrep, trivy) have no metadata object, or carry SARIF runs.
	var top map[string]json.RawMessage
	if json.Unmarshal(body, &top) == nil {
		if _, ok := top["report"]; ok {
			return false
		}
		_, version := top["version"]
		md, metadata := top["metadata"]
		_, runs := top["runs"]
		if version && metadata && !runs && len(bytes.TrimSpace(md)) > 0 && bytes.TrimSpace(md)[0] == '{' {
			return false
		}
	}
	return true
}

// CIExportResponse is the result of a run's uploaded tool export.
type CIExportResponse struct {
	IngestResponse
	// Files of the upload with their format (a ZIP has several).
	Files []CIExportFile `json:"files"`
	// FindingsDroppedOutOfScope counts findings the file filed on an asset
	// other than the run's repository; they were not ingested.
	FindingsDroppedOutOfScope int `json:"findings_dropped_out_of_scope"`
	// VEXStored counts findings of the run's repository a VEX statement was
	// stored on (a run never closes findings).
	VEXStored int `json:"vex_stored,omitempty"`
}

// CIExportFile is one converted file of a run's upload.
type CIExportFile struct {
	Name   string           `json:"name"`
	Format string           `json:"format,omitempty"`
	Error  *ImportFileError `json:"error,omitempty"`
}

// onlyAsset is the data scope of a run: its repository asset only.
type onlyAsset shared.ID

func (o onlyAsset) AssetsInScope(_ context.Context, ids []shared.ID) ([]shared.ID, error) {
	out := make([]shared.ID, 0, 1)
	for _, id := range ids {
		if id == shared.ID(o) {
			out = append(out, id)
		}
	}
	return out, nil
}

// uploadExport converts a run's tool export through findingimport.Convert
// (the same content sniffing, limits and archive checks as the import
// endpoint) and ingests each converted report for the run.
func (h *CIRunnerHandler) uploadExport(w http.ResponseWriter, r *http.Request, run *cirun.Run, body []byte) {
	resp := CIExportResponse{Files: []CIExportFile{}}
	total := &ingest.Output{}
	var firstErr error
	var refusedFile *findingimport.FileError
	_, refused := findingimport.Convert(r.Context(), findingimport.Upload{
		Name: "results", Body: bytes.NewReader(body), ReportIDPrefix: run.ID.String(),
		// Code reports are filed on the run's repository, whatever the file
		// names; ScopeImported then drops anything still elsewhere.
		Repository: run.Repository, Branch: run.Branch, CommitSHA: run.CommitSHA,
	}, func(c findingimport.Converted) {
		f := CIExportFile{Name: c.Name}
		if c.Error != nil {
			f.Error = &ImportFileError{Kind: c.Error.Kind, Message: c.Error.Message, Line: c.Error.Line, Column: c.Error.Column}
			if refusedFile == nil {
				refusedFile = c.Error
			}
			resp.Files = append(resp.Files, f)
			return
		}
		f.Format = string(c.Result.Format)
		resp.Files = append(resp.Files, f)
		if firstErr != nil {
			return
		}
		rep := c.Result.Report
		if len(rep.Findings) > 0 || len(rep.Dependencies) > 0 {
			out, dropped, err := h.svc.UploadImported(r.Context(), run, rep)
			resp.FindingsDroppedOutOfScope += dropped
			if err != nil {
				firstErr = err
				return
			}
			addOutput(total, out)
		}
		if len(c.Result.VEX) > 0 {
			if h.vex == nil {
				return
			}
			sum, err := h.vex.ApplyVEXStatements(r.Context(), findingimport.Request{
				TenantID: run.TenantID, Actor: onlyAsset(run.RepositoryAssetID), SessionID: run.ID.String(),
			}, c.Result.VEX)
			if err != nil {
				firstErr = err
				return
			}
			resp.VEXStored += sum.Stored
		}
	})
	if refused != nil {
		status := http.StatusBadRequest
		if refused.Kind == findingimport.KindTooLarge {
			status = http.StatusRequestEntityTooLarge
		}
		apierror.New(status, "UNREADABLE_RESULTS", refused.Message).WriteJSON(w)
		return
	}
	if firstErr != nil {
		h.writeErr(w, "upload CI results", firstErr)
		return
	}
	if len(resp.Files) == 1 && refusedFile != nil {
		status := http.StatusBadRequest
		if refusedFile.Kind == findingimport.KindTooLarge {
			status = http.StatusRequestEntityTooLarge
		}
		apierror.New(status, "UNREADABLE_RESULTS", refusedFile.Message).WithDetails(resp.Files[0]).WriteJSON(w)
		return
	}
	total.ReportID = run.ID.String()
	resp.IngestResponse = newIngestResponse(total)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(resp)
}

// addOutput sums the counts of one converted file's ingest.
func addOutput(t, o *ingest.Output) {
	if o == nil {
		return
	}
	t.AssetsCreated += o.AssetsCreated
	t.AssetsUpdated += o.AssetsUpdated
	t.FindingsCreated += o.FindingsCreated
	t.FindingsUpdated += o.FindingsUpdated
	t.FindingsSkipped += o.FindingsSkipped
	t.CVEsCreated += o.CVEsCreated
	t.CVEsUpdated += o.CVEsUpdated
	t.Errors = append(t.Errors, o.Errors...)
}

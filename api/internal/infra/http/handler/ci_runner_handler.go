package handler

// CI runner endpoints (docs/rfcs/RFC-051-ci-runner-identity-and-gate.md):
// the OIDC token exchange and the run-token routes a pipeline calls. Never
// logs a token: neither the CI provider's nor the run's.

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
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
	"github.com/openctemio/openctem/api/pkg/domain/scangov"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
	protov2 "github.com/openctemio/openctem/api/pkg/sensorproto/v2"
)

// CIRunService is what the CI runner endpoints need.
type CIRunService interface {
	Exchange(ctx context.Context, in cirunapp.ExchangeInput) (*cirunapp.ExchangeOutput, error)
	Authenticate(ctx context.Context, token string) (*cirun.Run, error)
	UploadReport(ctx context.Context, run *cirun.Run, report *ctis.Report) (*ingest.Output, error)
	KnownFindings(ctx context.Context, run *cirun.Run, out *ingest.Output) []cirun.KnownFinding
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
	// secretKeys derives the job's secret hashing key (nil: none).
	secretKeys SecretKeys
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
	// CommitSHA, optional, is the job's commit. Used only when the
	// provider's token signs none (CircleCI; Bitbucket and Jenkins tokens
	// without a commit claim); the run then marks the commit unverified.
	CommitSHA string `json:"commit_sha,omitempty"`
	// Repository, optional, is the repository's name ("workspace/name"),
	// used only when the token signs no name (Bitbucket). It is bound to the
	// repository id the token signs.
	Repository string `json:"repository,omitempty"`
	// BaseRef, optional, is the pull request's target branch as the job sees
	// it. It is accepted and ignored: the gate's baseline comes from a signed
	// claim or the code host, never from the job.
	BaseRef string `json:"base_ref,omitempty"`
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
	// SecretKey (base64) is the key the job hashes each raw secret it finds
	// with (HMAC-SHA256), sent as the CTIS partial fingerprint secretHMAC/v1,
	// so a secret finding keeps its identity without the raw value leaving
	// the job. Derived per organization and repository.
	SecretKey string `json:"secret_key,omitempty"`
}

// SecretKeys derives the per-repository key a CI job hashes secrets with.
type SecretKeys interface {
	ProducerKey(tenantID, assetID shared.ID) []byte
}

// SetSecretKeys makes the exchange hand out a secret hashing key (nil: none).
func (h *CIRunnerHandler) SetSecretKeys(k SecretKeys) { h.secretKeys = k }

// Exchange handles POST /api/v1/ci/oidc/exchange
// @Summary      Exchange a CI OIDC token for a run upload token
// @Description  A CI job (GitHub Actions, GitLab CI, Azure Pipelines, Bitbucket Pipelines, CircleCI, Jenkins with its OpenID Connect provider plugin) presents its OIDC token. When one of the organization's CI trust configurations admits it (issuer, audience, repository, ref, environment and event rules; fork pull requests refused by default), the platform creates a CI run on the repository asset and returns a run upload token that expires within 15 minutes. The same OIDC token exchanged again (a bounded number of times, while valid) gets a new token for the same run only. With aggregate true, the jobs of one pipeline run (same pipeline, provider run id, attempt and commit, from the verified token) share one run, each with its own token, and one final job evaluates it. Every refusal answers 401: before the token is admitted by a trust configuration with one generic message (CI_TOKEN_NOT_TRUSTED), after it with the reason (CI_TOKEN_<reason>).
// @Tags         CI
// @Accept       json
// @Produce      json
// @Param        body body CIExchangeRequest true "Tenant and OIDC token"
// @Success      201  {object}  CIExchangeResponse
// @Failure      400  {object}  apierror.Error
// @Failure      401  {object}  apierror.Error
// @Failure      403  {object}  apierror.Error "RUNNER_OUTDATED: the runner reports a version below the minimum supported one"
// @Failure      429  {object}  apierror.Error
// @Failure      503  {object}  apierror.Error "CI_ISSUER_UNAVAILABLE: the provider's keys cannot be fetched now; retry (Retry-After)"
// @Router       /ci/oidc/exchange [post]
// runnerOutdatedMessage tells the job exactly which line to change: the
// openctemio/ci release to pin, in each form a pipeline uses it.
func runnerOutdatedMessage(err error) string {
	var oe *cirunapp.RunnerOutdatedError
	if !errors.As(err, &oe) || oe.Pin == "" {
		return "This CI runner is older than the oldest openctemio/ci release this platform accepts; pin the current openctemio/ci release"
	}
	have := oe.Version
	if have == "" {
		have = "an older release"
	}
	return fmt.Sprintf("This CI runner (openctem-ci %s) is older than %s, the oldest openctemio/ci release this platform accepts. "+
		"Change the pin to %[3]s: GitHub `uses: openctemio/ci/.github/workflows/scan.yml@%[3]s` (or `openctemio/ci@%[3]s`); "+
		"GitLab `- remote: https://raw.githubusercontent.com/openctemio/ci/%[3]s/gitlab/templates/all.yml`; "+
		"other CI systems `ghcr.io/openctemio/ci:%[3]s`.", have, oe.Min, oe.Pin)
}

// ciRefusalHelp points the job at the refusal list.
const ciRefusalHelp = "See https://github.com/openctemio/ci/blob/main/docs/troubleshooting.md"

// ciNotTrustedMessage answers every refusal before a trust configuration
// admitted the token. It lists what to check without saying which check
// failed: a token from anyone on a shared issuer reaches this point, and the
// organization's configuration is not theirs to learn. An administrator
// sees the exact reason in the audit log.
const ciNotTrustedMessage = "The CI token was not accepted. Check that OPENCTEM_TENANT_ID is your organization's id, " +
	"that the job's id_token audience is openctem:tenant:<that id>, that the token is not expired, and that a CI trust " +
	"configuration of the organization admits this issuer, repository and ref (an administrator sees the exact reason " +
	"in the audit log). " + ciRefusalHelp

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
		RunID: req.RunID, Aggregate: req.Aggregate, Hints: cirun.Hints{CommitSHA: req.CommitSHA, Repository: req.Repository, BaseRef: req.BaseRef},
		ClientIP: getClientIP(r), UserAgent: r.UserAgent()})
	if err != nil {
		var refused *cirunapp.RefusedError
		if errors.As(err, &refused) {
			// The token was admitted by the organization's trust
			// configuration: the job is told why it was refused.
			apierror.New(http.StatusUnauthorized, apierror.Code("CI_TOKEN_"+strings.ToUpper(refused.Code)),
				"The CI token was not accepted: "+refused.Message+" "+ciRefusalHelp).WriteJSON(w)
			return
		}
		if errors.Is(err, cirunapp.ErrExchangeRefused) {
			apierror.New(http.StatusUnauthorized, "CI_TOKEN_NOT_TRUSTED", ciNotTrustedMessage).WriteJSON(w)
			return
		}
		if errors.Is(err, cirunapp.ErrIssuerUnavailable) {
			// Nothing was claimed: the same token may be retried.
			w.Header().Set("Retry-After", "30")
			apierror.New(http.StatusServiceUnavailable, "CI_ISSUER_UNAVAILABLE",
				"The CI provider's signing keys cannot be fetched right now (the provider is unreachable or has just rotated its keys); retry in 30 seconds").WriteJSON(w)
			return
		}
		if errors.Is(err, cirunapp.ErrRunnerOutdated) {
			apierror.New(http.StatusForbidden, "RUNNER_OUTDATED", runnerOutdatedMessage(err)).WriteJSON(w)
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
	if h.secretKeys != nil {
		if k := h.secretKeys.ProducerKey(run.TenantID, run.RepositoryAssetID); len(k) > 0 {
			resp.SecretKey = base64.StdEncoding.EncodeToString(k)
		}
	}
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
		ctx = scangov.WithOrigin(ctx, scangov.OriginCI)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// UploadResults handles POST /api/v1/ci/runs/{id}/results
// @Summary      Upload a CI run's results
// @Description  A CTIS report from the run, or a file a tool wrote in a format the importers read (SARIF, an SBOM, OSV results, ...; detected from the content, a ZIP of them too). It may name only the run's repository (an exported file's findings on any other asset are dropped and counted); the branch, commit and pull request come from the verified OIDC token, not from the report. Findings are recorded for the run's gate verdict. For a CTIS report, known lists the report's results that carry a decision the gate honors (false positive, duplicate, accepted risk, approved suppression), by index, so the job can leave them out of its own output.
// @Tags         CI
// @Accept       json
// @Produce      json
// @Param        id   path string true "Run ID"
// @Param        body body CTISIngestRequest true "CTIS report"
// @Success      201  {object}  CIUploadResponse
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
	_ = json.NewEncoder(w).Encode(CIUploadResponse{IngestResponse: newIngestResponse(out), Known: h.svc.KnownFindings(r.Context(), run, out)})
}

// CIUploadResponse is the result of a CI report upload: the ingest counts,
// and the results of this report that carry a decision the gate honors (a
// false positive, duplicate, accepted risk or approved suppression), by their
// index in the report. The job leaves those out of its own output.
type CIUploadResponse struct {
	IngestResponse
	Known []cirun.KnownFinding `json:"known"`
}

// decodeCTISReport accepts {"report": {...}} or a bare report, refusing
// fields outside the contract.
//
// The bounded I-JSON pre-pass runs first: nothing is decoded until the
// document's item counts are within ingest.CIReportBounds, so a small body
// cannot expand into gigabytes of decoded structs.
func decodeCTISReport(body []byte) (*ctis.Report, bool) {
	if ingest.CheckIJSONBounded(body, protov2.DefaultMaxJSONDepth, ingest.CIReportBounds) != nil {
		return nil, false
	}
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
	// RepoPolicy is the gate part of the repository's .openctem.yml. It can
	// only tighten the central policy; its exceptions become pending
	// suppression requests (default-branch runs only). An invalid file is
	// refused (400).
	RepoPolicy *cirun.RepoPolicy `json:"repo_policy,omitempty"`
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
	v, err := h.svc.Evaluate(r.Context(), run, cirunapp.EvaluateInput{ScanFailures: req.ScanFailures, RepoPolicy: req.RepoPolicy,
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
			// Like findings, statements belong to a run that is still
			// being judged; VEX never closes a finding, so the status of
			// the authenticated run is enough here.
			if run.Status == cirun.StatusEvaluated {
				firstErr = cirun.ErrRunEvaluated
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

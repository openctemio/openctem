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
	"net/http"
	"strings"
	"time"

	"github.com/openctemio/ctis"

	cirunapp "github.com/openctemio/openctem/api/internal/app/cirun"
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
	BaselineDiff(ctx context.Context, run *cirun.Run, fingerprints []string) (*cirunapp.BaselineDiffOutput, error)
	Evaluate(ctx context.Context, run *cirun.Run, in cirunapp.EvaluateInput) (*cirunapp.Verdict, error)
}

// CIRunnerHandler serves the pipeline side of CI runs.
type CIRunnerHandler struct {
	svc    CIRunService
	logger *logger.Logger
}

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
}

// Exchange handles POST /api/v1/ci/oidc/exchange
// @Summary      Exchange a CI OIDC token for a run upload token
// @Description  A GitHub Actions or GitLab CI job presents its OIDC token. When one of the organization's CI trust configurations admits it (issuer, audience, repository, ref, environment and event rules; fork pull requests refused by default), the platform creates a CI run on the repository asset and returns a run upload token that expires within 15 minutes. Each OIDC token can be exchanged once. Every refusal answers the same 401.
// @Tags         CI
// @Accept       json
// @Produce      json
// @Param        body body CIExchangeRequest true "Tenant and OIDC token"
// @Success      201  {object}  CIExchangeResponse
// @Failure      400  {object}  apierror.Error
// @Failure      401  {object}  apierror.Error
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
		RunID: req.RunID, ClientIP: getClientIP(r), UserAgent: r.UserAgent()})
	if err != nil {
		if errors.Is(err, cirunapp.ErrExchangeRefused) {
			apierror.Unauthorized("The CI token was not accepted").WriteJSON(w)
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
		PullRequest: run.PullRequest, DefaultBranch: run.DefaultBranch, IsDefaultBranch: run.IsDefaultBranch}
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
// @Description  A CTIS report from the run. It may name only the run's repository; the branch, commit and pull request come from the verified OIDC token, not from the report. Findings are recorded for the run's gate verdict.
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

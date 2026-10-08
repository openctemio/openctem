package handler

// CI administration (docs/rfcs/RFC-051-ci-runner-identity-and-gate.md): trust
// configurations, CI runs, gate policies and break-glass overrides. Tenant
// from the session; runs and overrides follow the caller's data scope (out of
// scope answers 404).

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	cirunapp "github.com/openctemio/openctem/api/internal/app/cirun"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/apierror"
	"github.com/openctemio/openctem/api/pkg/domain/cirun"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// CIAdminService is what the CI administration endpoints need.
type CIAdminService interface {
	ListTrustConfigs(ctx context.Context, tenantID shared.ID) ([]cirun.TrustConfig, error)
	GetTrustConfig(ctx context.Context, tenantID, id shared.ID) (*cirun.TrustConfig, error)
	CreateTrustConfig(ctx context.Context, tenantID shared.ID, in cirunapp.TrustConfigInput, a cirunapp.Actor) (*cirun.TrustConfig, error)
	UpdateTrustConfig(ctx context.Context, tenantID, id shared.ID, in cirunapp.TrustConfigInput, a cirunapp.Actor) (*cirun.TrustConfig, error)
	DeleteTrustConfig(ctx context.Context, tenantID, id shared.ID, a cirunapp.Actor) error
	PreviewTrust(ctx context.Context, tenantID shared.ID, in cirunapp.PreviewInput) (*cirunapp.PreviewResult, error)
	ListRuns(ctx context.Context, tenantID shared.ID, f cirun.RunFilter) ([]cirun.Run, int, error)
	GetRun(ctx context.Context, tenantID, id shared.ID) (*cirun.Run, error)
	ListGatePolicies(ctx context.Context, tenantID shared.ID) ([]cirun.GatePolicy, error)
	CreateGatePolicy(ctx context.Context, tenantID shared.ID, in cirunapp.GatePolicyInput, a cirunapp.Actor) (*cirun.GatePolicy, error)
	UpdateGatePolicy(ctx context.Context, tenantID, id shared.ID, in cirunapp.GatePolicyInput, a cirunapp.Actor) (*cirun.GatePolicy, error)
	DeleteGatePolicy(ctx context.Context, tenantID, id shared.ID, a cirunapp.Actor) error
	CreateOverride(ctx context.Context, tenantID shared.ID, in cirunapp.OverrideInput, a cirunapp.Actor) (*cirun.GateOverride, error)
	ListOverrides(ctx context.Context, tenantID shared.ID, assetID *shared.ID, scope *shared.DataScope) ([]cirun.GateOverride, error)
	GetOverride(ctx context.Context, tenantID, id shared.ID) (*cirun.GateOverride, error)
	RevokeOverride(ctx context.Context, tenantID, id shared.ID, a cirunapp.Actor) error
}

// CIAdminHandler serves /api/v1/ci administration.
type CIAdminHandler struct {
	svc       CIAdminService
	pipelines CIPipelineService
	coverage  CICoverageService
	settings  CISettingsService
	dataScope DataScopeEnforcer
	logger    *logger.Logger
}

// NewCIAdminHandler creates the handler. A nil data-scope enforcer leaves
// the lists unrestricted (tests).
func NewCIAdminHandler(svc CIAdminService, ds DataScopeEnforcer, log *logger.Logger) *CIAdminHandler {
	return &CIAdminHandler{svc: svc, dataScope: ds, logger: log.With("handler", "ci_admin")}
}

// ------------------------------------------------------------------ views --

// CITrustConfigResponse is a trust configuration.
type CITrustConfigResponse struct {
	ID            string      `json:"id"`
	Name          string      `json:"name"`
	Provider      string      `json:"provider"`
	Issuer        string      `json:"issuer"`
	Audience      string      `json:"audience"`
	DefaultBranch string      `json:"default_branch"`
	Rules         cirun.Rules `json:"rules"`
	Enabled       bool        `json:"enabled"`
	LastUsedAt    *time.Time  `json:"last_used_at,omitempty"`
	CreatedAt     time.Time   `json:"created_at"`
	UpdatedAt     time.Time   `json:"updated_at"`
}

func toCITrustResponse(c *cirun.TrustConfig) CITrustConfigResponse {
	return CITrustConfigResponse{ID: c.ID.String(), Name: c.Name, Provider: string(c.Provider), Issuer: c.Issuer,
		Audience: c.Audience, DefaultBranch: c.DefaultBranch, Rules: c.Rules, Enabled: c.Enabled,
		LastUsedAt: c.LastUsedAt, CreatedAt: c.CreatedAt, UpdatedAt: c.UpdatedAt}
}

// CITrustConfigRequest creates or changes a trust configuration.
type CITrustConfigRequest struct {
	Name     string `json:"name"`
	Provider string `json:"provider" enums:"github,gitlab,azure_devops,bitbucket,circleci,jenkins"`
	// Issuer defaults to the provider's public issuer (GitHub, gitlab.com).
	// A self-managed GitLab is its external URL; Azure Pipelines
	// https://vstoken.dev.azure.com/<organization id>; CircleCI
	// https://oidc.circleci.com/org/<organization id>; Bitbucket
	// https://api.bitbucket.org/2.0/workspaces/<workspace>/pipelines-config/identity/oidc;
	// Jenkins the plugin's issuer (<Jenkins URL>/oidc, or its alternate
	// issuer).
	Issuer string `json:"issuer,omitempty"`
	// Audience defaults to openctem:tenant:<tenant id> (Azure Pipelines:
	// api://AzureADTokenExchange, the only one it issues). Bitbucket,
	// CircleCI and Jenkins audiences must contain the tenant id.
	Audience      string      `json:"audience,omitempty"`
	DefaultBranch string      `json:"default_branch,omitempty"`
	Rules         cirun.Rules `json:"rules"`
	Enabled       *bool       `json:"enabled,omitempty"`
}

// CITrustConfigListResponse lists trust configurations.
type CITrustConfigListResponse struct {
	Data []CITrustConfigResponse `json:"data"`
}

// CIRunResponse is a CI run.
type CIRunResponse struct {
	ID                string `json:"id"`
	TrustConfigID     string `json:"trust_config_id,omitempty"`
	RepositoryAssetID string `json:"repository_asset_id"`
	Provider          string `json:"provider"`
	Repository        string `json:"repository"`
	Ref               string `json:"ref"`
	Branch            string `json:"branch,omitempty"`
	CommitSHA         string `json:"commit_sha"`
	// CommitVerified: the commit comes from the signed token (false: the
	// job reported it; its provider signs none).
	CommitVerified  bool   `json:"commit_verified"`
	PullRequest     string `json:"pull_request,omitempty"`
	DefaultBranch   string `json:"default_branch,omitempty"`
	IsDefaultBranch bool   `json:"is_default_branch"`
	Event           string `json:"event,omitempty"`
	Environment     string `json:"environment,omitempty"`
	Actor           string `json:"actor,omitempty"`
	ExternalRunID   string `json:"external_run_id,omitempty"`
	RunAttempt      string `json:"run_attempt,omitempty"`
	ExternalJobID   string `json:"external_job_id,omitempty"`
	Workflow        string `json:"workflow,omitempty"`
	PipelineURL     string `json:"pipeline_url,omitempty"`
	Fork            bool   `json:"fork"`
	PipelineID      string `json:"pipeline_id,omitempty"`
	// SensorVersion is the runner's version; Tools what its reports
	// declared; ScanFailures what it reported at evaluation. Labels only.
	SensorVersion string        `json:"sensor_version,omitempty"`
	Tools         []CIToolLabel `json:"tools"`
	ScanFailures  *int          `json:"scan_failures,omitempty"`
	TemplateRef   string        `json:"template_ref,omitempty"`
	Status        string        `json:"status"`
	Verdict       string        `json:"verdict,omitempty"`
	// VerdictDetail is the last verdict with its reasons and links (detail
	// view only).
	VerdictDetail *cirunapp.Verdict `json:"verdict_detail,omitempty"`
	EvaluatedAt   *time.Time        `json:"evaluated_at,omitempty"`
	ReportsCount  int               `json:"reports_count"`
	FindingsCount int               `json:"findings_count"`
	CreatedAt     time.Time         `json:"created_at"`
}

func toCIRunResponse(r *cirun.Run, withDetail bool) CIRunResponse {
	out := CIRunResponse{ID: r.ID.String(), RepositoryAssetID: r.RepositoryAssetID.String(), Provider: string(r.Provider),
		Repository: r.Repository, Ref: r.Ref, Branch: r.Branch, CommitSHA: r.CommitSHA, CommitVerified: r.CommitVerified,
		PullRequest: r.PullRequest, DefaultBranch: r.DefaultBranch, IsDefaultBranch: r.IsDefaultBranch, Event: r.Event, Environment: r.Environment,
		Actor: r.Actor, ExternalRunID: r.ExternalRunID, RunAttempt: r.RunAttempt,
		ExternalJobID: r.ExternalJobID, Workflow: r.Workflow,
		PipelineURL: r.PipelineURL, Fork: r.Fork, Status: r.Status, Verdict: r.Verdict, EvaluatedAt: r.EvaluatedAt,
		ReportsCount: r.ReportsCount, FindingsCount: r.FindingsCount, CreatedAt: r.CreatedAt}
	if r.TrustConfigID != nil {
		out.TrustConfigID = r.TrustConfigID.String()
	}
	if r.PipelineID != nil {
		out.PipelineID = r.PipelineID.String()
	}
	out.SensorVersion, out.ScanFailures, out.TemplateRef = r.SensorVersion, r.ScanFailures, r.TemplateRef
	out.Tools = make([]CIToolLabel, 0, len(r.Tools))
	for _, t := range r.Tools {
		out.Tools = append(out.Tools, CIToolLabel{Name: t.Name, Version: t.Version})
	}
	if withDetail && len(r.VerdictDetail) > 0 {
		var v cirunapp.Verdict
		if json.Unmarshal(r.VerdictDetail, &v) == nil {
			out.VerdictDetail = &v
		}
	}
	return out
}

// CIGatePolicyResponse is a gate policy.
type CIGatePolicyResponse struct {
	ID              string    `json:"id"`
	ScopeType       string    `json:"scope_type"`
	ScopeID         string    `json:"scope_id,omitempty"`
	Enabled         bool      `json:"enabled"`
	Mode            string    `json:"mode"`
	FailOnSeverity  string    `json:"fail_on_severity"`
	NewFindingsOnly bool      `json:"new_findings_only"`
	FailOnKEV       bool      `json:"fail_on_kev"`
	EPSSThreshold   *float64  `json:"epss_threshold,omitempty"`
	CreatedAt       time.Time `json:"created_at"`
	UpdatedAt       time.Time `json:"updated_at"`
}

func toCIPolicyResponse(p *cirun.GatePolicy) CIGatePolicyResponse {
	out := CIGatePolicyResponse{ID: p.ID.String(), ScopeType: p.ScopeType, Enabled: p.Enabled, Mode: p.Mode,
		FailOnSeverity: p.FailOnSeverity, NewFindingsOnly: p.NewFindingsOnly, FailOnKEV: p.FailOnKEV,
		EPSSThreshold: p.EPSSThreshold, CreatedAt: p.CreatedAt, UpdatedAt: p.UpdatedAt}
	if p.ScopeID != nil {
		out.ScopeID = p.ScopeID.String()
	}
	return out
}

// CIGatePolicyListResponse lists the gate policies and the built-in default.
type CIGatePolicyListResponse struct {
	Data    []CIGatePolicyResponse `json:"data"`
	Default CIGatePolicyResponse   `json:"default"`
}

// CIGatePolicyRequest creates or changes a gate policy. scope_type and
// scope_id are read on create only.
type CIGatePolicyRequest struct {
	ScopeType       string   `json:"scope_type,omitempty"`
	ScopeID         string   `json:"scope_id,omitempty"`
	Enabled         *bool    `json:"enabled,omitempty"`
	Mode            string   `json:"mode,omitempty"`
	FailOnSeverity  string   `json:"fail_on_severity,omitempty"`
	NewFindingsOnly *bool    `json:"new_findings_only,omitempty"`
	FailOnKEV       *bool    `json:"fail_on_kev,omitempty"`
	EPSSThreshold   *float64 `json:"epss_threshold,omitempty"`
}

// CIGateOverrideResponse is a break-glass override.
type CIGateOverrideResponse struct {
	ID                string     `json:"id"`
	RepositoryAssetID string     `json:"repository_asset_id"`
	CommitSHA         string     `json:"commit_sha"`
	Reason            string     `json:"reason"`
	CreatedBy         string     `json:"created_by,omitempty"`
	ExpiresAt         time.Time  `json:"expires_at"`
	RevokedAt         *time.Time `json:"revoked_at,omitempty"`
	Active            bool       `json:"active"`
	CreatedAt         time.Time  `json:"created_at"`
}

func toCIOverrideResponse(o *cirun.GateOverride, now time.Time) CIGateOverrideResponse {
	return CIGateOverrideResponse{ID: o.ID.String(), RepositoryAssetID: o.RepositoryAssetID.String(), CommitSHA: o.CommitSHA,
		Reason: o.Reason, CreatedBy: o.CreatedByEmail, ExpiresAt: o.ExpiresAt, RevokedAt: o.RevokedAt,
		Active: o.ActiveAt(now), CreatedAt: o.CreatedAt}
}

// CIGateOverrideListResponse lists overrides.
type CIGateOverrideListResponse struct {
	Data []CIGateOverrideResponse `json:"data"`
}

// CIGateOverrideRequest is a break-glass request.
type CIGateOverrideRequest struct {
	RepositoryAssetID string `json:"repository_asset_id"`
	CommitSHA         string `json:"commit_sha"`
	// Reason is required (10 to 2000 characters) and audited.
	Reason string `json:"reason"`
	// ExpiresInHours defaults to 24, at most 168.
	ExpiresInHours int `json:"expires_in_hours,omitempty"`
}

// ---------------------------------------------------------------- helpers --

func (h *CIAdminHandler) tenant(w http.ResponseWriter, r *http.Request) (shared.ID, bool) {
	id, err := shared.IDFromString(middleware.MustGetTenantID(r.Context()))
	if err != nil {
		apierror.Unauthorized("Invalid tenant ID").WriteJSON(w)
		return shared.ID{}, false
	}
	return id, true
}

func (h *CIAdminHandler) actor(r *http.Request) cirunapp.Actor {
	ctx := r.Context()
	return cirunapp.Actor{UserID: middleware.GetUserID(ctx), Email: auditActorEmail(ctx), IP: getClientIP(r),
		UserAgent: r.UserAgent(), RequestID: r.Header.Get("X-Request-ID")}
}

func pathID(w http.ResponseWriter, r *http.Request, what string) (shared.ID, bool) {
	id, err := shared.IDFromString(r.PathValue("id"))
	if err != nil {
		apierror.NotFound(what).WriteJSON(w)
		return shared.ID{}, false
	}
	return id, true
}

func (h *CIAdminHandler) writeErr(w http.ResponseWriter, err error, what, notFound string) {
	switch {
	case errors.Is(err, shared.ErrValidation):
		apierror.BadRequest(ciErrMessage(err)).WriteJSON(w)
	case errors.Is(err, shared.ErrConflict):
		apierror.Conflict(ciErrMessage(err)).WriteJSON(w)
	case errors.Is(err, shared.ErrNotFound):
		apierror.NotFound(notFound).WriteJSON(w)
	default:
		h.logger.Error("ci admin: "+what, "error", logger.SanitizeError(err))
		apierror.InternalServerError("failed to " + what).WriteJSON(w)
	}
}

// ciErrMessage drops the "validation failed: " class prefix.
func ciErrMessage(err error) string {
	msg := err.Error()
	for _, p := range []string{shared.ErrValidation.Error() + ": ", shared.ErrConflict.Error() + ": ", shared.ErrNotFound.Error() + ": "} {
		if len(msg) > len(p) && msg[:len(p)] == p {
			return msg[len(p):]
		}
	}
	return msg
}

func ciWriteJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// ---------------------------------------------------------- trust configs --

// ListTrustConfigs handles GET /api/v1/ci/trust-configs
// @Summary      List CI trust configurations
// @Description  Which CI pipelines (GitHub Actions, GitLab CI) may exchange their OIDC token for a run upload token.
// @Tags         CI
// @Produce      json
// @Security     BearerAuth
// @Success      200  {object}  CITrustConfigListResponse
// @Router       /ci/trust-configs [get]
func (h *CIAdminHandler) ListTrustConfigs(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := h.tenant(w, r)
	if !ok {
		return
	}
	list, err := h.svc.ListTrustConfigs(r.Context(), tenantID)
	if err != nil {
		h.writeErr(w, err, "list trust configurations", "CI trust configuration")
		return
	}
	out := CITrustConfigListResponse{Data: make([]CITrustConfigResponse, 0, len(list))}
	for i := range list {
		out.Data = append(out.Data, toCITrustResponse(&list[i]))
	}
	ciWriteJSON(w, http.StatusOK, out)
}

// GetTrustConfig handles GET /api/v1/ci/trust-configs/{id}
// @Summary      Get a CI trust configuration
// @Tags         CI
// @Produce      json
// @Security     BearerAuth
// @Param        id path string true "Trust configuration ID"
// @Success      200  {object}  CITrustConfigResponse
// @Failure      404  {object}  apierror.Error
// @Router       /ci/trust-configs/{id} [get]
func (h *CIAdminHandler) GetTrustConfig(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := h.tenant(w, r)
	if !ok {
		return
	}
	id, ok := pathID(w, r, "CI trust configuration")
	if !ok {
		return
	}
	c, err := h.svc.GetTrustConfig(r.Context(), tenantID, id)
	if err != nil {
		h.writeErr(w, err, "get trust configuration", "CI trust configuration")
		return
	}
	ciWriteJSON(w, http.StatusOK, toCITrustResponse(c))
}

// CreateTrustConfig handles POST /api/v1/ci/trust-configs
// @Summary      Create a CI trust configuration
// @Description  Rules must name at least one owner or repository. Fork pull requests are refused unless allow_fork_pull_requests is set. Audited.
// @Tags         CI
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        body body CITrustConfigRequest true "Trust configuration"
// @Success      201  {object}  CITrustConfigResponse
// @Failure      400  {object}  apierror.Error
// @Failure      409  {object}  apierror.Error
// @Router       /ci/trust-configs [post]
func (h *CIAdminHandler) CreateTrustConfig(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := h.tenant(w, r)
	if !ok {
		return
	}
	limitBody(w, r)
	var req CITrustConfigRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}
	c, err := h.svc.CreateTrustConfig(r.Context(), tenantID, cirunapp.TrustConfigInput{Name: req.Name, Provider: req.Provider,
		Issuer: req.Issuer, Audience: req.Audience, DefaultBranch: req.DefaultBranch, Rules: req.Rules, Enabled: req.Enabled},
		h.actor(r))
	if err != nil {
		h.writeErr(w, err, "create trust configuration", "CI trust configuration")
		return
	}
	ciWriteJSON(w, http.StatusCreated, toCITrustResponse(c))
}

// UpdateTrustConfig handles PUT /api/v1/ci/trust-configs/{id}
// @Summary      Change a CI trust configuration
// @Description  Replaces the configuration (the provider cannot change). Audited with before and after.
// @Tags         CI
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        id   path string true "Trust configuration ID"
// @Param        body body CITrustConfigRequest true "Trust configuration"
// @Success      200  {object}  CITrustConfigResponse
// @Failure      400  {object}  apierror.Error
// @Failure      404  {object}  apierror.Error
// @Router       /ci/trust-configs/{id} [put]
func (h *CIAdminHandler) UpdateTrustConfig(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := h.tenant(w, r)
	if !ok {
		return
	}
	id, ok := pathID(w, r, "CI trust configuration")
	if !ok {
		return
	}
	limitBody(w, r)
	var req CITrustConfigRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}
	c, err := h.svc.UpdateTrustConfig(r.Context(), tenantID, id, cirunapp.TrustConfigInput{Name: req.Name, Provider: req.Provider,
		Issuer: req.Issuer, Audience: req.Audience, DefaultBranch: req.DefaultBranch, Rules: req.Rules, Enabled: req.Enabled},
		h.actor(r))
	if err != nil {
		h.writeErr(w, err, "change trust configuration", "CI trust configuration")
		return
	}
	ciWriteJSON(w, http.StatusOK, toCITrustResponse(c))
}

// DeleteTrustConfig handles DELETE /api/v1/ci/trust-configs/{id}
// @Summary      Delete a CI trust configuration
// @Description  Pipelines it admitted can no longer exchange tokens; tokens already issued expire within 15 minutes. Audited.
// @Tags         CI
// @Security     BearerAuth
// @Param        id path string true "Trust configuration ID"
// @Success      204
// @Failure      404  {object}  apierror.Error
// @Router       /ci/trust-configs/{id} [delete]
func (h *CIAdminHandler) DeleteTrustConfig(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := h.tenant(w, r)
	if !ok {
		return
	}
	id, ok := pathID(w, r, "CI trust configuration")
	if !ok {
		return
	}
	if err := h.svc.DeleteTrustConfig(r.Context(), tenantID, id, h.actor(r)); err != nil {
		h.writeErr(w, err, "delete trust configuration", "CI trust configuration")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// -------------------------------------------------------------------- runs --

// ListRuns handles GET /api/v1/ci/runs
// @Summary      List CI runs
// @Description  CI pipeline runs (not sensors), newest first, on the repositories the caller may see.
// @Tags         CI
// @Produce      json
// @Security     BearerAuth
// @Param        repository_asset_id query string false "Repository asset"
// @Param        pipeline_id query string false "CI pipeline"
// @Param        verdict query string false "pass, fail or none"
// @Param        provider query string false "github, gitlab, azure_devops, bitbucket, circleci or jenkins"
// @Param        page query int false "Page (default 1)"
// @Param        per_page query int false "Per page (default 25, max 100)"
// @Success      200  {object}  ListResponse[CIRunResponse]
// @Router       /ci/runs [get]
func (h *CIAdminHandler) ListRuns(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := h.tenant(w, r)
	if !ok {
		return
	}
	q := r.URL.Query()
	f := cirun.RunFilter{Verdict: q.Get("verdict"), Provider: q.Get("provider")}
	if f.Verdict != "" && f.Verdict != cirun.VerdictPass && f.Verdict != cirun.VerdictFail && f.Verdict != cirun.VerdictNone {
		apierror.BadRequest("verdict must be pass, fail or none").WriteJSON(w)
		return
	}
	if f.Provider != "" && !cirun.Provider(f.Provider).IsValid() {
		apierror.BadRequest("provider must be github, gitlab, azure_devops, bitbucket, circleci or jenkins").WriteJSON(w)
		return
	}
	if v := q.Get("repository_asset_id"); v != "" {
		id, err := shared.IDFromString(v)
		if err != nil {
			apierror.BadRequest("repository_asset_id must be an id").WriteJSON(w)
			return
		}
		f.RepositoryAssetID = &id
	}
	if v := q.Get("pipeline_id"); v != "" {
		id, err := shared.IDFromString(v)
		if err != nil {
			apierror.BadRequest("pipeline_id must be an id").WriteJSON(w)
			return
		}
		f.PipelineID = &id
	}
	paging, ok := listPage(w, r, 25)
	if !ok {
		return
	}
	f.Page, f.PerPage = paging.Page, min(paging.PerPage, 100)
	scope, err := resolveDataScope(r.Context(), h.dataScope, tenantID)
	if err != nil {
		h.writeErr(w, err, "resolve data scope", "CI run")
		return
	}
	f.DataScope = scope
	runs, total, err := h.svc.ListRuns(r.Context(), tenantID, f)
	if err != nil {
		h.writeErr(w, err, "list CI runs", "CI run")
		return
	}
	data := make([]CIRunResponse, 0, len(runs))
	for i := range runs {
		data = append(data, toCIRunResponse(&runs[i], false))
	}
	pages := (total + f.PerPage - 1) / f.PerPage
	ciWriteJSON(w, http.StatusOK, ListResponse[CIRunResponse]{Data: data, Total: int64(total), Page: f.Page,
		PerPage: f.PerPage, TotalPages: pages, Links: NewPaginationLinks(r, f.Page, f.PerPage, pages)})
}

// GetRun handles GET /api/v1/ci/runs/{id}
// @Summary      Get a CI run
// @Description  The run with its last verdict (reasons and links). 404 when the repository is outside the caller's data scope.
// @Tags         CI
// @Produce      json
// @Security     BearerAuth
// @Param        id path string true "Run ID"
// @Success      200  {object}  CIRunResponse
// @Failure      404  {object}  apierror.Error
// @Router       /ci/runs/{id} [get]
func (h *CIAdminHandler) GetRun(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := h.tenant(w, r)
	if !ok {
		return
	}
	id, ok := pathID(w, r, "CI run")
	if !ok {
		return
	}
	run, err := h.svc.GetRun(r.Context(), tenantID, id)
	if err != nil {
		h.writeErr(w, err, "get CI run", "CI run")
		return
	}
	if !assetInDataScope(r.Context(), h.dataScope, tenantID, run.RepositoryAssetID) {
		apierror.NotFound("CI run").WriteJSON(w)
		return
	}
	ciWriteJSON(w, http.StatusOK, toCIRunResponse(run, true))
}

// ---------------------------------------------------------------- policies --

// ListGatePolicies handles GET /api/v1/ci/gate-policies
// @Summary      List CI gate policies
// @Description  The organization's, business units' and repositories' gate policies, and the built-in default used when none applies.
// @Tags         CI
// @Produce      json
// @Security     BearerAuth
// @Success      200  {object}  CIGatePolicyListResponse
// @Router       /ci/gate-policies [get]
func (h *CIAdminHandler) ListGatePolicies(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := h.tenant(w, r)
	if !ok {
		return
	}
	list, err := h.svc.ListGatePolicies(r.Context(), tenantID)
	if err != nil {
		h.writeErr(w, err, "list gate policies", "CI gate policy")
		return
	}
	def := cirun.DefaultGatePolicy()
	out := CIGatePolicyListResponse{Data: make([]CIGatePolicyResponse, 0, len(list)), Default: toCIPolicyResponse(&def)}
	for i := range list {
		out.Data = append(out.Data, toCIPolicyResponse(&list[i]))
	}
	ciWriteJSON(w, http.StatusOK, out)
}

func (req CIGatePolicyRequest) input() (cirunapp.GatePolicyInput, error) {
	in := cirunapp.GatePolicyInput{ScopeType: req.ScopeType, Enabled: req.Enabled, Mode: req.Mode,
		FailOnSeverity: req.FailOnSeverity, NewFindingsOnly: req.NewFindingsOnly, FailOnKEV: req.FailOnKEV,
		EPSSThreshold: req.EPSSThreshold}
	if req.ScopeID != "" {
		id, err := shared.IDFromString(req.ScopeID)
		if err != nil {
			return in, errors.New("scope_id must be an id")
		}
		in.ScopeID = &id
	}
	return in, nil
}

// CreateGatePolicy handles POST /api/v1/ci/gate-policies
// @Summary      Create a CI gate policy
// @Description  One policy per scope (tenant, business_unit or repository). Secrets always fail and accepted risk is always honored. Audited.
// @Tags         CI
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        body body CIGatePolicyRequest true "Policy"
// @Success      201  {object}  CIGatePolicyResponse
// @Failure      400  {object}  apierror.Error
// @Failure      404  {object}  apierror.Error
// @Failure      409  {object}  apierror.Error
// @Router       /ci/gate-policies [post]
func (h *CIAdminHandler) CreateGatePolicy(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := h.tenant(w, r)
	if !ok {
		return
	}
	limitBody(w, r)
	var req CIGatePolicyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}
	in, err := req.input()
	if err != nil {
		apierror.BadRequest(err.Error()).WriteJSON(w)
		return
	}
	p, err := h.svc.CreateGatePolicy(r.Context(), tenantID, in, h.actor(r))
	if err != nil {
		h.writeErr(w, err, "create gate policy", "Scope")
		return
	}
	ciWriteJSON(w, http.StatusCreated, toCIPolicyResponse(p))
}

// UpdateGatePolicy handles PATCH /api/v1/ci/gate-policies/{id}
// @Summary      Change a CI gate policy
// @Description  The scope cannot change. epss_threshold is replaced (omit it to clear it). Audited.
// @Tags         CI
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        id   path string true "Policy ID"
// @Param        body body CIGatePolicyRequest true "Changes"
// @Success      200  {object}  CIGatePolicyResponse
// @Failure      400  {object}  apierror.Error
// @Failure      404  {object}  apierror.Error
// @Router       /ci/gate-policies/{id} [patch]
func (h *CIAdminHandler) UpdateGatePolicy(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := h.tenant(w, r)
	if !ok {
		return
	}
	id, ok := pathID(w, r, "CI gate policy")
	if !ok {
		return
	}
	limitBody(w, r)
	var req CIGatePolicyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}
	in, err := req.input()
	if err != nil {
		apierror.BadRequest(err.Error()).WriteJSON(w)
		return
	}
	p, err := h.svc.UpdateGatePolicy(r.Context(), tenantID, id, in, h.actor(r))
	if err != nil {
		h.writeErr(w, err, "change gate policy", "CI gate policy")
		return
	}
	ciWriteJSON(w, http.StatusOK, toCIPolicyResponse(p))
}

// DeleteGatePolicy handles DELETE /api/v1/ci/gate-policies/{id}
// @Summary      Delete a CI gate policy
// @Tags         CI
// @Security     BearerAuth
// @Param        id path string true "Policy ID"
// @Success      204
// @Failure      404  {object}  apierror.Error
// @Router       /ci/gate-policies/{id} [delete]
func (h *CIAdminHandler) DeleteGatePolicy(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := h.tenant(w, r)
	if !ok {
		return
	}
	id, ok := pathID(w, r, "CI gate policy")
	if !ok {
		return
	}
	if err := h.svc.DeleteGatePolicy(r.Context(), tenantID, id, h.actor(r)); err != nil {
		h.writeErr(w, err, "delete gate policy", "CI gate policy")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// --------------------------------------------------------------- overrides --

// ListOverrides handles GET /api/v1/ci/gate-overrides
// @Summary      List CI gate break-glass overrides
// @Tags         CI
// @Produce      json
// @Security     BearerAuth
// @Param        repository_asset_id query string false "Repository asset"
// @Success      200  {object}  CIGateOverrideListResponse
// @Router       /ci/gate-overrides [get]
func (h *CIAdminHandler) ListOverrides(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := h.tenant(w, r)
	if !ok {
		return
	}
	var assetID *shared.ID
	if v := r.URL.Query().Get("repository_asset_id"); v != "" {
		id, err := shared.IDFromString(v)
		if err != nil {
			apierror.BadRequest("repository_asset_id must be an id").WriteJSON(w)
			return
		}
		assetID = &id
	}
	scope, err := resolveDataScope(r.Context(), h.dataScope, tenantID)
	if err != nil {
		h.writeErr(w, err, "resolve data scope", "CI gate override")
		return
	}
	list, err := h.svc.ListOverrides(r.Context(), tenantID, assetID, scope)
	if err != nil {
		h.writeErr(w, err, "list overrides", "CI gate override")
		return
	}
	now := time.Now()
	out := CIGateOverrideListResponse{Data: make([]CIGateOverrideResponse, 0, len(list))}
	for i := range list {
		out.Data = append(out.Data, toCIOverrideResponse(&list[i], now))
	}
	ciWriteJSON(w, http.StatusOK, out)
}

// CreateOverride handles POST /api/v1/ci/gate-overrides
// @Summary      Break-glass: let one commit pass the CI gate
// @Description  For one commit of one repository, until it expires (default 24 hours, at most 7 days). Requires a reason. Audited at high severity, and again each time it lets a failing run pass. 404 when the repository is outside the caller's data scope.
// @Tags         CI
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        body body CIGateOverrideRequest true "Override"
// @Success      201  {object}  CIGateOverrideResponse
// @Failure      400  {object}  apierror.Error
// @Failure      404  {object}  apierror.Error
// @Router       /ci/gate-overrides [post]
func (h *CIAdminHandler) CreateOverride(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := h.tenant(w, r)
	if !ok {
		return
	}
	limitBody(w, r)
	var req CIGateOverrideRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}
	assetID, err := shared.IDFromString(req.RepositoryAssetID)
	if err != nil {
		apierror.BadRequest("repository_asset_id must be an id").WriteJSON(w)
		return
	}
	if !assetInDataScope(r.Context(), h.dataScope, tenantID, assetID) {
		apierror.NotFound("Repository").WriteJSON(w)
		return
	}
	if req.ExpiresInHours < 0 || req.ExpiresInHours > int(cirun.MaxOverrideTTL/time.Hour) {
		apierror.BadRequest("expires_in_hours must be between 1 and 168").WriteJSON(w)
		return
	}
	o, err := h.svc.CreateOverride(r.Context(), tenantID, cirunapp.OverrideInput{RepositoryAssetID: assetID,
		CommitSHA: req.CommitSHA, Reason: req.Reason, Duration: time.Duration(req.ExpiresInHours) * time.Hour}, h.actor(r))
	if err != nil {
		h.writeErr(w, err, "create override", "Repository")
		return
	}
	ciWriteJSON(w, http.StatusCreated, toCIOverrideResponse(o, time.Now()))
}

// RevokeOverride handles POST /api/v1/ci/gate-overrides/{id}/revoke
// @Summary      Revoke a CI gate break-glass override
// @Tags         CI
// @Security     BearerAuth
// @Param        id path string true "Override ID"
// @Success      204
// @Failure      404  {object}  apierror.Error
// @Failure      409  {object}  apierror.Error
// @Router       /ci/gate-overrides/{id}/revoke [post]
func (h *CIAdminHandler) RevokeOverride(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := h.tenant(w, r)
	if !ok {
		return
	}
	id, ok := pathID(w, r, "CI gate override")
	if !ok {
		return
	}
	o, err := h.svc.GetOverride(r.Context(), tenantID, id)
	if err != nil {
		h.writeErr(w, err, "revoke override", "CI gate override")
		return
	}
	if !assetInDataScope(r.Context(), h.dataScope, tenantID, o.RepositoryAssetID) {
		apierror.NotFound("CI gate override").WriteJSON(w)
		return
	}
	if err := h.svc.RevokeOverride(r.Context(), tenantID, id, h.actor(r)); err != nil {
		h.writeErr(w, err, "revoke override", "CI gate override")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// CITrustPreviewRequest is a draft trust configuration and a sample token.
type CITrustPreviewRequest struct {
	Config CITrustConfigRequest `json:"config"`
	// IDToken is a sample token from a CI job. It is never stored and its
	// id is not recorded: the same token can still be exchanged.
	IDToken string `json:"id_token"`
	// CommitSHA and Repository are the job's own report, as an exchange
	// would send them (used only where the token signs nothing).
	CommitSHA  string `json:"commit_sha,omitempty"`
	Repository string `json:"repository,omitempty"`
}

// PreviewTrustConfig handles POST /api/v1/ci/trust-configs/preview
// @Summary      Preview a CI trust configuration against a sample token
// @Description  Verifies a sample token's signature, issuer and audience against the draft configuration's issuer keys (judged at the token's own issue time, so an expired sample is still shown, flagged expired), shows its claims and the normalized repository, ref, commit and run, and whether the rules would admit it. Nothing is stored; the token's id is not recorded. Rate limited.
// @Tags         CI
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        body body CITrustPreviewRequest true "Draft configuration and sample token"
// @Success      200  {object}  cirunapp.PreviewResult
// @Failure      400  {object}  apierror.Error
// @Failure      429  {object}  apierror.Error
// @Router       /ci/trust-configs/preview [post]
func (h *CIAdminHandler) PreviewTrustConfig(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	tenantID, ok := h.tenant(w, r)
	if !ok {
		return
	}
	limitBody(w, r)
	var req CITrustPreviewRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || strings.TrimSpace(req.IDToken) == "" {
		apierror.BadRequest("config and id_token are required").WriteJSON(w)
		return
	}
	c := req.Config
	out, err := h.svc.PreviewTrust(r.Context(), tenantID, cirunapp.PreviewInput{
		Config: cirunapp.TrustConfigInput{Name: c.Name, Provider: c.Provider, Issuer: c.Issuer, Audience: c.Audience,
			DefaultBranch: c.DefaultBranch, Rules: c.Rules},
		IDToken: strings.TrimSpace(req.IDToken),
		Hints:   cirun.Hints{CommitSHA: req.CommitSHA, Repository: req.Repository},
	})
	if err != nil {
		h.writeErr(w, err, "preview trust configuration", "CI trust configuration")
		return
	}
	ciWriteJSON(w, http.StatusOK, out)
}

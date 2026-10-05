package handler

// CI pipelines (docs/rfcs/RFC-051-ci-runner-identity-and-gate.md, "Pipelines
// in the fleet"): the logical identity of a CI scanner, listed in the fleet
// as a sensor in runner mode. Read-only: a pipeline is created by a verified
// token exchange and revoked with its trust configuration. Data scope:
// pipelines on repositories outside the caller's scope are not listed, and
// their ids answer 404.

import (
	"context"
	"net/http"
	"strconv"
	"strings"
	"time"

	cirunapp "github.com/openctemio/openctem/api/internal/app/cirun"
	"github.com/openctemio/openctem/api/pkg/apierror"
	"github.com/openctemio/openctem/api/pkg/domain/cirun"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// CIPipelineService is what the pipeline endpoints need.
type CIPipelineService interface {
	ListPipelines(ctx context.Context, tenantID shared.ID, in cirunapp.PipelineListInput) (*cirunapp.PipelineListOutput, error)
	AssessPipelines(ctx context.Context, tenantID shared.ID, f cirun.PipelineFilter) ([]cirunapp.PipelineView, error)
	GetPipeline(ctx context.Context, tenantID, id shared.ID) (*cirunapp.PipelineView, error)
	PipelineBranches(ctx context.Context, tenantID, id shared.ID) ([]cirun.PipelineBranch, error)
	PipelineGateTrend(ctx context.Context, tenantID, id shared.ID, limit int) ([]cirun.GatePoint, error)
}

// SetPipelineService wires the pipeline reads (nil leaves them 404).
func (h *CIAdminHandler) SetPipelineService(svc CIPipelineService) { h.pipelines = svc }

// CIToolLabel is a tool a run declared (a label).
type CIToolLabel struct {
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
}

// CIPipelineResponse is a CI pipeline with its computed status. Status is
// the one badge (severity order failing > degraded > stale > running/fresh;
// archived, revoked and never are inactive); freshness, gate and health are
// its three separate dimensions. A pipeline is never "offline".
type CIPipelineResponse struct {
	ID                string `json:"id"`
	Mode              string `json:"mode" enums:"runner"`
	Kind              string `json:"kind" enums:"ci_pipeline"`
	Role              string `json:"role" enums:"scanner"`
	Provider          string `json:"provider" enums:"github,gitlab"`
	RepositoryAssetID string `json:"repository_asset_id"`
	Repository        string `json:"repository"`
	WorkflowPath      string `json:"workflow_path"`
	WorkflowName      string `json:"workflow_name,omitempty"`
	TemplateRef       string `json:"template_ref,omitempty"`
	TemplateSHA       string `json:"template_sha,omitempty"`
	DefaultBranch     string `json:"default_branch,omitempty"`
	TrustConfigID     string `json:"trust_config_id,omitempty"`
	// Legacy: backfilled from runs that predate pipelines; the next run
	// confirms its repository id.
	Legacy bool `json:"legacy"`

	Status        string   `json:"status" enums:"retired,revoked,failing,degraded,stale,running,fresh,never,archived"`
	Freshness     string   `json:"freshness" enums:"running,fresh,stale,archived,never"`
	Gate          string   `json:"gate" enums:"passing,failing,none"`
	PRGate        string   `json:"pr_gate" enums:"passing,failing,none"`
	Health        string   `json:"health" enums:"ok,degraded,unknown"`
	HealthReasons []string `json:"health_reasons"`
	Inactive      bool     `json:"inactive"`
	Scheduled     bool     `json:"scheduled"`
	// StaleAfterSeconds is the expected-cadence threshold; StaleAt when the
	// pipeline turns stale without another run.
	StaleAfterSeconds int64      `json:"stale_after_seconds"`
	StaleAt           *time.Time `json:"stale_at,omitempty"`

	SensorVersion       string        `json:"sensor_version,omitempty"`
	VersionStatus       string        `json:"version_status" enums:"latest,update_available,unsupported,unknown"`
	Tools               []CIToolLabel `json:"tools"`
	RunsCount           int           `json:"runs_count"`
	FirstRunAt          *time.Time    `json:"first_run_at,omitempty"`
	LastRunAt           *time.Time    `json:"last_run_at,omitempty"`
	LastRunID           string        `json:"last_run_id,omitempty"`
	LastForkRunAt       *time.Time    `json:"last_fork_run_at,omitempty"`
	LastDefaultRunAt    *time.Time    `json:"last_default_run_at,omitempty"`
	LastDefaultVerdict  string        `json:"last_default_verdict,omitempty"`
	LastPRVerdict       string        `json:"last_pr_verdict,omitempty"`
	MedianIntervalSecs  int64         `json:"median_interval_seconds,omitempty"`
	ScheduleIntervalSec int64         `json:"schedule_interval_seconds,omitempty"`
	RevokedAt           *time.Time    `json:"revoked_at,omitempty"`
	RetiredAt           *time.Time    `json:"retired_at,omitempty"`
	RetireReason        string        `json:"retire_reason,omitempty"`
	CreatedAt           time.Time     `json:"created_at"`
}

// CIPipelineBranchResponse is one branch of a pipeline.
type CIPipelineBranchResponse struct {
	Branch          string    `json:"branch"`
	IsDefaultBranch bool      `json:"is_default_branch"`
	Runs            int       `json:"runs"`
	LastRunAt       time.Time `json:"last_run_at"`
	LastVerdict     string    `json:"last_verdict,omitempty"`
}

// CIGatePointResponse is one default-branch verdict.
type CIGatePointResponse struct {
	RunID       string    `json:"run_id"`
	Verdict     string    `json:"verdict"`
	CommitSHA   string    `json:"commit_sha"`
	EvaluatedAt time.Time `json:"evaluated_at"`
}

// CIPipelineDetailResponse is a pipeline with its branches and gate trend.
// Its runs are GET /ci/runs?pipeline_id=.
type CIPipelineDetailResponse struct {
	CIPipelineResponse
	Branches  []CIPipelineBranchResponse `json:"branches"`
	GateTrend []CIGatePointResponse      `json:"gate_trend"`
}

// CIPipelineListResponse is a page of pipelines with the status counts of
// every pipeline the filter admits (before the status filter).
type CIPipelineListResponse struct {
	ListResponse[CIPipelineResponse]
	Counts map[string]int `json:"counts"`
}

func toCIPipelineResponse(v *cirunapp.PipelineView) CIPipelineResponse {
	p, a := &v.Pipeline, &v.Assessment
	out := CIPipelineResponse{ID: p.ID.String(), Mode: FleetModeRunner, Kind: FleetKindCIPipeline, Role: fleetRoleScanner,
		Provider: string(p.Provider), RepositoryAssetID: p.RepositoryAssetID.String(), Repository: p.RepositoryName,
		WorkflowPath: p.WorkflowPath, WorkflowName: p.WorkflowName, TemplateRef: p.TemplateRef, TemplateSHA: p.TemplateSHA,
		DefaultBranch: p.DefaultBranch, Legacy: p.IsLegacy(),
		Status: string(a.Status), Freshness: string(a.Freshness), Gate: string(a.Gate), PRGate: string(a.PRGate),
		Health: string(a.Health), HealthReasons: append([]string{}, a.HealthReasons...), Inactive: a.Status.IsInactive(),
		Scheduled: a.Scheduled, StaleAfterSeconds: int64(a.StaleAfter / time.Second), StaleAt: a.StaleAt,
		SensorVersion: p.SensorVersion, VersionStatus: string(a.VersionStatus), Tools: make([]CIToolLabel, 0, len(p.Tools)),
		RunsCount: p.RunsCount, FirstRunAt: p.FirstRunAt, LastRunAt: p.LastRunAt, LastForkRunAt: p.LastForkRunAt,
		LastDefaultRunAt: p.LastDefaultRunAt, LastDefaultVerdict: p.LastDefaultVerdict, LastPRVerdict: p.LastPRVerdict,
		MedianIntervalSecs: int64(p.MedianInterval / time.Second), ScheduleIntervalSec: int64(p.ScheduleInterval / time.Second),
		RevokedAt: p.RevokedAt, RetiredAt: p.RetiredAt, RetireReason: p.RetireReason, CreatedAt: p.CreatedAt}
	if p.TrustConfigID != nil {
		out.TrustConfigID = p.TrustConfigID.String()
	}
	if p.LastRunID != nil {
		out.LastRunID = p.LastRunID.String()
	}
	for _, t := range p.Tools {
		out.Tools = append(out.Tools, CIToolLabel{Name: t.Name, Version: t.Version})
	}
	return out
}

// parsePipelineStatuses reads a comma-separated status filter.
func parsePipelineStatuses(raw string) ([]cirun.PipelineStatus, bool) {
	if strings.TrimSpace(raw) == "" {
		return nil, true
	}
	valid := map[cirun.PipelineStatus]bool{}
	for _, s := range cirun.AllPipelineStatuses() {
		valid[s] = true
	}
	parts := strings.Split(raw, ",")
	out := make([]cirun.PipelineStatus, 0, len(parts))
	for _, part := range parts {
		s := cirun.PipelineStatus(strings.TrimSpace(part))
		if !valid[s] {
			return nil, false
		}
		out = append(out, s)
	}
	return out, true
}

// ListPipelines handles GET /api/v1/ci/pipelines
// @Summary      List CI pipelines
// @Description  CI pipelines (sensors in runner mode) on the repositories the caller may see, most urgent first. Archived, revoked and never-run pipelines are hidden unless include_inactive=true or a status filter names them.
// @Tags         CI
// @Produce      json
// @Security     BearerAuth
// @Param        status query string false "Comma-separated statuses (revoked, failing, degraded, stale, running, fresh, never, archived)"
// @Param        include_inactive query bool false "Also list archived, revoked and never-run pipelines"
// @Param        provider query string false "github or gitlab"
// @Param        repository_asset_id query string false "Repository asset"
// @Param        search query string false "Repository, workflow path or name"
// @Param        page query int false "Page (default 1)"
// @Param        per_page query int false "Per page (default 25, max 200)"
// @Success      200  {object}  CIPipelineListResponse
// @Failure      400  {object}  apierror.Error
// @Router       /ci/pipelines [get]
func (h *CIAdminHandler) ListPipelines(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := h.tenant(w, r)
	if !ok {
		return
	}
	if h.pipelines == nil {
		apierror.NotFound("CI pipelines").WriteJSON(w)
		return
	}
	q := r.URL.Query()
	statuses, ok := parsePipelineStatuses(q.Get("status"))
	if !ok {
		apierror.BadRequest("status must be a comma-separated list of pipeline statuses").WriteJSON(w)
		return
	}
	in := cirunapp.PipelineListInput{Statuses: statuses, IncludeInactive: q.Get("include_inactive") == queryParamTrue,
		Search: truncateQuery(q.Get("search"), 255)}
	in.Filter.Provider = q.Get("provider")
	if in.Filter.Provider != "" && !cirun.Provider(in.Filter.Provider).IsValid() {
		apierror.BadRequest("provider must be github or gitlab").WriteJSON(w)
		return
	}
	if v := q.Get("repository_asset_id"); v != "" {
		id, err := shared.IDFromString(v)
		if err != nil {
			apierror.BadRequest("repository_asset_id must be an id").WriteJSON(w)
			return
		}
		in.Filter.RepositoryAssetID = &id
	}
	in.Page, _ = strconv.Atoi(q.Get("page"))
	in.PerPage, _ = strconv.Atoi(q.Get("per_page"))
	if in.Page < 1 {
		in.Page = 1
	}
	if in.PerPage < 1 || in.PerPage > cirunapp.MaxPipelinesPerPage {
		in.PerPage = 25
	}
	scope, err := resolveDataScope(r.Context(), h.dataScope, tenantID)
	if err != nil {
		h.writeErr(w, err, "resolve data scope", "CI pipeline")
		return
	}
	in.Filter.DataScope = scope
	out, err := h.pipelines.ListPipelines(r.Context(), tenantID, in)
	if err != nil {
		h.writeErr(w, err, "list CI pipelines", "CI pipeline")
		return
	}
	data := make([]CIPipelineResponse, 0, len(out.Items))
	for i := range out.Items {
		data = append(data, toCIPipelineResponse(&out.Items[i]))
	}
	counts := make(map[string]int, len(out.Counts))
	for k, v := range out.Counts {
		counts[string(k)] = v
	}
	pages := (out.Total + in.PerPage - 1) / in.PerPage
	ciWriteJSON(w, http.StatusOK, CIPipelineListResponse{ListResponse: ListResponse[CIPipelineResponse]{Data: data,
		Total: int64(out.Total), Page: in.Page, PerPage: in.PerPage, TotalPages: pages,
		Links: NewPaginationLinks(r, in.Page, in.PerPage, pages)}, Counts: counts})
}

// GetPipeline handles GET /api/v1/ci/pipelines/{id}
// @Summary      Get a CI pipeline
// @Description  The pipeline with its status, its branches (runs per branch; the branch is never part of its identity) and its default-branch gate trend. Its runs are GET /ci/runs?pipeline_id=. 404 when the repository is outside the caller's data scope.
// @Tags         CI
// @Produce      json
// @Security     BearerAuth
// @Param        id path string true "Pipeline ID"
// @Success      200  {object}  CIPipelineDetailResponse
// @Failure      404  {object}  apierror.Error
// @Router       /ci/pipelines/{id} [get]
func (h *CIAdminHandler) GetPipeline(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := h.tenant(w, r)
	if !ok {
		return
	}
	id, ok := pathID(w, r, "CI pipeline")
	if !ok {
		return
	}
	if h.pipelines == nil {
		apierror.NotFound("CI pipeline").WriteJSON(w)
		return
	}
	v, err := h.pipelines.GetPipeline(r.Context(), tenantID, id)
	if err != nil {
		h.writeErr(w, err, "get CI pipeline", "CI pipeline")
		return
	}
	if !assetInDataScope(r.Context(), h.dataScope, tenantID, v.RepositoryAssetID) {
		apierror.NotFound("CI pipeline").WriteJSON(w)
		return
	}
	branches, err := h.pipelines.PipelineBranches(r.Context(), tenantID, id)
	if err != nil {
		h.writeErr(w, err, "list CI pipeline branches", "CI pipeline")
		return
	}
	trend, err := h.pipelines.PipelineGateTrend(r.Context(), tenantID, id, 30)
	if err != nil {
		h.writeErr(w, err, "load CI pipeline gate trend", "CI pipeline")
		return
	}
	out := CIPipelineDetailResponse{CIPipelineResponse: toCIPipelineResponse(v),
		Branches: make([]CIPipelineBranchResponse, 0, len(branches)), GateTrend: make([]CIGatePointResponse, 0, len(trend))}
	for _, b := range branches {
		out.Branches = append(out.Branches, CIPipelineBranchResponse{Branch: b.Branch, IsDefaultBranch: b.IsDefaultBranch,
			Runs: b.Runs, LastRunAt: b.LastRunAt, LastVerdict: b.LastVerdict})
	}
	for _, g := range trend {
		out.GateTrend = append(out.GateTrend, CIGatePointResponse{RunID: g.RunID.String(), Verdict: g.Verdict,
			CommitSHA: g.CommitSHA, EvaluatedAt: g.EvaluatedAt})
	}
	ciWriteJSON(w, http.StatusOK, out)
}

// FleetRunners returns the tenant's pipelines as fleet rows, within the
// caller's data scope (the fleet read model).
func (h *CIAdminHandler) FleetRunners(ctx context.Context, tenantID shared.ID) ([]FleetItem, error) {
	if h.pipelines == nil {
		return []FleetItem{}, nil
	}
	scope, err := resolveDataScope(ctx, h.dataScope, tenantID)
	if err != nil {
		return nil, err
	}
	views, err := h.pipelines.AssessPipelines(ctx, tenantID, cirun.PipelineFilter{DataScope: scope})
	if err != nil {
		return nil, err
	}
	out := make([]FleetItem, 0, len(views))
	for i := range views {
		v := &views[i]
		name := v.RepositoryName
		if v.WorkflowName != "" {
			name += " · " + v.WorkflowName
		}
		st := v.Assessment.Status
		out = append(out, FleetItem{ID: v.ID.String(), Mode: FleetModeRunner, Kind: FleetKindCIPipeline,
			Role: fleetRoleScanner, Name: name, Description: v.WorkflowPath, Status: string(st),
			Attention: st == cirun.PipelineFailing || st == cirun.PipelineDegraded || st == cirun.PipelineStale,
			Inactive:  st.IsInactive(), LastSeenAt: v.LastRunAt, Version: v.SensorVersion, Provider: string(v.Provider),
			Repository: v.RepositoryName, RepositoryAssetID: v.RepositoryAssetID.String(), Workflow: v.WorkflowPath,
			Gate: string(v.Assessment.Gate), Freshness: string(v.Assessment.Freshness), Health: string(v.Assessment.Health),
			Links: FleetLinks{Self: "/api/v1/ci/pipelines/" + v.ID.String()}})
	}
	return out, nil
}

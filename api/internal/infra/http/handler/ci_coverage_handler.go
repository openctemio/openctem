package handler

// CI coverage, expected repositories and pipeline retirement
// (docs/rfcs/RFC-051-ci-runner-identity-and-gate.md §10.6). Coverage lists
// only repositories in the caller's data scope; marking a repository or
// retiring a pipeline out of scope answers 404.

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	cirunapp "github.com/openctemio/openctem/api/internal/app/cirun"
	"github.com/openctemio/openctem/api/pkg/apierror"
	"github.com/openctemio/openctem/api/pkg/domain/cirun"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// CICoverageService is what the coverage endpoints need.
type CICoverageService interface {
	Coverage(ctx context.Context, tenantID shared.ID, in cirunapp.CoverageInput) (*cirunapp.CoverageOutput, error)
	SetExpectation(ctx context.Context, tenantID, assetID shared.ID, caps []string, a cirunapp.Actor) (*cirun.Expectation, error)
	DeleteExpectation(ctx context.Context, tenantID, assetID shared.ID, a cirunapp.Actor) error
	RetirePipeline(ctx context.Context, tenantID, id shared.ID, reason string, a cirunapp.Actor) (*cirun.Pipeline, []shared.ID, error)
}

// SetCoverageService wires the coverage endpoints (nil leaves them 404).
func (h *CIAdminHandler) SetCoverageService(svc CICoverageService) { h.coverage = svc }

// CICapabilityCoverage is one capability of one repository.
type CICapabilityCoverage struct {
	Capability string     `json:"capability" enums:"sast,sca,secrets,iac"`
	State      string     `json:"state" enums:"fresh,stale,never"`
	Expected   bool       `json:"expected"`
	LastAt     *time.Time `json:"last_at,omitempty"`
	SourceKind string     `json:"source_kind,omitempty" enums:"ci_pipeline,scan"`
	PipelineID string     `json:"pipeline_id,omitempty"`
	SourceName string     `json:"source_name,omitempty"`
}

// CIRepositoryCoverage is one repository's coverage.
type CIRepositoryCoverage struct {
	RepositoryAssetID    string                 `json:"repository_asset_id"`
	Repository           string                 `json:"repository"`
	Criticality          string                 `json:"criticality"`
	Covered              bool                   `json:"covered"`
	Gap                  bool                   `json:"gap"`
	Expected             bool                   `json:"expected"`
	ExpectedCapabilities []string               `json:"expected_capabilities"`
	Pipelines            int                    `json:"pipelines"`
	Capabilities         []CICapabilityCoverage `json:"capabilities"`
}

// CICoverageSummary counts every repository in scope.
type CICoverageSummary struct {
	Repositories           int            `json:"repositories"`
	Covered                int            `json:"covered"`
	Uncovered              int            `json:"uncovered"`
	Expected               int            `json:"expected"`
	Gaps                   int            `json:"gaps"`
	UncoveredByCriticality map[string]int `json:"uncovered_by_criticality"`
	FreshByCapability      map[string]int `json:"fresh_by_capability"`
}

// CITemplateVersion is one version of a template and its pipelines.
type CITemplateVersion struct {
	Version     string     `json:"version"`
	PipelineIDs []string   `json:"pipeline_ids"`
	LastRunAt   *time.Time `json:"last_run_at,omitempty"`
}

// CITemplateDrift is a reusable workflow and the versions its pipelines run.
type CITemplateDrift struct {
	Template string              `json:"template"`
	Current  string              `json:"current"`
	Drifted  int                 `json:"drifted"`
	Total    int                 `json:"total"`
	Versions []CITemplateVersion `json:"versions"`
}

// CICoverageResponse is a page of repository coverage.
type CICoverageResponse struct {
	ListResponse[CIRepositoryCoverage]
	Summary   CICoverageSummary `json:"summary"`
	Templates []CITemplateDrift `json:"templates"`
	Truncated bool              `json:"truncated"`
}

// CICoverageExpectationRequest marks a repository as expected.
type CICoverageExpectationRequest struct {
	// Capabilities expected (sast, sca, secrets, iac); empty = all four.
	Capabilities []string `json:"capabilities"`
}

// CICoverageExpectationResponse is a repository's expectation.
type CICoverageExpectationResponse struct {
	RepositoryAssetID string   `json:"repository_asset_id"`
	Capabilities      []string `json:"capabilities"`
}

// CIRetirePipelineRequest retires a pipeline.
type CIRetirePipelineRequest struct {
	// Reason, 10 to 2000 characters (audited).
	Reason string `json:"reason"`
}

// CIRetirePipelineResponse is the retired pipeline and how many findings
// closed as source retired.
type CIRetirePipelineResponse struct {
	PipelineID     string `json:"pipeline_id"`
	FindingsClosed int    `json:"findings_closed"`
}

func toCICoverage(r *cirun.RepositoryCoverage) CIRepositoryCoverage {
	out := CIRepositoryCoverage{RepositoryAssetID: r.Repository.ID.String(), Repository: r.Repository.Name,
		Criticality: r.Repository.Criticality, Covered: r.Covered, Gap: r.Gap, Expected: r.Expected,
		ExpectedCapabilities: []string{}, Pipelines: r.Pipelines, Capabilities: make([]CICapabilityCoverage, 0, len(r.Capabilities))}
	for _, c := range r.ExpectedCapabilities {
		out.ExpectedCapabilities = append(out.ExpectedCapabilities, string(c))
	}
	for _, c := range r.Capabilities {
		cc := CICapabilityCoverage{Capability: string(c.Capability), State: string(c.State), Expected: c.Expected,
			LastAt: c.LastAt, SourceKind: c.SourceKind, SourceName: c.SourceName}
		if c.PipelineID != nil {
			cc.PipelineID = c.PipelineID.String()
		}
		out.Capabilities = append(out.Capabilities, cc)
	}
	return out
}

// GetCoverage handles GET /api/v1/ci/coverage
// @Summary      Repository coverage
// @Description  Repository x capability (sast, sca, secrets, iac) coverage from any executor: CI pipelines (their default-branch runs and the tools they reported) and daemon scans. A capability is fresh while its pipeline runs within its cadence (30 days for a scan), stale up to 90 days, never after. Gaps first (an expected capability not fresh), then uncovered, by criticality. Only repositories in the caller's data scope. Template drift lists reusable workflows whose pipelines run different versions.
// @Tags         CI
// @Produce      json
// @Security     BearerAuth
// @Param        filter query string false "gap, uncovered or covered"
// @Param        capability query string false "sast, sca, secrets or iac (with state)"
// @Param        state query string false "fresh, stale or never (with capability)"
// @Param        expected query bool false "Only repositories marked as expected"
// @Param        criticality query string false "critical, high, medium, low or none"
// @Param        search query string false "Repository name"
// @Param        page query int false "Page (default 1)"
// @Param        per_page query int false "Per page (default 25, max 200)"
// @Success      200  {object}  CICoverageResponse
// @Failure      400  {object}  apierror.Error
// @Router       /ci/coverage [get]
func (h *CIAdminHandler) GetCoverage(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := h.tenant(w, r)
	if !ok {
		return
	}
	if h.coverage == nil {
		apierror.NotFound("CI coverage").WriteJSON(w)
		return
	}
	q := r.URL.Query()
	in := cirunapp.CoverageInput{Filter: q.Get("filter"), Capability: cirun.Capability(q.Get("capability")),
		State: cirun.CoverageState(q.Get("state")), ExpectedOnly: q.Get("expected") == queryParamTrue,
		Criticality: q.Get("criticality"), Search: truncateQuery(q.Get("search"), 255)}
	switch in.Filter {
	case "", cirunapp.CoverageFilterGap, cirunapp.CoverageFilterUncovered, cirunapp.CoverageFilterCovered:
	default:
		apierror.BadRequest("filter must be gap, uncovered or covered").WriteJSON(w)
		return
	}
	if in.Capability != "" && !in.Capability.IsValid() {
		apierror.BadRequest("capability must be sast, sca, secrets or iac").WriteJSON(w)
		return
	}
	switch in.State {
	case "", cirun.CoverageFresh, cirun.CoverageStale, cirun.CoverageNever:
	default:
		apierror.BadRequest("state must be fresh, stale or never").WriteJSON(w)
		return
	}
	in.Page, _ = strconv.Atoi(q.Get("page"))
	in.PerPage, _ = strconv.Atoi(q.Get("per_page"))
	if in.Page < 1 {
		in.Page = 1
	}
	if in.PerPage < 1 || in.PerPage > cirunapp.MaxCoveragePerPage {
		in.PerPage = 25
	}
	scope, err := resolveDataScope(r.Context(), h.dataScope, tenantID)
	if err != nil {
		h.writeErr(w, err, "resolve data scope", "CI coverage")
		return
	}
	in.DataScope = scope
	out, err := h.coverage.Coverage(r.Context(), tenantID, in)
	if err != nil {
		h.writeErr(w, err, "compute CI coverage", "CI coverage")
		return
	}
	data := make([]CIRepositoryCoverage, 0, len(out.Items))
	for i := range out.Items {
		data = append(data, toCICoverage(&out.Items[i]))
	}
	sum := CICoverageSummary{Repositories: out.Summary.Repositories, Covered: out.Summary.Covered,
		Uncovered: out.Summary.Uncovered, Expected: out.Summary.Expected, Gaps: out.Summary.Gaps,
		UncoveredByCriticality: out.Summary.UncoveredByCriticality, FreshByCapability: map[string]int{}}
	for k, v := range out.Summary.FreshByCapability {
		sum.FreshByCapability[string(k)] = v
	}
	templates := make([]CITemplateDrift, 0, len(out.Templates))
	for _, t := range out.Templates {
		td := CITemplateDrift{Template: t.Template, Current: t.Current, Drifted: t.Drifted, Total: t.Total}
		for _, v := range t.Versions {
			tv := CITemplateVersion{Version: v.Version, LastRunAt: v.LastRunAt, PipelineIDs: make([]string, 0, len(v.Pipelines))}
			for _, id := range v.Pipelines {
				tv.PipelineIDs = append(tv.PipelineIDs, id.String())
			}
			td.Versions = append(td.Versions, tv)
		}
		templates = append(templates, td)
	}
	pages := (out.Total + in.PerPage - 1) / in.PerPage
	ciWriteJSON(w, http.StatusOK, CICoverageResponse{ListResponse: ListResponse[CIRepositoryCoverage]{Data: data,
		Total: int64(out.Total), Page: in.Page, PerPage: in.PerPage, TotalPages: pages,
		Links: NewPaginationLinks(r, in.Page, in.PerPage, pages)}, Summary: sum, Templates: templates, Truncated: out.Truncated})
}

// SetCoverageExpectation handles PUT /api/v1/ci/coverage/expected/{id}
// @Summary      Expect a repository to be covered
// @Description  Marks a repository as expected to be scanned (for the listed capabilities, all four when empty), so a capability that is not fresh shows as a gap and "never scanned" is visible. Audited. 404 when the repository is outside the caller's data scope.
// @Tags         CI
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        id   path string true "Repository asset ID"
// @Param        body body CICoverageExpectationRequest true "Capabilities"
// @Success      200  {object}  CICoverageExpectationResponse
// @Failure      400  {object}  apierror.Error
// @Failure      404  {object}  apierror.Error
// @Router       /ci/coverage/expected/{id} [put]
func (h *CIAdminHandler) SetCoverageExpectation(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := h.tenant(w, r)
	if !ok {
		return
	}
	id, ok := pathID(w, r, "Repository")
	if !ok {
		return
	}
	if h.coverage == nil || !assetInDataScope(r.Context(), h.dataScope, tenantID, id) {
		apierror.NotFound("Repository").WriteJSON(w)
		return
	}
	limitBody(w, r)
	var req CICoverageExpectationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}
	if len(req.Capabilities) > 8 {
		apierror.BadRequest("at most four capabilities").WriteJSON(w)
		return
	}
	e, err := h.coverage.SetExpectation(r.Context(), tenantID, id, req.Capabilities, h.actor(r))
	if err != nil {
		h.writeErr(w, err, "set coverage expectation", "Repository")
		return
	}
	resp := CICoverageExpectationResponse{RepositoryAssetID: id.String(), Capabilities: []string{}}
	for _, c := range e.Capabilities {
		resp.Capabilities = append(resp.Capabilities, string(c))
	}
	ciWriteJSON(w, http.StatusOK, resp)
}

// DeleteCoverageExpectation handles DELETE /api/v1/ci/coverage/expected/{id}
// @Summary      Stop expecting a repository to be covered
// @Description  Audited. 404 when the repository is outside the caller's data scope or was not expected.
// @Tags         CI
// @Security     BearerAuth
// @Param        id path string true "Repository asset ID"
// @Success      204
// @Failure      404  {object}  apierror.Error
// @Router       /ci/coverage/expected/{id} [delete]
func (h *CIAdminHandler) DeleteCoverageExpectation(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := h.tenant(w, r)
	if !ok {
		return
	}
	id, ok := pathID(w, r, "Repository")
	if !ok {
		return
	}
	if h.coverage == nil || !assetInDataScope(r.Context(), h.dataScope, tenantID, id) {
		apierror.NotFound("Repository").WriteJSON(w)
		return
	}
	if err := h.coverage.DeleteExpectation(r.Context(), tenantID, id, h.actor(r)); err != nil {
		h.writeErr(w, err, "delete coverage expectation", "Coverage expectation")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// RetirePipeline handles POST /api/v1/ci/pipelines/{id}/retire
// @Summary      Retire a CI pipeline
// @Description  The pipeline is hidden as retired and the open findings only it reported close as "source retired" (audited; each can be reopened). Findings another source still observes are untouched. The next verified run of the pipeline brings it back. 404 when its repository is outside the caller's data scope; 409 when already retired.
// @Tags         CI
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        id   path string true "Pipeline ID"
// @Param        body body CIRetirePipelineRequest true "Reason"
// @Success      200  {object}  CIRetirePipelineResponse
// @Failure      400  {object}  apierror.Error
// @Failure      404  {object}  apierror.Error
// @Failure      409  {object}  apierror.Error
// @Router       /ci/pipelines/{id}/retire [post]
func (h *CIAdminHandler) RetirePipeline(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := h.tenant(w, r)
	if !ok {
		return
	}
	id, ok := pathID(w, r, "CI pipeline")
	if !ok {
		return
	}
	if h.coverage == nil || h.pipelines == nil {
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
	limitBody(w, r)
	var req CIRetirePipelineRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}
	_, closed, err := h.coverage.RetirePipeline(r.Context(), tenantID, id, req.Reason, h.actor(r))
	if err != nil {
		h.writeErr(w, err, "retire CI pipeline", "CI pipeline")
		return
	}
	ciWriteJSON(w, http.StatusOK, CIRetirePipelineResponse{PipelineID: id.String(), FindingsClosed: len(closed)})
}

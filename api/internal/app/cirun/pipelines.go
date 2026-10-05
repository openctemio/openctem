package cirun

import (
	"context"
	"slices"
	"strings"

	"github.com/openctemio/openctem/api/pkg/domain/cirun"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// PipelineView is a pipeline with its computed status.
type PipelineView struct {
	cirun.Pipeline
	Assessment cirun.Assessment
}

// PipelineListInput narrows a pipeline listing.
type PipelineListInput struct {
	Filter cirun.PipelineFilter
	// Statuses keeps only these combined statuses (empty: all active ones,
	// or every status with IncludeInactive).
	Statuses []cirun.PipelineStatus
	// IncludeInactive also lists archived, revoked and never-run pipelines
	// (hidden by default; hidden is not deleted).
	IncludeInactive bool
	// Search matches the repository, workflow path and workflow name.
	Search  string
	Page    int
	PerPage int
}

// PipelineListOutput is one page of pipelines and the status counts of
// every pipeline the filter (not the status filter) admits.
type PipelineListOutput struct {
	Items  []PipelineView
	Total  int
	Counts map[cirun.PipelineStatus]int
}

// MaxPipelinesPerPage bounds a listing page.
const MaxPipelinesPerPage = 200

// ListPipelines lists the tenant's pipelines with their status, within the
// caller's data scope (in the filter). The status depends on the clock, so
// the listing is filtered and paged after it is computed; the tenant cap
// keeps that bounded.
func (s *Service) ListPipelines(ctx context.Context, tenantID shared.ID, in PipelineListInput) (*PipelineListOutput, error) {
	all, err := s.AssessPipelines(ctx, tenantID, in.Filter)
	if err != nil {
		return nil, err
	}
	out := &PipelineListOutput{Counts: map[cirun.PipelineStatus]int{}}
	for _, st := range cirun.AllPipelineStatuses() {
		out.Counts[st] = 0
	}
	q := strings.ToLower(strings.TrimSpace(in.Search))
	matched := make([]PipelineView, 0, len(all))
	for _, v := range all {
		if q != "" && !strings.Contains(strings.ToLower(v.RepositoryName), q) &&
			!strings.Contains(strings.ToLower(v.WorkflowPath), q) && !strings.Contains(strings.ToLower(v.WorkflowName), q) {
			continue
		}
		out.Counts[v.Assessment.Status]++
		switch {
		case len(in.Statuses) > 0:
			if !slices.Contains(in.Statuses, v.Assessment.Status) {
				continue
			}
		case !in.IncludeInactive && v.Assessment.Status.IsInactive():
			continue
		}
		matched = append(matched, v)
	}
	// Most urgent first, then by repository and workflow.
	rank := map[cirun.PipelineStatus]int{}
	for i, st := range cirun.AllPipelineStatuses() {
		rank[st] = i
	}
	slices.SortStableFunc(matched, func(a, b PipelineView) int {
		if d := rank[a.Assessment.Status] - rank[b.Assessment.Status]; d != 0 {
			return d
		}
		if c := strings.Compare(a.RepositoryName, b.RepositoryName); c != 0 {
			return c
		}
		return strings.Compare(a.WorkflowPath, b.WorkflowPath)
	})
	out.Total = len(matched)
	perPage := in.PerPage
	if perPage <= 0 || perPage > MaxPipelinesPerPage {
		perPage = 25
	}
	page := max(in.Page, 1)
	start := min((page-1)*perPage, len(matched))
	end := min(start+perPage, len(matched))
	out.Items = matched[start:end]
	return out, nil
}

// AssessPipelines returns every pipeline the filter admits with its status
// (the fleet read model; bounded by the tenant cap).
func (s *Service) AssessPipelines(ctx context.Context, tenantID shared.ID, f cirun.PipelineFilter) ([]PipelineView, error) {
	all, err := s.repo.ListPipelines(ctx, tenantID, f)
	if err != nil {
		return nil, err
	}
	now := s.now().UTC()
	out := make([]PipelineView, 0, len(all))
	for i := range all {
		out = append(out, PipelineView{Pipeline: all[i], Assessment: all[i].Assess(now, s.cfg.Versions)})
	}
	return out, nil
}

// GetPipeline returns one pipeline with its status. The caller checks the
// data scope on its repository asset.
func (s *Service) GetPipeline(ctx context.Context, tenantID, id shared.ID) (*PipelineView, error) {
	p, err := s.repo.GetPipeline(ctx, tenantID, id)
	if err != nil {
		return nil, err
	}
	return &PipelineView{Pipeline: *p, Assessment: p.Assess(s.now().UTC(), s.cfg.Versions)}, nil
}

// PipelineBranches returns the pipeline's branches (runs per branch).
func (s *Service) PipelineBranches(ctx context.Context, tenantID, id shared.ID) ([]cirun.PipelineBranch, error) {
	return s.repo.PipelineBranches(ctx, tenantID, id)
}

// PipelineGateTrend returns the pipeline's recent default-branch verdicts.
func (s *Service) PipelineGateTrend(ctx context.Context, tenantID, id shared.ID, limit int) ([]cirun.GatePoint, error) {
	return s.repo.PipelineGateTrend(ctx, tenantID, id, limit)
}

package cirun

import (
	"context"
	"fmt"
	"strings"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	auditdom "github.com/openctemio/openctem/api/pkg/domain/audit"
	"github.com/openctemio/openctem/api/pkg/domain/cirun"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// MaxCoverageRepositories bounds one coverage computation.
const MaxCoverageRepositories = 5000

// MaxCoveragePerPage bounds a coverage page.
const MaxCoveragePerPage = 200

// Coverage list filters.
const (
	CoverageFilterGap       = "gap"
	CoverageFilterUncovered = "uncovered"
	CoverageFilterCovered   = "covered"
)

// CoverageInput narrows the coverage listing.
type CoverageInput struct {
	DataScope *shared.DataScope
	// Filter: gap, uncovered or covered ("" = all).
	Filter string
	// Capability with State keeps repositories whose capability is in that
	// state.
	Capability   cirun.Capability
	State        cirun.CoverageState
	ExpectedOnly bool
	Criticality  string
	Search       string
	Page         int
	PerPage      int
}

// CoverageOutput is one page of repository coverage, the summary of every
// repository in scope, and template drift.
type CoverageOutput struct {
	Items     []cirun.RepositoryCoverage
	Total     int
	Summary   cirun.CoverageSummary
	Templates []cirun.TemplateDrift
	// Truncated: the tenant has more repositories than one computation
	// covers.
	Truncated bool
}

// Coverage computes repository x capability coverage within the caller's
// data scope.
func (s *Service) Coverage(ctx context.Context, tenantID shared.ID, in CoverageInput) (*CoverageOutput, error) {
	now := s.now().UTC()
	repos, err := s.repo.ListRepositories(ctx, tenantID, in.DataScope, MaxCoverageRepositories+1)
	if err != nil {
		return nil, fmt.Errorf("list repositories: %w", err)
	}
	out := &CoverageOutput{}
	if len(repos) > MaxCoverageRepositories {
		repos, out.Truncated = repos[:MaxCoverageRepositories], true
	}
	obs, err := s.repo.CoverageObservations(ctx, tenantID, now.Add(-cirun.CoverageWindow))
	if err != nil {
		return nil, err
	}
	pipes, err := s.repo.ListPipelines(ctx, tenantID, cirun.PipelineFilter{DataScope: in.DataScope})
	if err != nil {
		return nil, err
	}
	byID := make(map[shared.ID]cirun.Pipeline, len(pipes))
	for _, p := range pipes {
		byID[p.ID] = p
	}
	exps, err := s.repo.ListExpectations(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	rows := cirun.ComputeCoverage(repos, obs, byID, exps, now, s.cfg.Versions)
	cirun.SortCoverage(rows)
	out.Summary = cirun.Summarize(rows)
	out.Templates = cirun.ComputeTemplateDrift(pipes, now, s.cfg.Versions)

	q := strings.ToLower(strings.TrimSpace(in.Search))
	matched := rows[:0:0]
	for _, r := range rows {
		if !coverageMatches(r, in, q) {
			continue
		}
		matched = append(matched, r)
	}
	out.Total = len(matched)
	perPage := in.PerPage
	if perPage <= 0 || perPage > MaxCoveragePerPage {
		perPage = 25
	}
	page := max(in.Page, 1)
	start := min((page-1)*perPage, len(matched))
	end := min(start+perPage, len(matched))
	out.Items = matched[start:end]
	return out, nil
}

func coverageMatches(r cirun.RepositoryCoverage, in CoverageInput, q string) bool {
	switch in.Filter {
	case CoverageFilterGap:
		if !r.Gap {
			return false
		}
	case CoverageFilterUncovered:
		if r.Covered {
			return false
		}
	case CoverageFilterCovered:
		if !r.Covered {
			return false
		}
	}
	if in.ExpectedOnly && !r.Expected {
		return false
	}
	if in.Criticality != "" && r.Repository.Criticality != in.Criticality {
		return false
	}
	if q != "" && !strings.Contains(strings.ToLower(r.Repository.Name), q) {
		return false
	}
	if in.Capability != "" && in.State != "" {
		for _, c := range r.Capabilities {
			if c.Capability == in.Capability {
				return c.State == in.State
			}
		}
		return false
	}
	return true
}

// SetExpectation marks a repository as expected to be covered (audited).
// The caller has checked the repository is in its data scope.
func (s *Service) SetExpectation(ctx context.Context, tenantID, assetID shared.ID, caps []string, a Actor) (*cirun.Expectation, error) {
	parsed, err := cirun.ParseCapabilities(caps)
	if err != nil {
		return nil, err
	}
	ok, err := s.repo.RepositoryExists(ctx, tenantID, assetID)
	if err != nil {
		return nil, fmt.Errorf("check repository: %w", err)
	}
	if !ok {
		return nil, cirun.ErrRepositoryNotFound
	}
	now := s.now().UTC()
	e := &cirun.Expectation{TenantID: tenantID, RepositoryAssetID: assetID, Capabilities: parsed, CreatedAt: now, UpdatedAt: now}
	if uid, err := shared.IDFromString(a.UserID); err == nil {
		e.CreatedBy = &uid
	}
	if err := s.repo.UpsertExpectation(ctx, e); err != nil {
		return nil, err
	}
	names := make([]string, 0, len(parsed))
	for _, c := range parsed {
		names = append(names, string(c))
	}
	s.logAudit(ctx, tenantID, a, auditapp.NewSuccessEvent(auditdom.ActionCICoverageExpected, auditdom.ResourceTypeAsset, assetID.String()).
		WithMessage("Repository marked as expected to be covered by CI scanning").
		WithMetadata("capabilities", names))
	return e, nil
}

// DeleteExpectation removes a repository's expectation (audited).
func (s *Service) DeleteExpectation(ctx context.Context, tenantID, assetID shared.ID, a Actor) error {
	if err := s.repo.DeleteExpectation(ctx, tenantID, assetID); err != nil {
		return err
	}
	s.logAudit(ctx, tenantID, a, auditapp.NewSuccessEvent(auditdom.ActionCICoverageUnexpected, auditdom.ResourceTypeAsset, assetID.String()).
		WithMessage("Repository no longer expected to be covered by CI scanning"))
	return nil
}

// maxAuditedFindingIDs caps the finding ids written into one audit record.
const maxAuditedFindingIDs = 200

// RetirePipeline retires a pipeline: it is hidden as retired and the open
// findings only it reported close as "source retired" (audited, and each can
// be reopened). Findings another source still observes are untouched. The
// caller has checked the pipeline's repository is in its data scope.
func (s *Service) RetirePipeline(ctx context.Context, tenantID, id shared.ID, reason string, a Actor) (*cirun.Pipeline, []shared.ID, error) {
	reason = strings.TrimSpace(reason)
	if n := len([]rune(reason)); n < cirun.MinRetireReason || n > cirun.MaxRetireReason {
		return nil, nil, fmt.Errorf("%w: a reason of %d to %d characters is required", shared.ErrValidation,
			cirun.MinRetireReason, cirun.MaxRetireReason)
	}
	var by *shared.ID
	if uid, err := shared.IDFromString(a.UserID); err == nil {
		by = &uid
	}
	p, closed, err := s.repo.RetirePipeline(ctx, tenantID, id, by, reason, s.now().UTC())
	if err != nil {
		return nil, nil, err
	}
	ids := make([]string, 0, min(len(closed), maxAuditedFindingIDs))
	for i, f := range closed {
		if i == maxAuditedFindingIDs {
			break
		}
		ids = append(ids, f.String())
	}
	s.logAudit(ctx, tenantID, a, auditapp.NewSuccessEvent(auditdom.ActionCIPipelineRetired, auditdom.ResourceTypeCIPipeline, id.String()).
		WithResourceName(p.RepositoryName+" "+p.WorkflowPath).
		WithMessage(fmt.Sprintf("CI pipeline %s on %s retired; %d finding(s) only it reported closed as source retired",
			p.WorkflowPath, p.RepositoryName, len(closed))).
		WithMetadata("reason", reason).
		WithMetadata("findings_closed", len(closed)).
		WithMetadata("finding_ids", ids).
		WithSeverity(auditdom.SeverityHigh))
	return p, closed, nil
}

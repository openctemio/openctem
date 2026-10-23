package finding

// Duplicate candidates of a finding, with "known internally since".
// https://github.com/openctemio/openctem/blob/develop/api/docs/rfcs/RFC-121-bug-bounty-reports.md

import (
	"context"
	"fmt"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

// duplicateSuggester is implemented by the postgres finding repository.
type duplicateSuggester interface {
	DuplicateSuggestions(ctx context.Context, q vulnerability.DuplicateSuggestionQuery) ([]vulnerability.DuplicateSuggestion, error)
}

// DuplicateCandidatesResult is the answer for one finding.
type DuplicateCandidatesResult struct {
	FindingID shared.ID
	// ReportSubmittedAt is the bounty report's submission time, when the
	// finding has a report that says it.
	ReportSubmittedAt *time.Time
	Candidates        []vulnerability.DuplicateSuggestion
}

// KnownSince is the earliest first detection among the candidates.
func (r *DuplicateCandidatesResult) KnownSince() *time.Time {
	var out *time.Time
	for i := range r.Candidates {
		t := r.Candidates[i].FirstDetectedAt
		if out == nil || t.Before(*out) {
			out = &t
		}
	}
	return out
}

// DuplicateCandidates suggests findings that may describe the same issue as
// findingID. The finding must be in the caller's tenant and data scope
// (else not found); candidates come only from the caller's data scope, so
// the answer reveals nothing the caller could not list. Nothing is merged.
func (s *VulnerabilityService) DuplicateCandidates(ctx context.Context, tenantID, findingID string) (*DuplicateCandidatesResult, error) {
	tid, err := shared.IDFromString(tenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant id format", shared.ErrValidation)
	}
	id, err := shared.IDFromString(findingID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid id format", shared.ErrValidation)
	}
	repo, ok := s.findingRepo.(duplicateSuggester)
	if !ok {
		return nil, fmt.Errorf("%w: duplicate candidates are not available", shared.ErrValidation)
	}
	f, err := s.findingRepo.GetByID(ctx, tid, id)
	if err != nil {
		return nil, err
	}
	if err := s.assertFindingScope(ctx, f); err != nil {
		return nil, err
	}
	// Fail closed: an unwired enforcer is an error, never an unscoped read.
	scope, err := s.dataScope.ResolveStrict(ctx, tid)
	if err != nil {
		return nil, err
	}
	q := vulnerability.DuplicateSuggestionQuery{
		TenantID: tid, FindingID: id, AssetID: f.AssetID(), Scope: scope,
		Limit: vulnerability.MaxDuplicateSuggestions,
	}
	res := &DuplicateCandidatesResult{FindingID: id}
	if r := f.BountyReport(); r != nil {
		res.ReportSubmittedAt = r.SubmittedAt
		if r.Weakness != "" {
			q.ExtraCWEs = []string{r.Weakness}
		}
		if r.EndpointPath != "" {
			q.ExtraPaths = []string{r.EndpointPath}
		}
	}
	if f.AssetID().IsZero() {
		return res, nil
	}
	res.Candidates, err = repo.DuplicateSuggestions(s.dataScope.WithFindingViewer(ctx), q)
	if err != nil {
		return nil, err
	}
	return res, nil
}

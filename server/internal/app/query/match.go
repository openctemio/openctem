package query

import (
	"context"
	"errors"
	"fmt"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/querylang"
	"github.com/openctemio/openctem/api/pkg/querylang/pgsql"
)

// Matcher is an executor that also returns the findings a filter-only
// query selects (postgres.QueryExecutor).
type Matcher interface {
	Match(ctx context.Context, p *querylang.Plan, o pgsql.MatchOptions) (*querylang.Matches, error)
}

// ErrNotFindingFilter refuses a query that is not a filter over findings:
// only "findings where ..." selects findings for a remediation task.
var ErrNotFindingFilter = shared.NewDomainError("QUERY_NOT_FINDING_FILTER",
	"Only a findings query without pipeline stages selects findings: use \"findings where ...\" and remove the \"| ...\" stages.",
	shared.ErrValidation)

// MatchResult is what MatchFindings returns.
type MatchResult struct {
	// Query is the canonical text; Version is the language version it was
	// checked against.
	Query   string
	Version int
	// Description is the query in plain words.
	Description string
	Scope       Scope
	querylang.Matches
}

// LanguageVersion is the version of the query language a stored query was
// written for (the document version, querylang.DocumentVersion).
func LanguageVersion() int { return querylang.DocumentVersion }

// MatchFindings runs a filter-only findings query as the caller and returns
// the matching finding ids, under the same principal resolution, rules,
// limits and concurrency caps as Run.
func (s *Service) MatchFindings(ctx context.Context, c Caller, text string, o pgsql.MatchOptions) (*MatchResult, error) {
	m, ok := s.exec.(Matcher)
	if !ok {
		return nil, errors.New("query executor cannot match findings")
	}
	plan, err := s.plan(ctx, c, text)
	if err != nil {
		return nil, err
	}
	if plan.Entity().Name != querylang.Findings.Name || len(plan.Query().Pipeline) > 0 {
		return nil, ErrNotFindingFilter
	}
	release, err := s.limiter.acquire(c.TenantID, c.UserID)
	if err != nil {
		return nil, err
	}
	defer release()
	res, err := m.Match(ctx, plan, o)
	if err != nil {
		if errors.Is(err, pgsql.ErrMatchNeedsFilter) {
			return nil, ErrNotFindingFilter
		}
		return nil, fmt.Errorf("match findings: %w", err)
	}
	return &MatchResult{Query: querylang.Format(plan.Query()), Version: querylang.DocumentVersion,
		Description: querylang.Describe(plan), Scope: scopeOf(plan), Matches: *res}, nil
}

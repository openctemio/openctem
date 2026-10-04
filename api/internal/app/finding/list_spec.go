package finding

import (
	"context"
	"errors"
	"fmt"

	"github.com/openctemio/openctem/api/internal/app/datascope"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
	"github.com/openctemio/openctem/api/pkg/filterspec"
	"github.com/openctemio/openctem/api/pkg/pagination"
)

// Findings listed through the list query contract
// (docs/rfcs/RFC-048-list-query-contract.md): the handler decodes the
// request into a filterspec.Spec, and this service compiles it as the caller,
// so the tenant, the caller's data scope and the pentest membership rule are
// always part of the query.

// FilterCaller is the request's caller for a filtered read.
type FilterCaller struct {
	TenantID string
	UserID   string
	IsAdmin  bool
	// Has reports the caller's permissions (for permission-gated fields).
	Has func(permission string) bool
}

// findingWhereRepo is the part of the finding repository that runs compiled
// filters. postgres.FindingRepository implements it.
type findingWhereRepo interface {
	ListWhere(ctx context.Context, w *filterspec.Where, page pagination.Pagination) (pagination.Result[*vulnerability.Finding], error)
	CountWhere(ctx context.Context, w *filterspec.Where) (int64, error)
	GetStatsWhere(ctx context.Context, w *filterspec.Where) (*vulnerability.FindingStats, error)
}

var errNoFindingWhereRepo = errors.New("finding repository cannot run compiled filters")

// FilterActor resolves the caller's data scope and returns the actor every
// findings filter compiles as.
func (s *VulnerabilityService) FilterActor(ctx context.Context, c FilterCaller) (filterspec.Actor, error) {
	return filterActor(ctx, s.dataScope, c)
}

// filterActor resolves c's data scope with e. It fails closed: a member's
// read with no enforcer wired, or a failed scope lookup, is an error.
func filterActor(ctx context.Context, e *datascope.Enforcer, c FilterCaller) (filterspec.Actor, error) {
	tenantID, err := shared.IDFromString(c.TenantID)
	if err != nil {
		return filterspec.Actor{}, fmt.Errorf("%w: invalid tenant id format", shared.ErrValidation)
	}
	var userID shared.ID
	if c.UserID != "" {
		if userID, err = shared.IDFromString(c.UserID); err != nil {
			return filterspec.Actor{}, fmt.Errorf("%w: invalid acting user", shared.ErrValidation)
		}
	}
	var scope *shared.DataScope
	if !c.IsAdmin && c.UserID != "" {
		if e == nil {
			return filterspec.Actor{}, errors.New("data scope enforcer not configured")
		}
		scope, err = e.ResolveFor(ctx, tenantID, datascope.Caller{UserID: c.UserID, IsAdmin: false})
		if err != nil {
			return filterspec.Actor{}, fmt.Errorf("resolve data scope: %w", err)
		}
	}
	return filterspec.UserActor(filterspec.UserActorInput{
		TenantID: tenantID, UserID: userID, IsAdmin: c.IsAdmin, Scope: scope, Has: c.Has,
	})
}

// ListFindingsBySpec lists findings for a decoded filter, as the caller. A
// filter that does not compile for the caller (a field they may not use)
// returns a *filterspec.Error.
func (s *VulnerabilityService) ListFindingsBySpec(ctx context.Context, c FilterCaller, spec *filterspec.Spec) (pagination.Result[*vulnerability.Finding], error) {
	var empty pagination.Result[*vulnerability.Finding]
	repo, ok := s.findingRepo.(findingWhereRepo)
	if !ok {
		return empty, errNoFindingWhereRepo
	}
	actor, err := s.FilterActor(ctx, c)
	if err != nil {
		return empty, err
	}
	where, err := filterspec.Compile(spec, vulnerability.FindingFields, actor)
	if err != nil {
		return empty, err
	}
	return repo.ListWhere(ctx, where, pagination.New(spec.Page, spec.PerPage))
}

// GetFindingStatsBySpec computes the findings stats for a decoded filter, as
// the caller: the same compiled WHERE as ListFindingsBySpec, so the metric
// strip and the table count the same rows.
func (s *VulnerabilityService) GetFindingStatsBySpec(ctx context.Context, c FilterCaller, spec *filterspec.Spec) (*vulnerability.FindingStats, error) {
	repo, ok := s.findingRepo.(findingWhereRepo)
	if !ok {
		return nil, errNoFindingWhereRepo
	}
	actor, err := s.FilterActor(ctx, c)
	if err != nil {
		return nil, err
	}
	where, err := filterspec.Compile(spec, vulnerability.FindingFields, actor)
	if err != nil {
		return nil, err
	}
	return repo.GetStatsWhere(ctx, where)
}

// groupsArgOffset is the first placeholder the grouped-view queries leave to
// the filter ($1 is their tenant).
const groupsArgOffset = 2

// ListFindingGroupsBySpec groups the findings a decoded filter selects, as
// the caller: the filter is compiled once against FindingFieldsF and is the
// whole WHERE of every dimension's query.
func (s *FindingActionsService) ListFindingGroupsBySpec(
	ctx context.Context, c FilterCaller, groupBy string, spec *filterspec.Spec, page pagination.Pagination,
) (pagination.Result[*vulnerability.FindingGroup], error) {
	var empty pagination.Result[*vulnerability.FindingGroup]
	if !validGroupDimensions[groupBy] {
		return empty, fmt.Errorf("%w: invalid group_by: %s", shared.ErrValidation, groupBy)
	}
	actor, err := filterActor(ctx, s.dataScope, c)
	if err != nil {
		return empty, err
	}
	where, err := filterspec.CompileFrom(spec, vulnerability.FindingFieldsF, actor, groupsArgOffset)
	if err != nil {
		return empty, err
	}
	tid := actor.TenantID()
	filter := vulnerability.NewFindingFilter()
	filter.TenantID = &tid
	filter.Compiled = where
	return s.findingRepo.ListFindingGroups(ctx, tid, groupBy, filter, page)
}

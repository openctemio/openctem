package finding

import (
	"context"
	"errors"
	"fmt"

	"github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/internal/app/datascope"
	auditdom "github.com/openctemio/openctem/api/pkg/domain/audit"
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
	switch {
	case !c.IsAdmin && c.UserID != "":
		if e == nil {
			return filterspec.Actor{}, errors.New("data scope enforcer not configured")
		}
		scope, err = e.ResolveFor(ctx, tenantID, datascope.Caller{UserID: c.UserID, IsAdmin: false})
	case c.UserID != "" && e != nil:
		// An administrator is not narrowed to scope rows, but private
		// program assets stay hidden unless they are an owner or a member
		// (RFC-065 §15.3).
		scope, err = e.ResolveFor(ctx, tenantID, datascope.Caller{UserID: c.UserID, IsAdmin: true, IsOwner: e.CallerOf(ctx).IsOwner})
	}
	if err != nil {
		return filterspec.Actor{}, fmt.Errorf("resolve data scope: %w", err)
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
	where, err := filterspec.Compile(vulnerability.WithBranchOnlyDefault(spec), vulnerability.FindingFields, actor)
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
	where, err := filterspec.Compile(vulnerability.WithBranchOnlyDefault(spec), vulnerability.FindingFields, actor)
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
	where, err := filterspec.CompileFrom(vulnerability.WithBranchOnlyDefault(spec), vulnerability.FindingFieldsF, actor, groupsArgOffset)
	if err != nil {
		return empty, err
	}
	tid := actor.TenantID()
	filter := vulnerability.NewFindingFilter()
	filter.TenantID = &tid
	filter.Compiled = where
	return s.findingRepo.ListFindingGroups(ctx, tid, groupBy, filter, page)
}

// MaxExportRows caps one findings export (RFC-048 §3.7). A larger set is
// narrowed with the filter.
const MaxExportRows = 100000

// exportBatch is the number of rows read per export query.
const exportBatch = 1000

type findingExportRepo interface {
	ExportBatchWhere(ctx context.Context, w *filterspec.Where, afterID string, limit int) ([]*vulnerability.Finding, error)
}

// ExportResult describes a finished export.
type ExportResult struct {
	Rows      int
	Truncated bool
}

// ExportFindingsBySpec streams every finding a decoded filter selects, as
// the caller, to emit in batches (id order), up to MaxExportRows. The export
// is audit-logged with the filter's field and operator names (never its
// values) and the row count, whether it completes or not.
func (s *VulnerabilityService) ExportFindingsBySpec(
	ctx context.Context, c FilterCaller, spec *filterspec.Spec, format string, actx audit.AuditContext,
	emit func([]*vulnerability.Finding) error,
) (ExportResult, error) {
	var res ExportResult
	repo, ok := s.findingRepo.(findingExportRepo)
	if !ok {
		return res, errNoFindingWhereRepo
	}
	actor, err := s.FilterActor(ctx, c)
	if err != nil {
		return res, err
	}
	where, err := filterspec.Compile(vulnerability.WithBranchOnlyDefault(spec), vulnerability.FindingFields, actor)
	if err != nil {
		return res, err
	}
	defer func() { s.auditExport(ctx, actx, spec, format, res, err) }()

	after := ""
	for res.Rows < MaxExportRows {
		batch, berr := repo.ExportBatchWhere(ctx, where, after, min(exportBatch, MaxExportRows-res.Rows))
		if berr != nil {
			err = berr
			return res, err
		}
		if len(batch) == 0 {
			return res, nil
		}
		if eerr := emit(batch); eerr != nil {
			err = eerr
			return res, err
		}
		res.Rows += len(batch)
		after = batch[len(batch)-1].ID().String()
		if len(batch) < min(exportBatch, MaxExportRows) {
			return res, nil
		}
	}
	// At the cap: is there more?
	more, berr := repo.ExportBatchWhere(ctx, where, after, 1)
	if berr == nil && len(more) > 0 {
		res.Truncated = true
	}
	return res, nil
}

// auditExport records a findings export: who, the filter shape (field and
// operator names only, so no hostnames or free text land in the audit log),
// the format and how many rows left the system.
func (s *VulnerabilityService) auditExport(ctx context.Context, actx audit.AuditContext, spec *filterspec.Spec, format string, res ExportResult, err error) {
	if s.auditService == nil {
		return
	}
	shape := make([]string, 0, len(spec.Leaves()))
	for _, l := range spec.Leaves() {
		shape = append(shape, l.Field+":"+string(l.Op))
	}
	ev := audit.NewSuccessEvent(auditdom.ActionDataExported, auditdom.ResourceTypeFinding, "findings").
		WithMessage(fmt.Sprintf("Exported %d findings (%s)", res.Rows, format)).
		WithMetadata("rows", res.Rows).
		WithMetadata("truncated", res.Truncated).
		WithMetadata("format", format).
		WithMetadata("filter", shape).
		WithMetadata("search", spec.Q != "").
		WithSeverity(auditdom.SeverityMedium)
	if err != nil {
		ev = ev.WithMetadata("incomplete", true)
	}
	if lerr := s.auditService.LogEvent(ctx, actx, ev); lerr != nil {
		s.logger.Warn("audit findings export failed", "error", lerr)
	}
}

// relatedCVEsArgOffset is the first placeholder FindRelatedCVEs leaves to the
// filter ($1 tenant, $2 source CVE).
const relatedCVEsArgOffset = 3

// GetRelatedCVEsBySpec lists the CVEs sharing a component with cveID among
// the findings a decoded filter selects, as the caller. The source CVE's
// components come only from findings the caller may see (its visibility,
// without the filter), so an out-of-scope CVE reveals nothing.
func (s *FindingActionsService) GetRelatedCVEsBySpec(
	ctx context.Context, c FilterCaller, cveID string, spec *filterspec.Spec,
) ([]vulnerability.RelatedCVE, error) {
	if err := validateCVEID(cveID); err != nil {
		return nil, err
	}
	actor, err := filterActor(ctx, s.dataScope, c)
	if err != nil {
		return nil, err
	}
	filterW, err := filterspec.CompileFrom(vulnerability.WithBranchOnlyDefault(spec), vulnerability.FindingFieldsF, actor, relatedCVEsArgOffset)
	if err != nil {
		return nil, err
	}
	visW, err := filterspec.CompileFrom(&filterspec.Spec{}, vulnerability.FindingFieldsF, actor, filterW.NextArg)
	if err != nil {
		return nil, err
	}
	tid := actor.TenantID()
	filter := vulnerability.NewFindingFilter()
	filter.TenantID = &tid
	filter.Compiled = filterW
	filter.CompiledVisibility = visW
	return s.findingRepo.FindRelatedCVEs(ctx, tid, cveID, filter)
}

package finding

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/internal/app/datascope"
	auditdom "github.com/openctemio/openctem/api/pkg/domain/audit"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	tenantdom "github.com/openctemio/openctem/api/pkg/domain/tenant"
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
	// APIKey marks a request authenticated with an API key: a key never
	// inherits its holder's full-data role (datascope.Caller.APIKey).
	APIKey bool
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
	case c.UserID == "":
		// Every caller of this path is a request. A caller with no user is
		// not trusted as internal work: it compiles with an empty scope and
		// reads no scoped rows (fail closed). Background work uses
		// filterspec.SystemActor instead.
		scope = &shared.DataScope{TenantID: tenantID}
	case !c.IsAdmin:
		if e == nil {
			return filterspec.Actor{}, errors.New("data scope enforcer not configured")
		}
		// An API key never inherits its holder's full-data role.
		scope, err = e.ResolveFor(ctx, tenantID, datascope.Caller{UserID: c.UserID, IsAdmin: false, APIKey: c.APIKey})
	case e != nil:
		// An administrator is not narrowed to scope rows, but private
		// program assets stay hidden unless they are an owner or a member
		// (RFC-065 §15.3).
		scope, err = e.ResolveFor(ctx, tenantID, datascope.Caller{UserID: c.UserID, IsAdmin: true, IsOwner: e.CallerOf(ctx).IsOwner, APIKey: c.APIKey})
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

// findingDuplicatesRepo counts the duplicates of a page of findings.
type findingDuplicatesRepo interface {
	CountDuplicatesOfWhere(ctx context.Context, w *filterspec.Where, ids []shared.ID) (map[shared.ID]int, error)
}

// ListFindingsWithDuplicatesBySpec is ListFindingsBySpec plus, per listed
// finding, how many findings marked as its duplicates the caller can read.
// The count is compiled with the same actor as the list (tenant, data
// scope, private programs, pentest membership), so a duplicate on an asset
// outside the caller's scope is neither shown nor counted. One extra
// statement whatever the page size.
func (s *VulnerabilityService) ListFindingsWithDuplicatesBySpec(ctx context.Context, c FilterCaller, spec *filterspec.Spec) (pagination.Result[*vulnerability.Finding], map[shared.ID]int, error) {
	var empty pagination.Result[*vulnerability.Finding]
	repo, ok := s.findingRepo.(findingWhereRepo)
	if !ok {
		return empty, nil, errNoFindingWhereRepo
	}
	actor, err := s.FilterActor(ctx, c)
	if err != nil {
		return empty, nil, err
	}
	where, err := filterspec.Compile(vulnerability.WithBranchOnlyDefault(spec), vulnerability.FindingFields, actor)
	if err != nil {
		return empty, nil, err
	}
	result, err := repo.ListWhere(ctx, where, pagination.New(spec.Page, spec.PerPage))
	if err != nil {
		return empty, nil, err
	}
	dups, ok := s.findingRepo.(findingDuplicatesRepo)
	if !ok {
		return result, nil, nil
	}
	// The count is an enhancement: when it cannot be computed the list stands
	// without it.
	visible, err := filterspec.Compile(&filterspec.Spec{}, vulnerability.FindingFields, actor)
	if err != nil {
		s.logger.Debug("compile duplicate visibility failed", "error", err)
		return result, nil, nil
	}
	ids := make([]shared.ID, 0, len(result.Data))
	for _, f := range result.Data {
		ids = append(ids, f.ID())
	}
	counts, err := dups.CountDuplicatesOfWhere(ctx, visible, ids)
	if err != nil {
		s.logger.Debug("count duplicates failed", "error", err)
		return result, nil, nil
	}
	return result, counts, nil
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

type findingSLARepo interface {
	GetSLABreakdownWhere(ctx context.Context, w *filterspec.Where) (*vulnerability.SLABreakdown, error)
}

// GetFindingSLABreakdownBySpec splits the findings a decoded filter selects by
// SLA standing, as the caller: the same compiled WHERE as the list and stats.
func (s *VulnerabilityService) GetFindingSLABreakdownBySpec(ctx context.Context, c FilterCaller, spec *filterspec.Spec) (*vulnerability.SLABreakdown, error) {
	repo, ok := s.findingRepo.(findingSLARepo)
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
	return repo.GetSLABreakdownWhere(ctx, where)
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

// MaxExportRows caps one findings export, streamed in the request. A larger
// set is narrowed with the filter: exports past the cap are not offered yet
// (they will run as a background operation with a download link).
const MaxExportRows = 10000

type findingExportRepo interface {
	ExportSortedWhere(ctx context.Context, w *filterspec.Where, slotKey string, limit int,
		emit func([]*vulnerability.Finding) error) (int, bool, error)
}

// ExportResult describes a finished export.
type ExportResult struct {
	Rows      int
	Truncated bool
}

// ExportFindingsBySpec streams every finding a decoded filter selects, as
// the caller, to emit in batches, in the filter's sort (the list's order),
// up to MaxExportRows. One export runs per tenant and user across replicas
// (vulnerability.ErrExportInProgress otherwise). Every export that starts is
// audit-logged with the filter's field and operator names and the sort
// (never filter values) and the row count, whether it completes or not.
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
	res.Rows, res.Truncated, err = repo.ExportSortedWhere(ctx, where, c.TenantID+":"+c.UserID, MaxExportRows, emit)
	if errors.Is(err, vulnerability.ErrExportInProgress) {
		return res, err
	}
	s.auditExport(ctx, actx, spec, format, res, err)
	return res, err
}

// auditExport records a findings export: who, the filter shape (field and
// operator names only, so no hostnames or free text land in the audit log),
// the sort, the format and how many rows left the system.
func (s *VulnerabilityService) auditExport(ctx context.Context, actx audit.AuditContext, spec *filterspec.Spec, format string, res ExportResult, err error) {
	if s.auditService == nil {
		return
	}
	shape := make([]string, 0, len(spec.Leaves()))
	for _, l := range spec.Leaves() {
		shape = append(shape, l.Field+":"+string(l.Op))
	}
	sortKeys := make([]string, 0, len(spec.Sort))
	for _, k := range spec.Sort {
		if k.Desc {
			sortKeys = append(sortKeys, "-"+k.Field)
		} else {
			sortKeys = append(sortKeys, k.Field)
		}
	}
	ev := audit.NewSuccessEvent(auditdom.ActionDataExported, auditdom.ResourceTypeFinding, "findings").
		WithMessage(fmt.Sprintf("Exported %d findings (%s)", res.Rows, format)).
		WithMetadata("rows", res.Rows).
		WithMetadata("truncated", res.Truncated).
		WithMetadata("max_rows", MaxExportRows).
		WithMetadata("format", format).
		WithMetadata("filter", shape).
		WithMetadata("sort", sortKeys).
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

type findingFacetRepo interface {
	CountFacetsWhere(ctx context.Context, w *filterspec.Where, preds []string) ([]int64, error)
}

// QuickViewCount is one quick view with its count for the caller.
type QuickViewCount struct {
	Key    string
	Params string
	Count  int64
	// InformationalHidden, for a view that leaves informational findings
	// out, is how many it leaves out (the same params with
	// informational=true); nil for the other views.
	InformationalHidden *int64
}

// FindingViewSettingsReader reads the organization's findings work-view
// defaults (*tenant.TenantService).
type FindingViewSettingsReader interface {
	GetFindingViewSettings(ctx context.Context, tenantID string) (*tenantdom.FindingViewSettings, error)
}

// SetFindingViewSettings wires the organization defaults of the work views
// (nil: informational findings are left out unless the member chose).
func (s *VulnerabilityService) SetFindingViewSettings(r FindingViewSettingsReader) {
	s.findingViewSettings = r
}

// IncludeInformational resolves whether the caller's work views show
// informational findings: their own choice (memberChoice, nil = none), else
// the organization's default, else no. A failed settings read falls back to
// no (the default) and is logged: it only shapes a view, never access.
func (s *VulnerabilityService) IncludeInformational(ctx context.Context, tenantID string, memberChoice *bool) bool {
	if memberChoice != nil {
		return *memberChoice
	}
	if s.findingViewSettings == nil {
		return false
	}
	fv, err := s.findingViewSettings.GetFindingViewSettings(ctx, tenantID)
	if err != nil {
		s.logger.Warn("read finding view settings", "tenant_id", tenantID, "error", err)
		return false
	}
	return fv != nil && fv.IncludeInformational
}

// CountQuickViews counts every built-in quick view (vulnerability
// FindingQuickViews) for the caller, in one statement: each view's params
// are parsed with the strict findings registry and compiled as facets over
// the caller's scoped WHERE (the list's own default branch rule), so a
// count equals the total GET /findings?<params> returns to the same caller.
// includeInformational shapes the work views (IncludeInformational). It
// fails closed like every filtered read.
func (s *VulnerabilityService) CountQuickViews(ctx context.Context, c FilterCaller, includeInformational bool) ([]QuickViewCount, error) {
	repo, ok := s.findingRepo.(findingFacetRepo)
	if !ok {
		return nil, errNoFindingWhereRepo
	}
	actor, err := s.FilterActor(ctx, c)
	if err != nil {
		return nil, err
	}
	views := vulnerability.FindingQuickViews(includeInformational)
	parse := func(key, params string) (*filterspec.Spec, error) {
		q, perr := url.ParseQuery(params)
		if perr != nil {
			return nil, fmt.Errorf("quick view %s: %w", key, perr)
		}
		spec, perr := filterspec.ParseValues(q, vulnerability.FindingFields, filterspec.Options{Unknown: filterspec.UnknownStrict})
		if perr != nil {
			return nil, fmt.Errorf("quick view %s: %w", key, perr)
		}
		return spec, nil
	}
	facets := make([]*filterspec.Spec, len(views), 2*len(views))
	// hiddenAt[i] is the facet that counts what view i leaves out (-1: none).
	hiddenAt := make([]int, len(views))
	for i, v := range views {
		if facets[i], err = parse(v.Key, v.Params); err != nil {
			return nil, err
		}
		hiddenAt[i] = -1
	}
	for i, v := range views {
		if !strings.Contains(v.Params, vulnerability.ExcludeInformationalParam) {
			continue
		}
		hidden, perr := parse(v.Key, strings.Replace(v.Params, vulnerability.ExcludeInformationalParam, "informational=true", 1))
		if perr != nil {
			return nil, perr
		}
		hiddenAt[i] = len(facets)
		facets = append(facets, hidden)
	}
	where, preds, err := filterspec.CompileFacets(vulnerability.WithBranchOnlyDefault(&filterspec.Spec{}), facets, vulnerability.FindingFields, actor)
	if err != nil {
		return nil, err
	}
	counts, err := repo.CountFacetsWhere(ctx, where, preds)
	if err != nil {
		return nil, err
	}
	out := make([]QuickViewCount, len(views))
	for i, v := range views {
		out[i] = QuickViewCount{Key: v.Key, Params: v.Params, Count: counts[i]}
		if j := hiddenAt[i]; j >= 0 {
			n := counts[j]
			out[i].InformationalHidden = &n
		}
	}
	return out, nil
}

// CountSpecs counts the findings each decoded filter selects, as the caller,
// in one statement (facet counts over the caller's visibility). It backs the
// counts beside pinned views in the sidebar.
func (s *VulnerabilityService) CountSpecs(ctx context.Context, c FilterCaller, specs []*filterspec.Spec) ([]int64, error) {
	if len(specs) == 0 {
		return nil, nil
	}
	repo, ok := s.findingRepo.(findingFacetRepo)
	if !ok {
		return nil, errNoFindingWhereRepo
	}
	actor, err := s.FilterActor(ctx, c)
	if err != nil {
		return nil, err
	}
	where, preds, err := filterspec.CompileFacets(vulnerability.WithBranchOnlyDefault(&filterspec.Spec{}), specs, vulnerability.FindingFields, actor)
	if err != nil {
		return nil, err
	}
	return repo.CountFacetsWhere(ctx, where, preds)
}

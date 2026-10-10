package asset

// Software components inventory reads. Design:
// api/docs/rfcs/RFC-070-software-components-inventory.md.

import (
	"context"
	"fmt"
	"strings"

	"github.com/openctemio/openctem/api/internal/app/datascope"
	componentdom "github.com/openctemio/openctem/api/pkg/domain/component"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/software"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/pagination"
)

// ComponentService reads the software components inventory. Every read is
// limited to the tenant and the caller's data scope.
type ComponentService struct {
	repo         componentdom.Repository
	assetChecker assetTenantChecker
	dataScope    *datascope.Enforcer
	logger       *logger.Logger
}

// SetDataScope applies the caller's data scope (Layer 2) to every read: an
// asset outside it answers 404 and lists, counts, facets and detail only
// see in-scope assets. Nil (tests) leaves reads tenant-wide.
func (s *ComponentService) SetDataScope(e *datascope.Enforcer) {
	s.dataScope = e
}

// NewComponentService creates a ComponentService. assetChecker verifies that
// an asset id belongs to the caller's tenant (nil in tests that do not need it).
func NewComponentService(repo componentdom.Repository, assetChecker assetTenantChecker, log *logger.Logger) *ComponentService {
	return &ComponentService{repo: repo, assetChecker: assetChecker, logger: log.With("service", "component")}
}

// verifyAssetTenant returns ErrNotFound unless the asset is the tenant's and
// in the caller's scope.
func (s *ComponentService) verifyAssetTenant(ctx context.Context, tenantID, assetID shared.ID) error {
	if s.assetChecker != nil {
		if _, err := s.assetChecker.GetByID(ctx, tenantID, assetID); err != nil {
			return err
		}
	}
	return s.assertInScope(ctx, tenantID, assetID)
}

func (s *ComponentService) assertInScope(ctx context.Context, tenantID, assetID shared.ID) error {
	if s.dataScope == nil {
		return nil
	}
	return s.dataScope.AssertAsset(ctx, tenantID, assetID)
}

// callerScope is the caller's resolved data scope (nil: unrestricted).
func (s *ComponentService) callerScope(ctx context.Context, tenantID shared.ID) (*shared.DataScope, error) {
	if s.dataScope == nil {
		return nil, nil
	}
	return s.dataScope.Resolve(ctx, tenantID)
}

func parseID(v, what string) (shared.ID, error) {
	id, err := shared.IDFromString(v)
	if err != nil {
		return shared.ID{}, fmt.Errorf("%w: invalid %s id format", shared.ErrValidation, what)
	}
	return id, nil
}

// Accepted filter values.
var (
	componentSeverities    = map[string]bool{"critical": true, "high": true, "medium": true, "low": true}
	componentRelationships = map[string]bool{
		software.RelationshipDirect: true, software.RelationshipTransitive: true, software.RelationshipUnknown: true,
	}
	componentScopes = map[string]bool{
		software.ScopeRuntime: true, software.ScopeDevelopment: true, software.ScopeTest: true,
		software.ScopeOptional: true, software.ScopeBuild: true, software.ScopeProvided: true,
	}
)

const maxFilterValues = 50

func pickValues(in []string, allowed map[string]bool, what string) ([]string, error) {
	if len(in) > maxFilterValues {
		return nil, fmt.Errorf("%w: too many %s values", shared.ErrValidation, what)
	}
	out := make([]string, 0, len(in))
	for _, v := range in {
		v = strings.ToLower(strings.TrimSpace(v))
		if v == "" {
			continue
		}
		if allowed != nil && !allowed[v] {
			return nil, fmt.Errorf("%w: invalid %s %q", shared.ErrValidation, what, v)
		}
		out = append(out, v)
	}
	return out, nil
}

// ListComponentsInput selects packages.
type ListComponentsInput struct {
	TenantID     string
	Query        string
	Ecosystems   []string
	Licenses     []string
	Severities   []string
	KEV          *bool
	HasFix       *bool
	HasVulns     *bool
	Relationship []string
	Scopes       []string
	AssetID      string
	OwnerID      string
	Sort         string
}

func (s *ComponentService) buildFilter(ctx context.Context, in ListComponentsInput) (componentdom.Filter, error) {
	var f componentdom.Filter
	tid, err := parseID(in.TenantID, "tenant")
	if err != nil {
		return f, err
	}
	f.TenantID = tid
	if len(in.Query) > 200 {
		return f, fmt.Errorf("%w: search text is too long", shared.ErrValidation)
	}
	f.Query = in.Query
	if f.Severities, err = pickValues(in.Severities, componentSeverities, "severity"); err != nil {
		return f, err
	}
	if f.Relationship, err = pickValues(in.Relationship, componentRelationships, "relationship"); err != nil {
		return f, err
	}
	if f.Scopes, err = pickValues(in.Scopes, componentScopes, "scope"); err != nil {
		return f, err
	}
	ecos, err := pickValues(in.Ecosystems, nil, "ecosystem")
	if err != nil {
		return f, err
	}
	for _, e := range ecos {
		f.PURLTypes = append(f.PURLTypes, software.PURLTypeForFilter(e))
	}
	if len(in.Licenses) > maxFilterValues {
		return f, fmt.Errorf("%w: too many license values", shared.ErrValidation)
	}
	for _, l := range in.Licenses {
		if l = strings.TrimSpace(l); l != "" {
			f.Licenses = append(f.Licenses, l)
		}
	}
	f.KEV, f.HasFix, f.HasVulns = in.KEV, in.HasFix, in.HasVulns
	if in.Sort != "" && !componentdom.SortKeys[strings.TrimPrefix(in.Sort, "-")] {
		return f, fmt.Errorf("%w: invalid sort %q", shared.ErrValidation, in.Sort)
	}
	f.Sort = in.Sort
	if in.AssetID != "" {
		aid, err := parseID(in.AssetID, "asset")
		if err != nil {
			return f, err
		}
		if err := s.verifyAssetTenant(ctx, tid, aid); err != nil {
			return f, err
		}
		f.AssetID = &aid
	}
	if in.OwnerID != "" {
		oid, err := parseID(in.OwnerID, "owner")
		if err != nil {
			return f, err
		}
		f.OwnerID = &oid
	}
	if f.Scope, err = s.callerScope(ctx, tid); err != nil {
		return f, err
	}
	return f, nil
}

// ListComponents returns a page of packages and, when withFacets, the facets.
func (s *ComponentService) ListComponents(ctx context.Context, in ListComponentsInput, page pagination.Pagination,
	withFacets bool) (pagination.Result[componentdom.Package], componentdom.Facets, error) {
	f, err := s.buildFilter(ctx, in)
	if err != nil {
		return pagination.Result[componentdom.Package]{}, nil, err
	}
	res, err := s.repo.ListPackages(ctx, f, page)
	if err != nil {
		return res, nil, err
	}
	if !withFacets {
		return res, nil, nil
	}
	facets, err := s.repo.PackageFacets(ctx, f)
	return res, facets, err
}

// Summary returns the KPI strip for a filter.
func (s *ComponentService) Summary(ctx context.Context, in ListComponentsInput) (componentdom.Summary, error) {
	f, err := s.buildFilter(ctx, in)
	if err != nil {
		return componentdom.Summary{}, err
	}
	return s.repo.Summary(ctx, f)
}

func (s *ComponentService) productScope(ctx context.Context, tenantID, productID string) (shared.ID, shared.ID, *shared.DataScope, error) {
	tid, err := parseID(tenantID, "tenant")
	if err != nil {
		return shared.ID{}, shared.ID{}, nil, err
	}
	pid, err := parseID(productID, "component")
	if err != nil {
		return shared.ID{}, shared.ID{}, nil, err
	}
	scope, err := s.callerScope(ctx, tid)
	return tid, pid, scope, err
}

// GetComponent returns a package with an in-scope link (else not found).
func (s *ComponentService) GetComponent(ctx context.Context, tenantID, productID string) (*componentdom.PackageDetail, error) {
	tid, pid, scope, err := s.productScope(ctx, tenantID, productID)
	if err != nil {
		return nil, err
	}
	return s.repo.GetPackage(ctx, tid, pid, scope)
}

// ListVersions lists the in-scope versions of a package.
func (s *ComponentService) ListVersions(ctx context.Context, tenantID, productID string) ([]componentdom.Version, error) {
	tid, pid, scope, err := s.productScope(ctx, tenantID, productID)
	if err != nil {
		return nil, err
	}
	if _, err := s.repo.GetPackage(ctx, tid, pid, scope); err != nil {
		return nil, err
	}
	return s.repo.ListVersions(ctx, tid, pid, scope)
}

// UsageInput narrows where-used rows.
type UsageInput struct {
	VersionID    string
	Relationship []string
	Scopes       []string
}

// ListUsages lists where a package is used.
func (s *ComponentService) ListUsages(ctx context.Context, tenantID, productID string, in UsageInput,
	page pagination.Pagination) (pagination.Result[componentdom.Usage], error) {
	empty := pagination.NewResult([]componentdom.Usage{}, 0, page)
	tid, pid, scope, err := s.productScope(ctx, tenantID, productID)
	if err != nil {
		return empty, err
	}
	if _, err := s.repo.GetPackage(ctx, tid, pid, scope); err != nil {
		return empty, err
	}
	var f componentdom.UsageFilter
	if in.VersionID != "" {
		vid, err := parseID(in.VersionID, "version")
		if err != nil {
			return empty, err
		}
		f.VersionID = &vid
	}
	if f.Relationship, err = pickValues(in.Relationship, componentRelationships, "relationship"); err != nil {
		return empty, err
	}
	if f.Scopes, err = pickValues(in.Scopes, componentScopes, "scope"); err != nil {
		return empty, err
	}
	return s.repo.ListUsages(ctx, tid, pid, f, scope, page)
}

// ListVulnerabilities lists the vulnerabilities of a package.
func (s *ComponentService) ListVulnerabilities(ctx context.Context, tenantID, productID string, includeResolved bool,
	page pagination.Pagination) (pagination.Result[componentdom.Vulnerability], error) {
	empty := pagination.NewResult([]componentdom.Vulnerability{}, 0, page)
	tid, pid, scope, err := s.productScope(ctx, tenantID, productID)
	if err != nil {
		return empty, err
	}
	if _, err := s.repo.GetPackage(ctx, tid, pid, scope); err != nil {
		return empty, err
	}
	return s.repo.ListVulnerabilities(ctx, tid, pid, includeResolved, scope, page)
}

// ListAssetComponents lists one asset's package links.
func (s *ComponentService) ListAssetComponents(ctx context.Context, tenantID, assetID string,
	page pagination.Pagination) (pagination.Result[componentdom.Usage], error) {
	empty := pagination.NewResult([]componentdom.Usage{}, 0, page)
	tid, err := parseID(tenantID, "tenant")
	if err != nil {
		return empty, err
	}
	aid, err := parseID(assetID, "asset")
	if err != nil {
		return empty, err
	}
	if err := s.verifyAssetTenant(ctx, tid, aid); err != nil {
		return empty, err
	}
	return s.repo.ListAssetPackages(ctx, tid, aid, page)
}

// DependencyPaths returns the introduction paths of a version on an asset.
func (s *ComponentService) DependencyPaths(ctx context.Context, tenantID, assetID, versionID string, limit int) ([]componentdom.Path, error) {
	tid, err := parseID(tenantID, "tenant")
	if err != nil {
		return nil, err
	}
	aid, err := parseID(assetID, "asset")
	if err != nil {
		return nil, err
	}
	vid, err := parseID(versionID, "version")
	if err != nil {
		return nil, err
	}
	if err := s.verifyAssetTenant(ctx, tid, aid); err != nil {
		return nil, err
	}
	return s.repo.DependencyPaths(ctx, tid, aid, vid, limit)
}

// DependencyGraph returns a bounded part of an asset's dependency graph.
func (s *ComponentService) DependencyGraph(ctx context.Context, tenantID, assetID, focusVersionID string, depth, limit int) (*componentdom.Graph, error) {
	tid, err := parseID(tenantID, "tenant")
	if err != nil {
		return nil, err
	}
	aid, err := parseID(assetID, "asset")
	if err != nil {
		return nil, err
	}
	var focus *shared.ID
	if focusVersionID != "" {
		vid, err := parseID(focusVersionID, "version")
		if err != nil {
			return nil, err
		}
		focus = &vid
	}
	if err := s.verifyAssetTenant(ctx, tid, aid); err != nil {
		return nil, err
	}
	return s.repo.DependencyGraph(ctx, tid, aid, focus, depth, limit)
}

// GetFindingComponent returns the package version a finding names and how
// the finding's asset uses it. The caller has already authorized the finding.
func (s *ComponentService) GetFindingComponent(ctx context.Context, tenantID, versionID, assetID string) (*componentdom.FindingComponent, error) {
	tid, err := parseID(tenantID, "tenant")
	if err != nil {
		return nil, err
	}
	vid, err := parseID(versionID, "version")
	if err != nil {
		return nil, err
	}
	var aid *shared.ID
	if assetID != "" {
		id, err := parseID(assetID, "asset")
		if err != nil {
			return nil, err
		}
		aid = &id
	}
	return s.repo.GetFindingComponent(ctx, tid, vid, aid)
}

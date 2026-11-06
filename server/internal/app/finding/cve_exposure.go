package finding

// The vulnerability page for one CVE (docs/architecture/vulnerability-page.md):
// "are we affected", the counts, components, upgrade path, sources and
// timeline, all as the caller may see them.

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
	"github.com/openctemio/openctem/api/pkg/filterspec"
	"github.com/openctemio/openctem/api/pkg/pagination"
)

// cveExposureRepo is the part of the finding repository that answers the
// vulnerability page. postgres.FindingRepository implements it.
type cveExposureRepo interface {
	GetCVEExposure(ctx context.Context, q vulnerability.CVEExposureQuery) (*vulnerability.CVEExposure, error)
	ListCVEExposureAssets(ctx context.Context, q vulnerability.CVEExposureQuery, search string, page pagination.Pagination) (pagination.Result[vulnerability.CVEExposureAsset], error)
	ResolveVulnAlias(ctx context.Context, aliasID string) (string, error)
}

var errNoCVEExposureRepo = errors.New("finding repository cannot answer the vulnerability page")

// vulnPageIDPattern is a CVE or an advisory id the feed may alias to one
// (GHSA-…, PYSEC-…, GO-…), the same shape vuln_id_aliases accepts.
var (
	vulnPageCVEPattern   = regexp.MustCompile(`^CVE-[0-9]{4}-[0-9]{4,19}$`)
	vulnPageAliasPattern = regexp.MustCompile(`^[A-Z][A-Z0-9]*-[A-Za-z0-9._:-]+$`)
)

// maxCVEExposureSearch bounds the asset search text.
const maxCVEExposureSearch = 200

// ResolveVulnPageID turns the page's id into a CVE: a CVE id (any case) as
// is, an advisory id through the signed feed's aliases. An id of neither
// shape is a validation error; an advisory the feed does not tie to one CVE
// is not found.
func (s *VulnerabilityService) ResolveVulnPageID(ctx context.Context, id string) (string, error) {
	id = strings.TrimSpace(id)
	if len(id) > 64 {
		return "", fmt.Errorf("%w: invalid vulnerability id", shared.ErrValidation)
	}
	if up := strings.ToUpper(id); vulnPageCVEPattern.MatchString(up) {
		return up, nil
	}
	if !vulnPageAliasPattern.MatchString(id) || len(id) < 5 {
		return "", fmt.Errorf("%w: invalid vulnerability id", shared.ErrValidation)
	}
	repo, ok := s.findingRepo.(cveExposureRepo)
	if !ok {
		return "", errNoCVEExposureRepo
	}
	cve, err := repo.ResolveVulnAlias(ctx, id)
	if err != nil {
		return "", err
	}
	if cve == "" {
		return "", vulnerability.VulnerabilityNotFoundByCVEError(id)
	}
	return cve, nil
}

// cveExposureQuery compiles "findings of this CVE" as the caller: the same
// spec, registry and branch default the findings list uses for
// ?cve_id=CVE, so the page and that list count the same rows.
func (s *VulnerabilityService) cveExposureQuery(ctx context.Context, c FilterCaller, cveID string) (vulnerability.CVEExposureQuery, error) {
	actor, err := s.FilterActor(ctx, c)
	if err != nil {
		return vulnerability.CVEExposureQuery{}, err
	}
	spec := &filterspec.Spec{Root: &filterspec.Node{Leaf: &filterspec.Leaf{
		Field: "cve_id", Op: filterspec.OpIn, Values: []any{cveID},
	}}}
	where, err := filterspec.Compile(vulnerability.WithBranchOnlyDefault(spec), vulnerability.FindingFields, actor)
	if err != nil {
		return vulnerability.CVEExposureQuery{}, err
	}
	return vulnerability.CVEExposureQuery{
		Where: where, TenantID: actor.TenantID(), CVEID: cveID, AssetScope: actor.AssetScopeSQL,
	}, nil
}

// GetCVEExposure answers the vulnerability page for cveID (a CVE id, already
// resolved by ResolveVulnPageID). A CVE the catalog does not know still gets
// its findings counted (InCatalog false), never an error.
func (s *VulnerabilityService) GetCVEExposure(ctx context.Context, c FilterCaller, cveID string) (*vulnerability.CVEExposure, error) {
	if !vulnPageCVEPattern.MatchString(cveID) {
		return nil, fmt.Errorf("%w: invalid CVE id", shared.ErrValidation)
	}
	repo, ok := s.findingRepo.(cveExposureRepo)
	if !ok {
		return nil, errNoCVEExposureRepo
	}
	q, err := s.cveExposureQuery(ctx, c, cveID)
	if err != nil {
		return nil, err
	}
	inCatalog := false
	v, err := s.GetCatalogVulnerabilityByCVE(ctx, c.TenantID, cveID)
	switch {
	case err == nil:
		inCatalog = true
		q.CatalogFixed = v.FixedVersions()
	case !errors.Is(err, shared.ErrNotFound):
		return nil, err
	}
	out, err := repo.GetCVEExposure(ctx, q)
	if err != nil {
		return nil, err
	}
	out.InCatalog = inCatalog
	// The EPSS history exists only for CVEs some organization has a finding
	// of: show it only when the caller has one in scope, never for a CVE id
	// alone (it would tell one organization what another one runs).
	if tr, ok := s.findingRepo.(epssTrendRepo); ok && out.Findings.Total > 0 {
		pts, err := tr.EPSSTrend(ctx, cveID)
		if err != nil {
			return nil, err
		}
		out.EPSSTrend = pts
	}
	return out, nil
}

// epssTrendRepo reads a CVE's EPSS history (*postgres.FindingRepository).
type epssTrendRepo interface {
	EPSSTrend(ctx context.Context, cveID string) ([]vulnerability.EPSSPoint, error)
}

// ListCVEExposureAssets lists one page of the assets with a finding of
// cveID, as the caller, optionally narrowed by an asset-name search.
func (s *VulnerabilityService) ListCVEExposureAssets(ctx context.Context, c FilterCaller, cveID, search string, page, perPage int) (pagination.Result[vulnerability.CVEExposureAsset], error) {
	var empty pagination.Result[vulnerability.CVEExposureAsset]
	if !vulnPageCVEPattern.MatchString(cveID) {
		return empty, fmt.Errorf("%w: invalid CVE id", shared.ErrValidation)
	}
	if len(search) > maxCVEExposureSearch {
		return empty, fmt.Errorf("%w: search is too long", shared.ErrValidation)
	}
	repo, ok := s.findingRepo.(cveExposureRepo)
	if !ok {
		return empty, errNoCVEExposureRepo
	}
	q, err := s.cveExposureQuery(ctx, c, cveID)
	if err != nil {
		return empty, err
	}
	return repo.ListCVEExposureAssets(ctx, q, search, pagination.New(page, perPage))
}

// cveListRepo is the part of the finding repository that answers the
// vulnerabilities list. postgres.FindingRepository implements it.
type cveListRepo interface {
	ListCVEExposures(ctx context.Context, q vulnerability.CVEListQuery) (*vulnerability.CVEList, error)
}

// ListCVEExposures lists the vulnerabilities of the findings spec as the
// caller: the findings list's compiled filter (tenant, data scope, member
// visibility, branch default) grouped by CVE, then the options'
// vulnerability-level filters, sort and page.
func (s *VulnerabilityService) ListCVEExposures(ctx context.Context, c FilterCaller, spec *filterspec.Spec, opts vulnerability.CVEListOptions) (*vulnerability.CVEList, error) {
	if err := opts.Validate(); err != nil {
		return nil, err
	}
	repo, ok := s.findingRepo.(cveListRepo)
	if !ok {
		return nil, errNoCVEExposureRepo
	}
	actor, err := s.FilterActor(ctx, c)
	if err != nil {
		return nil, err
	}
	if spec == nil {
		spec = &filterspec.Spec{}
	}
	where, err := compileFor(c, spec, actor)
	if err != nil {
		return nil, err
	}
	return repo.ListCVEExposures(ctx, vulnerability.CVEListQuery{
		Where: where, TenantID: actor.TenantID(), AssetScope: actor.AssetScopeSQL, Options: opts,
	})
}

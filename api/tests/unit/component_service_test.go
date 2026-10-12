package unit

// Software components inventory service (RFC-070): input validation, tenant
// and asset checks before any read, and the not-found rule for packages
// without an in-scope link.

import (
	"context"
	"errors"
	"testing"

	"github.com/openctemio/openctem/api/internal/app/asset"
	assetdom "github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/domain/component"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/pagination"
)

type sbomCall struct {
	tenantID shared.ID
	assetID  *shared.ID
	limit    int
}

type mockComponentRepo struct {
	sbomEntries []component.SBOMEntry
	sbomCalls   []sbomCall

	filters     []component.Filter
	pkg         *component.PackageDetail
	getErr      error
	getCalls    int
	usageCalls  int
	vulnCalls   int
	graphCalls  int
	pathCalls   int
	assetCalls  int
	lastProduct shared.ID
}

func (m *mockComponentRepo) ListPackages(_ context.Context, f component.Filter, page pagination.Pagination) (pagination.Result[component.Package], error) {
	m.filters = append(m.filters, f)
	return pagination.NewResult([]component.Package{}, 0, page), nil
}

func (m *mockComponentRepo) PackageFacets(_ context.Context, f component.Filter) (component.Facets, error) {
	m.filters = append(m.filters, f)
	return component.Facets{}, nil
}

func (m *mockComponentRepo) Summary(_ context.Context, f component.Filter) (component.Summary, error) {
	m.filters = append(m.filters, f)
	return component.Summary{}, nil
}

func (m *mockComponentRepo) GetPackage(_ context.Context, _, productID shared.ID, _ *shared.DataScope) (*component.PackageDetail, error) {
	m.getCalls++
	m.lastProduct = productID
	if m.getErr != nil {
		return nil, m.getErr
	}
	if m.pkg == nil {
		return &component.PackageDetail{}, nil
	}
	return m.pkg, nil
}

func (m *mockComponentRepo) ListVersions(context.Context, shared.ID, shared.ID, *shared.DataScope) ([]component.Version, error) {
	return []component.Version{}, nil
}

func (m *mockComponentRepo) ListUsages(_ context.Context, _, _ shared.ID, _ component.UsageFilter, _ *shared.DataScope,
	page pagination.Pagination) (pagination.Result[component.Usage], error) {
	m.usageCalls++
	return pagination.NewResult([]component.Usage{}, 0, page), nil
}

func (m *mockComponentRepo) ListVulnerabilities(_ context.Context, _, _ shared.ID, _ bool, _ *shared.DataScope,
	page pagination.Pagination) (pagination.Result[component.Vulnerability], error) {
	m.vulnCalls++
	return pagination.NewResult([]component.Vulnerability{}, 0, page), nil
}

func (m *mockComponentRepo) ListAssetPackages(_ context.Context, _, _ shared.ID, page pagination.Pagination) (pagination.Result[component.Usage], error) {
	m.assetCalls++
	return pagination.NewResult([]component.Usage{}, 0, page), nil
}

func (m *mockComponentRepo) DependencyPaths(context.Context, shared.ID, shared.ID, shared.ID, int) ([]component.Path, error) {
	m.pathCalls++
	return nil, nil
}

func (m *mockComponentRepo) DependencyGraph(context.Context, shared.ID, shared.ID, *shared.ID, int, int) (*component.Graph, error) {
	m.graphCalls++
	return &component.Graph{}, nil
}

func (m *mockComponentRepo) ListSBOMEntries(_ context.Context, tenantID shared.ID, assetID *shared.ID, _ *shared.DataScope, limit int) ([]component.SBOMEntry, error) {
	m.sbomCalls = append(m.sbomCalls, sbomCall{tenantID: tenantID, assetID: assetID, limit: limit})
	return m.sbomEntries, nil
}

func (m *mockComponentRepo) GetVersion(context.Context, shared.ID, shared.ID, *shared.DataScope) (*component.FindingComponent, error) {
	return &component.FindingComponent{}, nil
}

func (m *mockComponentRepo) GetFindingComponent(context.Context, shared.ID, shared.ID, *shared.ID) (*component.FindingComponent, error) {
	return &component.FindingComponent{}, nil
}

type stubAssetChecker struct {
	err   error
	calls int
}

func (s *stubAssetChecker) GetByID(_ context.Context, _, _ shared.ID) (*assetdom.Asset, error) {
	s.calls++
	return nil, s.err
}

func TestComponentList_ValidatesFilters(t *testing.T) {
	tenant := shared.NewID().String()
	bad := []asset.ListComponentsInput{
		{TenantID: "nope"},
		{TenantID: tenant, Severities: []string{"urgent"}},
		{TenantID: tenant, Relationship: []string{"sibling"}},
		{TenantID: tenant, Scopes: []string{"prod-only"}},
		{TenantID: tenant, Sort: "-password"},
		{TenantID: tenant, AssetID: "not-a-uuid"},
		{TenantID: tenant, OwnerID: "not-a-uuid"},
	}
	for i, in := range bad {
		repo := &mockComponentRepo{}
		svc := asset.NewComponentService(repo, nil, logger.NewNop())
		if _, _, err := svc.ListComponents(context.Background(), in, pagination.New(1, 25), true); !errors.Is(err, shared.ErrValidation) {
			t.Errorf("case %d: want validation error, got %v", i, err)
		}
		if len(repo.filters) != 0 {
			t.Errorf("case %d: repository read with an invalid filter", i)
		}
	}
}

func TestComponentList_MapsFilters(t *testing.T) {
	repo := &mockComponentRepo{}
	svc := asset.NewComponentService(repo, nil, logger.NewNop())
	tenant := shared.NewID()
	kev := true
	_, _, err := svc.ListComponents(context.Background(), asset.ListComponentsInput{
		TenantID: tenant.String(), Ecosystems: []string{"go", "rubygems", "NPM"}, Severities: []string{"Critical"},
		Relationship: []string{"direct"}, KEV: &kev, Sort: "-assets",
	}, pagination.New(1, 25), true)
	if err != nil {
		t.Fatal(err)
	}
	if len(repo.filters) != 2 {
		t.Fatalf("want list and facets reads, got %d", len(repo.filters))
	}
	f := repo.filters[0]
	if f.TenantID != tenant {
		t.Fatal("filter not limited to the caller's tenant")
	}
	want := []string{"golang", "gem", "npm"}
	for i, w := range want {
		if i >= len(f.PURLTypes) || f.PURLTypes[i] != w {
			t.Fatalf("package URL types %v, want %v", f.PURLTypes, want)
		}
	}
	if len(f.Severities) != 1 || f.Severities[0] != "critical" || f.KEV == nil || !*f.KEV || f.Sort != "-assets" {
		t.Fatalf("filter %+v", f)
	}
}

// A foreign or out-of-scope asset answers not found before anything is read.
func TestComponentList_ForeignAssetNotFound(t *testing.T) {
	repo := &mockComponentRepo{}
	checker := &stubAssetChecker{err: shared.ErrNotFound}
	svc := asset.NewComponentService(repo, checker, logger.NewNop())
	_, _, err := svc.ListComponents(context.Background(), asset.ListComponentsInput{
		TenantID: shared.NewID().String(), AssetID: shared.NewID().String(),
	}, pagination.New(1, 25), false)
	if !errors.Is(err, shared.ErrNotFound) || len(repo.filters) != 0 || checker.calls != 1 {
		t.Fatalf("err %v, reads %d, checks %d", err, len(repo.filters), checker.calls)
	}

	for name, call := range map[string]func() error{
		"asset components": func() error {
			_, err := svc.ListAssetComponents(context.Background(), shared.NewID().String(), shared.NewID().String(), pagination.New(1, 25))
			return err
		},
		"paths": func() error {
			_, err := svc.DependencyPaths(context.Background(), shared.NewID().String(), shared.NewID().String(), shared.NewID().String(), 5)
			return err
		},
		"graph": func() error {
			_, err := svc.DependencyGraph(context.Background(), shared.NewID().String(), shared.NewID().String(), "", 0, 0)
			return err
		},
	} {
		if err := call(); !errors.Is(err, shared.ErrNotFound) {
			t.Errorf("%s: want not found, got %v", name, err)
		}
	}
	if repo.assetCalls+repo.pathCalls+repo.graphCalls != 0 {
		t.Fatal("an out-of-scope asset's packages were read")
	}
}

// A package without an in-scope link is not found, and its versions,
// usages and vulnerabilities are not read.
func TestComponentReads_RequireVisiblePackage(t *testing.T) {
	repo := &mockComponentRepo{getErr: component.ErrComponentNotFound}
	svc := asset.NewComponentService(repo, nil, logger.NewNop())
	tenant, pid := shared.NewID().String(), shared.NewID().String()
	if _, err := svc.ListVersions(context.Background(), tenant, pid); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("versions: %v", err)
	}
	if _, err := svc.ListUsages(context.Background(), tenant, pid, asset.UsageInput{}, pagination.New(1, 25)); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("usages: %v", err)
	}
	if _, err := svc.ListVulnerabilities(context.Background(), tenant, pid, false, pagination.New(1, 25)); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("vulnerabilities: %v", err)
	}
	if repo.usageCalls+repo.vulnCalls != 0 {
		t.Fatal("details of an invisible package were read")
	}
	if _, err := svc.GetComponent(context.Background(), tenant, "nope"); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("invalid id: %v", err)
	}
}

func TestComponentUsages_ValidatesFilters(t *testing.T) {
	repo := &mockComponentRepo{}
	svc := asset.NewComponentService(repo, nil, logger.NewNop())
	tenant, pid := shared.NewID().String(), shared.NewID().String()
	for _, in := range []asset.UsageInput{{VersionID: "x"}, {Relationship: []string{"cousin"}}, {Scopes: []string{"nightly"}}} {
		if _, err := svc.ListUsages(context.Background(), tenant, pid, in, pagination.New(1, 25)); !errors.Is(err, shared.ErrValidation) {
			t.Errorf("%+v: want validation error, got %v", in, err)
		}
	}
	if repo.usageCalls != 0 {
		t.Fatal("usages read with an invalid filter")
	}
}

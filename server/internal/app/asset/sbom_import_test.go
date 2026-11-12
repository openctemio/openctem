package asset

import (
	"context"
	"strings"
	"testing"

	assetdom "github.com/openctemio/openctem/api/pkg/domain/asset"
	componentdom "github.com/openctemio/openctem/api/pkg/domain/component"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/software"
	"github.com/openctemio/openctem/api/pkg/logger"
)

type fakeSBOMStore struct {
	res    software.PackageWriteResult
	writes int
}

func (f *fakeSBOMStore) WritePackages(context.Context, shared.ID, software.PackageSnapshot) (software.PackageWriteResult, error) {
	f.writes++
	return f.res, nil
}
func (f *fakeSBOMStore) EnsurePackageVersion(context.Context, shared.ID, software.PURL) (shared.ID, error) {
	return shared.NewID(), nil
}
func (f *fakeSBOMStore) ListSBOMEntries(context.Context, shared.ID, *shared.ID, *shared.DataScope, int) ([]componentdom.SBOMEntry, error) {
	return nil, nil
}

type anyAsset struct{}

func (anyAsset) GetByID(context.Context, shared.ID, shared.ID) (*assetdom.Asset, error) {
	return nil, nil
}

type recordingSink struct {
	tenants []shared.ID
	assets  [][]shared.ID
}

func (r *recordingSink) SoftwareChanged(tenantID shared.ID, assetIDs []shared.ID) {
	r.tenants = append(r.tenants, tenantID)
	r.assets = append(r.assets, assetIDs)
}

// An imported SBOM queues the vulnerability matcher for its asset, so its
// packages are matched in minutes; a preview or a write that changed
// nothing does not.
func TestImportSBOM_QueuesMatcher(t *testing.T) {
	tenant, asset := shared.NewID(), shared.NewID()
	cases := []struct {
		name   string
		dryRun bool
		res    software.PackageWriteResult
		queued bool
	}{
		{"written", false, software.PackageWriteResult{Links: 3}, true},
		{"only removed", false, software.PackageWriteResult{Removed: 2}, true},
		{"dry run", true, software.PackageWriteResult{Links: 3}, false},
		{"nothing changed", false, software.PackageWriteResult{}, false},
	}
	for _, c := range cases {
		store := &fakeSBOMStore{res: c.res}
		sink := &recordingSink{}
		svc := NewSBOMImportService(store, anyAsset{}, logger.NewNop())
		svc.SetSoftwareChangeSink(sink)
		if _, err := svc.ImportSBOM(context.Background(), tenant.String(), asset.String(), strings.NewReader(cdxSample), c.dryRun); err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if got := len(sink.tenants) == 1; got != c.queued {
			t.Fatalf("%s: queued %v, want %v", c.name, got, c.queued)
		}
		if c.queued && (sink.tenants[0] != tenant || len(sink.assets[0]) != 1 || sink.assets[0][0] != asset) {
			t.Fatalf("%s: queued %v %v", c.name, sink.tenants, sink.assets)
		}
	}
}

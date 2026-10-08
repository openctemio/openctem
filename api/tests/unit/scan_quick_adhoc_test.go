package unit

// Quick scans run ad hoc (owner decision D10): no asset group is left behind,
// the scan is marked ad hoc so the Configurations list leaves it out, and
// "Save as scan" (SaveQuickScan) turns it into a configuration.

import (
	"context"
	"errors"
	"testing"

	scanservice "github.com/openctemio/openctem/api/internal/app/scan"
	"github.com/openctemio/openctem/api/pkg/domain/scan"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/pagination"
)

func TestScanService_QuickScan_AdHocWithoutAssetGroup(t *testing.T) {
	svc, deps := newTestScanService()
	tenantID := shared.NewID()
	deps.toolRepo.addTool("nuclei", true)

	res, err := svc.QuickScan(context.Background(), scanservice.QuickScanInput{
		TenantID:    tenantID.String(),
		Targets:     []string{"example.com"},
		ScannerName: "nuclei",
	})
	if err != nil {
		t.Fatalf("quick scan: %v", err)
	}
	if n := len(deps.assetGroupRepo.groups); n != 0 {
		t.Fatalf("quick scan left %d asset group(s) behind, want none", n)
	}
	if res.AssetGroupID != "" {
		t.Errorf("result asset_group_id = %q, want empty", res.AssetGroupID)
	}
	sc := deps.scanRepo.scans[res.ScanID]
	if sc == nil {
		t.Fatal("no scan stored for the run")
	}
	if !sc.AdHoc {
		t.Error("quick scan is not marked ad hoc: it would show as a configuration")
	}
	if len(sc.Targets) != 1 || sc.Targets[0] != "example.com" {
		t.Errorf("targets not on the scan: %v", sc.Targets)
	}
}

// filterRecordingScanRepo records the filter ListScans passes down.
type filterRecordingScanRepo struct {
	*mockScanRepo
	last scan.Filter
}

func (r *filterRecordingScanRepo) List(ctx context.Context, f scan.Filter, p pagination.Pagination) (pagination.Result[*scan.Scan], error) {
	r.last = f
	return r.mockScanRepo.List(ctx, f, p)
}

func TestScanService_ListScans_LeavesOutAdHocUnlessAsked(t *testing.T) {
	_, deps := newTestScanService()
	repo := &filterRecordingScanRepo{mockScanRepo: deps.scanRepo}
	svc := newScanServiceWithRepo(repo, deps)
	tenantID := shared.NewID().String()

	if _, err := svc.ListScans(context.Background(), scanservice.ListScansInput{TenantID: tenantID}); err != nil {
		t.Fatal(err)
	}
	if !repo.last.ExcludeAdHoc {
		t.Error("default list includes unsaved quick scans")
	}
	if _, err := svc.ListScans(context.Background(), scanservice.ListScansInput{TenantID: tenantID, IncludeAdHoc: true}); err != nil {
		t.Fatal(err)
	}
	if repo.last.ExcludeAdHoc {
		t.Error("include_ad_hoc=true still leaves them out")
	}
}

func TestScanService_SaveQuickScan(t *testing.T) {
	svc, deps := newTestScanService()
	tenantID := shared.NewID()

	quick := createTestScanInRepo(deps, tenantID, "Quick Scan - 20261002-101010", scan.ScanTypeSingle)
	quick.AdHoc = true

	saved, err := svc.SaveQuickScan(context.Background(), tenantID.String(), quick.ID.String(), "  Nightly recon ")
	if err != nil {
		t.Fatalf("save: %v", err)
	}
	if saved.AdHoc || saved.Name != "Nightly recon" {
		t.Fatalf("saved: ad_hoc=%v name=%q", saved.AdHoc, saved.Name)
	}
	if stored := deps.scanRepo.scans[quick.ID.String()]; stored.AdHoc {
		t.Fatal("save not persisted")
	}

	// Saving twice, or saving a configuration, is refused.
	if _, err := svc.SaveQuickScan(context.Background(), tenantID.String(), quick.ID.String(), "Again"); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("saving a configuration: want ErrValidation, got %v", err)
	}

	other := createTestScanInRepo(deps, tenantID, "Quick Scan - 2", scan.ScanTypeSingle)
	other.AdHoc = true
	if _, err := svc.SaveQuickScan(context.Background(), tenantID.String(), other.ID.String(), "   "); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("empty name: want ErrValidation, got %v", err)
	}

	// Another tenant's quick scan is not found.
	if _, err := svc.SaveQuickScan(context.Background(), shared.NewID().String(), other.ID.String(), "Mine"); err == nil {
		t.Fatal("saved another tenant's quick scan")
	}
}

// newScanServiceWithRepo builds the service of newTestScanService around
// another scan repository.
func newScanServiceWithRepo(repo scan.Repository, deps *testScanServiceDeps) *scanservice.Service {
	return scanservice.NewService(
		repo,
		deps.templateRepo,
		deps.assetGroupRepo,
		deps.runRepo,
		deps.stepRepo,
		&mockStepRunRepo{},
		deps.commandRepo,
		&mockScannerTemplateRepo{},
		&mockTemplateSourceRepo{},
		deps.toolRepo,
		&mockTemplateSyncer{},
		deps.sensorSelector,
		deps.secValidator,
		logger.NewNop(),
		allowAllTargetChecks(scanservice.WithAuditService(deps.auditSvc))...,
	)
}

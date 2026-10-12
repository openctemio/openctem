package scan

import (
	"context"
	"errors"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/scan"
	"github.com/openctemio/openctem/api/pkg/domain/scangov"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

type stubApprovalAssets struct {
	got  [][]string
	resp scangov.AssetFacts
}

func (s *stubApprovalAssets) TargetAssetFacts(_ context.Context, _ shared.ID, names []string, _ []shared.ID, roots []string) (scangov.AssetFacts, error) {
	s.got = [][]string{names, roots}
	return s.resp, nil
}

type stubApprovalGate struct {
	err   error
	facts scangov.Facts
	def   scangov.Definition
}

func (g *stubApprovalGate) CheckRun(_ context.Context, _ *scan.Scan, def scangov.Definition, f scangov.Facts, _ string) error {
	g.def, g.facts = def, f
	return g.err
}

// The facts the approval rules read come from the definition and the
// inventory: selectors, CIDR width, schedule, placement, the scanner's tier.
func TestGovernanceSubjectOf(t *testing.T) {
	assets := &stubApprovalAssets{resp: scangov.AssetFacts{Expanded: 40, Tags: []string{"production"}, MaxCriticality: "high"}}
	s := &Service{}
	s.SetApprovalGate(nil, assets)
	zone := shared.NewID()
	sc := &scan.Scan{TenantID: shared.NewID(), ScanType: scan.ScanTypeSingle, ScannerName: "nuclei",
		Targets:      []string{"App.Example.com", "*.example.org", "10.0.0.0/16", "203.0.113.7"},
		ScheduleType: scan.ScheduleDaily, SensorPreference: scan.SensorPreferencePlatform, ScanZoneID: &zone}
	def, f, err := s.GovernanceSubjectOf(context.Background(), sc)
	if err != nil {
		t.Fatal(err)
	}
	if !f.DynamicSelectors || f.WidestCIDRPrefix != 16 || !f.Recurring || f.SensorPlacement != "platform" || f.ZoneID != zone.String() {
		t.Fatalf("facts: %+v", f)
	}
	if f.TargetCount != 3+40 || f.MaxCriticality != "high" || len(f.AssetTags) != 1 {
		t.Fatalf("target facts: %+v", f)
	}
	if len(assets.got[0]) != 2 || assets.got[1][0] != "example.org" {
		t.Fatalf("asset lookup: %v", assets.got)
	}
	if f.IntensityTier != 1 || def.Intensity != "active" || def.ScannerName != "nuclei" || def.ScanZoneID != zone.String() {
		t.Fatalf("definition: %+v facts %+v", def, f)
	}
	sc.ScheduleType = scan.ScheduleManual
	if _, f, _ := s.GovernanceSubjectOf(context.Background(), sc); f.Recurring {
		t.Fatal("a manual scan is not recurring")
	}
}

// Every run passes the approval gate; its refusal refuses the run.
func TestRequireApproval(t *testing.T) {
	s := &Service{}
	sc := &scan.Scan{TenantID: shared.NewID(), ScanType: scan.ScanTypeSingle, ScannerName: "zap", Targets: []string{"a.example.com"}}
	if err := s.requireApproval(context.Background(), sc, ""); err != nil {
		t.Fatalf("no gate wired: %v", err)
	}
	g := &stubApprovalGate{err: scangov.ErrApprovalRequired}
	s.SetApprovalGate(g, nil)
	if err := s.requireApproval(context.Background(), sc, ""); !errors.Is(err, scangov.ErrApprovalRequired) {
		t.Fatalf("gate refusal: %v", err)
	}
	if g.facts.IntensityTier != 2 || g.def.Digest() == "" {
		t.Fatalf("zap probes at T2: %+v", g.facts)
	}
}

// The rules read the scan declared intensity (RFC-071): a passive-tool scan
// declared intrusive is intrusive for approval, and changing the declared
// intensity changes what was approved. Never below what the tools probe.
func TestGovernanceSubjectOf_DeclaredIntensity(t *testing.T) {
	s := &Service{}
	sc := &scan.Scan{TenantID: shared.NewID(), ScanType: scan.ScanTypeSingle, ScannerName: "subfinder",
		Targets: []string{"example.com"}, Intensity: scan.IntensityIntrusive}
	def, f, err := s.GovernanceSubjectOf(context.Background(), sc)
	if err != nil {
		t.Fatal(err)
	}
	if f.IntensityTier != 2 || def.Intensity != "intrusive" {
		t.Fatalf("declared intrusive: tier %d intensity %s", f.IntensityTier, def.Intensity)
	}
	sc.Intensity = scan.IntensityPassive
	def2, f2, _ := s.GovernanceSubjectOf(context.Background(), sc)
	if f2.IntensityTier != 0 || def2.Intensity != "passive" || def2.Digest() == def.Digest() {
		t.Fatalf("declared passive: tier %d intensity %s, digest must change", f2.IntensityTier, def2.Intensity)
	}
	// A tool above the declared intensity is not hidden by it.
	sc.ScannerName = "zap"
	if _, f3, _ := s.GovernanceSubjectOf(context.Background(), sc); f3.IntensityTier != 2 {
		t.Fatalf("zap under a passive declaration: tier %d, want 2", f3.IntensityTier)
	}
}

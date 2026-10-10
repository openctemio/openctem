package scangov

import (
	"context"
	"errors"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/scan"
	"github.com/openctemio/openctem/api/pkg/domain/scangov"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// tierScans gives each scan the tier of its scanner.
type tierScans struct {
	fakeScans
	list  []*scan.Scan
	total int
}

func (f *tierScans) GovernanceSubjectOf(_ context.Context, sc *scan.Scan) (scangov.Definition, scangov.Facts, error) {
	tier := map[string]int{"zap": 2, "nuclei": 1, "subfinder": 0}[sc.ScannerName]
	return scangov.Definition{ScannerName: sc.ScannerName}, scangov.Facts{IntensityTier: tier, Tools: []string{sc.ScannerName}, WidestCIDRPrefix: -1}, nil
}

func (f *tierScans) GovernanceScans(_ context.Context, _ shared.ID, limit int) ([]*scan.Scan, int, error) {
	if len(f.list) > limit {
		return f.list[:limit], f.total, nil
	}
	return f.list, f.total, nil
}

func TestTestRules_CatchesExistingScans(t *testing.T) {
	ctx := context.Background()
	r := newRig(t, scangov.ModeOff, nil)
	mk := func(tid shared.ID, name, tool string) *scan.Scan {
		return &scan.Scan{ID: shared.NewID(), TenantID: tid, Name: name, ScannerName: tool}
	}
	foreign := mk(shared.NewID(), "another org", "zap")
	ts := &tierScans{list: []*scan.Scan{
		mk(r.tid, "web zap", "zap"), mk(r.tid, "nuclei weekly", "nuclei"), mk(r.tid, "subdomains", "subfinder"), foreign,
	}, total: 4}
	r.svc.SetScans(ts)
	r.svc.SetScanLister(ts)
	rules := []scangov.Rule{
		{Name: "Intrusive", Enabled: true, Conditions: scangov.Conditions{MinIntensity: "intrusive"}, Requirement: scangov.Requirement{Approvals: 1}},
		{Name: "Watch active", Enabled: true, Monitor: true, Conditions: scangov.Conditions{MinIntensity: "active"}, Requirement: scangov.Requirement{Approvals: 1}},
	}
	out, err := r.svc.TestRules(ctx, r.tid, rules)
	if err != nil {
		t.Fatal(err)
	}
	if out.Mode != scangov.ModeOn {
		t.Fatalf("Off is tested as On, got %s", out.Mode)
	}
	if out.Tested != 3 || out.Caught != 1 || out.Monitored != 1 || len(out.Scans) != 2 {
		t.Fatalf("result %+v", out)
	}
	for _, s := range out.Scans {
		if s.ScanID == foreign.ID.String() {
			t.Fatal("another tenant's scan was evaluated")
		}
	}
	if out.Scans[0].Name != "web zap" || !out.Scans[0].Evaluation.Required || out.Scans[1].Evaluation.Required {
		t.Fatalf("scans %+v", out.Scans)
	}
	var intrusive, watch int
	for id, n := range out.PerRule {
		switch id {
		case out.Scans[0].Evaluation.Matched[0].ID:
			intrusive = n
		default:
			watch = n
		}
	}
	if intrusive != 1 || watch != 2 {
		t.Fatalf("per rule %v", out.PerRule)
	}
	// Nothing was saved.
	if len(r.st.s.Rules) != 1 || r.st.s.Rules[0].Name != "Intrusive scans" {
		t.Fatalf("the tester changed the saved rules: %+v", r.st.s.Rules)
	}
	// Invalid rules are refused as a save would refuse them.
	if _, err := r.svc.TestRules(ctx, r.tid, []scangov.Rule{{Name: "", Enabled: true, Requirement: scangov.Requirement{Approvals: 1}}}); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("invalid rule: %v", err)
	}
}

// Strict raises every caught scan to two approvals; a truncated list says
// so.
func TestTestRules_StrictAndTruncation(t *testing.T) {
	r := newRig(t, scangov.ModeStrict, nil)
	var list []*scan.Scan
	for i := 0; i < MaxTestedScans+5; i++ {
		list = append(list, &scan.Scan{ID: shared.NewID(), TenantID: r.tid, Name: "s", ScannerName: "zap"})
	}
	ts := &tierScans{list: list, total: len(list)}
	r.svc.SetScans(ts)
	r.svc.SetScanLister(ts)
	out, err := r.svc.TestRules(context.Background(), r.tid, scangov.Preset(scangov.PresetLight))
	if err != nil {
		t.Fatal(err)
	}
	if out.Mode != scangov.ModeStrict || out.Tested != MaxTestedScans || !out.Truncated || out.Scans[0].Evaluation.Approvals != 2 {
		t.Fatalf("result mode %s tested %d truncated %v approvals %d", out.Mode, out.Tested, out.Truncated, out.Scans[0].Evaluation.Approvals)
	}
}

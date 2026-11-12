package exploration

import (
	"strings"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// A hidden step keeps only its kind (and, for an asset, how it leads down),
// whatever a reader filled in by mistake, and the story counts it.
func TestSeal_StripsAndCountsHiddenSteps(t *testing.T) {
	now := time.Now()
	sensor := shared.NewID()
	s := &Story{Steps: []Step{
		{Kind: StepAsset, Hidden: true, At: &now, Asset: &AssetStep{ID: shared.NewID(), Name: "secret.example.com", Via: "contains"}},
		{Kind: StepScan, Hidden: true, At: &now, Scan: &ScanStep{RunID: shared.NewID(), ScanName: "secret scan"}},
		{Kind: StepScopeEntry, Hidden: true, Scope: &ScopeStep{ID: shared.NewID(), Pattern: "*.secret.example.com"}},
		{Kind: StepReport, Hidden: true, Report: &ReportStep{Channel: "scan", SensorID: &sensor, SensorName: "secret sensor"}},
		{Kind: StepAsset, Asset: &AssetStep{ID: shared.NewID(), Name: "in.example.com", Subject: true}},
	}}
	s.Seal()
	if s.Hidden != 4 || len(s.Steps) != 5 {
		t.Fatalf("hidden %d, steps %d", s.Hidden, len(s.Steps))
	}
	for i, st := range s.Steps[:4] {
		if st.At != nil || st.Scan != nil || st.Scope != nil || st.Report != nil || st.Finding != nil {
			t.Fatalf("step %d keeps data: %+v", i, st)
		}
	}
	if a := s.Steps[0].Asset; a == nil || a.Via != "contains" || a.Name != "" || !a.ID.IsZero() {
		t.Fatalf("hidden asset keeps more than its edge: %+v", a)
	}
	if s.Steps[4].Asset == nil || s.Steps[4].Asset.Name != "in.example.com" {
		t.Fatalf("visible step changed: %+v", s.Steps[4])
	}
}

// The chain never grows past MaxSteps: the steps closest to the subject (the
// end of the chain) are kept and the story says it was cut.
func TestSeal_CapsTheChain(t *testing.T) {
	s := &Story{}
	for i := 0; i < MaxSteps+4; i++ {
		s.Steps = append(s.Steps, Step{Kind: StepAsset, Asset: &AssetStep{Name: "n" + strings.Repeat("x", i)}})
	}
	last := s.Steps[len(s.Steps)-1].Asset.Name
	s.Seal()
	if len(s.Steps) != MaxSteps || !s.Truncated {
		t.Fatalf("steps %d truncated %v", len(s.Steps), s.Truncated)
	}
	if s.Steps[len(s.Steps)-1].Asset.Name != last {
		t.Fatalf("the subject end of the chain was cut")
	}
}

// Reports are ordered by who saw it first; past MaxReports the rest are
// counted, never listed.
func TestPickReports_FirstSeenFirstAndCapped(t *testing.T) {
	base := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	in := []ReportStep{
		{Tool: "c", FirstSeenAt: base.Add(3 * time.Hour)},
		{Tool: "a", FirstSeenAt: base.Add(1 * time.Hour)},
		{Tool: "e", FirstSeenAt: base.Add(5 * time.Hour)},
		{Tool: "b", FirstSeenAt: base.Add(2 * time.Hour)},
		{Tool: "d", FirstSeenAt: base.Add(4 * time.Hour)},
	}
	got, more := PickReports(in)
	if len(got) != MaxReports || more != 2 {
		t.Fatalf("got %d reports, %d more", len(got), more)
	}
	for i, want := range []string{"a", "b", "c"} {
		if got[i].Tool != want {
			t.Fatalf("report %d = %s, want %s", i, got[i].Tool, want)
		}
	}
	if got, more := PickReports(nil); len(got) != 0 || more != 0 {
		t.Fatalf("empty: %v %d", got, more)
	}
}

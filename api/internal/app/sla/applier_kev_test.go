package sla

import (
	"context"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	sladom "github.com/openctemio/openctem/api/pkg/domain/sla"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// Known exploited deadline cap (docs/architecture/scoring-versions.md,
// "Known exploited deadline cap"): a KEV finding is due at most cap days
// after it is first seen as KEV; the cap only tightens.

const day = 24 * time.Hour

func kevService(t *testing.T, tenantID shared.ID, mutate func(p *sladom.Policy)) *Service {
	t.Helper()
	p, err := sladom.NewDefaultPolicy(tenantID)
	if err != nil {
		t.Fatal(err)
	}
	if mutate != nil {
		mutate(p)
	}
	return NewService(&memSLARepo{policies: []*sladom.Policy{p}}, logger.NewNop())
}

func kevFinding(t *testing.T, class string, sev vulnerability.Severity) *vulnerability.Finding {
	t.Helper()
	f := newAppliedFinding(t, class, sev)
	f.SetIsInKEV(true)
	return f
}

func within(t *testing.T, got *time.Time, lo, hi time.Time) {
	t.Helper()
	if got == nil || got.Before(lo) || got.After(hi) {
		t.Fatalf("deadline = %v, want in [%v, %v]", got, lo, hi)
	}
}

// A KEV finding in P3 (30 days) is due 14 days after first detection.
func TestKEVCap_FirstDeadlineCapped(t *testing.T) {
	tid := shared.NewID()
	f := kevFinding(t, "P3", vulnerability.SeverityLow)
	if err := NewApplier(kevService(t, tid, nil)).ApplyBatch(context.Background(), tid, []*vulnerability.Finding{f}); err != nil {
		t.Fatal(err)
	}
	want := f.FirstDetectedAt().Add(sladom.DefaultKEVCapDays * day)
	if f.SLADeadline() == nil || !f.SLADeadline().Equal(want) {
		t.Fatalf("deadline = %v, want %v", f.SLADeadline(), want)
	}
	if !f.SLAKEVCapped() {
		t.Fatal("a deadline the cap set must be marked")
	}
}

// A class window already shorter than the cap decides, unmarked.
func TestKEVCap_ShorterClassWindowWins(t *testing.T) {
	tid := shared.NewID()
	f := kevFinding(t, "P1", vulnerability.SeverityCritical) // P1 = 5 days
	if err := NewApplier(kevService(t, tid, nil)).ApplyBatch(context.Background(), tid, []*vulnerability.Finding{f}); err != nil {
		t.Fatal(err)
	}
	want := f.FirstDetectedAt().Add(5 * day)
	if f.SLADeadline() == nil || !f.SLADeadline().Equal(want) {
		t.Fatalf("deadline = %v, want %v", f.SLADeadline(), want)
	}
	if f.SLAKEVCapped() {
		t.Fatal("the class window decided: not marked")
	}
}

// KEV enrichment that arrives after the first deadline tightens it to
// now + cap at the pass that first sees it; a later pass does not move it.
func TestKEVCap_LateKEVEnrichment(t *testing.T) {
	tid := shared.NewID()
	svc := kevService(t, tid, nil)
	f := newAppliedFinding(t, "P3", vulnerability.SeverityLow)
	a := NewApplier(svc)
	if err := a.ApplyBatch(context.Background(), tid, []*vulnerability.Finding{f}); err != nil {
		t.Fatal(err)
	}
	if f.SLAKEVCapped() {
		t.Fatal("not KEV yet")
	}

	f.SetIsInKEV(true) // the KEV refresh flags the CVE
	before := time.Now()
	if err := a.ApplyBatch(context.Background(), tid, []*vulnerability.Finding{f}); err != nil {
		t.Fatal(err)
	}
	within(t, f.SLADeadline(), before.Add(14*day), time.Now().Add(14*day))
	if !f.SLAKEVCapped() {
		t.Fatal("late KEV must mark the deadline")
	}

	first := *f.SLADeadline()
	time.Sleep(5 * time.Millisecond)
	if err := a.ApplyBatch(context.Background(), tid, []*vulnerability.Finding{f}); err != nil {
		t.Fatal(err)
	}
	if !f.SLADeadline().Equal(first) || !f.SLAKEVCapped() {
		t.Fatalf("a later pass moved the deadline: %v -> %v", first, f.SLADeadline())
	}
}

// Tighten only: an earlier existing deadline is never extended to the cap.
func TestKEVCap_NeverExtends(t *testing.T) {
	tid := shared.NewID()
	f := kevFinding(t, "P3", vulnerability.SeverityLow)
	earlier := time.Now().Add(3 * day)
	f.SetSLADeadline(earlier)
	if err := NewApplier(kevService(t, tid, nil)).ApplyBatch(context.Background(), tid, []*vulnerability.Finding{f}); err != nil {
		t.Fatal(err)
	}
	if !f.SLADeadline().Equal(earlier) || f.SLAKEVCapped() {
		t.Fatalf("deadline = %v (capped %v), want the earlier %v kept", f.SLADeadline(), f.SLAKEVCapped(), earlier)
	}

	// An overdue deadline stays overdue: the cap never moves it later.
	f2 := kevFinding(t, "P3", vulnerability.SeverityLow)
	past := time.Now().Add(-10 * day)
	f2.SetSLADeadline(past)
	if err := NewApplier(kevService(t, tid, nil)).ApplyBatch(context.Background(), tid, []*vulnerability.Finding{f2}); err != nil {
		t.Fatal(err)
	}
	if !f2.SLADeadline().Equal(past) {
		t.Fatalf("overdue deadline moved to %v", f2.SLADeadline())
	}
}

// An informational finding under a policy without an info SLA stays without
// a deadline even when KEV: the cap tightens, it never creates a clock.
func TestKEVCap_InformationalExempt(t *testing.T) {
	tid := shared.NewID()
	f := kevFinding(t, "P1", vulnerability.SeverityInfo)
	if err := NewApplier(kevService(t, tid, nil)).ApplyBatch(context.Background(), tid, []*vulnerability.Finding{f}); err != nil {
		t.Fatal(err)
	}
	if f.SLADeadline() != nil || f.SLAKEVCapped() {
		t.Fatalf("informational KEV finding got deadline %v (capped %v)", f.SLADeadline(), f.SLAKEVCapped())
	}
}

// A cap of 0 turns it off: the class window decides.
func TestKEVCap_ZeroIsOff(t *testing.T) {
	tid := shared.NewID()
	svc := kevService(t, tid, func(p *sladom.Policy) {
		if err := p.UpdateKEVCapDays(0); err != nil {
			t.Fatal(err)
		}
	})
	f := kevFinding(t, "P3", vulnerability.SeverityLow)
	if err := NewApplier(svc).ApplyBatch(context.Background(), tid, []*vulnerability.Finding{f}); err != nil {
		t.Fatal(err)
	}
	want := f.FirstDetectedAt().Add(30 * day)
	if f.SLADeadline() == nil || !f.SLADeadline().Equal(want) || f.SLAKEVCapped() {
		t.Fatalf("deadline = %v (capped %v), want %v unmarked", f.SLADeadline(), f.SLAKEVCapped(), want)
	}
}

// The cap of the finding's own asset policy applies; another tenant's policy
// never does.
func TestKEVCap_AssetPolicyAndTenantIsolation(t *testing.T) {
	tid, other := shared.NewID(), shared.NewID()
	f := kevFinding(t, "P3", vulnerability.SeverityLow)

	def, _ := sladom.NewDefaultPolicy(tid)
	assetPol, _ := sladom.NewPolicy(tid, "crown jewels")
	assetPol.SetAssetID(f.AssetID())
	if err := assetPol.UpdateKEVCapDays(7); err != nil {
		t.Fatal(err)
	}
	foreign, _ := sladom.NewPolicy(other, "other tenant")
	foreign.SetAssetID(f.AssetID())
	if err := foreign.UpdateKEVCapDays(1); err != nil {
		t.Fatal(err)
	}
	svc := NewService(&memSLARepo{policies: []*sladom.Policy{foreign, def, assetPol}}, logger.NewNop())

	if err := NewApplier(svc).ApplyBatch(context.Background(), tid, []*vulnerability.Finding{f}); err != nil {
		t.Fatal(err)
	}
	want := f.FirstDetectedAt().Add(7 * day)
	if f.SLADeadline() == nil || !f.SLADeadline().Equal(want) {
		t.Fatalf("deadline = %v, want the asset policy's 7-day cap %v", f.SLADeadline(), want)
	}
}

// The per-finding path (a calculator without the batch load) reads the cap
// through KEVCapDays, or uses the platform default without it.
func TestKEVCap_PerFindingPath(t *testing.T) {
	f := kevFinding(t, "P3", vulnerability.SeverityLow)
	if err := NewApplier(policy()).ApplyBatch(context.Background(), shared.NewID(), []*vulnerability.Finding{f}); err != nil {
		t.Fatal(err)
	}
	want := f.FirstDetectedAt().Add(sladom.DefaultKEVCapDays * day)
	if f.SLADeadline() == nil || !f.SLADeadline().Equal(want) || !f.SLAKEVCapped() {
		t.Fatalf("deadline = %v (capped %v), want default cap %v", f.SLADeadline(), f.SLAKEVCapped(), want)
	}

	f2 := kevFinding(t, "P3", vulnerability.SeverityLow)
	if err := NewApplier(&capCalc{daysCalc: policy(), capDays: 0}).ApplyBatch(context.Background(), shared.NewID(), []*vulnerability.Finding{f2}); err != nil {
		t.Fatal(err)
	}
	if f2.SLAKEVCapped() || !f2.SLADeadline().Equal(f2.FirstDetectedAt().Add(90*day)) {
		t.Fatalf("cap 0 via KEVCapDays: deadline = %v (capped %v)", f2.SLADeadline(), f2.SLAKEVCapped())
	}
}

type capCalc struct {
	*daysCalc
	capDays int
}

func (c *capCalc) KEVCapDays(context.Context, string, string) (int, error) { return c.capDays, nil }

// An approved severity downgrade never relaxes a KEV finding past first
// detection + cap.
func TestKEVCap_RelaxBounded(t *testing.T) {
	tid := shared.NewID()
	svc := kevService(t, tid, nil)
	f := kevFinding(t, "P1", vulnerability.SeverityCritical)
	a := NewApplier(svc)
	if err := a.ApplyBatch(context.Background(), tid, []*vulnerability.Finding{f}); err != nil {
		t.Fatal(err)
	}
	// The downgrade lowers the class to P3 (30 days).
	f.SetPriorityClassification(vulnerability.PriorityClass("P3"), "downgraded")
	if err := a.RelaxForDecision(context.Background(), tid, []*vulnerability.Finding{f}); err != nil {
		t.Fatal(err)
	}
	want := f.FirstDetectedAt().Add(14 * day)
	if f.SLADeadline() == nil || !f.SLADeadline().Equal(want) || !f.SLAKEVCapped() {
		t.Fatalf("relaxed deadline = %v (capped %v), want %v", f.SLADeadline(), f.SLAKEVCapped(), want)
	}
}

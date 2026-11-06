package sla

import (
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	sladom "github.com/openctemio/openctem/api/pkg/domain/sla"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

func testPolicy(t *testing.T) *sladom.Policy {
	t.Helper()
	p, err := sladom.NewPolicy(shared.NewID(), "Production")
	if err != nil {
		t.Fatal(err)
	}
	if err := p.UpdatePriorityDays(3, 7, 30, 90); err != nil {
		t.Fatal(err)
	}
	if err := p.UpdateKEVCapDays(2); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestExplain_PriorityWindowFromTheOrganizationPolicy(t *testing.T) {
	e := explain(&EffectivePolicy{Policy: testPolicy(t)}, "P1", vulnerability.SeverityHigh)
	if e.PolicyScope != "organization" || e.Basis != "priority" || e.Days != 7 || e.KEVCapDays != 2 || e.PolicyName != "Production" {
		t.Fatalf("explain = %+v", e)
	}
}

func TestExplain_AssetPolicyScope(t *testing.T) {
	p := testPolicy(t)
	p.SetAssetID(shared.NewID())
	if e := explain(&EffectivePolicy{Policy: p}, "P0", vulnerability.SeverityCritical); e.PolicyScope != "asset" || e.Days != 3 {
		t.Fatalf("explain = %+v", e)
	}
}

func TestExplain_SeverityWhenNoClass(t *testing.T) {
	p := testPolicy(t)
	e := explain(&EffectivePolicy{Policy: p}, "", vulnerability.SeverityHigh)
	if e.Basis != "severity" || e.Days != p.GetDaysForSeverity("high") {
		t.Fatalf("explain = %+v", e)
	}
}

func TestExplain_PlatformDefaultMatchesTheDeadlineWriter(t *testing.T) {
	eff, err := effectivePolicy(shared.NewID().String(), nil, sladom.ErrNotFound)
	if err != nil {
		t.Fatal(err)
	}
	e := explain(eff, "P0", vulnerability.SeverityCritical)
	if e.PolicyScope != "platform" || e.PolicyID != "" || e.KEVCapDays != sladom.DefaultKEVCapDays {
		t.Fatalf("explain = %+v", e)
	}
	start := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	want, _ := deadlineForPriority(nil, "P0", vulnerability.SeverityCritical, start)
	got, _ := e.ExpectedDeadline(start, false)
	if !got.Equal(want) {
		t.Fatalf("expected deadline %v, writer computes %v", got, want)
	}
	if e := explain(eff, "", vulnerability.SeverityInfo); e.Basis != "none" {
		t.Fatalf("informational under platform defaults = %+v", e)
	}
}

func TestExplain_ExpectedDeadlineMatchesThePolicyAndCap(t *testing.T) {
	p := testPolicy(t)
	start := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	e := explain(&EffectivePolicy{Policy: p}, "P1", vulnerability.SeverityHigh)
	got, capped := e.ExpectedDeadline(start, false)
	if !got.Equal(p.CalculateDeadlineFor("P1", "high", start)) || capped {
		t.Fatalf("no KEV: %v capped %v", got, capped)
	}
	got, capped = e.ExpectedDeadline(start, true)
	if !got.Equal(start.Add(48*time.Hour)) || !capped {
		t.Fatalf("KEV: %v capped %v, want the 2-day cap", got, capped)
	}
}

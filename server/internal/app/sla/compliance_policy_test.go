package sla

import (
	"context"
	"testing"
	"time"

	"github.com/openctemio/openctem/server/pkg/domain/shared"
	sladom "github.com/openctemio/openctem/server/pkg/domain/sla"
	"github.com/openctemio/openctem/server/pkg/domain/vulnerability"
	"github.com/openctemio/openctem/server/pkg/logger"
)

func compliancePolicy(t *testing.T, tenant shared.ID, asset *shared.ID, isDefault bool, p2Days int, created time.Time) *sladom.Policy {
	t.Helper()
	p := sladom.Reconstitute(shared.NewID(), tenant, asset, "c", "", isDefault,
		30, 30, 90, 180, 0, 80, false, nil, true, created, created).
		WithPriorityDays(30, 30, p2Days, 180).WithPractice(sladom.PracticeCompliance)
	return p
}

func days(d time.Duration) int { return int(d / (24 * time.Hour)) }

// A compliance finding is governed only by compliance policies (asset, then
// tenant default, then the platform's compliance windows); a vulnerability
// finding never by one. Both the batch and the single-finding paths agree.
func TestCompliancePolicyResolution(t *testing.T) {
	tenant := shared.NewID()
	assetVuln, assetComp, plain := shared.NewID(), shared.NewID(), shared.NewID()
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	detected := time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)

	cases := []struct {
		name     string
		policies []*sladom.Policy
		asset    string
		practice string
		want     int // days for a P2 high finding
	}{
		{"no policy: platform compliance window", nil, plain.String(), sladom.PracticeCompliance, 90},
		{"no policy: platform vulnerability window", nil, plain.String(), "", 15},
		{"vulnerability default never governs compliance",
			[]*sladom.Policy{mkPolicy(tenant, nil, true, true, 7, t0).WithPriorityDays(1, 3, 7, 20)},
			plain.String(), sladom.PracticeCompliance, 90},
		{"compliance default never governs vulnerabilities",
			[]*sladom.Policy{compliancePolicy(t, tenant, nil, true, 120, t0)},
			plain.String(), "", 15},
		{"compliance default governs compliance",
			[]*sladom.Policy{mkPolicy(tenant, nil, true, true, 7, t0).WithPriorityDays(1, 3, 7, 20), compliancePolicy(t, tenant, nil, true, 120, t0)},
			plain.String(), sladom.PracticeCompliance, 120},
		{"asset vulnerability override never governs compliance",
			[]*sladom.Policy{mkPolicy(tenant, &assetVuln, false, true, 1, t0).WithPriorityDays(1, 1, 1, 1), compliancePolicy(t, tenant, nil, true, 120, t0)},
			assetVuln.String(), sladom.PracticeCompliance, 120},
		{"asset compliance override wins for compliance",
			[]*sladom.Policy{compliancePolicy(t, tenant, nil, true, 120, t0), compliancePolicy(t, tenant, &assetComp, false, 45, t0)},
			assetComp.String(), sladom.PracticeCompliance, 45},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			repo := &memSLARepo{policies: tc.policies}
			svc := NewService(repo, logger.NewNop())
			ctx := context.Background()
			fn, err := svc.SLADeadlineFunc(ctx, tenant.String())
			if err != nil {
				t.Fatal(err)
			}
			got, err := fn(tc.asset, tc.practice, "P2", vulnerability.SeverityHigh, detected)
			if err != nil || days(got.Sub(detected)) != tc.want {
				t.Fatalf("batch = %v (%d days), %v; want %d days", got, days(got.Sub(detected)), err, tc.want)
			}
			one, err := svc.CalculateSLADeadlineForPractice(ctx, tenant.String(), tc.asset, tc.practice, "P2", vulnerability.SeverityHigh, detected)
			if err != nil || !one.Equal(got) {
				t.Fatalf("single = %v, %v; batch %v", one, err, got)
			}
		})
	}
}

// A compliance policy starts from the compliance windows, has no known
// exploited cap, and the practice is only empty or compliance.
func TestPolicySetPractice(t *testing.T) {
	p, err := sladom.NewPolicy(shared.NewID(), "c")
	if err != nil {
		t.Fatal(err)
	}
	if err := p.SetPractice("aspm"); err == nil {
		t.Fatal("practice aspm accepted")
	}
	if err := p.SetPractice(sladom.PracticeCompliance); err != nil {
		t.Fatal(err)
	}
	if p.P1Days() != 30 || p.P2Days() != 90 || p.P3Days() != 180 || p.KEVCapDays() != 0 {
		t.Fatalf("compliance windows = %d/%d/%d cap %d", p.P1Days(), p.P2Days(), p.P3Days(), p.KEVCapDays())
	}
	if !p.Governs(sladom.PracticeCompliance) || p.Governs("infra") || p.Governs("") {
		t.Fatal("Governs is wrong for a compliance policy")
	}
}

// The applier gives a compliance finding the compliance window and never the
// known exploited cap.
func TestApplierCompliance(t *testing.T) {
	tenant, asset := shared.NewID(), shared.NewID()
	svc := NewService(&memSLARepo{}, logger.NewNop())
	f, err := vulnerability.NewFinding(tenant, asset, vulnerability.FindingSourceVA, "nessus", vulnerability.SeverityHigh, "CIS check")
	if err != nil {
		t.Fatal(err)
	}
	f.SetFindingType(vulnerability.FindingTypeCompliance)
	f.SetPriorityClassification(vulnerability.PriorityClass("P2"), "test")
	f.SetIsInKEV(true)
	if err := NewApplier(svc).ApplyBatch(context.Background(), tenant, []*vulnerability.Finding{f}); err != nil {
		t.Fatal(err)
	}
	if f.SLADeadline() == nil || days(f.SLADeadline().Sub(f.FirstDetectedAt())) != 90 {
		t.Fatalf("compliance deadline = %v", f.SLADeadline())
	}
}

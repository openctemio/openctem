package postgres

import (
	"context"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/openctemio/openctem/api/pkg/domain/suppression"
)

func suppressionHits(label string) float64 {
	return testutil.ToFloat64(suppressionRuleHits.WithLabelValues(label))
}

// An approval counts the findings it closed, an ingest hit counts once per
// finding however often it is recorded, and an unknown applied_by lands in the
// closed "other" label.
func TestSuppressionRuleHitsCounter_DB(t *testing.T) {
	ctx := context.Background()
	db := openGroupsDB(t)
	repo := NewSuppressionRepository(&DB{DB: db})
	tenant := seedTestTenant(ctx, t, db)
	requester := seedGroupsUser(ctx, t, db, "supp.metric.req")
	approver := seedGroupsUser(ctx, t, db, "supp.metric.appr")
	asset := seedOwnedAsset(ctx, t, db, tenant, nil)

	rule, reviewed := newPendingRule(ctx, t, repo, tenant, requester, approver, suppression.SuppressionTypeFalsePositive, func(r *suppression.Rule) {
		r.SetRuleIDPattern("metric.rule")
	})
	for range 3 {
		seedOpenFinding(ctx, t, db, tenant, openFindingSeed{asset: asset, rule: "metric.rule", path: "a.go"})
	}

	approvalBefore := suppressionHits(suppressionHitApproval)
	res, err := repo.Approve(ctx, rule, reviewed, approver, nil, suppression.MaxFindingsAppliedOnApprove)
	if err != nil {
		t.Fatal(err)
	}
	if res.Applied != 3 {
		t.Fatalf("applied = %d, want 3", res.Applied)
	}
	if got := suppressionHits(suppressionHitApproval) - approvalBefore; got != 3 {
		t.Errorf("approval hits = %v, want 3", got)
	}

	f := seedOpenFinding(ctx, t, db, tenant, openFindingSeed{asset: asset, rule: "metric.rule", path: "b.go"})
	ingestBefore := suppressionHits(suppressionHitIngest)
	for range 2 {
		if err := repo.RecordSuppression(ctx, f, rule.ID(), "system"); err != nil {
			t.Fatal(err)
		}
	}
	if got := suppressionHits(suppressionHitIngest) - ingestBefore; got != 1 {
		t.Errorf("ingest hits after recording the same finding twice = %v, want 1", got)
	}

	otherBefore := suppressionHits(suppressionHitOther)
	g := seedOpenFinding(ctx, t, db, tenant, openFindingSeed{asset: asset, rule: "metric.rule", path: "c.go"})
	if err := repo.RecordSuppression(ctx, g, rule.ID(), "someone-else"); err != nil {
		t.Fatal(err)
	}
	if got := suppressionHits(suppressionHitOther) - otherBefore; got != 1 {
		t.Errorf("other hits = %v, want 1", got)
	}
}

func TestObserveSuppressionHits_Labels(t *testing.T) {
	before := suppressionHits(suppressionHitOther)
	observeSuppressionHits("tenant-controlled-value", 2)
	observeSuppressionHits("system", 0)
	if got := suppressionHits(suppressionHitOther) - before; got != 2 {
		t.Errorf("other = %v, want 2", got)
	}
}

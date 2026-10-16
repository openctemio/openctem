package postgres

import (
	"context"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/suppression"
)

// The approval preview lists only findings of assets the caller's data scope
// admits, never another tenant's, and counts the same set.
func TestSuppressionPreviewSample_RespectsDataScope_DB(t *testing.T) {
	ctx := context.Background()
	db := openGroupsDB(t)
	repo := NewSuppressionRepository(&DB{DB: db})
	tenant := seedTestTenant(ctx, t, db)
	requester := seedGroupsUser(ctx, t, db, "supp.sample.req")
	approver := seedGroupsUser(ctx, t, db, "supp.sample.appr")
	visible := seedOwnedAsset(ctx, t, db, tenant, nil)
	hidden := seedOwnedAsset(ctx, t, db, tenant, nil)

	rule, _ := newPendingRule(ctx, t, repo, tenant, requester, approver, suppression.SuppressionTypeFalsePositive, func(r *suppression.Rule) {
		r.SetRuleIDPattern("sample.rule")
	})

	var visibleIDs, hiddenIDs []shared.ID
	for range 4 {
		visibleIDs = append(visibleIDs, seedOpenFinding(ctx, t, db, tenant, openFindingSeed{asset: visible, rule: "sample.rule", path: "v.go"}))
	}
	for range 3 {
		hiddenIDs = append(hiddenIDs, seedOpenFinding(ctx, t, db, tenant, openFindingSeed{asset: hidden, rule: "sample.rule", path: "h.go"}))
	}
	otherTenant := seedTestTenant(ctx, t, db)
	otherAsset := seedOwnedAsset(ctx, t, db, otherTenant, nil)
	foreign := seedOpenFinding(ctx, t, db, otherTenant, openFindingSeed{asset: otherAsset, rule: "sample.rule", path: "x.go"})

	onlyVisible := func(_ context.Context, _ shared.ID, _ []shared.ID) (func(shared.ID) bool, error) {
		return func(a shared.ID) bool { return a == visible }, nil
	}

	total, err := repo.CountMatchingOpenFindings(ctx, rule, suppression.MaxFindingsAppliedOnApprove)
	if err != nil || total != 7 {
		t.Fatalf("organization-wide count = %d, %v; want 7", total, err)
	}

	n, sample, err := repo.SampleMatchingOpenFindings(ctx, rule, onlyVisible, suppression.MaxFindingsAppliedOnApprove, 10)
	if err != nil {
		t.Fatal(err)
	}
	if n != 4 || len(sample) != 4 {
		t.Fatalf("in scope = %d, sample = %d; want 4 and 4", n, len(sample))
	}
	allowed := map[shared.ID]bool{}
	for _, id := range visibleIDs {
		allowed[id] = true
	}
	for _, f := range sample {
		if !allowed[f.ID] {
			t.Errorf("sample lists %s, which is outside the caller's scope or tenant", f.ID)
		}
		if f.AssetID != visible || f.Title == "" || f.Status != "new" {
			t.Errorf("sample row incomplete: %+v", f)
		}
	}
	for _, id := range append(hiddenIDs, foreign) {
		for _, f := range sample {
			if f.ID == id {
				t.Errorf("sample leaks %s", id)
			}
		}
	}

	// The sample is capped, the count is not.
	n, sample, err = repo.SampleMatchingOpenFindings(ctx, rule, onlyVisible, suppression.MaxFindingsAppliedOnApprove, 2)
	if err != nil || n != 4 || len(sample) != 2 {
		t.Fatalf("capped sample: in scope = %d, sample = %d, err = %v; want 4, 2", n, len(sample), err)
	}

	// No scope filter wired: nothing is counted or listed.
	n, sample, err = repo.SampleMatchingOpenFindings(ctx, rule, nil, suppression.MaxFindingsAppliedOnApprove, 10)
	if err != nil || n != 0 || len(sample) != 0 {
		t.Fatalf("nil scope: in scope = %d, sample = %d, err = %v; want 0, 0", n, len(sample), err)
	}

	// A scope that admits every asset of the tenant still never reaches
	// another tenant's findings.
	all := func(_ context.Context, _ shared.ID, _ []shared.ID) (func(shared.ID) bool, error) {
		return func(shared.ID) bool { return true }, nil
	}
	n, sample, err = repo.SampleMatchingOpenFindings(ctx, rule, all, suppression.MaxFindingsAppliedOnApprove, 50)
	if err != nil || n != 7 || len(sample) != 7 {
		t.Fatalf("full scope: in scope = %d, sample = %d, err = %v; want 7, 7", n, len(sample), err)
	}
	for _, f := range sample {
		if f.ID == foreign {
			t.Fatal("full-scope sample leaks another tenant's finding")
		}
	}
}

// The message of a secret finding can quote the secret: the preview sample
// carries the rule id and path, never the message.
func TestSuppressionPreviewSample_NeverCarriesASecretMessage_DB(t *testing.T) {
	ctx := context.Background()
	db := openGroupsDB(t)
	repo := NewSuppressionRepository(&DB{DB: db})
	tenant := seedTestTenant(ctx, t, db)
	requester := seedGroupsUser(ctx, t, db, "supp.sample.req2")
	approver := seedGroupsUser(ctx, t, db, "supp.sample.appr2")
	asset := seedOwnedAsset(ctx, t, db, tenant, nil)
	rule, _ := newPendingRule(ctx, t, repo, tenant, requester, approver, suppression.SuppressionTypeFalsePositive, func(r *suppression.Rule) {
		r.SetRuleIDPattern("leak.rule")
	})
	secret := seedOpenFinding(ctx, t, db, tenant, openFindingSeed{asset: asset, rule: "leak.rule", path: "s.go", source: "secret"})
	plain := seedOpenFinding(ctx, t, db, tenant, openFindingSeed{asset: asset, rule: "leak.rule", path: "p.go"})
	if _, err := db.ExecContext(ctx, `UPDATE findings SET message = 'token AKIA-REAL-VALUE found' WHERE id = ANY($1::uuid[])`,
		"{"+secret.String()+","+plain.String()+"}"); err != nil {
		t.Fatal(err)
	}
	all := func(_ context.Context, _ shared.ID, _ []shared.ID) (func(shared.ID) bool, error) {
		return func(shared.ID) bool { return true }, nil
	}
	_, sample, err := repo.SampleMatchingOpenFindings(ctx, rule, all, suppression.MaxFindingsAppliedOnApprove, 10)
	if err != nil || len(sample) != 2 {
		t.Fatalf("sample = %d, %v", len(sample), err)
	}
	for _, f := range sample {
		if f.ID == secret && (f.Title != "" || f.RuleID != "leak.rule" || f.FilePath != "s.go") {
			t.Errorf("secret sample = %+v: no message, but rule and path", f)
		}
		if f.ID == plain && f.Title == "" {
			t.Errorf("a plain finding lost its message: %+v", f)
		}
	}
}

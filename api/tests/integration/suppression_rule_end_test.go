package integration

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/suppression"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// TestSuppressionRule_EndRequired_DB: through the real repository a rule
// created without an end is stored with 90 days, one beyond a year is
// refused, the end cannot be removed, the review flag round-trips and is
// cleared by an edit, and another tenant cannot read or edit the rule.
func TestSuppressionRule_EndRequired_DB(t *testing.T) {
	db := setupTestDB(t)
	pdb := &postgres.DB{DB: db}
	ctx := context.Background()
	tenant := createTestTenant(t, db, "sup-end")
	other := createTestTenant(t, db, "sup-end-other")
	requester := shared.NewID()
	t.Cleanup(func() {
		for _, id := range []shared.ID{tenant, other} {
			_, _ = db.Exec(`DELETE FROM suppression_rules WHERE tenant_id = $1`, id.String())
			_, _ = db.Exec(`DELETE FROM tenants WHERE id = $1`, id.String())
		}
		_, _ = db.Exec(`DELETE FROM users WHERE id = $1`, requester.String())
		_ = db.Close()
	})
	if _, err := db.Exec(`INSERT INTO users (id, email, name) VALUES ($1, $2, 'sup')`, requester.String(), requester.String()+"@example.com"); err != nil {
		t.Fatal(err)
	}
	svc := suppression.NewService(postgres.NewSuppressionRepository(pdb), logger.NewNop())
	create := func(end *string) (*suppression.Rule, error) {
		return svc.CreateRule(ctx, suppression.CreateRuleInput{TenantID: tenant, Name: "fixtures", RuleID: "go.fixture",
			SuppressionType: suppression.SuppressionTypeFalsePositive, RequestedBy: requester, ExpiresAt: end})
	}
	rule, err := create(nil)
	if err != nil {
		t.Fatal(err)
	}
	var stored time.Time
	if err := db.QueryRow(`SELECT expires_at FROM suppression_rules WHERE id = $1`, rule.ID().String()).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if d := time.Until(stored); d < 89*24*time.Hour || d > 90*24*time.Hour {
		t.Fatalf("stored end in %v, want 90 days", d)
	}
	tooLate := time.Now().Add(366 * 24 * time.Hour).Format(time.RFC3339)
	if _, err := create(&tooLate); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("366 days: %v", err)
	}
	empty := ""
	if _, err := svc.UpdateRule(ctx, suppression.UpdateRuleInput{TenantID: tenant, RuleID: rule.ID(), ExpiresAt: &empty, UpdatedBy: requester}); !errors.Is(err, suppression.ErrRuleEndRequired) {
		t.Fatalf("clear end: %v", err)
	}

	// The review flag round-trips and an edit clears it.
	if _, err := db.Exec(`UPDATE suppression_rules SET review_flagged_at = now(), review_reason = 'no_end_date' WHERE id = $1`, rule.ID().String()); err != nil {
		t.Fatal(err)
	}
	got, err := svc.GetRule(ctx, tenant, rule.ID())
	if err != nil || got.ReviewFlaggedAt() == nil || got.ReviewReason() != suppression.ReviewReasonNoEndDate {
		t.Fatalf("flag not read back: %v %+v", err, got)
	}
	// Another tenant reaches nothing.
	if _, err := svc.GetRule(ctx, other, rule.ID()); err == nil {
		t.Fatal("tenant B read tenant A's rule")
	}
	soon := time.Now().Add(30 * 24 * time.Hour).Format(time.RFC3339)
	if _, err := svc.UpdateRule(ctx, suppression.UpdateRuleInput{TenantID: other, RuleID: rule.ID(), ExpiresAt: &soon, UpdatedBy: requester}); err == nil {
		t.Fatal("tenant B edited tenant A's rule")
	}
	if _, err := svc.UpdateRule(ctx, suppression.UpdateRuleInput{TenantID: tenant, RuleID: rule.ID(), ExpiresAt: &soon, UpdatedBy: requester}); err != nil {
		t.Fatal(err)
	}
	var flagged bool
	if err := db.QueryRow(`SELECT review_flagged_at IS NOT NULL OR review_reason <> '' FROM suppression_rules WHERE id = $1`, rule.ID().String()).Scan(&flagged); err != nil || flagged {
		t.Fatalf("edit did not clear the flag: %v %v", flagged, err)
	}
}

package suppression

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

func TestRuleEnd(t *testing.T) {
	now := time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)
	if end, err := RuleEnd(nil, now); err != nil || !end.Equal(now.Add(DefaultRuleDuration)) {
		t.Fatalf("default: %v %v", end, err)
	}
	ok := now.Add(365 * 24 * time.Hour)
	if end, err := RuleEnd(&ok, now); err != nil || !end.Equal(ok) {
		t.Fatalf("365 days: %v %v", end, err)
	}
	for name, at := range map[string]time.Time{
		"past":     now.Add(-time.Minute),
		"now":      now,
		"too late": now.Add(MaxRuleDuration + time.Second),
	} {
		at := at
		if _, err := RuleEnd(&at, now); !errors.Is(err, shared.ErrValidation) {
			t.Fatalf("%s: %v, want a validation error", name, err)
		}
	}
}

// A rule always ends: created without an end it gets 90 days, beyond a year
// it is refused, and the end can never be removed; editing a flagged rule
// clears the flag.
func TestService_RuleEndRequired(t *testing.T) {
	ctx := context.Background()
	tenant := shared.NewID()
	repo := newMockRepository()
	svc := NewService(repo, nil)
	create := func(end *string) (*Rule, error) {
		return svc.CreateRule(ctx, CreateRuleInput{TenantID: tenant, Name: "r", SuppressionType: SuppressionTypeFalsePositive, ReasonCode: "detection_error", Description: "fixture rule used by tests",
			RuleID: "x", RequestedBy: shared.NewID(), ExpiresAt: end})
	}
	rule, err := create(nil)
	if err != nil || rule.ExpiresAt() == nil {
		t.Fatalf("no end: %v %+v", err, rule)
	}
	if d := time.Until(*rule.ExpiresAt()); d < DefaultRuleDuration-time.Minute || d > DefaultRuleDuration {
		t.Fatalf("default end in %v", d)
	}
	tooLate := time.Now().Add(400 * 24 * time.Hour).Format(time.RFC3339)
	if _, err := create(&tooLate); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("400 days: %v", err)
	}
	empty := ""
	if _, err := svc.UpdateRule(ctx, UpdateRuleInput{TenantID: tenant, RuleID: rule.ID(), ExpiresAt: &empty, UpdatedBy: shared.NewID()}); !errors.Is(err, ErrRuleEndRequired) {
		t.Fatalf("clear end: %v, want ErrRuleEndRequired", err)
	}
	if _, err := svc.UpdateRule(ctx, UpdateRuleInput{TenantID: tenant, RuleID: rule.ID(), ExpiresAt: &tooLate, UpdatedBy: shared.NewID()}); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("update beyond a year: %v", err)
	}

	flagged := time.Now()
	stored, _ := repo.FindByID(ctx, tenant, rule.ID())
	data := RuleData{ID: stored.ID(), TenantID: tenant, Name: "r", RuleID: "x", SuppressionType: SuppressionTypeFalsePositive,
		Status: RuleStatusPending, RequestedBy: stored.RequestedBy(), ExpiresAt: stored.ExpiresAt(),
		ReviewFlaggedAt: &flagged, ReviewReason: ReviewReasonNoEndDate}
	if err := repo.Save(ctx, ReconstituteRule(data)); err != nil {
		t.Fatal(err)
	}
	soon := time.Now().Add(30 * 24 * time.Hour).Format(time.RFC3339)
	updated, err := svc.UpdateRule(ctx, UpdateRuleInput{TenantID: tenant, RuleID: rule.ID(), ExpiresAt: &soon, UpdatedBy: shared.NewID()})
	if err != nil || updated.ReviewFlaggedAt() != nil || updated.ReviewReason() != "" {
		t.Fatalf("edit of a flagged rule: %v flag=%v", err, updated.ReviewFlaggedAt())
	}
}

package ingest

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/domain/suppression"
	"github.com/openctemio/api/pkg/domain/vulnerability"
	"github.com/openctemio/api/pkg/logger"
)

// --- stub checker ------------------------------------------------------------

type appliedSuppression struct {
	findingID shared.ID
	ruleID    shared.ID
}

type stubSuppressionChecker struct {
	rules       []*suppression.Rule
	listErr     error
	applyErr    error
	gotTenantID shared.ID
	listCalls   int
	applied     []appliedSuppression
}

func (s *stubSuppressionChecker) ListActiveRules(_ context.Context, tenantID shared.ID) ([]*suppression.Rule, error) {
	s.listCalls++
	s.gotTenantID = tenantID
	return s.rules, s.listErr
}

func (s *stubSuppressionChecker) ApplySuppression(_ context.Context, findingID, ruleID shared.ID) error {
	if s.applyErr != nil {
		return s.applyErr
	}
	s.applied = append(s.applied, appliedSuppression{findingID: findingID, ruleID: ruleID})
	return nil
}

// --- builders ----------------------------------------------------------------

func buildRule(tenantID shared.ID, status suppression.RuleStatus, toolName, ruleIDPat string, expiresAt *time.Time) *suppression.Rule {
	now := time.Now().UTC()
	approver := shared.NewID()
	return suppression.ReconstituteRule(suppression.RuleData{
		ID:              shared.NewID(),
		TenantID:        tenantID,
		ToolName:        toolName,
		RuleID:          ruleIDPat,
		Name:            "test rule",
		SuppressionType: suppression.SuppressionTypeFalsePositive,
		Status:          status,
		RequestedBy:     shared.NewID(),
		RequestedAt:     now,
		ApprovedBy:      &approver,
		ApprovedAt:      &now,
		ExpiresAt:       expiresAt,
		CreatedAt:       now,
		UpdatedAt:       now,
	})
}

func buildSuppFinding(t *testing.T, tenantID, assetID shared.ID, toolName, ruleID, fp string) *vulnerability.Finding {
	t.Helper()
	f, err := vulnerability.NewFinding(
		tenantID, assetID,
		vulnerability.FindingSourceExternal, toolName,
		vulnerability.SeverityHigh, "test finding",
	)
	if err != nil {
		t.Fatalf("NewFinding: %v", err)
	}
	f.SetRuleID(ruleID)
	f.SetFingerprint(fp)
	return f
}

// --- tests -------------------------------------------------------------------

// An active (approved, non-expired) rule matching a new finding stamps it
// resolved+suppressed BEFORE persist and returns the finding→rule decision.
func TestApplySuppressions_ActiveRuleSuppressesMatch(t *testing.T) {
	tenantID := shared.NewID()
	assetID := shared.NewID()
	checker := &stubSuppressionChecker{
		rules: []*suppression.Rule{buildRule(tenantID, suppression.RuleStatusApproved, "semgrep", "sql-injection", nil)},
	}
	p := NewFindingProcessor(&stubFindingRepository{}, nil, nil, logger.NewNop())
	p.SetSuppressionChecker(checker)

	f := buildSuppFinding(t, tenantID, assetID, "semgrep", "sql-injection", "fp-1")
	findings := []*vulnerability.Finding{f}

	decisions := p.applySuppressions(context.Background(), tenantID, findings)

	if len(decisions) != 1 {
		t.Fatalf("expected 1 suppression decision, got %d", len(decisions))
	}
	if f.Status() != vulnerability.FindingStatusResolved {
		t.Fatalf("status = %q, want resolved", f.Status())
	}
	if !f.Status().IsClosed() {
		t.Fatal("suppressed finding must be in the closed category (out of the open backlog)")
	}
	if f.Resolution() != "suppressed" {
		t.Fatalf("resolution = %q, want suppressed", f.Resolution())
	}
	// Rules are loaded once per batch, tenant-scoped.
	if checker.listCalls != 1 {
		t.Fatalf("ListActiveRules called %d times, want 1 (once per batch)", checker.listCalls)
	}
	if checker.gotTenantID != tenantID {
		t.Fatal("ListActiveRules must be tenant-scoped to the ingest tenant")
	}
}

// A pending or expired rule must NOT suppress — Rule.Matches re-checks IsActive,
// so even if such a rule leaks into the list it can never suppress.
func TestApplySuppressions_PendingOrExpiredRuleDoesNotSuppress(t *testing.T) {
	tenantID := shared.NewID()
	assetID := shared.NewID()
	past := time.Now().UTC().Add(-time.Hour)

	cases := map[string]*suppression.Rule{
		"pending": buildRule(tenantID, suppression.RuleStatusPending, "semgrep", "sql-injection", nil),
		"expired": buildRule(tenantID, suppression.RuleStatusApproved, "semgrep", "sql-injection", &past),
	}
	for name, rule := range cases {
		t.Run(name, func(t *testing.T) {
			checker := &stubSuppressionChecker{rules: []*suppression.Rule{rule}}
			p := NewFindingProcessor(&stubFindingRepository{}, nil, nil, logger.NewNop())
			p.SetSuppressionChecker(checker)

			f := buildSuppFinding(t, tenantID, assetID, "semgrep", "sql-injection", "fp-1")
			decisions := p.applySuppressions(context.Background(), tenantID, []*vulnerability.Finding{f})

			if len(decisions) != 0 {
				t.Fatalf("expected no suppression, got %d", len(decisions))
			}
			if f.Status() != vulnerability.FindingStatusNew {
				t.Fatalf("status = %q, want new (untouched)", f.Status())
			}
			if f.Resolution() != "" {
				t.Fatalf("resolution = %q, want empty", f.Resolution())
			}
		})
	}
}

// A finding that matches no active rule (tool mismatch) is left untouched.
func TestApplySuppressions_NonMatchingFinding_Untouched(t *testing.T) {
	tenantID := shared.NewID()
	assetID := shared.NewID()
	checker := &stubSuppressionChecker{
		rules: []*suppression.Rule{buildRule(tenantID, suppression.RuleStatusApproved, "semgrep", "sql-injection", nil)},
	}
	p := NewFindingProcessor(&stubFindingRepository{}, nil, nil, logger.NewNop())
	p.SetSuppressionChecker(checker)

	// Different tool → no match.
	f := buildSuppFinding(t, tenantID, assetID, "trivy", "sql-injection", "fp-1")
	decisions := p.applySuppressions(context.Background(), tenantID, []*vulnerability.Finding{f})

	if len(decisions) != 0 {
		t.Fatalf("expected no suppression, got %d", len(decisions))
	}
	if f.Status() != vulnerability.FindingStatusNew {
		t.Fatalf("status = %q, want new (untouched)", f.Status())
	}
}

// With no checker wired, suppression is a no-op — ingest behaves as before.
func TestApplySuppressions_NilChecker_NoOp(t *testing.T) {
	tenantID := shared.NewID()
	p := NewFindingProcessor(&stubFindingRepository{}, nil, nil, logger.NewNop())

	f := buildSuppFinding(t, tenantID, shared.NewID(), "semgrep", "sql-injection", "fp-1")
	decisions := p.applySuppressions(context.Background(), tenantID, []*vulnerability.Finding{f})

	if decisions != nil {
		t.Fatalf("expected nil decisions with no checker, got %v", decisions)
	}
	if f.Status() != vulnerability.FindingStatusNew {
		t.Fatalf("status = %q, want new (untouched)", f.Status())
	}
}

// A lookup error never fails ingest — suppression is skipped, findings still land.
func TestApplySuppressions_ListError_SkipsGracefully(t *testing.T) {
	tenantID := shared.NewID()
	checker := &stubSuppressionChecker{listErr: errors.New("db down")}
	p := NewFindingProcessor(&stubFindingRepository{}, nil, nil, logger.NewNop())
	p.SetSuppressionChecker(checker)

	f := buildSuppFinding(t, tenantID, shared.NewID(), "semgrep", "sql-injection", "fp-1")
	decisions := p.applySuppressions(context.Background(), tenantID, []*vulnerability.Finding{f})

	if len(decisions) != 0 {
		t.Fatalf("expected no decisions on lookup error, got %d", len(decisions))
	}
	if f.Status() != vulnerability.FindingStatusNew {
		t.Fatalf("status = %q, want new (untouched)", f.Status())
	}
}

// The disposition (resolved + resolution="suppressed") is exactly the sentinel
// the auto-reopen query excludes, so a re-ingested suppressed finding stays
// suppressed. This asserts the domain-level contract the SQL predicate relies on.
func TestApplySuppressions_DispositionSurvivesReopenPredicate(t *testing.T) {
	tenantID := shared.NewID()
	checker := &stubSuppressionChecker{
		rules: []*suppression.Rule{buildRule(tenantID, suppression.RuleStatusApproved, "semgrep", "sql-injection", nil)},
	}
	p := NewFindingProcessor(&stubFindingRepository{}, nil, nil, logger.NewNop())
	p.SetSuppressionChecker(checker)

	f := buildSuppFinding(t, tenantID, shared.NewID(), "semgrep", "sql-injection", "fp-1")
	p.applySuppressions(context.Background(), tenantID, []*vulnerability.Finding{f})

	// AutoReopenByFingerprintsBatch excludes resolution IN
	// ('false_positive','accepted_risk','duplicate','suppressed'). Assert our
	// resolution is that sentinel so re-ingest never reopens a suppressed finding.
	if f.Resolution() != "suppressed" {
		t.Fatalf("resolution = %q, want the auto-reopen-excluded sentinel 'suppressed'", f.Resolution())
	}
}

// recordSuppressions records the finding→rule link only for successfully-created
// findings and returns the count. A finding that failed to persist is not linked.
func TestRecordSuppressions_OnlyForCreated(t *testing.T) {
	tenantID := shared.NewID()
	checker := &stubSuppressionChecker{}
	p := NewFindingProcessor(&stubFindingRepository{}, nil, nil, logger.NewNop())
	p.SetSuppressionChecker(checker)

	f0 := buildSuppFinding(t, tenantID, shared.NewID(), "semgrep", "r0", "fp-0")
	f1 := buildSuppFinding(t, tenantID, shared.NewID(), "semgrep", "r1", "fp-1")
	newFindings := []*vulnerability.Finding{f0, f1}

	rule0 := shared.NewID()
	rule1 := shared.NewID()
	decisions := map[int]shared.ID{0: rule0, 1: rule1}
	// Index 1 failed to persist.
	errorsByIndex := map[int]string{1: "insert failed"}

	n := p.recordSuppressions(context.Background(), newFindings, decisions, errorsByIndex)
	if n != 1 {
		t.Fatalf("recorded %d, want 1 (only the created finding)", n)
	}
	if len(checker.applied) != 1 {
		t.Fatalf("ApplySuppression called %d times, want 1", len(checker.applied))
	}
	if checker.applied[0].findingID != f0.ID() || checker.applied[0].ruleID != rule0 {
		t.Fatal("recorded link does not match the created finding + its rule")
	}
}

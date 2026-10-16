package suppression

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// mockRepository implements Repository for testing
type mockRepository struct {
	rules      map[shared.ID]*Rule
	saveErr    error
	findErr    error
	deleteErr  error
	auditCalls []auditCall
	// matching is what CountMatchingOpenFindings and Approve see: the number
	// of open findings the rule matches.
	matching   int
	applyLimit int
}

type auditCall struct {
	ruleID  shared.ID
	action  string
	userID  *shared.ID
	details map[string]any
}

// reviewedAt is the version an approver saw: the rule's updated_at.
func reviewedAt(r *Rule) *time.Time {
	t := r.UpdatedAt()
	return &t
}

func newMockRepository() *mockRepository {
	return &mockRepository{
		rules: make(map[shared.ID]*Rule),
	}
}

func (m *mockRepository) Save(_ context.Context, rule *Rule) error {
	if m.saveErr != nil {
		return m.saveErr
	}
	m.rules[rule.ID()] = rule
	return nil
}

// SaveWithAudit mirrors the atomic repository method: the rule save and the
// audit record either both take effect or neither does. A save error aborts
// before the audit is recorded.
func (m *mockRepository) SaveWithAudit(_ context.Context, rule *Rule, action string, userID *shared.ID, details map[string]any) error {
	if m.saveErr != nil {
		return m.saveErr
	}
	m.rules[rule.ID()] = rule
	m.auditCalls = append(m.auditCalls, auditCall{rule.ID(), action, userID, details})
	return nil
}

// Approve mirrors the atomic repository method: save, apply (capped at
// limit) and audit with the count.
func (m *mockRepository) Approve(_ context.Context, rule *Rule, _ time.Time, actorID shared.ID, details map[string]any, limit int) (ApplyResult, error) {
	if m.saveErr != nil {
		return ApplyResult{}, m.saveErr
	}
	m.applyLimit = limit
	res := ApplyResult{Applied: min(m.matching, limit), Capped: m.matching > limit}
	m.rules[rule.ID()] = rule
	d := map[string]any{"applied_findings": res.Applied, "capped": res.Capped}
	for k, v := range details {
		d[k] = v
	}
	m.auditCalls = append(m.auditCalls, auditCall{rule.ID(), "approved", &actorID, d})
	return res, nil
}

func (m *mockRepository) CountMatchingOpenFindings(_ context.Context, _ *Rule, limit int) (int, error) {
	return min(m.matching, limit+1), nil
}

func (m *mockRepository) FindByID(_ context.Context, tenantID, ruleID shared.ID) (*Rule, error) {
	if m.findErr != nil {
		return nil, m.findErr
	}
	rule, ok := m.rules[ruleID]
	if !ok || rule.TenantID() != tenantID {
		return nil, nil
	}
	return rule, nil
}

func (m *mockRepository) FindByTenant(_ context.Context, tenantID shared.ID, filter RuleFilter) ([]*Rule, error) {
	var result []*Rule
	for _, rule := range m.rules {
		if rule.TenantID() != tenantID {
			continue
		}
		if filter.Status != nil && rule.Status() != *filter.Status {
			continue
		}
		if filter.ToolName != nil && rule.ToolName() != *filter.ToolName {
			continue
		}
		result = append(result, rule)
	}
	return result, nil
}

func (m *mockRepository) FindActiveByTenant(_ context.Context, tenantID shared.ID) ([]*Rule, error) {
	var result []*Rule
	for _, rule := range m.rules {
		if rule.TenantID() != tenantID {
			continue
		}
		if rule.IsActive() {
			result = append(result, rule)
		}
	}
	return result, nil
}

func (m *mockRepository) FindPendingByTenant(_ context.Context, tenantID shared.ID) ([]*Rule, error) {
	var result []*Rule
	for _, rule := range m.rules {
		if rule.TenantID() != tenantID {
			continue
		}
		if rule.Status() == RuleStatusPending {
			result = append(result, rule)
		}
	}
	return result, nil
}

func (m *mockRepository) Delete(_ context.Context, tenantID, ruleID shared.ID) error {
	if m.deleteErr != nil {
		return m.deleteErr
	}
	delete(m.rules, ruleID)
	return nil
}

func (m *mockRepository) FindMatchingRules(_ context.Context, tenantID shared.ID, match FindingMatch) ([]*Rule, error) {
	var result []*Rule
	for _, rule := range m.rules {
		if rule.TenantID() != tenantID {
			continue
		}
		if rule.Matches(match) {
			result = append(result, rule)
		}
	}
	return result, nil
}

func (m *mockRepository) RecordSuppression(_ context.Context, findingID, ruleID shared.ID, suppressedBy string) error {
	return nil
}

func (m *mockRepository) RecordAudit(_ context.Context, ruleID shared.ID, action string, userID *shared.ID, details map[string]any) error {
	m.auditCalls = append(m.auditCalls, auditCall{ruleID, action, userID, details})
	return nil
}

func (m *mockRepository) ExpireRules(_ context.Context) (int64, error) {
	count := int64(0)
	for _, rule := range m.rules {
		if rule.IsExpired() && rule.Status() == RuleStatusApproved {
			// Would normally update status
			count++
		}
	}
	return count, nil
}

func (m *mockRepository) FindSuppressionsByFinding(_ context.Context, findingID shared.ID) ([]*FindingSuppression, error) {
	return nil, nil
}

func (m *mockRepository) RemoveSuppression(_ context.Context, findingID, ruleID shared.ID) error {
	return nil
}

func TestService_CreateRule(t *testing.T) {
	ctx := context.Background()
	tenantID := shared.NewID()
	userID := shared.NewID()

	t.Run("create valid rule", func(t *testing.T) {
		repo := newMockRepository()
		svc := NewService(repo, nil)

		input := CreateRuleInput{
			TenantID:        tenantID,
			Name:            "Test Rule",
			Description:     "Test description",
			SuppressionType: SuppressionTypeFalsePositive,
			RuleID:          "sql-injection",
			ToolName:        "semgrep",
			RequestedBy:     userID,
		}

		rule, err := svc.CreateRule(ctx, input)
		if err != nil {
			t.Fatalf("CreateRule() error = %v", err)
		}

		if rule.Name() != "Test Rule" {
			t.Errorf("Name = %v, want %v", rule.Name(), "Test Rule")
		}
		if rule.Status() != RuleStatusPending {
			t.Errorf("Status = %v, want %v", rule.Status(), RuleStatusPending)
		}
		if len(repo.auditCalls) != 1 || repo.auditCalls[0].action != "created" {
			t.Error("Expected audit call for 'created'")
		}
	})

	t.Run("create rule with expiry", func(t *testing.T) {
		repo := newMockRepository()
		svc := NewService(repo, nil)

		expiresAt := time.Now().Add(30 * 24 * time.Hour).Format(time.RFC3339)
		input := CreateRuleInput{
			TenantID:        tenantID,
			Name:            "Expiring Rule",
			SuppressionType: SuppressionTypeAcceptedRisk,
			RuleID:          "test-*",
			RequestedBy:     userID,
			ExpiresAt:       &expiresAt,
		}

		rule, err := svc.CreateRule(ctx, input)
		if err != nil {
			t.Fatalf("CreateRule() error = %v", err)
		}

		if rule.ExpiresAt() == nil {
			t.Error("ExpiresAt should be set")
		}
	})

	t.Run("fail on invalid criteria", func(t *testing.T) {
		repo := newMockRepository()
		svc := NewService(repo, nil)

		input := CreateRuleInput{
			TenantID:        tenantID,
			Name:            "Invalid Rule",
			SuppressionType: SuppressionTypeFalsePositive,
			// No criteria set
			RequestedBy: userID,
		}

		_, err := svc.CreateRule(ctx, input)
		if err == nil {
			t.Error("CreateRule() should fail with no criteria")
		}
	})
}

func TestService_ApproveRule(t *testing.T) {
	ctx := context.Background()
	tenantID := shared.NewID()
	userID := shared.NewID()
	approverID := shared.NewID()

	t.Run("approve pending rule", func(t *testing.T) {
		repo := newMockRepository()
		svc := NewService(repo, nil)

		// Create a pending rule
		createInput := CreateRuleInput{
			TenantID:        tenantID,
			Name:            "Test Rule",
			SuppressionType: SuppressionTypeFalsePositive,
			RuleID:          "test-rule",
			RequestedBy:     userID,
		}
		rule, _ := svc.CreateRule(ctx, createInput)

		// Approve it
		approveInput := ApproveRuleInput{
			TenantID:          tenantID,
			RuleID:            rule.ID(),
			ApprovedBy:        approverID,
			ReviewedUpdatedAt: reviewedAt(rule),
		}

		approved, err := svc.ApproveRule(ctx, approveInput)
		if err != nil {
			t.Fatalf("ApproveRule() error = %v", err)
		}

		if approved.Rule.Status() != RuleStatusApproved {
			t.Errorf("Status = %v, want %v", approved.Rule.Status(), RuleStatusApproved)
		}
		if approved.SelfApproved {
			t.Error("an approval by a second person is not a self-approval")
		}
	})

	t.Run("fail on non-existent rule", func(t *testing.T) {
		repo := newMockRepository()
		svc := NewService(repo, nil)

		now := time.Now().UTC()
		input := ApproveRuleInput{
			TenantID:          tenantID,
			RuleID:            shared.NewID(),
			ApprovedBy:        approverID,
			ReviewedUpdatedAt: &now,
		}

		_, err := svc.ApproveRule(ctx, input)
		if err != ErrRuleNotFound {
			t.Errorf("ApproveRule() error = %v, want %v", err, ErrRuleNotFound)
		}
	})
}

func TestService_RejectRule(t *testing.T) {
	ctx := context.Background()
	tenantID := shared.NewID()
	userID := shared.NewID()
	rejecterID := shared.NewID()

	t.Run("reject pending rule", func(t *testing.T) {
		repo := newMockRepository()
		svc := NewService(repo, nil)

		// Create a pending rule
		createInput := CreateRuleInput{
			TenantID:        tenantID,
			Name:            "Test Rule",
			SuppressionType: SuppressionTypeFalsePositive,
			RuleID:          "test-rule",
			RequestedBy:     userID,
		}
		rule, _ := svc.CreateRule(ctx, createInput)

		// Reject it
		rejectInput := RejectRuleInput{
			TenantID:   tenantID,
			RuleID:     rule.ID(),
			RejectedBy: rejecterID,
			Reason:     "Too broad",
		}

		rejected, err := svc.RejectRule(ctx, rejectInput)
		if err != nil {
			t.Fatalf("RejectRule() error = %v", err)
		}

		if rejected.Status() != RuleStatusRejected {
			t.Errorf("Status = %v, want %v", rejected.Status(), RuleStatusRejected)
		}
		if rejected.RejectionReason() != "Too broad" {
			t.Errorf("RejectionReason = %v, want %v", rejected.RejectionReason(), "Too broad")
		}
	})
}

func TestService_UpdateRule(t *testing.T) {
	ctx := context.Background()
	tenantID := shared.NewID()
	userID := shared.NewID()
	approverID := shared.NewID()

	t.Run("update pending rule", func(t *testing.T) {
		repo := newMockRepository()
		svc := NewService(repo, nil)

		// Create a pending rule
		createInput := CreateRuleInput{
			TenantID:        tenantID,
			Name:            "Original Name",
			SuppressionType: SuppressionTypeFalsePositive,
			RuleID:          "test-rule",
			RequestedBy:     userID,
		}
		rule, _ := svc.CreateRule(ctx, createInput)

		// Update it
		newName := "Updated Name"
		updateInput := UpdateRuleInput{
			TenantID:  tenantID,
			RuleID:    rule.ID(),
			Name:      &newName,
			UpdatedBy: userID,
		}

		updated, err := svc.UpdateRule(ctx, updateInput)
		if err != nil {
			t.Fatalf("UpdateRule() error = %v", err)
		}

		if updated.Name() != "Updated Name" {
			t.Errorf("Name = %v, want %v", updated.Name(), "Updated Name")
		}
	})

	t.Run("fail to update approved rule", func(t *testing.T) {
		repo := newMockRepository()
		svc := NewService(repo, nil)

		// Create and approve a rule
		createInput := CreateRuleInput{
			TenantID:        tenantID,
			Name:            "Test Rule",
			SuppressionType: SuppressionTypeFalsePositive,
			RuleID:          "test-rule",
			RequestedBy:     userID,
		}
		rule, _ := svc.CreateRule(ctx, createInput)
		svc.ApproveRule(ctx, ApproveRuleInput{
			TenantID:          tenantID,
			RuleID:            rule.ID(),
			ApprovedBy:        approverID,
			ReviewedUpdatedAt: reviewedAt(rule),
		})

		// Try to update
		newName := "Should Fail"
		updateInput := UpdateRuleInput{
			TenantID:  tenantID,
			RuleID:    rule.ID(),
			Name:      &newName,
			UpdatedBy: userID,
		}

		_, err := svc.UpdateRule(ctx, updateInput)
		if err != ErrRuleNotPending {
			t.Errorf("UpdateRule() error = %v, want %v", err, ErrRuleNotPending)
		}
	})
}

func TestService_ListActiveRules(t *testing.T) {
	ctx := context.Background()
	tenantID := shared.NewID()
	userID := shared.NewID()
	approverID := shared.NewID()

	repo := newMockRepository()
	svc := NewService(repo, nil)

	// Create multiple rules
	for i := 0; i < 3; i++ {
		createInput := CreateRuleInput{
			TenantID:        tenantID,
			Name:            "Test Rule",
			SuppressionType: SuppressionTypeFalsePositive,
			RuleID:          "test-*",
			RequestedBy:     userID,
		}
		rule, _ := svc.CreateRule(ctx, createInput)

		// Approve only first 2
		if i < 2 {
			svc.ApproveRule(ctx, ApproveRuleInput{
				TenantID:          tenantID,
				RuleID:            rule.ID(),
				ApprovedBy:        approverID,
				ReviewedUpdatedAt: reviewedAt(rule),
			})
		}
	}

	active, err := svc.ListActiveRules(ctx, tenantID)
	if err != nil {
		t.Fatalf("ListActiveRules() error = %v", err)
	}

	if len(active) != 2 {
		t.Errorf("ListActiveRules() returned %d rules, want 2", len(active))
	}
}

func TestService_DeleteRule(t *testing.T) {
	ctx := context.Background()
	tenantID := shared.NewID()
	userID := shared.NewID()

	t.Run("delete existing rule", func(t *testing.T) {
		repo := newMockRepository()
		svc := NewService(repo, nil)

		// Create a rule
		createInput := CreateRuleInput{
			TenantID:        tenantID,
			Name:            "Test Rule",
			SuppressionType: SuppressionTypeFalsePositive,
			RuleID:          "test-rule",
			RequestedBy:     userID,
		}
		rule, _ := svc.CreateRule(ctx, createInput)

		// Delete it
		err := svc.DeleteRule(ctx, tenantID, rule.ID(), userID)
		if err != nil {
			t.Fatalf("DeleteRule() error = %v", err)
		}

		// Verify it's gone
		_, err = svc.GetRule(ctx, tenantID, rule.ID())
		if err != ErrRuleNotFound {
			t.Errorf("GetRule() after delete should return ErrRuleNotFound")
		}
	})

	t.Run("fail on non-existent rule", func(t *testing.T) {
		repo := newMockRepository()
		svc := NewService(repo, nil)

		err := svc.DeleteRule(ctx, tenantID, shared.NewID(), userID)
		if err != ErrRuleNotFound {
			t.Errorf("DeleteRule() error = %v, want %v", err, ErrRuleNotFound)
		}
	})
}

type fakeApprovers struct {
	count int
	owner shared.ID
}

func (f fakeApprovers) CountEligibleApprovers(context.Context, shared.ID) (int, error) {
	return f.count, nil
}

func (f fakeApprovers) IsTenantOwner(_ context.Context, _ shared.ID, user shared.ID) (bool, error) {
	return user == f.owner, nil
}

// Owner decision B16: the requester may not approve their own rule while a
// second person could; a lone owner may, and the approval says so.
func TestService_ApproveRule_FourEyes(t *testing.T) {
	ctx := context.Background()
	tenantID := shared.NewID()
	requester := shared.NewID()

	newPending := func(svc *Service) *Rule {
		t.Helper()
		rule, err := svc.CreateRule(ctx, CreateRuleInput{
			TenantID: tenantID, Name: "r", SuppressionType: SuppressionTypeFalsePositive,
			RuleID: "x", RequestedBy: requester,
		})
		if err != nil {
			t.Fatal(err)
		}
		return rule
	}
	approveOwn := func(svc *Service, rule *Rule) (*ApproveResult, error) {
		return svc.ApproveRule(ctx, ApproveRuleInput{
			TenantID: tenantID, RuleID: rule.ID(), ApprovedBy: requester, ReviewedUpdatedAt: reviewedAt(rule),
		})
	}

	t.Run("refused when two people can approve", func(t *testing.T) {
		svc := NewService(newMockRepository(), nil)
		svc.SetApproverDirectory(fakeApprovers{count: 2, owner: requester})
		if _, err := approveOwn(svc, newPending(svc)); !errors.Is(err, ErrSelfApproval) || !errors.Is(err, shared.ErrForbidden) {
			t.Fatalf("self-approval with a second approver = %v, want ErrSelfApproval (forbidden)", err)
		}
	})
	t.Run("lone owner without reason or fresh code is refused", func(t *testing.T) {
		svc := NewService(newMockRepository(), nil)
		svc.SetApproverDirectory(fakeApprovers{count: 1, owner: requester})
		svc.SetTOTPVerifier(fakeTOTP{good: "123456"})
		rule := newPending(svc)
		if _, err := approveOwn(svc, rule); !errors.Is(err, ErrSelfApprovalNeedsReason) {
			t.Fatalf("no reason = %v, want ErrSelfApprovalNeedsReason", err)
		}
		for _, code := range []string{"", "000000"} {
			_, err := svc.ApproveRule(ctx, ApproveRuleInput{TenantID: tenantID, RuleID: rule.ID(), ApprovedBy: requester,
				ReviewedUpdatedAt: reviewedAt(rule), SelfApprovalReason: "alone", TOTPCode: code})
			if !errors.Is(err, ErrSelfApprovalBadCode) || !IsSelfApprovalRefusal(err) {
				t.Fatalf("code %q = %v, want ErrSelfApprovalBadCode", code, err)
			}
		}
		if rule.Status() != RuleStatusPending {
			t.Fatalf("refused self-approval changed the rule: %s", rule.Status())
		}
	})
	t.Run("lone owner without a verifier fails closed", func(t *testing.T) {
		svc := NewService(newMockRepository(), nil)
		svc.SetApproverDirectory(fakeApprovers{count: 1, owner: requester})
		rule := newPending(svc)
		if _, err := svc.ApproveRule(ctx, ApproveRuleInput{TenantID: tenantID, RuleID: rule.ID(), ApprovedBy: requester,
			ReviewedUpdatedAt: reviewedAt(rule), SelfApprovalReason: "alone", TOTPCode: "123456"}); !errors.Is(err, ErrSelfApprovalBadCode) {
			t.Fatalf("no verifier = %v, want ErrSelfApprovalBadCode", err)
		}
	})
	t.Run("lone owner may approve with reason and fresh code, flagged", func(t *testing.T) {
		repo := newMockRepository()
		svc := NewService(repo, nil)
		svc.SetApproverDirectory(fakeApprovers{count: 1, owner: requester})
		svc.SetTOTPVerifier(fakeTOTP{good: "123456"})
		rule := newPending(svc)
		res, err := svc.ApproveRule(ctx, ApproveRuleInput{TenantID: tenantID, RuleID: rule.ID(), ApprovedBy: requester,
			ReviewedUpdatedAt: reviewedAt(rule), SelfApprovalReason: "only member", TOTPCode: "123456"})
		if err != nil {
			t.Fatalf("lone owner self-approval: %v", err)
		}
		if !res.SelfApproved || res.Rule.Status() != RuleStatusApproved {
			t.Fatalf("result = %+v, want approved and SelfApproved", res)
		}
		last := repo.auditCalls[len(repo.auditCalls)-1]
		if last.details["self_approved"] != true {
			t.Fatalf("rule audit details = %v, want self_approved", last.details)
		}
	})
	t.Run("lone non-owner may not", func(t *testing.T) {
		svc := NewService(newMockRepository(), nil)
		svc.SetApproverDirectory(fakeApprovers{count: 1, owner: shared.NewID()})
		if _, err := approveOwn(svc, newPending(svc)); !errors.Is(err, ErrSelfApproval) {
			t.Fatalf("lone non-owner self-approval = %v, want ErrSelfApproval", err)
		}
	})
	t.Run("no directory wired fails closed", func(t *testing.T) {
		svc := NewService(newMockRepository(), nil)
		if _, err := approveOwn(svc, newPending(svc)); !errors.Is(err, ErrSelfApproval) {
			t.Fatalf("self-approval without a directory = %v, want ErrSelfApproval", err)
		}
	})
}

// fakeTOTP accepts one code.
type fakeTOTP struct{ good string }

func (f fakeTOTP) VerifyFreshTOTP(_ context.Context, _, code string) error {
	if code != f.good {
		return ErrSelfApprovalBadCode
	}
	return nil
}

// The approval pins the version the approver reviewed.
func TestService_ApproveRule_PinsReviewedVersion(t *testing.T) {
	ctx := context.Background()
	tenantID := shared.NewID()
	svc := NewService(newMockRepository(), nil)
	rule, err := svc.CreateRule(ctx, CreateRuleInput{
		TenantID: tenantID, Name: "r", SuppressionType: SuppressionTypeFalsePositive,
		RuleID: "narrow.rule", RequestedBy: shared.NewID(),
	})
	if err != nil {
		t.Fatal(err)
	}
	seen := rule.UpdatedAt()

	if _, err := svc.ApproveRule(ctx, ApproveRuleInput{TenantID: tenantID, RuleID: rule.ID(), ApprovedBy: shared.NewID()}); !errors.Is(err, ErrReviewedVersionRequired) {
		t.Fatalf("approve without a reviewed version = %v, want ErrReviewedVersionRequired", err)
	}

	// The requester broadens the pending rule after the approver loaded it.
	time.Sleep(time.Millisecond)
	broader := "*"
	if _, err := svc.UpdateRule(ctx, UpdateRuleInput{TenantID: tenantID, RuleID: rule.ID(), RuleIDPat: &broader, UpdatedBy: rule.RequestedBy()}); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.ApproveRule(ctx, ApproveRuleInput{
		TenantID: tenantID, RuleID: rule.ID(), ApprovedBy: shared.NewID(), ReviewedUpdatedAt: &seen,
	}); !errors.Is(err, ErrRuleChangedSinceReview) {
		t.Fatalf("approve a changed rule = %v, want ErrRuleChangedSinceReview", err)
	}
}

// Approving a rule closes the open findings it matches (research 134
// decision 2): the result and the rule's audit entry carry the count, capped
// at MaxFindingsAppliedOnApprove.
func TestService_ApproveRule_AppliesToExistingFindings(t *testing.T) {
	ctx := context.Background()
	tenantID := shared.NewID()
	newPending := func(svc *Service) *Rule {
		rule, err := svc.CreateRule(ctx, CreateRuleInput{
			TenantID: tenantID, Name: "r", SuppressionType: SuppressionTypeFalsePositive,
			RuleID: "semgrep.sqli", RequestedBy: shared.NewID(),
		})
		if err != nil {
			t.Fatal(err)
		}
		return rule
	}

	t.Run("count in result and audit", func(t *testing.T) {
		repo := newMockRepository()
		repo.matching = 7
		svc := NewService(repo, nil)
		rule := newPending(svc)
		res, err := svc.ApproveRule(ctx, ApproveRuleInput{TenantID: tenantID, RuleID: rule.ID(), ApprovedBy: shared.NewID(), ReviewedUpdatedAt: reviewedAt(rule)})
		if err != nil {
			t.Fatal(err)
		}
		if res.AppliedFindings != 7 || res.Capped {
			t.Fatalf("result = %+v, want 7 applied, not capped", res)
		}
		last := repo.auditCalls[len(repo.auditCalls)-1]
		if last.action != "approved" || last.details["applied_findings"] != 7 {
			t.Fatalf("audit = %+v, want approved with applied_findings 7", last)
		}
		if repo.applyLimit != MaxFindingsAppliedOnApprove {
			t.Fatalf("limit = %d, want %d", repo.applyLimit, MaxFindingsAppliedOnApprove)
		}
	})

	t.Run("capped", func(t *testing.T) {
		repo := newMockRepository()
		repo.matching = MaxFindingsAppliedOnApprove + 5
		svc := NewService(repo, nil)
		rule := newPending(svc)
		res, err := svc.ApproveRule(ctx, ApproveRuleInput{TenantID: tenantID, RuleID: rule.ID(), ApprovedBy: shared.NewID(), ReviewedUpdatedAt: reviewedAt(rule)})
		if err != nil {
			t.Fatal(err)
		}
		if res.AppliedFindings != MaxFindingsAppliedOnApprove || !res.Capped {
			t.Fatalf("result = %+v, want capped at %d", res, MaxFindingsAppliedOnApprove)
		}
	})

	t.Run("preview", func(t *testing.T) {
		repo := newMockRepository()
		svc := NewService(repo, nil)
		rule := newPending(svc)
		repo.matching = 3
		p, err := svc.PreviewRule(ctx, tenantID, rule.ID())
		if err != nil || p.MatchingOpenFindings != 3 || p.Capped || p.Limit != MaxFindingsAppliedOnApprove {
			t.Fatalf("preview = %+v, %v; want 3 not capped", p, err)
		}
		repo.matching = MaxFindingsAppliedOnApprove * 3
		p, err = svc.PreviewRule(ctx, tenantID, rule.ID())
		if err != nil || p.MatchingOpenFindings != MaxFindingsAppliedOnApprove || !p.Capped {
			t.Fatalf("preview = %+v, %v; want capped", p, err)
		}
		if _, err := svc.PreviewRule(ctx, shared.NewID(), rule.ID()); !errors.Is(err, ErrRuleNotFound) {
			t.Fatalf("other tenant preview err = %v, want ErrRuleNotFound", err)
		}
	})
}

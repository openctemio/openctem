package suppression

import (
	"context"
	"testing"
	"time"

	"github.com/openctemio/api/pkg/domain/shared"
)

// mockRepository implements Repository for testing
type mockRepository struct {
	rules      map[shared.ID]*Rule
	saveErr    error
	findErr    error
	deleteErr  error
	auditCalls []auditCall
}

type auditCall struct {
	ruleID  shared.ID
	action  string
	userID  *shared.ID
	details map[string]any
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
			TenantID:   tenantID,
			RuleID:     rule.ID(),
			ApprovedBy: approverID,
		}

		approved, err := svc.ApproveRule(ctx, approveInput)
		if err != nil {
			t.Fatalf("ApproveRule() error = %v", err)
		}

		if approved.Status() != RuleStatusApproved {
			t.Errorf("Status = %v, want %v", approved.Status(), RuleStatusApproved)
		}
	})

	t.Run("fail on non-existent rule", func(t *testing.T) {
		repo := newMockRepository()
		svc := NewService(repo, nil)

		input := ApproveRuleInput{
			TenantID:   tenantID,
			RuleID:     shared.NewID(),
			ApprovedBy: approverID,
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
			TenantID:   tenantID,
			RuleID:     rule.ID(),
			ApprovedBy: approverID,
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
				TenantID:   tenantID,
				RuleID:     rule.ID(),
				ApprovedBy: approverID,
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

package unit

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/openctemio/api/internal/infra/http/handler"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/domain/suppression"
	"github.com/openctemio/api/pkg/logger"
)

// MockSuppressionRepository implements suppression.Repository for handler tests.
type MockSuppressionRepository struct {
	rules map[shared.ID]*suppression.Rule
}

func NewMockSuppressionRepository() *MockSuppressionRepository {
	return &MockSuppressionRepository{
		rules: make(map[shared.ID]*suppression.Rule),
	}
}

func (m *MockSuppressionRepository) Save(_ context.Context, rule *suppression.Rule) error {
	m.rules[rule.ID()] = rule
	return nil
}

func (m *MockSuppressionRepository) FindByID(_ context.Context, tenantID, ruleID shared.ID) (*suppression.Rule, error) {
	rule, ok := m.rules[ruleID]
	if !ok || rule.TenantID() != tenantID {
		return nil, nil
	}
	return rule, nil
}

func (m *MockSuppressionRepository) Delete(_ context.Context, tenantID, ruleID shared.ID) error {
	delete(m.rules, ruleID)
	return nil
}

func (m *MockSuppressionRepository) FindByTenant(_ context.Context, tenantID shared.ID, filter suppression.RuleFilter) ([]*suppression.Rule, error) {
	var result []*suppression.Rule
	for _, rule := range m.rules {
		if rule.TenantID() != tenantID {
			continue
		}
		if filter.Status != nil && rule.Status() != *filter.Status {
			continue
		}
		result = append(result, rule)
	}
	return result, nil
}

func (m *MockSuppressionRepository) FindActiveByTenant(_ context.Context, tenantID shared.ID) ([]*suppression.Rule, error) {
	var result []*suppression.Rule
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

func (m *MockSuppressionRepository) FindPendingByTenant(_ context.Context, tenantID shared.ID) ([]*suppression.Rule, error) {
	var result []*suppression.Rule
	for _, rule := range m.rules {
		if rule.TenantID() != tenantID {
			continue
		}
		if rule.Status() == suppression.RuleStatusPending {
			result = append(result, rule)
		}
	}
	return result, nil
}

func (m *MockSuppressionRepository) FindMatchingRules(_ context.Context, tenantID shared.ID, match suppression.FindingMatch) ([]*suppression.Rule, error) {
	return nil, nil
}

func (m *MockSuppressionRepository) ExpireRules(_ context.Context) (int64, error) {
	return 0, nil
}

func (m *MockSuppressionRepository) RecordSuppression(_ context.Context, findingID, ruleID shared.ID, appliedBy string) error {
	return nil
}

func (m *MockSuppressionRepository) FindSuppressionsByFinding(_ context.Context, findingID shared.ID) ([]*suppression.FindingSuppression, error) {
	return nil, nil
}

func (m *MockSuppressionRepository) RemoveSuppression(_ context.Context, findingID, ruleID shared.ID) error {
	return nil
}

func (m *MockSuppressionRepository) RecordAudit(_ context.Context, ruleID shared.ID, action string, userID *shared.ID, details map[string]any) error {
	return nil
}

// withSuppressionContext adds tenant and user context for suppression handler tests.
func withSuppressionContext(req *http.Request, tenantID, userID shared.ID) *http.Request {
	ctx := req.Context()
	ctx = context.WithValue(ctx, logger.ContextKey("tenant_id"), tenantID.String())
	ctx = context.WithValue(ctx, logger.ContextKey("user_id"), userID.String())
	return req.WithContext(ctx)
}

func TestSuppressionHandler_CreateRule(t *testing.T) {
	tenantID := shared.NewID()
	userID := shared.NewID()

	repo := NewMockSuppressionRepository()
	svc := suppression.NewService(repo, nil)
	log := logger.NewNop()
	h := handler.NewSuppressionHandler(svc, log)

	t.Run("create valid rule", func(t *testing.T) {
		body := `{
			"name": "Test Rule",
			"description": "Test description",
			"suppression_type": "false_positive",
			"rule_id": "sql-injection",
			"tool_name": "semgrep"
		}`

		req := httptest.NewRequest(http.MethodPost, "/api/v1/suppressions", bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")
		req = withSuppressionContext(req, tenantID, userID)

		rr := httptest.NewRecorder()
		h.CreateRule(rr, req)

		if rr.Code != http.StatusCreated {
			t.Errorf("CreateRule() status = %d, want %d", rr.Code, http.StatusCreated)
			t.Logf("Response: %s", rr.Body.String())
		}

		var resp map[string]any
		if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
			t.Fatalf("Failed to parse response: %v", err)
		}

		if resp["status"] != "pending" {
			t.Errorf("status = %v, want 'pending'", resp["status"])
		}
		if resp["name"] != "Test Rule" {
			t.Errorf("name = %v, want 'Test Rule'", resp["name"])
		}
	})

	t.Run("invalid request body", func(t *testing.T) {
		body := `invalid json`

		req := httptest.NewRequest(http.MethodPost, "/api/v1/suppressions", bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")
		req = withSuppressionContext(req, tenantID, userID)

		rr := httptest.NewRecorder()
		h.CreateRule(rr, req)

		if rr.Code != http.StatusBadRequest {
			t.Errorf("CreateRule() status = %d, want %d", rr.Code, http.StatusBadRequest)
		}
	})

	t.Run("missing criteria", func(t *testing.T) {
		body := `{
			"name": "Test Rule",
			"suppression_type": "false_positive"
		}`

		req := httptest.NewRequest(http.MethodPost, "/api/v1/suppressions", bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")
		req = withSuppressionContext(req, tenantID, userID)

		rr := httptest.NewRecorder()
		h.CreateRule(rr, req)

		if rr.Code != http.StatusBadRequest {
			t.Errorf("CreateRule() status = %d, want %d (missing criteria)", rr.Code, http.StatusBadRequest)
		}
	})
}

func TestSuppressionHandler_ListRules(t *testing.T) {
	tenantID := shared.NewID()
	userID := shared.NewID()

	repo := NewMockSuppressionRepository()
	svc := suppression.NewService(repo, nil)
	log := logger.NewNop()
	h := handler.NewSuppressionHandler(svc, log)

	// Create some rules
	for i := 0; i < 3; i++ {
		input := suppression.CreateRuleInput{
			TenantID:        tenantID,
			Name:            "Test Rule",
			SuppressionType: suppression.SuppressionTypeFalsePositive,
			RuleID:          "test-*",
			RequestedBy:     userID,
		}
		svc.CreateRule(context.Background(), input)
	}

	t.Run("list all rules", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/suppressions", nil)
		req = withSuppressionContext(req, tenantID, userID)

		rr := httptest.NewRecorder()
		h.ListRules(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("ListRules() status = %d, want %d", rr.Code, http.StatusOK)
		}

		var resp map[string]any
		if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
			t.Fatalf("Failed to parse response: %v", err)
		}

		total, ok := resp["total"].(float64)
		if !ok || int(total) != 3 {
			t.Errorf("total = %v, want 3", resp["total"])
		}
	})
}

func TestSuppressionHandler_ApproveRule(t *testing.T) {
	tenantID := shared.NewID()
	userID := shared.NewID()

	repo := NewMockSuppressionRepository()
	svc := suppression.NewService(repo, nil)
	log := logger.NewNop()
	h := handler.NewSuppressionHandler(svc, log)

	// Create a rule
	input := suppression.CreateRuleInput{
		TenantID:        tenantID,
		Name:            "Test Rule",
		SuppressionType: suppression.SuppressionTypeFalsePositive,
		RuleID:          "test-rule",
		RequestedBy:     userID,
	}
	rule, _ := svc.CreateRule(context.Background(), input)

	t.Run("approve pending rule", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/suppressions/"+rule.ID().String()+"/approve", bytes.NewBufferString("{}"))
		req.Header.Set("Content-Type", "application/json")
		req.SetPathValue("id", rule.ID().String())
		req = withSuppressionContext(req, tenantID, userID)

		rr := httptest.NewRecorder()
		h.ApproveRule(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("ApproveRule() status = %d, want %d", rr.Code, http.StatusOK)
			t.Logf("Response: %s", rr.Body.String())
		}

		var resp map[string]any
		if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
			t.Fatalf("Failed to parse response: %v", err)
		}

		if resp["status"] != "approved" {
			t.Errorf("status = %v, want 'approved'", resp["status"])
		}
	})

	t.Run("approve non-existent rule", func(t *testing.T) {
		fakeID := shared.NewID()
		req := httptest.NewRequest(http.MethodPost, "/api/v1/suppressions/"+fakeID.String()+"/approve", bytes.NewBufferString("{}"))
		req.Header.Set("Content-Type", "application/json")
		req.SetPathValue("id", fakeID.String())
		req = withSuppressionContext(req, tenantID, userID)

		rr := httptest.NewRecorder()
		h.ApproveRule(rr, req)

		if rr.Code != http.StatusNotFound {
			t.Errorf("ApproveRule() status = %d, want %d", rr.Code, http.StatusNotFound)
		}
	})
}

func TestSuppressionHandler_RejectRule(t *testing.T) {
	tenantID := shared.NewID()
	userID := shared.NewID()

	repo := NewMockSuppressionRepository()
	svc := suppression.NewService(repo, nil)
	log := logger.NewNop()
	h := handler.NewSuppressionHandler(svc, log)

	// Create a rule
	input := suppression.CreateRuleInput{
		TenantID:        tenantID,
		Name:            "Test Rule",
		SuppressionType: suppression.SuppressionTypeFalsePositive,
		RuleID:          "test-rule",
		RequestedBy:     userID,
	}
	rule, _ := svc.CreateRule(context.Background(), input)

	t.Run("reject pending rule", func(t *testing.T) {
		body := `{"reason": "Too broad"}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/suppressions/"+rule.ID().String()+"/reject", bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")
		req.SetPathValue("id", rule.ID().String())
		req = withSuppressionContext(req, tenantID, userID)

		rr := httptest.NewRecorder()
		h.RejectRule(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("RejectRule() status = %d, want %d", rr.Code, http.StatusOK)
			t.Logf("Response: %s", rr.Body.String())
		}

		var resp map[string]any
		if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
			t.Fatalf("Failed to parse response: %v", err)
		}

		if resp["status"] != "rejected" {
			t.Errorf("status = %v, want 'rejected'", resp["status"])
		}
		if resp["rejection_reason"] != "Too broad" {
			t.Errorf("rejection_reason = %v, want 'Too broad'", resp["rejection_reason"])
		}
	})
}

func TestSuppressionHandler_UpdateRule(t *testing.T) {
	tenantID := shared.NewID()
	userID := shared.NewID()

	repo := NewMockSuppressionRepository()
	svc := suppression.NewService(repo, nil)
	log := logger.NewNop()
	h := handler.NewSuppressionHandler(svc, log)

	// Create a rule
	input := suppression.CreateRuleInput{
		TenantID:        tenantID,
		Name:            "Original Name",
		SuppressionType: suppression.SuppressionTypeFalsePositive,
		RuleID:          "test-rule",
		RequestedBy:     userID,
	}
	rule, _ := svc.CreateRule(context.Background(), input)

	t.Run("update pending rule", func(t *testing.T) {
		body := `{"name": "Updated Name", "description": "New description"}`
		req := httptest.NewRequest(http.MethodPut, "/api/v1/suppressions/"+rule.ID().String(), bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")
		req.SetPathValue("id", rule.ID().String())
		req = withSuppressionContext(req, tenantID, userID)

		rr := httptest.NewRecorder()
		h.UpdateRule(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("UpdateRule() status = %d, want %d", rr.Code, http.StatusOK)
			t.Logf("Response: %s", rr.Body.String())
		}

		var resp map[string]any
		if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
			t.Fatalf("Failed to parse response: %v", err)
		}

		if resp["name"] != "Updated Name" {
			t.Errorf("name = %v, want 'Updated Name'", resp["name"])
		}
	})

	t.Run("update approved rule fails", func(t *testing.T) {
		// First approve the rule
		approveReq := httptest.NewRequest(http.MethodPost, "/api/v1/suppressions/"+rule.ID().String()+"/approve", bytes.NewBufferString("{}"))
		approveReq.Header.Set("Content-Type", "application/json")
		approveReq.SetPathValue("id", rule.ID().String())
		approveReq = withSuppressionContext(approveReq, tenantID, userID)
		h.ApproveRule(httptest.NewRecorder(), approveReq)

		// Now try to update
		body := `{"name": "Should Fail"}`
		req := httptest.NewRequest(http.MethodPut, "/api/v1/suppressions/"+rule.ID().String(), bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")
		req.SetPathValue("id", rule.ID().String())
		req = withSuppressionContext(req, tenantID, userID)

		rr := httptest.NewRecorder()
		h.UpdateRule(rr, req)

		if rr.Code != http.StatusBadRequest {
			t.Errorf("UpdateRule() on approved status = %d, want %d", rr.Code, http.StatusBadRequest)
		}
	})
}

func TestSuppressionHandler_DeleteRule(t *testing.T) {
	tenantID := shared.NewID()
	userID := shared.NewID()

	repo := NewMockSuppressionRepository()
	svc := suppression.NewService(repo, nil)
	log := logger.NewNop()
	h := handler.NewSuppressionHandler(svc, log)

	// Create a rule
	input := suppression.CreateRuleInput{
		TenantID:        tenantID,
		Name:            "Test Rule",
		SuppressionType: suppression.SuppressionTypeFalsePositive,
		RuleID:          "test-rule",
		RequestedBy:     userID,
	}
	rule, _ := svc.CreateRule(context.Background(), input)

	t.Run("delete existing rule", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodDelete, "/api/v1/suppressions/"+rule.ID().String(), nil)
		req.SetPathValue("id", rule.ID().String())
		req = withSuppressionContext(req, tenantID, userID)

		rr := httptest.NewRecorder()
		h.DeleteRule(rr, req)

		if rr.Code != http.StatusNoContent {
			t.Errorf("DeleteRule() status = %d, want %d", rr.Code, http.StatusNoContent)
		}
	})

	t.Run("delete non-existent rule", func(t *testing.T) {
		fakeID := shared.NewID()
		req := httptest.NewRequest(http.MethodDelete, "/api/v1/suppressions/"+fakeID.String(), nil)
		req.SetPathValue("id", fakeID.String())
		req = withSuppressionContext(req, tenantID, userID)

		rr := httptest.NewRecorder()
		h.DeleteRule(rr, req)

		if rr.Code != http.StatusNotFound {
			t.Errorf("DeleteRule() status = %d, want %d", rr.Code, http.StatusNotFound)
		}
	})
}

func TestSuppressionHandler_ListActiveRules(t *testing.T) {
	tenantID := shared.NewID()
	userID := shared.NewID()

	repo := NewMockSuppressionRepository()
	svc := suppression.NewService(repo, nil)
	log := logger.NewNop()
	h := handler.NewSuppressionHandler(svc, log)

	// Create rules and approve some
	for i := 0; i < 3; i++ {
		input := suppression.CreateRuleInput{
			TenantID:        tenantID,
			Name:            "Test Rule",
			SuppressionType: suppression.SuppressionTypeFalsePositive,
			RuleID:          "test-*",
			RequestedBy:     userID,
		}
		rule, _ := svc.CreateRule(context.Background(), input)

		// Approve only first 2
		if i < 2 {
			svc.ApproveRule(context.Background(), suppression.ApproveRuleInput{
				TenantID:   tenantID,
				RuleID:     rule.ID(),
				ApprovedBy: userID,
			})
		}
	}

	t.Run("list active rules", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/suppressions/active", nil)
		req = withSuppressionContext(req, tenantID, userID)

		rr := httptest.NewRecorder()
		h.ListActiveRules(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("ListActiveRules() status = %d, want %d", rr.Code, http.StatusOK)
		}

		var resp map[string]any
		if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
			t.Fatalf("Failed to parse response: %v", err)
		}

		count, ok := resp["count"].(float64)
		if !ok || int(count) != 2 {
			t.Errorf("count = %v, want 2", resp["count"])
		}
	})
}

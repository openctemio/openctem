package suppression

import (
	"testing"
	"time"

	"github.com/openctemio/api/pkg/domain/shared"
)

func TestNewRule(t *testing.T) {
	tenantID := shared.NewID()
	userID := shared.NewID()

	tests := []struct {
		name            string
		tenantID        shared.ID
		ruleName        string
		suppressionType SuppressionType
		requestedBy     shared.ID
		wantErr         bool
	}{
		{
			name:            "valid rule",
			tenantID:        tenantID,
			ruleName:        "Test Rule",
			suppressionType: SuppressionTypeFalsePositive,
			requestedBy:     userID,
			wantErr:         false,
		},
		{
			name:            "zero tenant ID",
			tenantID:        shared.ID{},
			ruleName:        "Test Rule",
			suppressionType: SuppressionTypeFalsePositive,
			requestedBy:     userID,
			wantErr:         true,
		},
		{
			name:            "empty name",
			tenantID:        tenantID,
			ruleName:        "",
			suppressionType: SuppressionTypeFalsePositive,
			requestedBy:     userID,
			wantErr:         true,
		},
		{
			name:            "invalid suppression type",
			tenantID:        tenantID,
			ruleName:        "Test Rule",
			suppressionType: SuppressionType("invalid"),
			requestedBy:     userID,
			wantErr:         true,
		},
		{
			name:            "zero requestedBy",
			tenantID:        tenantID,
			ruleName:        "Test Rule",
			suppressionType: SuppressionTypeFalsePositive,
			requestedBy:     shared.ID{},
			wantErr:         true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule, err := NewRule(tt.tenantID, tt.ruleName, tt.suppressionType, tt.requestedBy)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewRule() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && rule == nil {
				t.Error("NewRule() returned nil rule without error")
			}
			if !tt.wantErr {
				if rule.Status() != RuleStatusPending {
					t.Errorf("NewRule() status = %v, want %v", rule.Status(), RuleStatusPending)
				}
			}
		})
	}
}

func TestRule_Approve(t *testing.T) {
	tenantID := shared.NewID()
	userID := shared.NewID()
	approverID := shared.NewID()

	t.Run("approve pending rule", func(t *testing.T) {
		rule, _ := NewRule(tenantID, "Test Rule", SuppressionTypeFalsePositive, userID)

		err := rule.Approve(approverID)
		if err != nil {
			t.Fatalf("Approve() unexpected error: %v", err)
		}

		if rule.Status() != RuleStatusApproved {
			t.Errorf("Status = %v, want %v", rule.Status(), RuleStatusApproved)
		}
		if rule.ApprovedBy() == nil || *rule.ApprovedBy() != approverID {
			t.Error("ApprovedBy not set correctly")
		}
		if rule.ApprovedAt() == nil {
			t.Error("ApprovedAt should be set")
		}
	})

	t.Run("cannot approve already approved", func(t *testing.T) {
		rule, _ := NewRule(tenantID, "Test Rule", SuppressionTypeFalsePositive, userID)
		_ = rule.Approve(approverID)

		err := rule.Approve(approverID)
		if err == nil {
			t.Error("Approve() should fail for already approved rule")
		}
	})

	t.Run("cannot approve rejected rule", func(t *testing.T) {
		rule, _ := NewRule(tenantID, "Test Rule", SuppressionTypeFalsePositive, userID)
		_ = rule.Reject(approverID, "test reason")

		err := rule.Approve(approverID)
		if err == nil {
			t.Error("Approve() should fail for rejected rule")
		}
	})
}

func TestRule_Reject(t *testing.T) {
	tenantID := shared.NewID()
	userID := shared.NewID()
	rejecterID := shared.NewID()

	t.Run("reject pending rule", func(t *testing.T) {
		rule, _ := NewRule(tenantID, "Test Rule", SuppressionTypeFalsePositive, userID)

		err := rule.Reject(rejecterID, "This is too broad")
		if err != nil {
			t.Fatalf("Reject() unexpected error: %v", err)
		}

		if rule.Status() != RuleStatusRejected {
			t.Errorf("Status = %v, want %v", rule.Status(), RuleStatusRejected)
		}
		if rule.RejectedBy() == nil || *rule.RejectedBy() != rejecterID {
			t.Error("RejectedBy not set correctly")
		}
		if rule.RejectedAt() == nil {
			t.Error("RejectedAt should be set")
		}
		if rule.RejectionReason() != "This is too broad" {
			t.Errorf("RejectionReason = %q, want %q", rule.RejectionReason(), "This is too broad")
		}
	})

	t.Run("cannot reject approved rule", func(t *testing.T) {
		rule, _ := NewRule(tenantID, "Test Rule", SuppressionTypeFalsePositive, userID)
		_ = rule.Approve(rejecterID)

		err := rule.Reject(rejecterID, "reason")
		if err == nil {
			t.Error("Reject() should fail for approved rule")
		}
	})
}

func TestRule_Validate(t *testing.T) {
	tenantID := shared.NewID()
	userID := shared.NewID()

	t.Run("valid with rule_id", func(t *testing.T) {
		rule, _ := NewRule(tenantID, "Test", SuppressionTypeFalsePositive, userID)
		rule.SetRuleIDPattern("semgrep.sql-injection")

		if err := rule.Validate(); err != nil {
			t.Errorf("Validate() unexpected error: %v", err)
		}
	})

	t.Run("valid with tool_name and rule_id", func(t *testing.T) {
		rule, _ := NewRule(tenantID, "Test", SuppressionTypeFalsePositive, userID)
		rule.SetToolName("semgrep")
		rule.SetRuleIDPattern("sql-*") // tool_name alone is not enough, need rule_id or path

		if err := rule.Validate(); err != nil {
			t.Errorf("Validate() unexpected error: %v", err)
		}
	})

	t.Run("valid with path_pattern", func(t *testing.T) {
		rule, _ := NewRule(tenantID, "Test", SuppressionTypeFalsePositive, userID)
		rule.SetPathPattern("tests/**")

		if err := rule.Validate(); err != nil {
			t.Errorf("Validate() unexpected error: %v", err)
		}
	})

	t.Run("invalid - no criteria", func(t *testing.T) {
		rule, _ := NewRule(tenantID, "Test", SuppressionTypeFalsePositive, userID)
		// No criteria set

		if err := rule.Validate(); err == nil {
			t.Error("Validate() should fail when no criteria set")
		}
	})
}

func TestRule_IsExpired(t *testing.T) {
	tenantID := shared.NewID()
	userID := shared.NewID()

	t.Run("not expired - no expiry", func(t *testing.T) {
		rule, _ := NewRule(tenantID, "Test", SuppressionTypeFalsePositive, userID)

		if rule.IsExpired() {
			t.Error("Rule without expiry should not be expired")
		}
	})

	t.Run("not expired - future expiry", func(t *testing.T) {
		rule, _ := NewRule(tenantID, "Test", SuppressionTypeFalsePositive, userID)
		future := time.Now().Add(24 * time.Hour)
		rule.SetExpiresAt(&future)

		if rule.IsExpired() {
			t.Error("Rule with future expiry should not be expired")
		}
	})

	t.Run("expired - past expiry", func(t *testing.T) {
		rule, _ := NewRule(tenantID, "Test", SuppressionTypeFalsePositive, userID)
		past := time.Now().Add(-24 * time.Hour)
		rule.SetExpiresAt(&past)

		if !rule.IsExpired() {
			t.Error("Rule with past expiry should be expired")
		}
	})
}

func TestRule_Matches(t *testing.T) {
	tenantID := shared.NewID()
	userID := shared.NewID()
	approverID := shared.NewID()

	tests := []struct {
		name        string
		ruleID      string
		toolName    string
		pathPattern string
		match       FindingMatch
		want        bool
	}{
		{
			name:   "exact rule ID match",
			ruleID: "sql-injection",
			match:  FindingMatch{RuleID: "sql-injection"},
			want:   true,
		},
		{
			name:   "rule ID no match",
			ruleID: "sql-injection",
			match:  FindingMatch{RuleID: "xss"},
			want:   false,
		},
		{
			name:   "wildcard rule ID match",
			ruleID: "semgrep.*",
			match:  FindingMatch{RuleID: "semgrep.sql-injection"},
			want:   true,
		},
		{
			name:   "wildcard rule ID no match",
			ruleID: "semgrep.*",
			match:  FindingMatch{RuleID: "gitleaks.secret"},
			want:   false,
		},
		{
			name:     "tool name match",
			toolName: "semgrep",
			match:    FindingMatch{ToolName: "semgrep"},
			want:     true,
		},
		{
			name:     "tool name case insensitive",
			toolName: "Semgrep",
			match:    FindingMatch{ToolName: "semgrep"},
			want:     true,
		},
		{
			name:        "path pattern match",
			pathPattern: "tests/**",
			match:       FindingMatch{FilePath: "tests/unit/test.go"},
			want:        true,
		},
		{
			name:        "path pattern no match",
			pathPattern: "tests/**",
			match:       FindingMatch{FilePath: "src/main.go"},
			want:        false,
		},
		{
			name:     "combined criteria - all match",
			ruleID:   "sql-*",
			toolName: "semgrep",
			match:    FindingMatch{RuleID: "sql-injection", ToolName: "semgrep"},
			want:     true,
		},
		{
			name:     "combined criteria - partial match fails",
			ruleID:   "sql-*",
			toolName: "semgrep",
			match:    FindingMatch{RuleID: "sql-injection", ToolName: "gitleaks"},
			want:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule, _ := NewRule(tenantID, "Test", SuppressionTypeFalsePositive, userID)
			if tt.ruleID != "" {
				rule.SetRuleIDPattern(tt.ruleID)
			}
			if tt.toolName != "" {
				rule.SetToolName(tt.toolName)
			}
			if tt.pathPattern != "" {
				rule.SetPathPattern(tt.pathPattern)
			}
			// Approve the rule so IsActive() returns true
			_ = rule.Approve(approverID)

			got := rule.Matches(tt.match)
			if got != tt.want {
				t.Errorf("Matches() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSuppressionType_IsValid(t *testing.T) {
	tests := []struct {
		typ  SuppressionType
		want bool
	}{
		{SuppressionTypeFalsePositive, true},
		{SuppressionTypeAcceptedRisk, true},
		{SuppressionTypeWontFix, true},
		{SuppressionType("invalid"), false},
		{SuppressionType(""), false},
	}

	for _, tt := range tests {
		t.Run(string(tt.typ), func(t *testing.T) {
			if got := tt.typ.IsValid(); got != tt.want {
				t.Errorf("IsValid() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestRuleStatus_IsValid(t *testing.T) {
	tests := []struct {
		status RuleStatus
		want   bool
	}{
		{RuleStatusPending, true},
		{RuleStatusApproved, true},
		{RuleStatusRejected, true},
		{RuleStatusExpired, true},
		{RuleStatus("invalid"), false},
		{RuleStatus(""), false},
	}

	for _, tt := range tests {
		t.Run(string(tt.status), func(t *testing.T) {
			if got := tt.status.IsValid(); got != tt.want {
				t.Errorf("IsValid() = %v, want %v", got, tt.want)
			}
		})
	}
}

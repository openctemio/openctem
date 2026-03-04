package app

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/domain/vulnerability"
	"github.com/openctemio/api/pkg/logger"
)

// =============================================================================
// Mock AssignmentRuleRepository
// =============================================================================

// MockAssignmentRuleRepository implements AssignmentRuleRepository for testing.
type MockAssignmentRuleRepository struct {
	rules []*AssignmentRule
	err   error
}

func (m *MockAssignmentRuleRepository) ListActiveByTenant(_ context.Context, _ shared.ID) ([]*AssignmentRule, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.rules, nil
}

// =============================================================================
// Helper: create a test finding
// =============================================================================

func newTestFinding(t *testing.T, sev vulnerability.Severity, toolName string, source vulnerability.FindingSource, findingType vulnerability.FindingType) *vulnerability.Finding {
	t.Helper()

	tenantID := shared.NewID()
	assetID := shared.NewID()

	f, err := vulnerability.NewFinding(tenantID, assetID, source, toolName, sev, "test finding message")
	require.NoError(t, err)

	// To set finding type we need to use ReconstituteFinding since FindingType is private
	data := vulnerability.FindingData{
		ID:              f.ID(),
		TenantID:        tenantID,
		AssetID:         assetID,
		Source:          source,
		ToolName:        toolName,
		Severity:        sev,
		Message:         "test finding message",
		FindingType:     findingType,
		Status:          vulnerability.FindingStatusNew,
		SLAStatus:       vulnerability.SLAStatusNotApplicable,
		FirstDetectedAt: f.FirstDetectedAt(),
		LastSeenAt:      f.LastSeenAt(),
		CreatedAt:       f.CreatedAt(),
		UpdatedAt:       f.UpdatedAt(),
	}

	return vulnerability.ReconstituteFinding(data)
}

// =============================================================================
// Tests for EvaluateRules
// =============================================================================

// TestEvaluateRules tests the AssignmentEngine.EvaluateRules method.
//
// Run with: go test -v ./internal/app/ -run TestEvaluateRules
func TestEvaluateRules(t *testing.T) {
	log := logger.NewNop()
	tenantID := shared.NewID()

	t.Run("NoRules_ReturnsEmpty", func(t *testing.T) {
		repo := &MockAssignmentRuleRepository{rules: []*AssignmentRule{}}
		engine := NewAssignmentEngine(repo, log)

		finding := newTestFinding(t, vulnerability.SeverityHigh, "semgrep", vulnerability.FindingSourceSAST, vulnerability.FindingTypeVulnerability)

		result, err := engine.EvaluateRules(context.Background(), tenantID, finding)

		require.NoError(t, err)
		assert.Empty(t, result)
	})

	t.Run("NilFinding_ReturnsError", func(t *testing.T) {
		repo := &MockAssignmentRuleRepository{rules: []*AssignmentRule{}}
		engine := NewAssignmentEngine(repo, log)

		result, err := engine.EvaluateRules(context.Background(), tenantID, nil)

		require.Error(t, err)
		assert.Nil(t, result)
	})

	t.Run("SingleMatchingRule_SeverityEq", func(t *testing.T) {
		groupID := shared.NewID()
		repo := &MockAssignmentRuleRepository{
			rules: []*AssignmentRule{
				{
					ID:            shared.NewID(),
					TenantID:      tenantID,
					Name:          "Critical to Security",
					Priority:      10,
					IsActive:      true,
					TargetGroupID: groupID,
					Conditions: []RuleCondition{
						{Type: "severity", Op: "eq", Value: "critical"},
					},
				},
			},
		}
		engine := NewAssignmentEngine(repo, log)

		finding := newTestFinding(t, vulnerability.SeverityCritical, "nuclei", vulnerability.FindingSourceDAST, vulnerability.FindingTypeVulnerability)

		result, err := engine.EvaluateRules(context.Background(), tenantID, finding)

		require.NoError(t, err)
		require.Len(t, result, 1)
		assert.Equal(t, groupID, result[0])
	})

	t.Run("MultipleMatchingRules_ReturnsUniqueGroupIDs", func(t *testing.T) {
		groupID1 := shared.NewID()
		groupID2 := shared.NewID()
		repo := &MockAssignmentRuleRepository{
			rules: []*AssignmentRule{
				{
					ID:            shared.NewID(),
					TenantID:      tenantID,
					Name:          "High Severity",
					Priority:      10,
					IsActive:      true,
					TargetGroupID: groupID1,
					Conditions: []RuleCondition{
						{Type: "severity", Op: "eq", Value: "high"},
					},
				},
				{
					ID:            shared.NewID(),
					TenantID:      tenantID,
					Name:          "SAST Findings",
					Priority:      5,
					IsActive:      true,
					TargetGroupID: groupID2,
					Conditions: []RuleCondition{
						{Type: "source", Op: "eq", Value: "sast"},
					},
				},
			},
		}
		engine := NewAssignmentEngine(repo, log)

		finding := newTestFinding(t, vulnerability.SeverityHigh, "semgrep", vulnerability.FindingSourceSAST, vulnerability.FindingTypeVulnerability)

		result, err := engine.EvaluateRules(context.Background(), tenantID, finding)

		require.NoError(t, err)
		require.Len(t, result, 2)
		assert.Contains(t, result, groupID1)
		assert.Contains(t, result, groupID2)
	})

	t.Run("MultipleRulesSameGroup_DeduplicatesGroupIDs", func(t *testing.T) {
		groupID := shared.NewID()
		repo := &MockAssignmentRuleRepository{
			rules: []*AssignmentRule{
				{
					ID:            shared.NewID(),
					TenantID:      tenantID,
					Name:          "Rule 1",
					Priority:      10,
					IsActive:      true,
					TargetGroupID: groupID,
					Conditions: []RuleCondition{
						{Type: "severity", Op: "eq", Value: "critical"},
					},
				},
				{
					ID:            shared.NewID(),
					TenantID:      tenantID,
					Name:          "Rule 2",
					Priority:      5,
					IsActive:      true,
					TargetGroupID: groupID, // Same group
					Conditions: []RuleCondition{
						{Type: "source", Op: "eq", Value: "dast"},
					},
				},
			},
		}
		engine := NewAssignmentEngine(repo, log)

		finding := newTestFinding(t, vulnerability.SeverityCritical, "nuclei", vulnerability.FindingSourceDAST, vulnerability.FindingTypeVulnerability)

		result, err := engine.EvaluateRules(context.Background(), tenantID, finding)

		require.NoError(t, err)
		require.Len(t, result, 1, "duplicate group IDs should be deduplicated")
		assert.Equal(t, groupID, result[0])
	})

	t.Run("NoMatchingRules_ReturnsEmpty", func(t *testing.T) {
		repo := &MockAssignmentRuleRepository{
			rules: []*AssignmentRule{
				{
					ID:            shared.NewID(),
					TenantID:      tenantID,
					Name:          "Critical Only",
					Priority:      10,
					IsActive:      true,
					TargetGroupID: shared.NewID(),
					Conditions: []RuleCondition{
						{Type: "severity", Op: "eq", Value: "critical"},
					},
				},
			},
		}
		engine := NewAssignmentEngine(repo, log)

		// Finding is low severity, rule expects critical
		finding := newTestFinding(t, vulnerability.SeverityLow, "semgrep", vulnerability.FindingSourceSAST, vulnerability.FindingTypeVulnerability)

		result, err := engine.EvaluateRules(context.Background(), tenantID, finding)

		require.NoError(t, err)
		assert.Empty(t, result)
	})

	t.Run("RuleWithInOperator", func(t *testing.T) {
		groupID := shared.NewID()
		repo := &MockAssignmentRuleRepository{
			rules: []*AssignmentRule{
				{
					ID:            shared.NewID(),
					TenantID:      tenantID,
					Name:          "High or Critical Severity",
					Priority:      10,
					IsActive:      true,
					TargetGroupID: groupID,
					Conditions: []RuleCondition{
						{Type: "severity", Op: "in", Value: "critical,high,medium"},
					},
				},
			},
		}
		engine := NewAssignmentEngine(repo, log)

		finding := newTestFinding(t, vulnerability.SeverityHigh, "nuclei", vulnerability.FindingSourceDAST, vulnerability.FindingTypeVulnerability)

		result, err := engine.EvaluateRules(context.Background(), tenantID, finding)

		require.NoError(t, err)
		require.Len(t, result, 1)
		assert.Equal(t, groupID, result[0])
	})

	t.Run("RuleWithInOperator_NoMatch", func(t *testing.T) {
		repo := &MockAssignmentRuleRepository{
			rules: []*AssignmentRule{
				{
					ID:            shared.NewID(),
					TenantID:      tenantID,
					Name:          "Critical or High Only",
					Priority:      10,
					IsActive:      true,
					TargetGroupID: shared.NewID(),
					Conditions: []RuleCondition{
						{Type: "severity", Op: "in", Value: "critical,high"},
					},
				},
			},
		}
		engine := NewAssignmentEngine(repo, log)

		finding := newTestFinding(t, vulnerability.SeverityLow, "semgrep", vulnerability.FindingSourceSAST, vulnerability.FindingTypeVulnerability)

		result, err := engine.EvaluateRules(context.Background(), tenantID, finding)

		require.NoError(t, err)
		assert.Empty(t, result)
	})

	t.Run("RuleWithContainsOperator", func(t *testing.T) {
		groupID := shared.NewID()
		repo := &MockAssignmentRuleRepository{
			rules: []*AssignmentRule{
				{
					ID:            shared.NewID(),
					TenantID:      tenantID,
					Name:          "Nuclei Tool",
					Priority:      10,
					IsActive:      true,
					TargetGroupID: groupID,
					Conditions: []RuleCondition{
						{Type: "tool_name", Op: "contains", Value: "nucl"},
					},
				},
			},
		}
		engine := NewAssignmentEngine(repo, log)

		finding := newTestFinding(t, vulnerability.SeverityHigh, "nuclei", vulnerability.FindingSourceDAST, vulnerability.FindingTypeVulnerability)

		result, err := engine.EvaluateRules(context.Background(), tenantID, finding)

		require.NoError(t, err)
		require.Len(t, result, 1)
		assert.Equal(t, groupID, result[0])
	})

	t.Run("RuleWithContainsOperator_CaseInsensitive", func(t *testing.T) {
		groupID := shared.NewID()
		repo := &MockAssignmentRuleRepository{
			rules: []*AssignmentRule{
				{
					ID:            shared.NewID(),
					TenantID:      tenantID,
					Name:          "Semgrep Tool",
					Priority:      10,
					IsActive:      true,
					TargetGroupID: groupID,
					Conditions: []RuleCondition{
						{Type: "tool_name", Op: "contains", Value: "SEMGREP"},
					},
				},
			},
		}
		engine := NewAssignmentEngine(repo, log)

		finding := newTestFinding(t, vulnerability.SeverityHigh, "semgrep", vulnerability.FindingSourceSAST, vulnerability.FindingTypeVulnerability)

		result, err := engine.EvaluateRules(context.Background(), tenantID, finding)

		require.NoError(t, err)
		require.Len(t, result, 1)
		assert.Equal(t, groupID, result[0])
	})

	t.Run("RuleWithNeqOperator", func(t *testing.T) {
		groupID := shared.NewID()
		repo := &MockAssignmentRuleRepository{
			rules: []*AssignmentRule{
				{
					ID:            shared.NewID(),
					TenantID:      tenantID,
					Name:          "Not Low Severity",
					Priority:      10,
					IsActive:      true,
					TargetGroupID: groupID,
					Conditions: []RuleCondition{
						{Type: "severity", Op: "neq", Value: "low"},
					},
				},
			},
		}
		engine := NewAssignmentEngine(repo, log)

		finding := newTestFinding(t, vulnerability.SeverityHigh, "semgrep", vulnerability.FindingSourceSAST, vulnerability.FindingTypeVulnerability)

		result, err := engine.EvaluateRules(context.Background(), tenantID, finding)

		require.NoError(t, err)
		require.Len(t, result, 1)
		assert.Equal(t, groupID, result[0])
	})

	t.Run("RuleWithNeqOperator_NoMatch", func(t *testing.T) {
		repo := &MockAssignmentRuleRepository{
			rules: []*AssignmentRule{
				{
					ID:            shared.NewID(),
					TenantID:      tenantID,
					Name:          "Not Low Severity",
					Priority:      10,
					IsActive:      true,
					TargetGroupID: shared.NewID(),
					Conditions: []RuleCondition{
						{Type: "severity", Op: "neq", Value: "low"},
					},
				},
			},
		}
		engine := NewAssignmentEngine(repo, log)

		// Finding IS low, so neq("low") should not match
		finding := newTestFinding(t, vulnerability.SeverityLow, "semgrep", vulnerability.FindingSourceSAST, vulnerability.FindingTypeVulnerability)

		result, err := engine.EvaluateRules(context.Background(), tenantID, finding)

		require.NoError(t, err)
		assert.Empty(t, result)
	})

	t.Run("EmptyConditions_AlwaysMatches", func(t *testing.T) {
		groupID := shared.NewID()
		repo := &MockAssignmentRuleRepository{
			rules: []*AssignmentRule{
				{
					ID:            shared.NewID(),
					TenantID:      tenantID,
					Name:          "Catch All",
					Priority:      1,
					IsActive:      true,
					TargetGroupID: groupID,
					Conditions:    []RuleCondition{}, // Empty conditions
				},
			},
		}
		engine := NewAssignmentEngine(repo, log)

		finding := newTestFinding(t, vulnerability.SeverityInfo, "any-tool", vulnerability.FindingSourceSAST, vulnerability.FindingTypeVulnerability)

		result, err := engine.EvaluateRules(context.Background(), tenantID, finding)

		require.NoError(t, err)
		require.Len(t, result, 1)
		assert.Equal(t, groupID, result[0])
	})

	t.Run("MultipleConditions_AllMustMatch", func(t *testing.T) {
		groupID := shared.NewID()
		repo := &MockAssignmentRuleRepository{
			rules: []*AssignmentRule{
				{
					ID:            shared.NewID(),
					TenantID:      tenantID,
					Name:          "Critical SAST",
					Priority:      10,
					IsActive:      true,
					TargetGroupID: groupID,
					Conditions: []RuleCondition{
						{Type: "severity", Op: "eq", Value: "critical"},
						{Type: "source", Op: "eq", Value: "sast"},
					},
				},
			},
		}
		engine := NewAssignmentEngine(repo, log)

		// Matches both conditions
		finding := newTestFinding(t, vulnerability.SeverityCritical, "semgrep", vulnerability.FindingSourceSAST, vulnerability.FindingTypeVulnerability)

		result, err := engine.EvaluateRules(context.Background(), tenantID, finding)

		require.NoError(t, err)
		require.Len(t, result, 1)
		assert.Equal(t, groupID, result[0])
	})

	t.Run("MultipleConditions_PartialMatch_ReturnsEmpty", func(t *testing.T) {
		repo := &MockAssignmentRuleRepository{
			rules: []*AssignmentRule{
				{
					ID:            shared.NewID(),
					TenantID:      tenantID,
					Name:          "Critical SAST",
					Priority:      10,
					IsActive:      true,
					TargetGroupID: shared.NewID(),
					Conditions: []RuleCondition{
						{Type: "severity", Op: "eq", Value: "critical"},
						{Type: "source", Op: "eq", Value: "sast"},
					},
				},
			},
		}
		engine := NewAssignmentEngine(repo, log)

		// Only matches severity, not source
		finding := newTestFinding(t, vulnerability.SeverityCritical, "nuclei", vulnerability.FindingSourceDAST, vulnerability.FindingTypeVulnerability)

		result, err := engine.EvaluateRules(context.Background(), tenantID, finding)

		require.NoError(t, err)
		assert.Empty(t, result)
	})

	t.Run("FindingTypeCondition", func(t *testing.T) {
		groupID := shared.NewID()
		repo := &MockAssignmentRuleRepository{
			rules: []*AssignmentRule{
				{
					ID:            shared.NewID(),
					TenantID:      tenantID,
					Name:          "Secrets Only",
					Priority:      10,
					IsActive:      true,
					TargetGroupID: groupID,
					Conditions: []RuleCondition{
						{Type: "finding_type", Op: "eq", Value: "secret"},
					},
				},
			},
		}
		engine := NewAssignmentEngine(repo, log)

		finding := newTestFinding(t, vulnerability.SeverityHigh, "gitleaks", vulnerability.FindingSourceSecret, vulnerability.FindingTypeSecret)

		result, err := engine.EvaluateRules(context.Background(), tenantID, finding)

		require.NoError(t, err)
		require.Len(t, result, 1)
		assert.Equal(t, groupID, result[0])
	})

	t.Run("ToolNameCondition", func(t *testing.T) {
		groupID := shared.NewID()
		repo := &MockAssignmentRuleRepository{
			rules: []*AssignmentRule{
				{
					ID:            shared.NewID(),
					TenantID:      tenantID,
					Name:          "Trivy Findings",
					Priority:      10,
					IsActive:      true,
					TargetGroupID: groupID,
					Conditions: []RuleCondition{
						{Type: "tool_name", Op: "eq", Value: "trivy"},
					},
				},
			},
		}
		engine := NewAssignmentEngine(repo, log)

		finding := newTestFinding(t, vulnerability.SeverityMedium, "trivy", vulnerability.FindingSourceSCA, vulnerability.FindingTypeVulnerability)

		result, err := engine.EvaluateRules(context.Background(), tenantID, finding)

		require.NoError(t, err)
		require.Len(t, result, 1)
		assert.Equal(t, groupID, result[0])
	})

	t.Run("RepoError_ReturnsError", func(t *testing.T) {
		repo := &MockAssignmentRuleRepository{
			err: assert.AnError,
		}
		engine := NewAssignmentEngine(repo, log)

		finding := newTestFinding(t, vulnerability.SeverityHigh, "semgrep", vulnerability.FindingSourceSAST, vulnerability.FindingTypeVulnerability)

		result, err := engine.EvaluateRules(context.Background(), tenantID, finding)

		require.Error(t, err)
		assert.Nil(t, result)
	})
}

// =============================================================================
// Tests for ParseConditions
// =============================================================================

// TestParseConditions tests the ParseConditions function.
//
// Run with: go test -v ./internal/app/ -run TestParseConditions
func TestParseConditions(t *testing.T) {
	t.Run("ValidJSON", func(t *testing.T) {
		data := []byte(`[
			{"type": "severity", "op": "eq", "value": "critical"},
			{"type": "tool_name", "op": "contains", "value": "nuclei"}
		]`)

		conditions, err := ParseConditions(data)

		require.NoError(t, err)
		require.Len(t, conditions, 2)
		assert.Equal(t, "severity", conditions[0].Type)
		assert.Equal(t, "eq", conditions[0].Op)
		assert.Equal(t, "critical", conditions[0].Value)
		assert.Equal(t, "tool_name", conditions[1].Type)
		assert.Equal(t, "contains", conditions[1].Op)
		assert.Equal(t, "nuclei", conditions[1].Value)
	})

	t.Run("InvalidJSON", func(t *testing.T) {
		data := []byte(`not valid json`)

		conditions, err := ParseConditions(data)

		require.Error(t, err)
		assert.Nil(t, conditions)
	})

	t.Run("EmptyArray", func(t *testing.T) {
		data := []byte(`[]`)

		conditions, err := ParseConditions(data)

		require.NoError(t, err)
		assert.Empty(t, conditions)
	})

	t.Run("SingleCondition", func(t *testing.T) {
		data := []byte(`[{"type": "severity", "op": "in", "value": "high,critical"}]`)

		conditions, err := ParseConditions(data)

		require.NoError(t, err)
		require.Len(t, conditions, 1)
		assert.Equal(t, "in", conditions[0].Op)
		assert.Equal(t, "high,critical", conditions[0].Value)
	})
}

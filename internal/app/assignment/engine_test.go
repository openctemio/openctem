package assignment

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/openctemio/api/pkg/domain/accesscontrol"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/domain/vulnerability"
	"github.com/openctemio/api/pkg/logger"
)

// =============================================================================
// Helper: create a test finding with optional tags and file path
// =============================================================================

func newTestFinding(t *testing.T, sev vulnerability.Severity, toolName string, source vulnerability.FindingSource, findingType vulnerability.FindingType) *vulnerability.Finding {
	t.Helper()

	tenantID := shared.NewID()
	assetID := shared.NewID()

	f, err := vulnerability.NewFinding(tenantID, assetID, source, toolName, sev, "test finding message")
	require.NoError(t, err)

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

func newTestFindingWithTags(t *testing.T, sev vulnerability.Severity, toolName string, source vulnerability.FindingSource, findingType vulnerability.FindingType, tags []string) *vulnerability.Finding {
	t.Helper()

	f := newTestFinding(t, sev, toolName, source, findingType)
	f.SetTags(tags)
	return f
}

func newTestFindingWithFilePath(t *testing.T, sev vulnerability.Severity, toolName string, source vulnerability.FindingSource, findingType vulnerability.FindingType, filePath string) *vulnerability.Finding {
	t.Helper()

	tenantID := shared.NewID()
	assetID := shared.NewID()

	f, err := vulnerability.NewFinding(tenantID, assetID, source, toolName, sev, "test finding message")
	require.NoError(t, err)

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
		FilePath:        filePath,
		FirstDetectedAt: f.FirstDetectedAt(),
		LastSeenAt:      f.LastSeenAt(),
		CreatedAt:       f.CreatedAt(),
		UpdatedAt:       f.UpdatedAt(),
	}

	return vulnerability.ReconstituteFinding(data)
}

// Helper: create a domain AssignmentRule for tests
func makeRule(t *testing.T, tenantID, groupID shared.ID, conds accesscontrol.AssignmentConditions, opts accesscontrol.AssignmentOptions) *accesscontrol.AssignmentRule {
	t.Helper()
	rule, err := accesscontrol.NewAssignmentRule(tenantID, "test-rule", conds, groupID, nil)
	require.NoError(t, err)
	rule.UpdatePriority(10)
	rule.UpdateOptions(opts)
	return rule
}

// =============================================================================
// Mock: implements accesscontrol.Repository (minimal, for engine tests)
// =============================================================================

type mockACRepo struct {
	accesscontrol.Repository // embed to satisfy interface for methods we don't use
	rules                    []*accesscontrol.AssignmentRule
	err                      error
	createdFGAs              []*accesscontrol.FindingGroupAssignment
}

func (m *mockACRepo) ListActiveRulesByPriority(_ context.Context, _ shared.ID) ([]*accesscontrol.AssignmentRule, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.rules, nil
}

func (m *mockACRepo) BulkCreateFindingGroupAssignments(_ context.Context, fgas []*accesscontrol.FindingGroupAssignment) (int, error) {
	m.createdFGAs = append(m.createdFGAs, fgas...)
	return len(fgas), nil
}

// =============================================================================
// Tests for MatchesConditions
// =============================================================================

func TestMatchesConditions(t *testing.T) {
	log := logger.NewNop()
	engine := NewEngine(nil, log)

	t.Run("EmptyConditions_AlwaysMatches", func(t *testing.T) {
		finding := newTestFinding(t, vulnerability.SeverityInfo, "any-tool", vulnerability.FindingSourceSAST, vulnerability.FindingTypeVulnerability)
		assert.True(t, engine.MatchesConditions(accesscontrol.AssignmentConditions{}, finding))
	})

	t.Run("FindingSeverity_Match", func(t *testing.T) {
		finding := newTestFinding(t, vulnerability.SeverityCritical, "nuclei", vulnerability.FindingSourceDAST, vulnerability.FindingTypeVulnerability)
		conds := accesscontrol.AssignmentConditions{FindingSeverity: []string{"critical", "high"}}
		assert.True(t, engine.MatchesConditions(conds, finding))
	})

	t.Run("FindingSeverity_NoMatch", func(t *testing.T) {
		finding := newTestFinding(t, vulnerability.SeverityLow, "nuclei", vulnerability.FindingSourceDAST, vulnerability.FindingTypeVulnerability)
		conds := accesscontrol.AssignmentConditions{FindingSeverity: []string{"critical", "high"}}
		assert.False(t, engine.MatchesConditions(conds, finding))
	})

	t.Run("FindingSeverity_CaseInsensitive", func(t *testing.T) {
		finding := newTestFinding(t, vulnerability.SeverityCritical, "nuclei", vulnerability.FindingSourceDAST, vulnerability.FindingTypeVulnerability)
		conds := accesscontrol.AssignmentConditions{FindingSeverity: []string{"CRITICAL"}}
		assert.True(t, engine.MatchesConditions(conds, finding))
	})

	t.Run("FindingSource_Match", func(t *testing.T) {
		finding := newTestFinding(t, vulnerability.SeverityHigh, "semgrep", vulnerability.FindingSourceSAST, vulnerability.FindingTypeVulnerability)
		conds := accesscontrol.AssignmentConditions{FindingSource: []string{"sast"}}
		assert.True(t, engine.MatchesConditions(conds, finding))
	})

	t.Run("FindingSource_NoMatch", func(t *testing.T) {
		finding := newTestFinding(t, vulnerability.SeverityHigh, "semgrep", vulnerability.FindingSourceSAST, vulnerability.FindingTypeVulnerability)
		conds := accesscontrol.AssignmentConditions{FindingSource: []string{"dast", "sca"}}
		assert.False(t, engine.MatchesConditions(conds, finding))
	})

	t.Run("FindingType_Match", func(t *testing.T) {
		finding := newTestFinding(t, vulnerability.SeverityHigh, "gitleaks", vulnerability.FindingSourceSecret, vulnerability.FindingTypeSecret)
		conds := accesscontrol.AssignmentConditions{FindingType: []string{"secret"}}
		assert.True(t, engine.MatchesConditions(conds, finding))
	})

	t.Run("FindingType_NoMatch", func(t *testing.T) {
		finding := newTestFinding(t, vulnerability.SeverityHigh, "gitleaks", vulnerability.FindingSourceSecret, vulnerability.FindingTypeSecret)
		conds := accesscontrol.AssignmentConditions{FindingType: []string{"vulnerability", "misconfiguration"}}
		assert.False(t, engine.MatchesConditions(conds, finding))
	})

	t.Run("AssetTags_AnyMatch", func(t *testing.T) {
		finding := newTestFindingWithTags(t, vulnerability.SeverityHigh, "semgrep", vulnerability.FindingSourceSAST, vulnerability.FindingTypeVulnerability, []string{"production", "web", "critical"})
		conds := accesscontrol.AssignmentConditions{AssetTags: []string{"web"}}
		assert.True(t, engine.MatchesConditions(conds, finding))
	})

	t.Run("AssetTags_NoMatch", func(t *testing.T) {
		finding := newTestFindingWithTags(t, vulnerability.SeverityHigh, "semgrep", vulnerability.FindingSourceSAST, vulnerability.FindingTypeVulnerability, []string{"production"})
		conds := accesscontrol.AssignmentConditions{AssetTags: []string{"staging", "test"}}
		assert.False(t, engine.MatchesConditions(conds, finding))
	})

	t.Run("AssetTags_EmptyFindingTags", func(t *testing.T) {
		finding := newTestFinding(t, vulnerability.SeverityHigh, "semgrep", vulnerability.FindingSourceSAST, vulnerability.FindingTypeVulnerability)
		conds := accesscontrol.AssignmentConditions{AssetTags: []string{"web"}}
		assert.False(t, engine.MatchesConditions(conds, finding))
	})

	t.Run("FilePathPattern_Match", func(t *testing.T) {
		finding := newTestFindingWithFilePath(t, vulnerability.SeverityHigh, "semgrep", vulnerability.FindingSourceSAST, vulnerability.FindingTypeVulnerability, "src/auth/login.go")
		conds := accesscontrol.AssignmentConditions{FilePathPattern: "src/auth/*.go"}
		assert.True(t, engine.MatchesConditions(conds, finding))
	})

	t.Run("FilePathPattern_NoMatch", func(t *testing.T) {
		finding := newTestFindingWithFilePath(t, vulnerability.SeverityHigh, "semgrep", vulnerability.FindingSourceSAST, vulnerability.FindingTypeVulnerability, "src/api/handler.go")
		conds := accesscontrol.AssignmentConditions{FilePathPattern: "src/auth/*.go"}
		assert.False(t, engine.MatchesConditions(conds, finding))
	})

	t.Run("FilePathPattern_EmptyFilePath", func(t *testing.T) {
		finding := newTestFinding(t, vulnerability.SeverityHigh, "semgrep", vulnerability.FindingSourceSAST, vulnerability.FindingTypeVulnerability)
		conds := accesscontrol.AssignmentConditions{FilePathPattern: "src/*.go"}
		assert.False(t, engine.MatchesConditions(conds, finding))
	})

	t.Run("MultipleConditions_ANDLogic", func(t *testing.T) {
		finding := newTestFinding(t, vulnerability.SeverityCritical, "semgrep", vulnerability.FindingSourceSAST, vulnerability.FindingTypeVulnerability)
		conds := accesscontrol.AssignmentConditions{
			FindingSeverity: []string{"critical"},
			FindingSource:   []string{"sast"},
		}
		assert.True(t, engine.MatchesConditions(conds, finding))
	})

	t.Run("MultipleConditions_PartialMatch_Fails", func(t *testing.T) {
		finding := newTestFinding(t, vulnerability.SeverityCritical, "nuclei", vulnerability.FindingSourceDAST, vulnerability.FindingTypeVulnerability)
		conds := accesscontrol.AssignmentConditions{
			FindingSeverity: []string{"critical"},
			FindingSource:   []string{"sast"}, // doesn't match
		}
		assert.False(t, engine.MatchesConditions(conds, finding))
	})
}

// =============================================================================
// Tests for EvaluateRules
// =============================================================================

func TestEvaluateRules(t *testing.T) {
	log := logger.NewNop()
	tenantID := shared.NewID()

	t.Run("NoRules_ReturnsEmpty", func(t *testing.T) {
		repo := &mockACRepo{rules: []*accesscontrol.AssignmentRule{}}
		engine := NewEngine(repo, log)

		finding := newTestFinding(t, vulnerability.SeverityHigh, "semgrep", vulnerability.FindingSourceSAST, vulnerability.FindingTypeVulnerability)
		results, err := engine.EvaluateRules(context.Background(), tenantID, finding)

		require.NoError(t, err)
		assert.Empty(t, results)
	})

	t.Run("NilFinding_ReturnsError", func(t *testing.T) {
		repo := &mockACRepo{rules: []*accesscontrol.AssignmentRule{}}
		engine := NewEngine(repo, log)

		results, err := engine.EvaluateRules(context.Background(), tenantID, nil)
		require.Error(t, err)
		assert.Nil(t, results)
	})

	t.Run("SingleMatchingRule", func(t *testing.T) {
		groupID := shared.NewID()
		rule := makeRule(t, tenantID, groupID,
			accesscontrol.AssignmentConditions{FindingSeverity: []string{"critical"}},
			accesscontrol.AssignmentOptions{},
		)
		repo := &mockACRepo{rules: []*accesscontrol.AssignmentRule{rule}}
		engine := NewEngine(repo, log)

		finding := newTestFinding(t, vulnerability.SeverityCritical, "nuclei", vulnerability.FindingSourceDAST, vulnerability.FindingTypeVulnerability)
		results, err := engine.EvaluateRules(context.Background(), tenantID, finding)

		require.NoError(t, err)
		require.Len(t, results, 1)
		assert.Equal(t, groupID, results[0].GroupID)
		assert.Equal(t, rule.ID(), results[0].RuleID)
	})

	t.Run("MultipleMatchingRules_UniqueGroups", func(t *testing.T) {
		groupID1 := shared.NewID()
		groupID2 := shared.NewID()
		rule1 := makeRule(t, tenantID, groupID1,
			accesscontrol.AssignmentConditions{FindingSeverity: []string{"critical"}},
			accesscontrol.AssignmentOptions{},
		)
		rule2 := makeRule(t, tenantID, groupID2,
			accesscontrol.AssignmentConditions{FindingSource: []string{"dast"}},
			accesscontrol.AssignmentOptions{},
		)
		repo := &mockACRepo{rules: []*accesscontrol.AssignmentRule{rule1, rule2}}
		engine := NewEngine(repo, log)

		finding := newTestFinding(t, vulnerability.SeverityCritical, "nuclei", vulnerability.FindingSourceDAST, vulnerability.FindingTypeVulnerability)
		results, err := engine.EvaluateRules(context.Background(), tenantID, finding)

		require.NoError(t, err)
		require.Len(t, results, 2)
	})

	t.Run("DuplicateGroups_Deduplicated", func(t *testing.T) {
		groupID := shared.NewID()
		rule1 := makeRule(t, tenantID, groupID,
			accesscontrol.AssignmentConditions{FindingSeverity: []string{"critical"}},
			accesscontrol.AssignmentOptions{},
		)
		rule2 := makeRule(t, tenantID, groupID, // same group
			accesscontrol.AssignmentConditions{FindingSource: []string{"dast"}},
			accesscontrol.AssignmentOptions{},
		)
		repo := &mockACRepo{rules: []*accesscontrol.AssignmentRule{rule1, rule2}}
		engine := NewEngine(repo, log)

		finding := newTestFinding(t, vulnerability.SeverityCritical, "nuclei", vulnerability.FindingSourceDAST, vulnerability.FindingTypeVulnerability)
		results, err := engine.EvaluateRules(context.Background(), tenantID, finding)

		require.NoError(t, err)
		require.Len(t, results, 1, "duplicate groups should be deduplicated")
	})

	t.Run("CatchAllRule_EmptyConditions", func(t *testing.T) {
		groupID := shared.NewID()
		rule := makeRule(t, tenantID, groupID,
			accesscontrol.AssignmentConditions{},
			accesscontrol.AssignmentOptions{},
		)
		repo := &mockACRepo{rules: []*accesscontrol.AssignmentRule{rule}}
		engine := NewEngine(repo, log)

		finding := newTestFinding(t, vulnerability.SeverityInfo, "any-tool", vulnerability.FindingSourceManual, vulnerability.FindingTypeVulnerability)
		results, err := engine.EvaluateRules(context.Background(), tenantID, finding)

		require.NoError(t, err)
		require.Len(t, results, 1)
		assert.Equal(t, groupID, results[0].GroupID)
	})

	t.Run("NoMatch_ReturnsEmpty", func(t *testing.T) {
		rule := makeRule(t, tenantID, shared.NewID(),
			accesscontrol.AssignmentConditions{FindingSeverity: []string{"critical"}},
			accesscontrol.AssignmentOptions{},
		)
		repo := &mockACRepo{rules: []*accesscontrol.AssignmentRule{rule}}
		engine := NewEngine(repo, log)

		finding := newTestFinding(t, vulnerability.SeverityLow, "semgrep", vulnerability.FindingSourceSAST, vulnerability.FindingTypeVulnerability)
		results, err := engine.EvaluateRules(context.Background(), tenantID, finding)

		require.NoError(t, err)
		assert.Empty(t, results)
	})

	t.Run("RepoError_ReturnsError", func(t *testing.T) {
		repo := &mockACRepo{err: assert.AnError}
		engine := NewEngine(repo, log)

		finding := newTestFinding(t, vulnerability.SeverityHigh, "semgrep", vulnerability.FindingSourceSAST, vulnerability.FindingTypeVulnerability)
		results, err := engine.EvaluateRules(context.Background(), tenantID, finding)

		require.Error(t, err)
		assert.Nil(t, results)
	})

	t.Run("OptionsPassedThrough", func(t *testing.T) {
		groupID := shared.NewID()
		opts := accesscontrol.AssignmentOptions{
			NotifyGroup:        true,
			SetFindingPriority: "p1",
		}
		rule := makeRule(t, tenantID, groupID,
			accesscontrol.AssignmentConditions{FindingSeverity: []string{"critical"}},
			opts,
		)
		repo := &mockACRepo{rules: []*accesscontrol.AssignmentRule{rule}}
		engine := NewEngine(repo, log)

		finding := newTestFinding(t, vulnerability.SeverityCritical, "nuclei", vulnerability.FindingSourceDAST, vulnerability.FindingTypeVulnerability)
		results, err := engine.EvaluateRules(context.Background(), tenantID, finding)

		require.NoError(t, err)
		require.Len(t, results, 1)
		assert.True(t, results[0].Options.NotifyGroup)
		assert.Equal(t, "p1", results[0].Options.SetFindingPriority)
	})
}

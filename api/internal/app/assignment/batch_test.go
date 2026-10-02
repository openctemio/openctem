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

// countingACRepo wraps mockACRepo and counts ListActiveRulesByPriority calls so
// we can prove EvaluateBatch lists rules once for the whole batch.
type countingACRepo struct {
	mockACRepo
	listCalls int
}

func (m *countingACRepo) ListActiveRulesByPriority(ctx context.Context, tid shared.ID) ([]*accesscontrol.AssignmentRule, error) {
	m.listCalls++
	return m.mockACRepo.ListActiveRulesByPriority(ctx, tid)
}

// recordingFindingRepo captures Update calls for priority-override assertions.
type recordingFindingRepo struct {
	vulnerability.FindingRepository // embedded; unused methods never called
	updated                         []*vulnerability.Finding
}

func (r *recordingFindingRepo) Update(_ context.Context, f *vulnerability.Finding) error {
	r.updated = append(r.updated, f)
	return nil
}

func TestEvaluateBatch_ListsRulesOnce(t *testing.T) {
	tenantID := shared.NewID()
	groupID := shared.NewID()
	repo := &countingACRepo{mockACRepo: mockACRepo{
		rules: []*accesscontrol.AssignmentRule{
			makeRule(t, tenantID, groupID, accesscontrol.AssignmentConditions{}, accesscontrol.AssignmentOptions{}), // catch-all
		},
	}}
	engine := NewEngine(repo, logger.NewNop())

	findings := []*vulnerability.Finding{
		newTestFinding(t, vulnerability.SeverityHigh, "t", vulnerability.FindingSourceSAST, vulnerability.FindingTypeVulnerability),
		newTestFinding(t, vulnerability.SeverityLow, "t", vulnerability.FindingSourceSCA, vulnerability.FindingTypeVulnerability),
		newTestFinding(t, vulnerability.SeverityMedium, "t", vulnerability.FindingSourceDAST, vulnerability.FindingTypeVulnerability),
	}

	matches, err := engine.EvaluateBatch(context.Background(), tenantID, findings)
	require.NoError(t, err)
	assert.Len(t, matches, 3, "catch-all rule should match every finding")
	assert.Equal(t, 1, repo.listCalls, "rules must be listed once for the whole batch, not per finding")
}

func TestBatchAssigner_ApplyBatch_RoutesToGroups(t *testing.T) {
	tenantID := shared.NewID()
	groupID := shared.NewID()
	repo := &mockACRepo{rules: []*accesscontrol.AssignmentRule{
		makeRule(t, tenantID, groupID, accesscontrol.AssignmentConditions{
			FindingSeverity: []string{"high"},
		}, accesscontrol.AssignmentOptions{}),
	}}
	engine := NewEngine(repo, logger.NewNop())
	ba := NewBatchAssigner(engine, repo, nil, logger.NewNop())

	findings := []*vulnerability.Finding{
		newTestFinding(t, vulnerability.SeverityHigh, "t", vulnerability.FindingSourceSAST, vulnerability.FindingTypeVulnerability),
		newTestFinding(t, vulnerability.SeverityHigh, "t", vulnerability.FindingSourceSCA, vulnerability.FindingTypeVulnerability),
		newTestFinding(t, vulnerability.SeverityLow, "t", vulnerability.FindingSourceDAST, vulnerability.FindingTypeVulnerability), // no match
	}

	created, err := ba.ApplyBatch(context.Background(), tenantID, findings)
	require.NoError(t, err)
	assert.Equal(t, 2, created, "only the two high-severity findings should route")
	assert.Len(t, repo.createdFGAs, 2)
	for _, fga := range repo.createdFGAs {
		assert.Equal(t, groupID, fga.GroupID())
	}
}

func TestBatchAssigner_ApplyBatch_NoRules_NoOp(t *testing.T) {
	repo := &mockACRepo{} // no rules
	engine := NewEngine(repo, logger.NewNop())
	ba := NewBatchAssigner(engine, repo, nil, logger.NewNop())

	created, err := ba.ApplyBatch(context.Background(), shared.NewID(), []*vulnerability.Finding{
		newTestFinding(t, vulnerability.SeverityHigh, "t", vulnerability.FindingSourceSAST, vulnerability.FindingTypeVulnerability),
	})
	require.NoError(t, err)
	assert.Zero(t, created)
	assert.Empty(t, repo.createdFGAs)
}

func TestBatchAssigner_ApplyBatch_AppliesPriorityOverride(t *testing.T) {
	tenantID := shared.NewID()
	groupID := shared.NewID()
	repo := &mockACRepo{rules: []*accesscontrol.AssignmentRule{
		makeRule(t, tenantID, groupID, accesscontrol.AssignmentConditions{}, accesscontrol.AssignmentOptions{
			SetFindingPriority: "critical",
		}),
	}}
	engine := NewEngine(repo, logger.NewNop())
	fr := &recordingFindingRepo{}
	ba := NewBatchAssigner(engine, repo, fr, logger.NewNop())

	f := newTestFinding(t, vulnerability.SeverityLow, "t", vulnerability.FindingSourceSAST, vulnerability.FindingTypeVulnerability)
	_, err := ba.ApplyBatch(context.Background(), tenantID, []*vulnerability.Finding{f})
	require.NoError(t, err)

	require.Len(t, fr.updated, 1, "priority override should persist via findingRepo.Update")
	require.NotNil(t, fr.updated[0].Rank())
	assert.InDelta(t, 90.0, *fr.updated[0].Rank(), 0.001, "critical → rank 90")
}

func TestBatchAssigner_Empty_NoOp(t *testing.T) {
	repo := &mockACRepo{}
	ba := NewBatchAssigner(NewEngine(repo, logger.NewNop()), repo, nil, logger.NewNop())
	created, err := ba.ApplyBatch(context.Background(), shared.NewID(), nil)
	require.NoError(t, err)
	assert.Zero(t, created)
}

package unit

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/openctemio/api/pkg/domain/accesscontrol"
	"github.com/openctemio/api/pkg/domain/shared"
)

// =============================================================================
// FindingGroupAssignment Entity Tests
// =============================================================================

func TestNewFindingGroupAssignment_Success(t *testing.T) {
	tenantID := shared.NewID()
	findingID := shared.NewID()
	groupID := shared.NewID()
	ruleID := shared.NewID()

	fga, err := accesscontrol.NewFindingGroupAssignment(tenantID, findingID, groupID, &ruleID)
	require.NoError(t, err)
	require.NotNil(t, fga)

	assert.False(t, fga.ID().IsZero(), "ID should be generated")
	assert.Equal(t, tenantID, fga.TenantID())
	assert.Equal(t, findingID, fga.FindingID())
	assert.Equal(t, groupID, fga.GroupID())
	assert.Equal(t, &ruleID, fga.RuleID())
	assert.False(t, fga.AssignedAt().IsZero(), "AssignedAt should be set")
}

func TestNewFindingGroupAssignment_NilRuleID(t *testing.T) {
	tenantID := shared.NewID()
	findingID := shared.NewID()
	groupID := shared.NewID()

	fga, err := accesscontrol.NewFindingGroupAssignment(tenantID, findingID, groupID, nil)
	require.NoError(t, err)
	require.NotNil(t, fga)
	assert.Nil(t, fga.RuleID(), "RuleID should be nil for manual assignment")
}

func TestNewFindingGroupAssignment_ZeroTenantID(t *testing.T) {
	_, err := accesscontrol.NewFindingGroupAssignment(shared.ID{}, shared.NewID(), shared.NewID(), nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, shared.ErrValidation)
}

func TestNewFindingGroupAssignment_ZeroFindingID(t *testing.T) {
	_, err := accesscontrol.NewFindingGroupAssignment(shared.NewID(), shared.ID{}, shared.NewID(), nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, shared.ErrValidation)
}

func TestNewFindingGroupAssignment_ZeroGroupID(t *testing.T) {
	_, err := accesscontrol.NewFindingGroupAssignment(shared.NewID(), shared.NewID(), shared.ID{}, nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, shared.ErrValidation)
}

func TestReconstituteFindingGroupAssignment(t *testing.T) {
	id := shared.NewID()
	tenantID := shared.NewID()
	findingID := shared.NewID()
	groupID := shared.NewID()
	ruleID := shared.NewID()
	assignedAt := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)

	fga := accesscontrol.ReconstituteFindingGroupAssignment(id, tenantID, findingID, groupID, &ruleID, assignedAt)
	require.NotNil(t, fga)

	assert.Equal(t, id, fga.ID())
	assert.Equal(t, tenantID, fga.TenantID())
	assert.Equal(t, findingID, fga.FindingID())
	assert.Equal(t, groupID, fga.GroupID())
	assert.Equal(t, &ruleID, fga.RuleID())
	assert.Equal(t, assignedAt, fga.AssignedAt())
}

func TestReconstituteFindingGroupAssignment_NilRuleID(t *testing.T) {
	fga := accesscontrol.ReconstituteFindingGroupAssignment(
		shared.NewID(), shared.NewID(), shared.NewID(), shared.NewID(),
		nil, time.Now(),
	)
	require.NotNil(t, fga)
	assert.Nil(t, fga.RuleID())
}

package unit

import (
	"context"
	"testing"
	"time"

	"github.com/openctemio/api/pkg/domain/pentest"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// 1. Domain: CampaignRole Value Object (6.1 partial)
// =============================================================================

func TestCampaignRole_IsValid(t *testing.T) {
	valid := []string{"lead", "tester", "reviewer", "observer"}
	for _, r := range valid {
		role := pentest.CampaignRole(r)
		assert.True(t, role.IsValid(), "expected %q to be valid", r)
	}

	invalid := []string{"admin", "manager", "", "LEAD", "Lead", "owner", "member", " lead"}
	for _, r := range invalid {
		role := pentest.CampaignRole(r)
		assert.False(t, role.IsValid(), "expected %q to be invalid", r)
	}
}

func TestCampaignRole_CanWriteFindings(t *testing.T) {
	tests := []struct {
		role     pentest.CampaignRole
		canWrite bool
	}{
		{pentest.CampaignRoleLead, true},
		{pentest.CampaignRoleTester, true},
		{pentest.CampaignRoleReviewer, false},
		{pentest.CampaignRoleObserver, false},
	}
	for _, tc := range tests {
		assert.Equal(t, tc.canWrite, tc.role.CanWriteFindings(), "role %s CanWriteFindings", tc.role)
	}
}

func TestCampaignRole_CanManageCampaign(t *testing.T) {
	assert.True(t, pentest.CampaignRoleLead.CanManageCampaign())
	assert.False(t, pentest.CampaignRoleTester.CanManageCampaign())
	assert.False(t, pentest.CampaignRoleReviewer.CanManageCampaign())
	assert.False(t, pentest.CampaignRoleObserver.CanManageCampaign())
}

func TestCampaignRole_CanManageTeam(t *testing.T) {
	// Only lead can add/remove/change team members
	assert.True(t, pentest.CampaignRoleLead.CanManageTeam())
	assert.False(t, pentest.CampaignRoleTester.CanManageTeam())
	assert.False(t, pentest.CampaignRoleReviewer.CanManageTeam())
	assert.False(t, pentest.CampaignRoleObserver.CanManageTeam())
}

func TestCampaignRole_CanGenerateReport(t *testing.T) {
	assert.True(t, pentest.CampaignRoleLead.CanGenerateReport())
	assert.False(t, pentest.CampaignRoleTester.CanGenerateReport())
	assert.False(t, pentest.CampaignRoleReviewer.CanGenerateReport())
	assert.False(t, pentest.CampaignRoleObserver.CanGenerateReport())
}

func TestCampaignRole_CanUploadEvidence(t *testing.T) {
	assert.True(t, pentest.CampaignRoleLead.CanUploadEvidence())
	assert.True(t, pentest.CampaignRoleTester.CanUploadEvidence())
	assert.True(t, pentest.CampaignRoleReviewer.CanUploadEvidence())
	assert.False(t, pentest.CampaignRoleObserver.CanUploadEvidence())
}

func TestCampaignRole_CanSubmitRetest(t *testing.T) {
	assert.True(t, pentest.CampaignRoleLead.CanSubmitRetest())
	assert.True(t, pentest.CampaignRoleTester.CanSubmitRetest())
	assert.True(t, pentest.CampaignRoleReviewer.CanSubmitRetest())
	assert.False(t, pentest.CampaignRoleObserver.CanSubmitRetest())
}

// =============================================================================
// 2. Domain: CampaignMember Entity
// =============================================================================

func TestCampaignMember_New(t *testing.T) {
	tenantID := shared.NewID()
	campaignID := shared.NewID()
	userID := shared.NewID()
	addedBy := shared.NewID()

	member, err := pentest.NewCampaignMember(tenantID, campaignID, userID, pentest.CampaignRoleTester, &addedBy)
	require.NoError(t, err)

	assert.Equal(t, tenantID, member.TenantID())
	assert.Equal(t, campaignID, member.CampaignID())
	assert.Equal(t, userID, member.UserID())
	assert.Equal(t, pentest.CampaignRoleTester, member.Role())
	assert.Equal(t, &addedBy, member.AddedBy())
	assert.False(t, member.ID().IsZero())
	assert.False(t, member.CreatedAt().IsZero())
}

func TestCampaignMember_New_AllRoles(t *testing.T) {
	roles := []pentest.CampaignRole{
		pentest.CampaignRoleLead,
		pentest.CampaignRoleTester,
		pentest.CampaignRoleReviewer,
		pentest.CampaignRoleObserver,
	}
	for _, role := range roles {
		member, err := pentest.NewCampaignMember(shared.NewID(), shared.NewID(), shared.NewID(), role, nil)
		require.NoError(t, err, "role %s should be accepted", role)
		assert.Equal(t, role, member.Role())
	}
}

func TestCampaignMember_New_InvalidRole(t *testing.T) {
	_, err := pentest.NewCampaignMember(shared.NewID(), shared.NewID(), shared.NewID(), "invalid", nil)
	require.Error(t, err)
	assert.True(t, shared.IsValidation(err))
}

func TestCampaignMember_New_EmptyRole(t *testing.T) {
	_, err := pentest.NewCampaignMember(shared.NewID(), shared.NewID(), shared.NewID(), "", nil)
	require.Error(t, err)
}

func TestCampaignMember_New_NilAddedBy(t *testing.T) {
	member, err := pentest.NewCampaignMember(shared.NewID(), shared.NewID(), shared.NewID(), pentest.CampaignRoleTester, nil)
	require.NoError(t, err)
	assert.Nil(t, member.AddedBy())
}

func TestCampaignMember_ChangeRole(t *testing.T) {
	member := createTestMember(t, pentest.CampaignRoleTester)

	err := member.ChangeRole(pentest.CampaignRoleReviewer)
	require.NoError(t, err)
	assert.Equal(t, pentest.CampaignRoleReviewer, member.Role())
}

func TestCampaignMember_ChangeRole_LeadToTester(t *testing.T) {
	member := createTestMember(t, pentest.CampaignRoleLead)

	err := member.ChangeRole(pentest.CampaignRoleTester)
	require.NoError(t, err)
	assert.Equal(t, pentest.CampaignRoleTester, member.Role())
}

func TestCampaignMember_ChangeRole_TesterToObserver(t *testing.T) {
	member := createTestMember(t, pentest.CampaignRoleTester)

	err := member.ChangeRole(pentest.CampaignRoleObserver)
	require.NoError(t, err)
	assert.Equal(t, pentest.CampaignRoleObserver, member.Role())
}

func TestCampaignMember_ChangeRole_Invalid(t *testing.T) {
	member := createTestMember(t, pentest.CampaignRoleTester)

	err := member.ChangeRole("invalid")
	require.Error(t, err)
	assert.Equal(t, pentest.CampaignRoleTester, member.Role()) // unchanged
}

func TestCampaignMember_ChangeRole_SameRole(t *testing.T) {
	member := createTestMember(t, pentest.CampaignRoleTester)

	// Changing to same role should succeed (idempotent)
	err := member.ChangeRole(pentest.CampaignRoleTester)
	require.NoError(t, err)
	assert.Equal(t, pentest.CampaignRoleTester, member.Role())
}

// =============================================================================
// 3. Status Transition × Role — FULL Matrix (6.2)
//    Tests ALL 4 roles × ALL transitions to ensure no gaps
// =============================================================================

func TestPentestStatusTransitionRoles_AllowedTransitions(t *testing.T) {
	allowed := []struct {
		name string
		from string
		to   string
		role pentest.CampaignRole
	}{
		// === LEAD: can do ALL transitions ===
		{"lead: draft→confirmed", "draft", "confirmed", pentest.CampaignRoleLead},
		{"lead: draft→in_review", "draft", "in_review", pentest.CampaignRoleLead},
		{"lead: draft→false_positive", "draft", "false_positive", pentest.CampaignRoleLead},
		{"lead: draft→accepted_risk", "draft", "accepted_risk", pentest.CampaignRoleLead},
		{"lead: in_review→confirmed", "in_review", "confirmed", pentest.CampaignRoleLead},
		{"lead: in_review→false_positive", "in_review", "false_positive", pentest.CampaignRoleLead},
		{"lead: in_review→accepted_risk", "in_review", "accepted_risk", pentest.CampaignRoleLead},
		{"lead: confirmed→remediation", "confirmed", "remediation", pentest.CampaignRoleLead},
		{"lead: confirmed→false_positive", "confirmed", "false_positive", pentest.CampaignRoleLead},
		{"lead: confirmed→accepted_risk", "confirmed", "accepted_risk", pentest.CampaignRoleLead},
		{"lead: remediation→retest", "remediation", "retest", pentest.CampaignRoleLead},
		{"lead: remediation→false_positive", "remediation", "false_positive", pentest.CampaignRoleLead},
		{"lead: remediation→accepted_risk", "remediation", "accepted_risk", pentest.CampaignRoleLead},
		{"lead: retest→verified", "retest", "verified", pentest.CampaignRoleLead},
		{"lead: retest→remediation", "retest", "remediation", pentest.CampaignRoleLead},
		{"lead: retest→false_positive", "retest", "false_positive", pentest.CampaignRoleLead},
		{"lead: retest→accepted_risk", "retest", "accepted_risk", pentest.CampaignRoleLead},
		{"lead: verified→remediation", "verified", "remediation", pentest.CampaignRoleLead},
		{"lead: false_positive→draft", "false_positive", "draft", pentest.CampaignRoleLead},
		{"lead: false_positive→confirmed", "false_positive", "confirmed", pentest.CampaignRoleLead},
		{"lead: accepted_risk→draft", "accepted_risk", "draft", pentest.CampaignRoleLead},
		{"lead: accepted_risk→confirmed", "accepted_risk", "confirmed", pentest.CampaignRoleLead},

		// === TESTER: limited to submit + remediation flow ===
		{"tester: draft→in_review", "draft", "in_review", pentest.CampaignRoleTester},
		{"tester: confirmed→remediation", "confirmed", "remediation", pentest.CampaignRoleTester},
		{"tester: remediation→retest", "remediation", "retest", pentest.CampaignRoleTester},

		// === REVIEWER: quality assurance transitions ===
		{"reviewer: in_review→confirmed", "in_review", "confirmed", pentest.CampaignRoleReviewer},
		{"reviewer: confirmed→remediation", "confirmed", "remediation", pentest.CampaignRoleReviewer},
		{"reviewer: remediation→retest", "remediation", "retest", pentest.CampaignRoleReviewer},
		{"reviewer: retest→verified", "retest", "verified", pentest.CampaignRoleReviewer},
		{"reviewer: confirmed→false_positive", "confirmed", "false_positive", pentest.CampaignRoleReviewer},
		{"reviewer: confirmed→accepted_risk", "confirmed", "accepted_risk", pentest.CampaignRoleReviewer},
		{"reviewer: remediation→false_positive", "remediation", "false_positive", pentest.CampaignRoleReviewer},
		{"reviewer: remediation→accepted_risk", "remediation", "accepted_risk", pentest.CampaignRoleReviewer},
		{"reviewer: retest→false_positive", "retest", "false_positive", pentest.CampaignRoleReviewer},
		{"reviewer: retest→accepted_risk", "retest", "accepted_risk", pentest.CampaignRoleReviewer},
		{"reviewer: retest→remediation", "retest", "remediation", pentest.CampaignRoleReviewer},
		{"reviewer: verified→remediation", "verified", "remediation", pentest.CampaignRoleReviewer},
		{"reviewer: false_positive→draft", "false_positive", "draft", pentest.CampaignRoleReviewer},
		{"reviewer: false_positive→confirmed", "false_positive", "confirmed", pentest.CampaignRoleReviewer},
		{"reviewer: accepted_risk→draft", "accepted_risk", "draft", pentest.CampaignRoleReviewer},
		{"reviewer: accepted_risk→confirmed", "accepted_risk", "confirmed", pentest.CampaignRoleReviewer},
	}

	for _, tc := range allowed {
		t.Run(tc.name, func(t *testing.T) {
			assert.True(t, pentest.IsTransitionAllowedForRole(tc.from, tc.to, tc.role),
				"expected %s→%s ALLOWED for %s", tc.from, tc.to, tc.role)
		})
	}
}

func TestPentestStatusTransitionRoles_DeniedTransitions(t *testing.T) {
	denied := []struct {
		name string
		from string
		to   string
		role pentest.CampaignRole
	}{
		// === TESTER cannot confirm/verify/false_positive/accepted_risk ===
		{"tester: draft→confirmed DENIED (bypass review)", "draft", "confirmed", pentest.CampaignRoleTester},
		{"tester: in_review→confirmed DENIED", "in_review", "confirmed", pentest.CampaignRoleTester},
		{"tester: retest→verified DENIED (bypass reviewer)", "retest", "verified", pentest.CampaignRoleTester},
		{"tester: draft→false_positive DENIED", "draft", "false_positive", pentest.CampaignRoleTester},
		{"tester: confirmed→false_positive DENIED", "confirmed", "false_positive", pentest.CampaignRoleTester},
		{"tester: confirmed→accepted_risk DENIED", "confirmed", "accepted_risk", pentest.CampaignRoleTester},
		{"tester: verified→remediation DENIED", "verified", "remediation", pentest.CampaignRoleTester},
		{"tester: false_positive→draft DENIED", "false_positive", "draft", pentest.CampaignRoleTester},
		{"tester: accepted_risk→draft DENIED", "accepted_risk", "draft", pentest.CampaignRoleTester},

		// === REVIEWER cannot create (draft→in_review) ===
		{"reviewer: draft→in_review DENIED", "draft", "in_review", pentest.CampaignRoleReviewer},
		{"reviewer: draft→confirmed DENIED", "draft", "confirmed", pentest.CampaignRoleReviewer},

		// === OBSERVER cannot do ANY transition ===
		{"observer: draft→in_review DENIED", "draft", "in_review", pentest.CampaignRoleObserver},
		{"observer: draft→confirmed DENIED", "draft", "confirmed", pentest.CampaignRoleObserver},
		{"observer: in_review→confirmed DENIED", "in_review", "confirmed", pentest.CampaignRoleObserver},
		{"observer: confirmed→remediation DENIED", "confirmed", "remediation", pentest.CampaignRoleObserver},
		{"observer: remediation→retest DENIED", "remediation", "retest", pentest.CampaignRoleObserver},
		{"observer: retest→verified DENIED", "retest", "verified", pentest.CampaignRoleObserver},
		{"observer: confirmed→false_positive DENIED", "confirmed", "false_positive", pentest.CampaignRoleObserver},
		{"observer: verified→remediation DENIED", "verified", "remediation", pentest.CampaignRoleObserver},
	}

	for _, tc := range denied {
		t.Run(tc.name, func(t *testing.T) {
			assert.False(t, pentest.IsTransitionAllowedForRole(tc.from, tc.to, tc.role),
				"expected %s→%s DENIED for %s", tc.from, tc.to, tc.role)
		})
	}
}

func TestPentestStatusTransitionRoles_InvalidTransition(t *testing.T) {
	// Transition not in domain (e.g., draft→verified) should be denied for ALL roles
	allRoles := []pentest.CampaignRole{
		pentest.CampaignRoleLead, pentest.CampaignRoleTester,
		pentest.CampaignRoleReviewer, pentest.CampaignRoleObserver,
	}
	invalidTransitions := []struct{ from, to string }{
		{"draft", "verified"},
		{"draft", "remediation"},
		{"draft", "retest"},
		{"in_review", "remediation"},
		{"in_review", "retest"},
		{"in_review", "verified"},
		{"confirmed", "verified"},
		{"confirmed", "retest"},
		{"remediation", "confirmed"},
		{"verified", "confirmed"},
		{"verified", "draft"},
	}
	for _, tr := range invalidTransitions {
		for _, role := range allRoles {
			assert.False(t, pentest.IsTransitionAllowedForRole(tr.from, tr.to, role),
				"invalid transition %s→%s should be denied for %s", tr.from, tr.to, role)
		}
	}
}

// =============================================================================
// 4. Finding Ownership — Complete Coverage (6.3, 6.10, 6.11, 6.20, E7-E10, E30)
// =============================================================================

func TestRequireFindingOwnership_LeadBypass_Edit(t *testing.T) {
	userID := shared.NewID()
	otherID := shared.NewID()
	err := pentest.RequireFindingOwnership(&otherID, nil, userID, pentest.CampaignRoleLead, "edit")
	assert.NoError(t, err, "lead can edit any finding")
}

func TestRequireFindingOwnership_LeadBypass_Delete(t *testing.T) {
	userID := shared.NewID()
	otherID := shared.NewID()
	err := pentest.RequireFindingOwnership(&otherID, nil, userID, pentest.CampaignRoleLead, "delete")
	assert.NoError(t, err, "lead can delete any finding")
}

func TestRequireFindingOwnership_LeadBypass_Status(t *testing.T) {
	userID := shared.NewID()
	otherID := shared.NewID()
	err := pentest.RequireFindingOwnership(&otherID, nil, userID, pentest.CampaignRoleLead, "status")
	assert.NoError(t, err, "lead can change status of any finding")
}

func TestRequireFindingOwnership_TesterCreator_Edit(t *testing.T) {
	userID := shared.NewID()
	err := pentest.RequireFindingOwnership(&userID, nil, userID, pentest.CampaignRoleTester, "edit")
	assert.NoError(t, err, "tester can edit own finding")
}

func TestRequireFindingOwnership_TesterCreator_Delete(t *testing.T) {
	userID := shared.NewID()
	err := pentest.RequireFindingOwnership(&userID, nil, userID, pentest.CampaignRoleTester, "delete")
	assert.NoError(t, err, "tester can delete own finding")
}

func TestRequireFindingOwnership_TesterCreator_Status(t *testing.T) {
	userID := shared.NewID()
	err := pentest.RequireFindingOwnership(&userID, nil, userID, pentest.CampaignRoleTester, "status")
	assert.NoError(t, err, "tester can change status of own finding")
}

func TestRequireFindingOwnership_TesterAssignee_Edit(t *testing.T) {
	creator := shared.NewID()
	assignee := shared.NewID()
	err := pentest.RequireFindingOwnership(&creator, &assignee, assignee, pentest.CampaignRoleTester, "edit")
	assert.NoError(t, err, "E7: assignee can edit assigned finding")
}

func TestRequireFindingOwnership_TesterAssignee_CannotDelete(t *testing.T) {
	creator := shared.NewID()
	assignee := shared.NewID()
	err := pentest.RequireFindingOwnership(&creator, &assignee, assignee, pentest.CampaignRoleTester, "delete")
	assert.Error(t, err, "E8: assignee CANNOT delete, only creator can")
}

func TestRequireFindingOwnership_TesterAssignee_Status(t *testing.T) {
	creator := shared.NewID()
	assignee := shared.NewID()
	// E30: Assignee can submit for review (status change)
	err := pentest.RequireFindingOwnership(&creator, &assignee, assignee, pentest.CampaignRoleTester, "status")
	assert.NoError(t, err, "E30: assignee can change status (e.g., draft→in_review)")
}

func TestRequireFindingOwnership_TesterOther_EditDenied(t *testing.T) {
	creator := shared.NewID()
	otherUser := shared.NewID()
	err := pentest.RequireFindingOwnership(&creator, nil, otherUser, pentest.CampaignRoleTester, "edit")
	assert.Error(t, err, "tester cannot edit finding they didn't create and aren't assigned to")
}

func TestRequireFindingOwnership_TesterOther_DeleteDenied(t *testing.T) {
	creator := shared.NewID()
	otherUser := shared.NewID()
	err := pentest.RequireFindingOwnership(&creator, nil, otherUser, pentest.CampaignRoleTester, "delete")
	assert.Error(t, err, "tester cannot delete finding they didn't create")
}

func TestRequireFindingOwnership_TesterOther_StatusDenied(t *testing.T) {
	creator := shared.NewID()
	otherUser := shared.NewID()
	err := pentest.RequireFindingOwnership(&creator, nil, otherUser, pentest.CampaignRoleTester, "status")
	assert.Error(t, err, "tester cannot change status of unrelated finding")
}

func TestRequireFindingOwnership_NilCreatedBy_TesterDenied(t *testing.T) {
	userID := shared.NewID()
	// E9: created_by = nil (user deleted) → tester denied
	err := pentest.RequireFindingOwnership(nil, nil, userID, pentest.CampaignRoleTester, "edit")
	assert.Error(t, err, "E9: nil created_by → tester cannot edit")
	err = pentest.RequireFindingOwnership(nil, nil, userID, pentest.CampaignRoleTester, "delete")
	assert.Error(t, err, "E9: nil created_by → tester cannot delete")
}

func TestRequireFindingOwnership_NilCreatedBy_LeadCanEdit(t *testing.T) {
	userID := shared.NewID()
	// E9: lead bypass works even with nil created_by
	err := pentest.RequireFindingOwnership(nil, nil, userID, pentest.CampaignRoleLead, "edit")
	assert.NoError(t, err, "E9: lead can edit finding with nil created_by")
	err = pentest.RequireFindingOwnership(nil, nil, userID, pentest.CampaignRoleLead, "delete")
	assert.NoError(t, err, "E9: lead can delete finding with nil created_by")
}

func TestRequireFindingOwnership_NilCreatedBy_ButAssigned_TesterCanEdit(t *testing.T) {
	assignee := shared.NewID()
	// created_by nil but user is assignee → can edit (not delete)
	err := pentest.RequireFindingOwnership(nil, &assignee, assignee, pentest.CampaignRoleTester, "edit")
	assert.NoError(t, err, "assignee can edit even if created_by is nil")
	err = pentest.RequireFindingOwnership(nil, &assignee, assignee, pentest.CampaignRoleTester, "delete")
	assert.Error(t, err, "assignee cannot delete even if created_by is nil")
}

func TestRequireFindingOwnership_BothCreatorAndAssignee(t *testing.T) {
	userID := shared.NewID()
	// User is both creator AND assignee — all actions allowed for tester
	err := pentest.RequireFindingOwnership(&userID, &userID, userID, pentest.CampaignRoleTester, "edit")
	assert.NoError(t, err)
	err = pentest.RequireFindingOwnership(&userID, &userID, userID, pentest.CampaignRoleTester, "delete")
	assert.NoError(t, err)
	err = pentest.RequireFindingOwnership(&userID, &userID, userID, pentest.CampaignRoleTester, "status")
	assert.NoError(t, err)
}

// E1: Role change tester→observer loses edit on own findings
// This is tested implicitly: observer never reaches ownership check because
// requireCampaignAccess("lead","tester") fails for observer BEFORE ownership check.
// We verify the authorization flow order here:
func TestE1_RoleChangeObserver_OwnershipIrrelevant(t *testing.T) {
	// Observer role: CanWriteFindings = false → service rejects before ownership check
	assert.False(t, pentest.CampaignRoleObserver.CanWriteFindings(),
		"E1: observer cannot write findings regardless of ownership")
	// Observer: no transitions allowed
	assert.False(t, pentest.IsTransitionAllowedForRole("draft", "in_review", pentest.CampaignRoleObserver),
		"E1: observer cannot transition finding status")
}

// =============================================================================
// 5. Campaign Lock — All Statuses (6.6, E15)
// =============================================================================

func TestCampaignWritable_Planning_AllowAll(t *testing.T) {
	assert.NoError(t, pentest.RequireCampaignWritable(pentest.CampaignStatusPlanning, false))
	assert.NoError(t, pentest.RequireCampaignWritable(pentest.CampaignStatusPlanning, true))
}

func TestCampaignWritable_InProgress_AllowAll(t *testing.T) {
	assert.NoError(t, pentest.RequireCampaignWritable(pentest.CampaignStatusInProgress, false))
	assert.NoError(t, pentest.RequireCampaignWritable(pentest.CampaignStatusInProgress, true))
}

func TestCampaignWritable_OnHold_BlockNewAllowExisting(t *testing.T) {
	err := pentest.RequireCampaignWritable(pentest.CampaignStatusOnHold, false)
	assert.Error(t, err, "E15: on_hold blocks new findings")

	err = pentest.RequireCampaignWritable(pentest.CampaignStatusOnHold, true)
	assert.NoError(t, err, "on_hold allows updating existing findings")
}

func TestCampaignWritable_Completed_BlockAll(t *testing.T) {
	assert.Error(t, pentest.RequireCampaignWritable(pentest.CampaignStatusCompleted, false))
	assert.Error(t, pentest.RequireCampaignWritable(pentest.CampaignStatusCompleted, true))
}

func TestCampaignWritable_Cancelled_BlockAll(t *testing.T) {
	assert.Error(t, pentest.RequireCampaignWritable(pentest.CampaignStatusCanceled, false))
	assert.Error(t, pentest.RequireCampaignWritable(pentest.CampaignStatusCanceled, true))
}

// =============================================================================
// 6. Campaign Status Transitions (6.13)
// =============================================================================

func TestCampaignStatusTransition_CancelledToPlanning(t *testing.T) {
	// E12: canceled → planning (undo accidental cancel)
	transitions := pentest.CampaignStatusTransitions
	allowed, ok := transitions[pentest.CampaignStatusCanceled]
	require.True(t, ok, "canceled should have transitions defined")
	assert.Contains(t, allowed, pentest.CampaignStatusPlanning,
		"E12: canceled should allow transition to planning")
}

func TestCampaignStatusTransition_CompletedNotTerminal(t *testing.T) {
	// completed → in_progress (reopen)
	transitions := pentest.CampaignStatusTransitions
	allowed := transitions[pentest.CampaignStatusCompleted]
	assert.Contains(t, allowed, pentest.CampaignStatusInProgress,
		"completed should allow reopen to in_progress")
}

func TestCampaignStatusTransition_AllExistingTransitionsPreserved(t *testing.T) {
	// Verify existing transitions aren't broken by our changes
	transitions := pentest.CampaignStatusTransitions

	// planning → in_progress, canceled
	assert.Contains(t, transitions[pentest.CampaignStatusPlanning], pentest.CampaignStatusInProgress)
	assert.Contains(t, transitions[pentest.CampaignStatusPlanning], pentest.CampaignStatusCanceled)

	// in_progress → on_hold, completed, canceled
	assert.Contains(t, transitions[pentest.CampaignStatusInProgress], pentest.CampaignStatusOnHold)
	assert.Contains(t, transitions[pentest.CampaignStatusInProgress], pentest.CampaignStatusCompleted)
	assert.Contains(t, transitions[pentest.CampaignStatusInProgress], pentest.CampaignStatusCanceled)

	// on_hold → in_progress, canceled
	assert.Contains(t, transitions[pentest.CampaignStatusOnHold], pentest.CampaignStatusInProgress)
	assert.Contains(t, transitions[pentest.CampaignStatusOnHold], pentest.CampaignStatusCanceled)
}

// =============================================================================
// 7. Assign Validation (6.19, E29)
// =============================================================================

func TestValidateAssigneeRole_Lead(t *testing.T) {
	assert.NoError(t, pentest.ValidateAssigneeRole(pentest.CampaignRoleLead))
}

func TestValidateAssigneeRole_Tester(t *testing.T) {
	assert.NoError(t, pentest.ValidateAssigneeRole(pentest.CampaignRoleTester))
}

func TestValidateAssigneeRole_Reviewer(t *testing.T) {
	assert.NoError(t, pentest.ValidateAssigneeRole(pentest.CampaignRoleReviewer))
}

func TestValidateAssigneeRole_ObserverDenied(t *testing.T) {
	// E29: Cannot assign finding to observer
	err := pentest.ValidateAssigneeRole(pentest.CampaignRoleObserver)
	assert.Error(t, err, "E29: should deny assigning to observer")
	assert.True(t, shared.IsValidation(err))
}

func TestValidateAssigneeRole_InvalidRoleDenied(t *testing.T) {
	err := pentest.ValidateAssigneeRole("invalid")
	assert.Error(t, err)
}

// =============================================================================
// 8. CTEM Status Mapping (6.16, 6.17, E22-E28)
// =============================================================================

func TestCTEMStatusMapping_DraftExcluded(t *testing.T) {
	// E23: Draft = Phase 4 internal → excluded from CTEM dashboard
	_, excluded := pentest.MapToCTEMStatus("draft")
	assert.True(t, excluded, "E23: draft should be excluded from dashboard")
}

func TestCTEMStatusMapping_InReviewExcluded(t *testing.T) {
	_, excluded := pentest.MapToCTEMStatus("in_review")
	assert.True(t, excluded, "in_review should be excluded from dashboard")
}

func TestCTEMStatusMapping_ConfirmedPassthrough(t *testing.T) {
	mapped, excluded := pentest.MapToCTEMStatus("confirmed")
	assert.False(t, excluded)
	assert.Equal(t, "confirmed", mapped, "confirmed maps to confirmed (Phase 4→5 handoff)")
}

func TestCTEMStatusMapping_RemediationToInProgress(t *testing.T) {
	mapped, excluded := pentest.MapToCTEMStatus("remediation")
	assert.False(t, excluded)
	assert.Equal(t, "in_progress", mapped, "E27: remediation → in_progress")
}

func TestCTEMStatusMapping_RetestToFixApplied(t *testing.T) {
	mapped, excluded := pentest.MapToCTEMStatus("retest")
	assert.False(t, excluded)
	assert.Equal(t, "fix_applied", mapped, "E28: retest → fix_applied (fix done, awaiting verify)")
}

func TestCTEMStatusMapping_VerifiedToResolved(t *testing.T) {
	mapped, excluded := pentest.MapToCTEMStatus("verified")
	assert.False(t, excluded)
	assert.Equal(t, "resolved", mapped, "E22: verified → resolved")
}

func TestCTEMStatusMapping_FalsePositivePassthrough(t *testing.T) {
	mapped, excluded := pentest.MapToCTEMStatus("false_positive")
	assert.False(t, excluded)
	assert.Equal(t, "false_positive", mapped)
}

func TestCTEMStatusMapping_AcceptedRiskPassthrough(t *testing.T) {
	mapped, excluded := pentest.MapToCTEMStatus("accepted_risk")
	assert.False(t, excluded)
	assert.Equal(t, "accepted_risk", mapped)
}

func TestCTEMStatusMapping_UnknownStatus(t *testing.T) {
	// Unknown status should pass through unchanged
	mapped, excluded := pentest.MapToCTEMStatus("unknown_status")
	assert.False(t, excluded)
	assert.Equal(t, "unknown_status", mapped)
}

// =============================================================================
// 9. Scope Validation (6.18, E25)
// =============================================================================

func TestValidateFindingScope_InScope(t *testing.T) {
	assetID := shared.NewID()
	scopeAssetIDs := []string{assetID.String(), shared.NewID().String()}

	warning := pentest.ValidateFindingScope(scopeAssetIDs, nil, assetID.String())
	assert.Empty(t, warning, "asset in scope → no warning")
}

func TestValidateFindingScope_OutOfScope(t *testing.T) {
	assetID := shared.NewID()
	scopeAssetIDs := []string{shared.NewID().String()}

	// E25: Allowed but with warning
	warning := pentest.ValidateFindingScope(scopeAssetIDs, nil, assetID.String())
	assert.NotEmpty(t, warning, "E25: asset not in scope → warning")
}

func TestValidateFindingScope_NoScopeDefined(t *testing.T) {
	assetID := shared.NewID()
	// No scope = no validation = no warning
	warning := pentest.ValidateFindingScope(nil, nil, assetID.String())
	assert.Empty(t, warning, "no scope defined → skip validation")
}

func TestValidateFindingScope_EmptyScope(t *testing.T) {
	assetID := shared.NewID()
	// Empty arrays = no scope defined
	warning := pentest.ValidateFindingScope([]string{}, []string{}, assetID.String())
	assert.Empty(t, warning, "empty scope arrays → skip validation")
}

func TestValidateFindingScope_InAssetGroup(t *testing.T) {
	assetID := shared.NewID()
	groupID := shared.NewID()

	// Asset not in direct scope but in a group
	// Scope validation only checks assetIDs (group membership checked elsewhere)
	// If only groups defined (no assetIDs), skip direct asset check
	warning := pentest.ValidateFindingScope(nil, []string{groupID.String()}, assetID.String())
	assert.Empty(t, warning, "only groups defined → skip direct asset check")
}

// =============================================================================
// 10. Retest → Finding Status per Role (6.7)
// =============================================================================

func TestResolveRetestFindingStatus_PassedByLead(t *testing.T) {
	status := pentest.ResolveRetestFindingStatus("passed", pentest.CampaignRoleLead)
	assert.Equal(t, "verified", status, "lead passed → verified")
}

func TestResolveRetestFindingStatus_PassedByReviewer(t *testing.T) {
	status := pentest.ResolveRetestFindingStatus("passed", pentest.CampaignRoleReviewer)
	assert.Equal(t, "verified", status, "reviewer passed → verified")
}

func TestResolveRetestFindingStatus_PassedByTester_NoAutoVerify(t *testing.T) {
	// CRITICAL: tester "passed" should NOT auto-verify (security gap fix)
	status := pentest.ResolveRetestFindingStatus("passed", pentest.CampaignRoleTester)
	assert.Empty(t, status, "tester passed → NO status change (stays at retest)")
}

func TestResolveRetestFindingStatus_FailedByAnyRole(t *testing.T) {
	roles := []pentest.CampaignRole{
		pentest.CampaignRoleLead,
		pentest.CampaignRoleTester,
		pentest.CampaignRoleReviewer,
	}
	for _, role := range roles {
		status := pentest.ResolveRetestFindingStatus("failed", role)
		assert.Equal(t, "remediation", status, "failed → remediation for %s", role)
	}
}

func TestResolveRetestFindingStatus_PartialNoChange(t *testing.T) {
	roles := []pentest.CampaignRole{
		pentest.CampaignRoleLead,
		pentest.CampaignRoleTester,
		pentest.CampaignRoleReviewer,
	}
	for _, role := range roles {
		status := pentest.ResolveRetestFindingStatus("partial", role)
		assert.Empty(t, status, "partial → no change for %s", role)
	}
}

func TestResolveRetestFindingStatus_CancelledNoChange(t *testing.T) {
	status := pentest.ResolveRetestFindingStatus("canceled", pentest.CampaignRoleLead)
	assert.Empty(t, status, "canceled retest → no status change")
}

// =============================================================================
// 11. Role × CRUD Permission Matrix (6.1)
//     Tests which roles can do which operations
// =============================================================================

func TestRolePermissionMatrix_CampaignOperations(t *testing.T) {
	tests := []struct {
		operation string
		role      pentest.CampaignRole
		allowed   bool
	}{
		// Campaign management: lead only
		{"manage_campaign", pentest.CampaignRoleLead, true},
		{"manage_campaign", pentest.CampaignRoleTester, false},
		{"manage_campaign", pentest.CampaignRoleReviewer, false},
		{"manage_campaign", pentest.CampaignRoleObserver, false},
		// Create finding: lead + tester
		{"write_finding", pentest.CampaignRoleLead, true},
		{"write_finding", pentest.CampaignRoleTester, true},
		{"write_finding", pentest.CampaignRoleReviewer, false},
		{"write_finding", pentest.CampaignRoleObserver, false},
		// Team management: lead only
		{"manage_team", pentest.CampaignRoleLead, true},
		{"manage_team", pentest.CampaignRoleTester, false},
		{"manage_team", pentest.CampaignRoleReviewer, false},
		{"manage_team", pentest.CampaignRoleObserver, false},
		// Generate report: lead only
		{"generate_report", pentest.CampaignRoleLead, true},
		{"generate_report", pentest.CampaignRoleTester, false},
		{"generate_report", pentest.CampaignRoleReviewer, false},
		{"generate_report", pentest.CampaignRoleObserver, false},
		// Upload evidence: lead + tester + reviewer
		{"upload_evidence", pentest.CampaignRoleLead, true},
		{"upload_evidence", pentest.CampaignRoleTester, true},
		{"upload_evidence", pentest.CampaignRoleReviewer, true},
		{"upload_evidence", pentest.CampaignRoleObserver, false},
		// Submit retest: lead + tester + reviewer
		{"submit_retest", pentest.CampaignRoleLead, true},
		{"submit_retest", pentest.CampaignRoleTester, true},
		{"submit_retest", pentest.CampaignRoleReviewer, true},
		{"submit_retest", pentest.CampaignRoleObserver, false},
	}

	for _, tc := range tests {
		t.Run(tc.operation+"_"+string(tc.role), func(t *testing.T) {
			var result bool
			switch tc.operation {
			case "manage_campaign":
				result = tc.role.CanManageCampaign()
			case "write_finding":
				result = tc.role.CanWriteFindings()
			case "manage_team":
				result = tc.role.CanManageTeam()
			case "generate_report":
				result = tc.role.CanGenerateReport()
			case "upload_evidence":
				result = tc.role.CanUploadEvidence()
			case "submit_retest":
				result = tc.role.CanSubmitRetest()
			}
			assert.Equal(t, tc.allowed, result)
		})
	}
}

// =============================================================================
// 12. Lead Integrity Domain Rules (6.5)
// =============================================================================

func TestCampaignRole_IsLead(t *testing.T) {
	assert.True(t, pentest.CampaignRoleLead.IsLead())
	assert.False(t, pentest.CampaignRoleTester.IsLead())
	assert.False(t, pentest.CampaignRoleReviewer.IsLead())
	assert.False(t, pentest.CampaignRoleObserver.IsLead())
}

// =============================================================================
// 13. CampaignMember Reconstitute (for loading from DB)
// =============================================================================

func TestCampaignMember_Reconstitute(t *testing.T) {
	id := shared.NewID()
	tenantID := shared.NewID()
	campaignID := shared.NewID()
	userID := shared.NewID()
	addedBy := shared.NewID()

	member := pentest.ReconstituteCampaignMember(
		id, tenantID, campaignID, userID,
		pentest.CampaignRoleLead, &addedBy,
		mustParseTime(t, "2026-03-21T10:00:00Z"),
	)

	assert.Equal(t, id, member.ID())
	assert.Equal(t, tenantID, member.TenantID())
	assert.Equal(t, campaignID, member.CampaignID())
	assert.Equal(t, userID, member.UserID())
	assert.Equal(t, pentest.CampaignRoleLead, member.Role())
	assert.Equal(t, &addedBy, member.AddedBy())
}

// =============================================================================
// Helpers
// =============================================================================

func createTestMember(t *testing.T, role pentest.CampaignRole) *pentest.CampaignMember {
	t.Helper()
	member, err := pentest.NewCampaignMember(
		shared.NewID(), shared.NewID(), shared.NewID(), role, nil,
	)
	require.NoError(t, err)
	return member
}

func stubContext() context.Context {
	return context.Background()
}

func mustParseTime(t *testing.T, s string) time.Time {
	t.Helper()
	parsed, err := time.Parse(time.RFC3339, s)
	require.NoError(t, err)
	return parsed
}

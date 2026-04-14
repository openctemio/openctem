package unit

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/openctemio/api/internal/app"
	"github.com/openctemio/api/pkg/domain/pentest"
	"github.com/openctemio/api/pkg/domain/shared"
)

// =============================================================================
// Edge cases for AddCampaignMember (RFC E5, E6 + cross-tenant injection)
// =============================================================================

func TestAddCampaignMember_CrossTenantInjection_Blocked(t *testing.T) {
	// SECURITY: an admin in tenant A should not be able to add members to a
	// campaign in tenant B by guessing the campaign UUID. The service must
	// verify the campaign exists in the caller's tenant before inserting.
	svc, campaignRepo, _ := newTeamTestService(t)
	ctx := context.Background()

	// Caller's tenant: no campaign matches → GetByID returns nil + error.
	campaignRepo.getByID = nil
	campaignRepo.getByIDErr = pentest.ErrCampaignNotFound

	_, err := svc.AddCampaignMember(ctx, app.CampaignAddMemberInput{
		TenantID:   shared.NewID().String(),
		CampaignID: shared.NewID().String(), // foreign campaign UUID
		UserID:     shared.NewID().String(),
		Role:       "tester",
		ActorID:    shared.NewID().String(),
	})

	if err == nil {
		t.Fatal("expected cross-tenant injection to be blocked")
	}
	if !errors.Is(err, pentest.ErrCampaignNotFound) {
		t.Errorf("expected ErrCampaignNotFound (404 mapping), got %v", err)
	}
}

// =============================================================================
// Edge cases for ResolveRetestFindingStatus role × result matrix (RFC §3.7)
// =============================================================================

func TestResolveRetestFindingStatus_AllCombinations(t *testing.T) {
	tests := []struct {
		name   string
		result string
		role   pentest.CampaignRole
		want   string
	}{
		{"lead+passed", "passed", pentest.CampaignRoleLead, "verified"},
		{"reviewer+passed", "passed", pentest.CampaignRoleReviewer, "verified"},
		{"tester+passed", "passed", pentest.CampaignRoleTester, ""},
		{"observer+passed", "passed", pentest.CampaignRoleObserver, ""},
		{"lead+failed", "failed", pentest.CampaignRoleLead, "remediation"},
		{"tester+failed", "failed", pentest.CampaignRoleTester, "remediation"},
		{"reviewer+failed", "failed", pentest.CampaignRoleReviewer, "remediation"},
		{"observer+failed", "failed", pentest.CampaignRoleObserver, "remediation"},
		{"any+partial", "partial", pentest.CampaignRoleLead, ""},
		{"any+canceled", "canceled", pentest.CampaignRoleLead, ""},
		{"unknown+passed", "passed", pentest.CampaignRole("ghost"), ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := pentest.ResolveRetestFindingStatus(tc.result, tc.role)
			if got != tc.want {
				t.Errorf("result=%q role=%q: want %q, got %q", tc.result, tc.role, tc.want, got)
			}
		})
	}
}

// =============================================================================
// Edge cases for IsTransitionAllowedForRole
// =============================================================================

func TestIsTransitionAllowedForRole_Matrix(t *testing.T) {
	type tc struct {
		from, to string
		role     pentest.CampaignRole
		want     bool
	}
	tests := []tc{
		// Lead always allowed for any defined transition
		{"draft", "confirmed", pentest.CampaignRoleLead, true},
		{"draft", "in_review", pentest.CampaignRoleLead, true},
		{"in_review", "confirmed", pentest.CampaignRoleLead, true},
		{"confirmed", "remediation", pentest.CampaignRoleLead, true},
		{"retest", "verified", pentest.CampaignRoleLead, true},

		// Tester: only own draft→in_review, confirmed→remediation, remediation→retest
		{"draft", "in_review", pentest.CampaignRoleTester, true},
		{"draft", "confirmed", pentest.CampaignRoleTester, false}, // skip review
		{"in_review", "confirmed", pentest.CampaignRoleTester, false},
		{"confirmed", "remediation", pentest.CampaignRoleTester, true},
		{"remediation", "retest", pentest.CampaignRoleTester, true},
		{"retest", "verified", pentest.CampaignRoleTester, false}, // security: no auto-verify

		// Reviewer: review + verify
		{"in_review", "confirmed", pentest.CampaignRoleReviewer, true},
		{"retest", "verified", pentest.CampaignRoleReviewer, true},
		{"draft", "confirmed", pentest.CampaignRoleReviewer, false},
		{"draft", "in_review", pentest.CampaignRoleReviewer, false},

		// Observer: nothing
		{"draft", "in_review", pentest.CampaignRoleObserver, false},
		{"in_review", "confirmed", pentest.CampaignRoleObserver, false},
		{"retest", "verified", pentest.CampaignRoleObserver, false},
	}
	for _, c := range tests {
		got := pentest.IsTransitionAllowedForRole(c.from, c.to, c.role)
		if got != c.want {
			t.Errorf("transition %s→%s as %s: want %v, got %v", c.from, c.to, c.role, c.want, got)
		}
	}
}

// =============================================================================
// Edge cases for RequireCampaignWritable lock semantics
// =============================================================================

func TestRequireCampaignWritable_AllowExistingUpdates(t *testing.T) {
	// On_hold: allowExistingUpdates=true → allow, =false → block
	if err := pentest.RequireCampaignWritable(pentest.CampaignStatusOnHold, true); err != nil {
		t.Errorf("on_hold + allowExistingUpdates: want nil, got %v", err)
	}
	if err := pentest.RequireCampaignWritable(pentest.CampaignStatusOnHold, false); err == nil {
		t.Error("on_hold + !allowExistingUpdates: expected ErrCampaignOnHold")
	}

	// Completed: always blocked regardless of allowExistingUpdates
	if err := pentest.RequireCampaignWritable(pentest.CampaignStatusCompleted, true); err == nil {
		t.Error("completed + true: expected forbidden")
	}
	if err := pentest.RequireCampaignWritable(pentest.CampaignStatusCompleted, false); err == nil {
		t.Error("completed + false: expected forbidden")
	}

	// Canceled: always blocked
	if err := pentest.RequireCampaignWritable(pentest.CampaignStatusCanceled, true); err == nil {
		t.Error("canceled + true: expected forbidden")
	}

	// In_progress, planning: always allowed
	for _, s := range []pentest.CampaignStatus{pentest.CampaignStatusPlanning, pentest.CampaignStatusInProgress} {
		if err := pentest.RequireCampaignWritable(s, false); err != nil {
			t.Errorf("%s: want nil, got %v", s, err)
		}
	}
}

// =============================================================================
// Edge cases for RemoveCampaignMember
// =============================================================================

func TestRemoveCampaignMember_NonExistentMember(t *testing.T) {
	svc, _, memberRepo := newTeamTestService(t)
	ctx := context.Background()

	tenantID := shared.NewID()
	campaignID := shared.NewID()
	leadID := shared.NewID()
	missingUserID := shared.NewID()

	// Lead exists but the target user is not in the campaign
	memberRepo.listByCampaign = []*pentest.CampaignMember{
		pentest.ReconstituteCampaignMember(shared.NewID(), tenantID, campaignID, leadID, pentest.CampaignRoleLead, nil, time.Now()),
	}

	_, err := svc.RemoveCampaignMember(ctx, app.CampaignRemoveMemberInput{
		TenantID:   tenantID.String(),
		CampaignID: campaignID.String(),
		UserID:     missingUserID.String(),
	})

	if err == nil {
		t.Fatal("expected ErrMemberNotFound for missing user")
	}
	if !errors.Is(err, pentest.ErrMemberNotFound) {
		t.Errorf("expected ErrMemberNotFound, got %v", err)
	}
}

// =============================================================================
// Edge cases for UpdateCampaignMemberRole
// =============================================================================

func TestUpdateCampaignMemberRole_PromoteToLead(t *testing.T) {
	svc, _, memberRepo := newTeamTestService(t)
	ctx := context.Background()

	tenantID := shared.NewID()
	campaignID := shared.NewID()
	leadID := shared.NewID()
	testerID := shared.NewID()

	// 1 lead + 1 tester. Promote tester to lead.
	memberRepo.listByCampaign = []*pentest.CampaignMember{
		pentest.ReconstituteCampaignMember(shared.NewID(), tenantID, campaignID, leadID, pentest.CampaignRoleLead, nil, time.Now()),
		pentest.ReconstituteCampaignMember(shared.NewID(), tenantID, campaignID, testerID, pentest.CampaignRoleTester, nil, time.Now()),
	}

	err := svc.UpdateCampaignMemberRole(ctx, app.CampaignUpdateMemberRoleInput{
		TenantID:   tenantID.String(),
		CampaignID: campaignID.String(),
		UserID:     testerID.String(),
		NewRole:    "lead",
		ActorID:    leadID.String(),
	})

	if err != nil {
		t.Fatalf("expected promotion to succeed, got %v", err)
	}
	if !memberRepo.updateRoleCalled {
		t.Error("expected UpdateRole to be called")
	}
}

func TestUpdateCampaignMemberRole_DowngradeNonLast(t *testing.T) {
	svc, _, memberRepo := newTeamTestService(t)
	ctx := context.Background()

	tenantID := shared.NewID()
	campaignID := shared.NewID()
	lead1 := shared.NewID()
	lead2 := shared.NewID()

	// 2 leads. Demoting one is allowed.
	memberRepo.listByCampaign = []*pentest.CampaignMember{
		pentest.ReconstituteCampaignMember(shared.NewID(), tenantID, campaignID, lead1, pentest.CampaignRoleLead, nil, time.Now()),
		pentest.ReconstituteCampaignMember(shared.NewID(), tenantID, campaignID, lead2, pentest.CampaignRoleLead, nil, time.Now()),
	}

	err := svc.UpdateCampaignMemberRole(ctx, app.CampaignUpdateMemberRoleInput{
		TenantID:   tenantID.String(),
		CampaignID: campaignID.String(),
		UserID:     lead1.String(),
		NewRole:    "tester",
	})

	if err != nil {
		t.Errorf("expected lead→tester demote to succeed (2 leads), got %v", err)
	}
}

// Note: CampaignRole_IsLead/IsReadOnly tests are in campaign_rbac_test.go

// =============================================================================
// Edge cases for MapToCTEMStatus (RFC §3.13)
// =============================================================================

func TestMapToCTEMStatus_AllPentestStatuses(t *testing.T) {
	tests := []struct {
		input    string
		mapped   string
		excluded bool
	}{
		{"draft", "", true},
		{"in_review", "", true},
		{"confirmed", "confirmed", false},
		{"remediation", "in_progress", false},
		{"retest", "fix_applied", false},
		{"verified", "resolved", false},
		{"false_positive", "false_positive", false},
		{"accepted_risk", "accepted_risk", false},
		{"unknown_xyz", "unknown_xyz", false}, // pass-through
	}
	for _, tc := range tests {
		mapped, excluded := pentest.MapToCTEMStatus(tc.input)
		if mapped != tc.mapped {
			t.Errorf("MapToCTEMStatus(%q): mapped want %q, got %q", tc.input, tc.mapped, mapped)
		}
		if excluded != tc.excluded {
			t.Errorf("MapToCTEMStatus(%q): excluded want %v, got %v", tc.input, tc.excluded, excluded)
		}
	}
}

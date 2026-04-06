package unit

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/openctemio/api/internal/app"
	"github.com/openctemio/api/pkg/domain/pentest"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/logger"
)

// --- Team management service tests ---

func newTeamTestService(t *testing.T) (*app.PentestService, *teamMockCampaignRepo, *teamMockMemberRepo) {
	t.Helper()
	log := logger.NewNop()
	campaignRepo := &teamMockCampaignRepo{}
	findingRepo := newMockPentestFindingRepo()
	retestRepo := newMockPentestRetestRepo()
	templateRepo := newMockPentestTemplateRepo()
	reportRepo := newMockPentestReportRepo()

	svc := app.NewPentestService(campaignRepo, findingRepo, retestRepo, templateRepo, reportRepo, log)

	memberRepo := &teamMockMemberRepo{}
	svc.SetCampaignMemberRepository(memberRepo)

	return svc, campaignRepo, memberRepo
}

func TestAddCampaignMember_Success(t *testing.T) {
	svc, campaignRepo, memberRepo := newTeamTestService(t)
	ctx := context.Background()

	tenantID := shared.NewID()
	campaignID := shared.NewID()
	userID := shared.NewID()
	actorID := shared.NewID()

	campaign, _ := pentest.NewCampaign(tenantID, "Test Campaign", pentest.CampaignTypeExternal, pentest.CampaignPriorityHigh)
	campaignRepo.getByID = campaign

	member, err := svc.AddCampaignMember(ctx, app.CampaignAddMemberInput{
		TenantID:   tenantID.String(),
		CampaignID: campaignID.String(),
		UserID:     userID.String(),
		Role:       "tester",
		ActorID:    actorID.String(),
	})

	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if member == nil {
		t.Fatal("expected member, got nil")
	}
	if member.Role() != pentest.CampaignRoleTester {
		t.Errorf("expected tester, got %s", member.Role())
	}
	if !memberRepo.createCalled {
		t.Error("expected memberRepo.Create to be called")
	}
}

func TestAddCampaignMember_InvalidRole(t *testing.T) {
	svc, campaignRepo, _ := newTeamTestService(t)
	ctx := context.Background()

	tenantID := shared.NewID()
	campaign, _ := pentest.NewCampaign(tenantID, "Test", pentest.CampaignTypeExternal, pentest.CampaignPriorityHigh)
	campaignRepo.getByID = campaign

	_, err := svc.AddCampaignMember(ctx, app.CampaignAddMemberInput{
		TenantID:   tenantID.String(),
		CampaignID: shared.NewID().String(),
		UserID:     shared.NewID().String(),
		Role:       "hacker",
		ActorID:    shared.NewID().String(),
	})

	if err == nil {
		t.Fatal("expected validation error for invalid role")
	}
	if !shared.IsValidation(err) {
		t.Errorf("expected validation error, got %v", err)
	}
}

func TestAddCampaignMember_DuplicateReturnsConflict(t *testing.T) {
	svc, campaignRepo, memberRepo := newTeamTestService(t)
	ctx := context.Background()

	tenantID := shared.NewID()
	campaign, _ := pentest.NewCampaign(tenantID, "Test", pentest.CampaignTypeExternal, pentest.CampaignPriorityHigh)
	campaignRepo.getByID = campaign
	memberRepo.createErr = pentest.ErrMemberAlreadyExists

	_, err := svc.AddCampaignMember(ctx, app.CampaignAddMemberInput{
		TenantID:   tenantID.String(),
		CampaignID: shared.NewID().String(),
		UserID:     shared.NewID().String(),
		Role:       "tester",
		ActorID:    shared.NewID().String(),
	})

	if err == nil {
		t.Fatal("expected conflict error")
	}
	if !errors.Is(err, shared.ErrConflict) {
		t.Errorf("expected conflict error, got %v", err)
	}
}

func TestRemoveCampaignMember_Success(t *testing.T) {
	svc, _, memberRepo := newTeamTestService(t)
	ctx := context.Background()

	tenantID := shared.NewID()
	campaignID := shared.NewID()
	userID := shared.NewID()
	leadID := shared.NewID()

	// Campaign has 1 lead + 1 tester (target), removal should succeed
	memberRepo.listByCampaign = []*pentest.CampaignMember{
		pentest.ReconstituteCampaignMember(shared.NewID(), tenantID, campaignID, leadID, pentest.CampaignRoleLead, nil, time.Now()),
		pentest.ReconstituteCampaignMember(shared.NewID(), tenantID, campaignID, userID, pentest.CampaignRoleTester, nil, time.Now()),
	}

	err := svc.RemoveCampaignMember(ctx, app.CampaignRemoveMemberInput{
		TenantID:   tenantID.String(),
		CampaignID: campaignID.String(),
		UserID:     userID.String(),
		ActorID:    leadID.String(),
	})

	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if !memberRepo.deleteByUserIDCalled {
		t.Error("expected deleteByUserID to be called")
	}
}

func TestRemoveCampaignMember_LastLeadBlocked(t *testing.T) {
	svc, _, memberRepo := newTeamTestService(t)
	ctx := context.Background()

	tenantID := shared.NewID()
	campaignID := shared.NewID()
	leadID := shared.NewID()

	// Campaign has only 1 lead — removal must fail
	memberRepo.listByCampaign = []*pentest.CampaignMember{
		pentest.ReconstituteCampaignMember(shared.NewID(), tenantID, campaignID, leadID, pentest.CampaignRoleLead, nil, time.Now()),
		pentest.ReconstituteCampaignMember(shared.NewID(), tenantID, campaignID, shared.NewID(), pentest.CampaignRoleObserver, nil, time.Now()),
	}

	err := svc.RemoveCampaignMember(ctx, app.CampaignRemoveMemberInput{
		TenantID:   tenantID.String(),
		CampaignID: campaignID.String(),
		UserID:     leadID.String(),
	})

	if err == nil {
		t.Fatal("expected error when removing last lead")
	}
	if !errors.Is(err, pentest.ErrLastLead) {
		t.Errorf("expected ErrLastLead, got %v", err)
	}
}

func TestRemoveCampaignMember_LeadSelfRemoveBlocked(t *testing.T) {
	svc, _, memberRepo := newTeamTestService(t)
	ctx := context.Background()

	tenantID := shared.NewID()
	campaignID := shared.NewID()
	leadID := shared.NewID()
	lead2ID := shared.NewID()

	// Campaign has 2 leads — self-remove still blocked
	memberRepo.listByCampaign = []*pentest.CampaignMember{
		pentest.ReconstituteCampaignMember(shared.NewID(), tenantID, campaignID, leadID, pentest.CampaignRoleLead, nil, time.Now()),
		pentest.ReconstituteCampaignMember(shared.NewID(), tenantID, campaignID, lead2ID, pentest.CampaignRoleLead, nil, time.Now()),
	}

	err := svc.RemoveCampaignMember(ctx, app.CampaignRemoveMemberInput{
		TenantID:   tenantID.String(),
		CampaignID: campaignID.String(),
		UserID:     leadID.String(),
		ActorID:    leadID.String(), // self-remove
	})

	if err == nil {
		t.Fatal("expected error when lead self-removes")
	}
	if !errors.Is(err, pentest.ErrLeadSelfRemove) {
		t.Errorf("expected ErrLeadSelfRemove, got %v", err)
	}
}

func TestUpdateCampaignMemberRole_DemoteLastLeadBlocked(t *testing.T) {
	svc, _, memberRepo := newTeamTestService(t)
	ctx := context.Background()

	tenantID := shared.NewID()
	campaignID := shared.NewID()
	leadID := shared.NewID()

	// Campaign has only 1 lead — demoting to tester must fail
	memberRepo.listByCampaign = []*pentest.CampaignMember{
		pentest.ReconstituteCampaignMember(shared.NewID(), tenantID, campaignID, leadID, pentest.CampaignRoleLead, nil, time.Now()),
		pentest.ReconstituteCampaignMember(shared.NewID(), tenantID, campaignID, shared.NewID(), pentest.CampaignRoleTester, nil, time.Now()),
	}

	err := svc.UpdateCampaignMemberRole(ctx, app.CampaignUpdateMemberRoleInput{
		TenantID:   tenantID.String(),
		CampaignID: campaignID.String(),
		UserID:     leadID.String(),
		NewRole:    "tester",
	})

	if err == nil {
		t.Fatal("expected error when demoting last lead")
	}
	if !errors.Is(err, pentest.ErrLastLead) {
		t.Errorf("expected ErrLastLead, got %v", err)
	}
}

func TestUpdateCampaignMemberRole_Success(t *testing.T) {
	svc, _, memberRepo := newTeamTestService(t)
	ctx := context.Background()

	tenantID := shared.NewID()
	campaignID := shared.NewID()
	userID := shared.NewID()

	// Need a member in the list so UpdateRole can find them
	existingMember := pentest.ReconstituteCampaignMember(
		shared.NewID(), tenantID, campaignID, userID,
		pentest.CampaignRoleTester, nil, time.Now(),
	)
	memberRepo.listByCampaign = []*pentest.CampaignMember{existingMember}

	err := svc.UpdateCampaignMemberRole(ctx, app.CampaignUpdateMemberRoleInput{
		TenantID:   tenantID.String(),
		CampaignID: campaignID.String(),
		UserID:     userID.String(),
		NewRole:    "reviewer",
	})

	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
}

func TestListCampaignMembers_Success(t *testing.T) {
	svc, _, memberRepo := newTeamTestService(t)
	ctx := context.Background()

	memberRepo.listByCampaign = []*pentest.CampaignMember{}

	members, err := svc.ListCampaignMembers(ctx, shared.NewID().String(), shared.NewID().String())
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if members == nil {
		t.Fatal("expected empty slice, got nil")
	}
}

func TestGetUserCampaignRole_Success(t *testing.T) {
	svc, _, memberRepo := newTeamTestService(t)
	ctx := context.Background()

	memberRepo.getUserRole = pentest.CampaignRoleLead

	role, err := svc.GetUserCampaignRole(ctx, shared.NewID().String(), shared.NewID().String(), shared.NewID().String())
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if role != pentest.CampaignRoleLead {
		t.Errorf("expected lead, got %s", role)
	}
}

func TestGetUserCampaignRole_NotMember(t *testing.T) {
	svc, _, memberRepo := newTeamTestService(t)
	ctx := context.Background()

	memberRepo.getUserRoleErr = pentest.ErrMemberNotFound

	_, err := svc.GetUserCampaignRole(ctx, shared.NewID().String(), shared.NewID().String(), shared.NewID().String())
	if err == nil {
		t.Fatal("expected error for non-member")
	}
}

// --- Mock repositories specific to team tests ---

type teamMockCampaignRepo struct {
	pentest.CampaignRepository
	getByID    *pentest.Campaign
	getByIDErr error
}

func (m *teamMockCampaignRepo) GetByID(_ context.Context, _, _ shared.ID) (*pentest.Campaign, error) {
	return m.getByID, m.getByIDErr
}

func (m *teamMockCampaignRepo) Create(_ context.Context, _ *pentest.Campaign) error {
	return nil
}

type teamMockMemberRepo struct {
	createCalled         bool
	createErr            error
	deleteByUserIDCalled bool
	getUserRole          pentest.CampaignRole
	getUserRoleErr       error
	updateRoleCalled     bool
	listByCampaign       []*pentest.CampaignMember
}

func (m *teamMockMemberRepo) Create(_ context.Context, _ *pentest.CampaignMember) error {
	m.createCalled = true
	return m.createErr
}

func (m *teamMockMemberRepo) GetByID(_ context.Context, _, _ shared.ID) (*pentest.CampaignMember, error) {
	return nil, nil
}

func (m *teamMockMemberRepo) GetUserRole(_ context.Context, _, _, _ string) (pentest.CampaignRole, error) {
	return m.getUserRole, m.getUserRoleErr
}

func (m *teamMockMemberRepo) UpdateRole(_ context.Context, _, _ shared.ID, _ pentest.CampaignRole) error {
	m.updateRoleCalled = true
	return nil
}

func (m *teamMockMemberRepo) Delete(_ context.Context, _, _ shared.ID) error {
	return nil
}

func (m *teamMockMemberRepo) DeleteByUserID(_ context.Context, _, _, _ string) error {
	m.deleteByUserIDCalled = true
	return nil
}

func (m *teamMockMemberRepo) ListByCampaign(_ context.Context, _, _ string) ([]*pentest.CampaignMember, error) {
	return m.listByCampaign, nil
}

func (m *teamMockMemberRepo) ListByUser(_ context.Context, _, _ string) ([]*pentest.CampaignMember, error) {
	return nil, nil
}

func (m *teamMockMemberRepo) CountByRoleInTx(_ context.Context, _ *sql.Tx, _, _ string, _ pentest.CampaignRole) (int64, error) {
	return 1, nil
}

func (m *teamMockMemberRepo) BatchListByCampaignIDs(_ context.Context, _ string, _ []string) (map[string][]*pentest.CampaignMember, error) {
	return nil, nil
}

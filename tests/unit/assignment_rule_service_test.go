package unit

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/openctemio/api/internal/app"
	"github.com/openctemio/api/pkg/domain/accesscontrol"
	"github.com/openctemio/api/pkg/domain/group"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/domain/vulnerability"
	"github.com/openctemio/api/pkg/logger"
	"github.com/openctemio/api/pkg/pagination"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// Mock repositories for AssignmentRuleService tests
// =============================================================================

// mockACRepoForRules implements accesscontrol.Repository for assignment rule tests.
type mockACRepoForRules struct {
	mockAccessControlRepo // embed full stub

	// CreateAssignmentRule
	createRuleErr   error
	createRuleCalls int

	// GetAssignmentRule
	getRuleResult *accesscontrol.AssignmentRule
	getRuleErr    error
	getRuleCalls  int

	// UpdateAssignmentRule
	updateRuleErr   error
	updateRuleCalls int

	// DeleteAssignmentRule
	deleteRuleErr   error
	deleteRuleCalls int

	// ListAssignmentRules
	listRulesResult []*accesscontrol.AssignmentRule
	listRulesErr    error
	listRulesCalls  int

	// CountAssignmentRules
	countRulesResult int64
	countRulesErr    error
	countRulesCalls  int

	// Track last saved rule
	lastCreatedRule *accesscontrol.AssignmentRule
	lastUpdatedRule *accesscontrol.AssignmentRule
}

func (m *mockACRepoForRules) CreateAssignmentRule(_ context.Context, r *accesscontrol.AssignmentRule) error {
	m.createRuleCalls++
	m.lastCreatedRule = r
	return m.createRuleErr
}

func (m *mockACRepoForRules) GetAssignmentRule(_ context.Context, _, _ shared.ID) (*accesscontrol.AssignmentRule, error) {
	m.getRuleCalls++
	return m.getRuleResult, m.getRuleErr
}

func (m *mockACRepoForRules) UpdateAssignmentRule(_ context.Context, _ shared.ID, r *accesscontrol.AssignmentRule) error {
	m.updateRuleCalls++
	m.lastUpdatedRule = r
	return m.updateRuleErr
}

func (m *mockACRepoForRules) DeleteAssignmentRule(_ context.Context, _, _ shared.ID) error {
	m.deleteRuleCalls++
	return m.deleteRuleErr
}

func (m *mockACRepoForRules) ListAssignmentRules(_ context.Context, _ shared.ID, _ accesscontrol.AssignmentRuleFilter) ([]*accesscontrol.AssignmentRule, error) {
	m.listRulesCalls++
	return m.listRulesResult, m.listRulesErr
}

func (m *mockACRepoForRules) CountAssignmentRules(_ context.Context, _ shared.ID, _ accesscontrol.AssignmentRuleFilter) (int64, error) {
	m.countRulesCalls++
	return m.countRulesResult, m.countRulesErr
}
func (m *mockACRepoForRules) GetAssetOwnerByID(_ context.Context, _ shared.ID) (*accesscontrol.AssetOwner, error) {
	return nil, nil
}
func (m *mockACRepoForRules) GetAssetOwnerByUser(_ context.Context, _, _ shared.ID) (*accesscontrol.AssetOwner, error) {
	return nil, nil
}
func (m *mockACRepoForRules) DeleteAssetOwnerByID(_ context.Context, _ shared.ID) error {
	return nil
}
func (m *mockACRepoForRules) DeleteAssetOwnerByUser(_ context.Context, _, _ shared.ID) error {
	return nil
}
func (m *mockACRepoForRules) ListAssetOwnersWithNames(_ context.Context, _, _ shared.ID) ([]*accesscontrol.AssetOwnerWithNames, error) {
	return nil, nil
}
func (m *mockACRepoForRules) GetPrimaryOwnerBrief(_ context.Context, _, _ shared.ID) (*accesscontrol.OwnerBrief, error) {
	return nil, nil
}
func (m *mockACRepoForRules) RefreshAccessForDirectOwnerAdd(_ context.Context, _, _ shared.ID, _ string) error {
	return nil
}
func (m *mockACRepoForRules) RefreshAccessForDirectOwnerRemove(_ context.Context, _, _ shared.ID) error {
	return nil
}

// mockGroupRepoForRules implements group.Repository for assignment rule tests.
type mockGroupRepoForRules struct {
	getByIDResult *group.Group
	getByIDErr    error
	getByIDCalls  int
}

func (m *mockGroupRepoForRules) GetByID(_ context.Context, _ shared.ID) (*group.Group, error) {
	m.getByIDCalls++
	return m.getByIDResult, m.getByIDErr
}

// Stub remaining group.Repository methods
func (m *mockGroupRepoForRules) Create(_ context.Context, _ *group.Group) error { return nil }
func (m *mockGroupRepoForRules) GetBySlug(_ context.Context, _ shared.ID, _ string) (*group.Group, error) {
	return nil, nil
}
func (m *mockGroupRepoForRules) Update(_ context.Context, _ *group.Group) error { return nil }
func (m *mockGroupRepoForRules) Delete(_ context.Context, _ shared.ID) error    { return nil }
func (m *mockGroupRepoForRules) List(_ context.Context, _ shared.ID, _ group.ListFilter) ([]*group.Group, error) {
	return nil, nil
}
func (m *mockGroupRepoForRules) Count(_ context.Context, _ shared.ID, _ group.ListFilter) (int64, error) {
	return 0, nil
}
func (m *mockGroupRepoForRules) ExistsBySlug(_ context.Context, _ shared.ID, _ string) (bool, error) {
	return false, nil
}
func (m *mockGroupRepoForRules) ListByIDs(_ context.Context, _ []shared.ID) ([]*group.Group, error) {
	return nil, nil
}
func (m *mockGroupRepoForRules) GetByExternalID(_ context.Context, _ shared.ID, _ group.ExternalSource, _ string) (*group.Group, error) {
	return nil, nil
}
func (m *mockGroupRepoForRules) AddMember(_ context.Context, _ *group.Member) error { return nil }
func (m *mockGroupRepoForRules) GetMember(_ context.Context, _, _ shared.ID) (*group.Member, error) {
	return nil, nil
}
func (m *mockGroupRepoForRules) UpdateMember(_ context.Context, _ *group.Member) error { return nil }
func (m *mockGroupRepoForRules) RemoveMember(_ context.Context, _, _ shared.ID) error  { return nil }
func (m *mockGroupRepoForRules) ListMembers(_ context.Context, _ shared.ID) ([]*group.Member, error) {
	return nil, nil
}
func (m *mockGroupRepoForRules) ListMembersWithUserInfo(_ context.Context, _ shared.ID) ([]*group.MemberWithUser, error) {
	return nil, nil
}
func (m *mockGroupRepoForRules) CountMembers(_ context.Context, _ shared.ID) (int64, error) {
	return 0, nil
}
func (m *mockGroupRepoForRules) GetMemberStats(_ context.Context, _ shared.ID) (*group.MemberStats, error) {
	return nil, nil
}
func (m *mockGroupRepoForRules) IsMember(_ context.Context, _, _ shared.ID) (bool, error) {
	return false, nil
}
func (m *mockGroupRepoForRules) ListGroupsByUser(_ context.Context, _, _ shared.ID) ([]*group.GroupWithRole, error) {
	return nil, nil
}
func (m *mockGroupRepoForRules) ListGroupIDsByUser(_ context.Context, _, _ shared.ID) ([]shared.ID, error) {
	return nil, nil
}
func (m *mockGroupRepoForRules) AssignPermissionSet(_ context.Context, _, _ shared.ID, _ *shared.ID) error {
	return nil
}
func (m *mockGroupRepoForRules) RemovePermissionSet(_ context.Context, _, _ shared.ID) error {
	return nil
}
func (m *mockGroupRepoForRules) ListPermissionSetIDs(_ context.Context, _ shared.ID) ([]shared.ID, error) {
	return nil, nil
}
func (m *mockGroupRepoForRules) ListGroupsWithPermissionSet(_ context.Context, _ shared.ID) ([]*group.Group, error) {
	return nil, nil
}

// =============================================================================
// Helpers
// =============================================================================

func newAssignmentRuleService(acRepo *mockACRepoForRules, groupRepo *mockGroupRepoForRules) *app.AssignmentRuleService {
	log := logger.New(logger.Config{Level: "error"})
	return app.NewAssignmentRuleService(acRepo, groupRepo, log)
}

func makeActiveGroup(tenantID shared.ID) *group.Group {
	g, _ := group.NewGroup(tenantID, "Test Group", "test-group", group.GroupTypeTeam)
	return g
}

func makeInactiveGroup(tenantID shared.ID) *group.Group {
	g := group.Reconstitute(
		shared.NewID(), tenantID,
		"Inactive Group", "inactive-group", "",
		group.GroupTypeTeam,
		nil, nil,
		group.GroupSettings{},
		group.NotificationConfig{},
		nil,
		false, // isActive = false
		time.Now(), time.Now(),
	)
	return g
}

func makeExistingRule(tenantID, targetGroupID shared.ID) *accesscontrol.AssignmentRule {
	return accesscontrol.ReconstituteAssignmentRule(
		shared.NewID(), tenantID,
		"Existing Rule", "A test rule",
		10, true,
		accesscontrol.AssignmentConditions{AssetTypes: []string{"host"}},
		targetGroupID,
		accesscontrol.AssignmentOptions{},
		time.Now(), time.Now(),
		nil,
	)
}

// =============================================================================
// CreateRule Tests
// =============================================================================

func TestCreateRule_Success(t *testing.T) {
	tenantID := shared.NewID()
	targetGroupID := shared.NewID()
	activeGroup := makeActiveGroup(tenantID)

	acRepo := &mockACRepoForRules{}
	groupRepo := &mockGroupRepoForRules{getByIDResult: activeGroup}
	svc := newAssignmentRuleService(acRepo, groupRepo)

	input := app.CreateRuleInput{
		TenantID:      tenantID.String(),
		Name:          "Auto-assign web assets",
		Description:   "Route web assets to security team",
		Priority:      10,
		Conditions:    accesscontrol.AssignmentConditions{AssetTypes: []string{"website"}},
		TargetGroupID: targetGroupID.String(),
	}

	rule, err := svc.CreateRule(context.Background(), input, shared.NewID().String())
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if rule == nil {
		t.Fatal("expected rule, got nil")
	}
	if rule.Name() != "Auto-assign web assets" {
		t.Errorf("expected name 'Auto-assign web assets', got '%s'", rule.Name())
	}
	if acRepo.createRuleCalls != 1 {
		t.Errorf("expected 1 create call, got %d", acRepo.createRuleCalls)
	}
	if groupRepo.getByIDCalls != 1 {
		t.Errorf("expected 1 group lookup, got %d", groupRepo.getByIDCalls)
	}
}

func TestCreateRule_InvalidTenantID(t *testing.T) {
	acRepo := &mockACRepoForRules{}
	groupRepo := &mockGroupRepoForRules{}
	svc := newAssignmentRuleService(acRepo, groupRepo)

	input := app.CreateRuleInput{
		TenantID:      "not-a-uuid",
		Name:          "Test",
		TargetGroupID: shared.NewID().String(),
	}

	_, err := svc.CreateRule(context.Background(), input, "")
	if err == nil {
		t.Fatal("expected error for invalid tenant ID")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected validation error, got: %v", err)
	}
}

func TestCreateRule_InvalidTargetGroupID(t *testing.T) {
	acRepo := &mockACRepoForRules{}
	groupRepo := &mockGroupRepoForRules{}
	svc := newAssignmentRuleService(acRepo, groupRepo)

	input := app.CreateRuleInput{
		TenantID:      shared.NewID().String(),
		Name:          "Test",
		TargetGroupID: "invalid",
	}

	_, err := svc.CreateRule(context.Background(), input, "")
	if err == nil {
		t.Fatal("expected error for invalid target group ID")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected validation error, got: %v", err)
	}
}

func TestCreateRule_TargetGroupNotFound(t *testing.T) {
	acRepo := &mockACRepoForRules{}
	groupRepo := &mockGroupRepoForRules{getByIDErr: group.ErrGroupNotFound}
	svc := newAssignmentRuleService(acRepo, groupRepo)

	input := app.CreateRuleInput{
		TenantID:      shared.NewID().String(),
		Name:          "Test",
		TargetGroupID: shared.NewID().String(),
	}

	_, err := svc.CreateRule(context.Background(), input, "")
	if err == nil {
		t.Fatal("expected error for missing group")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected validation error, got: %v", err)
	}
}

func TestCreateRule_TargetGroupInactive(t *testing.T) {
	tenantID := shared.NewID()
	inactiveGroup := makeInactiveGroup(tenantID)

	acRepo := &mockACRepoForRules{}
	groupRepo := &mockGroupRepoForRules{getByIDResult: inactiveGroup}
	svc := newAssignmentRuleService(acRepo, groupRepo)

	input := app.CreateRuleInput{
		TenantID:      tenantID.String(),
		Name:          "Test",
		TargetGroupID: shared.NewID().String(),
	}

	_, err := svc.CreateRule(context.Background(), input, "")
	if err == nil {
		t.Fatal("expected error for inactive group")
	}
	if !errors.Is(err, accesscontrol.ErrTargetGroupInactive) {
		t.Errorf("expected ErrTargetGroupInactive, got: %v", err)
	}
}

func TestCreateRule_RepoError(t *testing.T) {
	tenantID := shared.NewID()
	activeGroup := makeActiveGroup(tenantID)

	acRepo := &mockACRepoForRules{createRuleErr: errors.New("db error")}
	groupRepo := &mockGroupRepoForRules{getByIDResult: activeGroup}
	svc := newAssignmentRuleService(acRepo, groupRepo)

	input := app.CreateRuleInput{
		TenantID:      tenantID.String(),
		Name:          "Test Rule",
		TargetGroupID: shared.NewID().String(),
	}

	_, err := svc.CreateRule(context.Background(), input, "")
	if err == nil {
		t.Fatal("expected repo error")
	}
}

// =============================================================================
// GetRule Tests
// =============================================================================

func TestGetRule_Success(t *testing.T) {
	tenantID := shared.NewID()
	targetGroupID := shared.NewID()
	existingRule := makeExistingRule(tenantID, targetGroupID)

	acRepo := &mockACRepoForRules{getRuleResult: existingRule}
	groupRepo := &mockGroupRepoForRules{}
	svc := newAssignmentRuleService(acRepo, groupRepo)

	rule, err := svc.GetRule(context.Background(), tenantID.String(), existingRule.ID().String())
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if rule.Name() != "Existing Rule" {
		t.Errorf("expected 'Existing Rule', got '%s'", rule.Name())
	}
	if acRepo.getRuleCalls != 1 {
		t.Errorf("expected 1 get call, got %d", acRepo.getRuleCalls)
	}
}

func TestGetRule_InvalidID(t *testing.T) {
	acRepo := &mockACRepoForRules{}
	groupRepo := &mockGroupRepoForRules{}
	svc := newAssignmentRuleService(acRepo, groupRepo)

	_, err := svc.GetRule(context.Background(), shared.NewID().String(), "bad-id")
	if err == nil {
		t.Fatal("expected error for invalid ID")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected validation error, got: %v", err)
	}
}

func TestGetRule_NotFound(t *testing.T) {
	acRepo := &mockACRepoForRules{getRuleErr: accesscontrol.ErrAssignmentRuleNotFound}
	groupRepo := &mockGroupRepoForRules{}
	svc := newAssignmentRuleService(acRepo, groupRepo)

	_, err := svc.GetRule(context.Background(), shared.NewID().String(), shared.NewID().String())
	if err == nil {
		t.Fatal("expected not found error")
	}
	if !errors.Is(err, accesscontrol.ErrAssignmentRuleNotFound) {
		t.Errorf("expected ErrAssignmentRuleNotFound, got: %v", err)
	}
}

// =============================================================================
// UpdateRule Tests
// =============================================================================

func TestUpdateRule_Success(t *testing.T) {
	tenantID := shared.NewID()
	targetGroupID := shared.NewID()
	existingRule := makeExistingRule(tenantID, targetGroupID)

	acRepo := &mockACRepoForRules{getRuleResult: existingRule}
	groupRepo := &mockGroupRepoForRules{}
	svc := newAssignmentRuleService(acRepo, groupRepo)

	newName := "Updated Rule Name"
	newDesc := "Updated description"
	newPriority := 20
	isActive := false

	input := app.UpdateRuleInput{
		Name:        &newName,
		Description: &newDesc,
		Priority:    &newPriority,
		IsActive:    &isActive,
	}

	rule, err := svc.UpdateRule(context.Background(), tenantID.String(), existingRule.ID().String(), input)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if rule.Name() != "Updated Rule Name" {
		t.Errorf("expected updated name, got '%s'", rule.Name())
	}
	if rule.Description() != "Updated description" {
		t.Errorf("expected updated description, got '%s'", rule.Description())
	}
	if rule.Priority() != 20 {
		t.Errorf("expected priority 20, got %d", rule.Priority())
	}
	if rule.IsActive() {
		t.Error("expected rule to be deactivated")
	}
	if acRepo.updateRuleCalls != 1 {
		t.Errorf("expected 1 update call, got %d", acRepo.updateRuleCalls)
	}
}

func TestUpdateRule_ChangeTargetGroup(t *testing.T) {
	tenantID := shared.NewID()
	oldGroupID := shared.NewID()
	newGroupID := shared.NewID()
	existingRule := makeExistingRule(tenantID, oldGroupID)
	activeGroup := makeActiveGroup(tenantID)

	acRepo := &mockACRepoForRules{getRuleResult: existingRule}
	groupRepo := &mockGroupRepoForRules{getByIDResult: activeGroup}
	svc := newAssignmentRuleService(acRepo, groupRepo)

	newTargetGroupID := newGroupID.String()
	input := app.UpdateRuleInput{
		TargetGroupID: &newTargetGroupID,
	}

	rule, err := svc.UpdateRule(context.Background(), tenantID.String(), existingRule.ID().String(), input)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if rule.TargetGroupID() != newGroupID {
		t.Error("expected target group to be updated")
	}
	if groupRepo.getByIDCalls != 1 {
		t.Errorf("expected group lookup for new target, got %d calls", groupRepo.getByIDCalls)
	}
}

func TestUpdateRule_TargetGroupInactive(t *testing.T) {
	tenantID := shared.NewID()
	existingRule := makeExistingRule(tenantID, shared.NewID())
	inactiveGroup := makeInactiveGroup(tenantID)

	acRepo := &mockACRepoForRules{getRuleResult: existingRule}
	groupRepo := &mockGroupRepoForRules{getByIDResult: inactiveGroup}
	svc := newAssignmentRuleService(acRepo, groupRepo)

	newTargetGroupID := shared.NewID().String()
	input := app.UpdateRuleInput{
		TargetGroupID: &newTargetGroupID,
	}

	_, err := svc.UpdateRule(context.Background(), tenantID.String(), existingRule.ID().String(), input)
	if err == nil {
		t.Fatal("expected error for inactive target group")
	}
	if !errors.Is(err, accesscontrol.ErrTargetGroupInactive) {
		t.Errorf("expected ErrTargetGroupInactive, got: %v", err)
	}
}

func TestUpdateRule_InvalidID(t *testing.T) {
	acRepo := &mockACRepoForRules{}
	groupRepo := &mockGroupRepoForRules{}
	svc := newAssignmentRuleService(acRepo, groupRepo)

	_, err := svc.UpdateRule(context.Background(), shared.NewID().String(), "invalid", app.UpdateRuleInput{})
	if err == nil {
		t.Fatal("expected error for invalid ID")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected validation error, got: %v", err)
	}
}

func TestUpdateRule_NotFound(t *testing.T) {
	acRepo := &mockACRepoForRules{getRuleErr: accesscontrol.ErrAssignmentRuleNotFound}
	groupRepo := &mockGroupRepoForRules{}
	svc := newAssignmentRuleService(acRepo, groupRepo)

	_, err := svc.UpdateRule(context.Background(), shared.NewID().String(), shared.NewID().String(), app.UpdateRuleInput{})
	if err == nil {
		t.Fatal("expected not found error")
	}
	if !errors.Is(err, accesscontrol.ErrAssignmentRuleNotFound) {
		t.Errorf("expected ErrAssignmentRuleNotFound, got: %v", err)
	}
}

func TestUpdateRule_EmptyName(t *testing.T) {
	tenantID := shared.NewID()
	existingRule := makeExistingRule(tenantID, shared.NewID())

	acRepo := &mockACRepoForRules{getRuleResult: existingRule}
	groupRepo := &mockGroupRepoForRules{}
	svc := newAssignmentRuleService(acRepo, groupRepo)

	emptyName := ""
	input := app.UpdateRuleInput{Name: &emptyName}

	_, err := svc.UpdateRule(context.Background(), tenantID.String(), existingRule.ID().String(), input)
	if err == nil {
		t.Fatal("expected error for empty name")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected validation error, got: %v", err)
	}
}

// =============================================================================
// DeleteRule Tests
// =============================================================================

func TestDeleteRule_Success(t *testing.T) {
	acRepo := &mockACRepoForRules{}
	groupRepo := &mockGroupRepoForRules{}
	svc := newAssignmentRuleService(acRepo, groupRepo)

	err := svc.DeleteRule(context.Background(), shared.NewID().String(), shared.NewID().String())
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if acRepo.deleteRuleCalls != 1 {
		t.Errorf("expected 1 delete call, got %d", acRepo.deleteRuleCalls)
	}
}

func TestDeleteRule_InvalidID(t *testing.T) {
	acRepo := &mockACRepoForRules{}
	groupRepo := &mockGroupRepoForRules{}
	svc := newAssignmentRuleService(acRepo, groupRepo)

	err := svc.DeleteRule(context.Background(), shared.NewID().String(), "not-uuid")
	if err == nil {
		t.Fatal("expected error for invalid ID")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected validation error, got: %v", err)
	}
}

func TestDeleteRule_NotFound(t *testing.T) {
	acRepo := &mockACRepoForRules{deleteRuleErr: accesscontrol.ErrAssignmentRuleNotFound}
	groupRepo := &mockGroupRepoForRules{}
	svc := newAssignmentRuleService(acRepo, groupRepo)

	err := svc.DeleteRule(context.Background(), shared.NewID().String(), shared.NewID().String())
	if err == nil {
		t.Fatal("expected not found error")
	}
	if !errors.Is(err, accesscontrol.ErrAssignmentRuleNotFound) {
		t.Errorf("expected ErrAssignmentRuleNotFound, got: %v", err)
	}
}

// =============================================================================
// ListRules Tests
// =============================================================================

func TestListRules_Success(t *testing.T) {
	tenantID := shared.NewID()
	rule1 := makeExistingRule(tenantID, shared.NewID())
	rule2 := makeExistingRule(tenantID, shared.NewID())

	acRepo := &mockACRepoForRules{
		listRulesResult:  []*accesscontrol.AssignmentRule{rule1, rule2},
		countRulesResult: 2,
	}
	groupRepo := &mockGroupRepoForRules{}
	svc := newAssignmentRuleService(acRepo, groupRepo)

	input := app.ListAssignmentRulesInput{
		TenantID: tenantID.String(),
		Limit:    10,
	}

	output, err := svc.ListRules(context.Background(), input)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if len(output.Rules) != 2 {
		t.Errorf("expected 2 rules, got %d", len(output.Rules))
	}
	if output.TotalCount != 2 {
		t.Errorf("expected total count 2, got %d", output.TotalCount)
	}
}

func TestListRules_DefaultLimit(t *testing.T) {
	tenantID := shared.NewID()

	acRepo := &mockACRepoForRules{
		listRulesResult:  []*accesscontrol.AssignmentRule{},
		countRulesResult: 0,
	}
	groupRepo := &mockGroupRepoForRules{}
	svc := newAssignmentRuleService(acRepo, groupRepo)

	input := app.ListAssignmentRulesInput{
		TenantID: tenantID.String(),
		// Limit = 0 should default to 50
	}

	_, err := svc.ListRules(context.Background(), input)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
}

func TestListRules_InvalidTenantID(t *testing.T) {
	acRepo := &mockACRepoForRules{}
	groupRepo := &mockGroupRepoForRules{}
	svc := newAssignmentRuleService(acRepo, groupRepo)

	input := app.ListAssignmentRulesInput{
		TenantID: "invalid",
	}

	_, err := svc.ListRules(context.Background(), input)
	if err == nil {
		t.Fatal("expected error for invalid tenant ID")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected validation error, got: %v", err)
	}
}

func TestListRules_WithFilters(t *testing.T) {
	tenantID := shared.NewID()
	targetGroupID := shared.NewID()

	acRepo := &mockACRepoForRules{
		listRulesResult:  []*accesscontrol.AssignmentRule{},
		countRulesResult: 0,
	}
	groupRepo := &mockGroupRepoForRules{}
	svc := newAssignmentRuleService(acRepo, groupRepo)

	isActive := true
	tgid := targetGroupID.String()
	input := app.ListAssignmentRulesInput{
		TenantID:      tenantID.String(),
		IsActive:      &isActive,
		TargetGroupID: &tgid,
		Search:        "web",
		Limit:         25,
		Offset:        10,
		OrderBy:       "priority",
		OrderDesc:     true,
	}

	_, err := svc.ListRules(context.Background(), input)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if acRepo.listRulesCalls != 1 {
		t.Errorf("expected 1 list call, got %d", acRepo.listRulesCalls)
	}
	if acRepo.countRulesCalls != 1 {
		t.Errorf("expected 1 count call, got %d", acRepo.countRulesCalls)
	}
}

func TestListRules_InvalidTargetGroupID(t *testing.T) {
	acRepo := &mockACRepoForRules{}
	groupRepo := &mockGroupRepoForRules{}
	svc := newAssignmentRuleService(acRepo, groupRepo)

	invalidID := "not-uuid"
	input := app.ListAssignmentRulesInput{
		TenantID:      shared.NewID().String(),
		TargetGroupID: &invalidID,
	}

	_, err := svc.ListRules(context.Background(), input)
	if err == nil {
		t.Fatal("expected error for invalid target group ID filter")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected validation error, got: %v", err)
	}
}

// =============================================================================
// TestRule Tests
// =============================================================================

func TestTestRule_Success(t *testing.T) {
	tenantID := shared.NewID()
	targetGroupID := shared.NewID()
	existingRule := makeExistingRule(tenantID, targetGroupID)

	acRepo := &mockACRepoForRules{getRuleResult: existingRule}
	groupRepo := &mockGroupRepoForRules{}
	svc := newAssignmentRuleService(acRepo, groupRepo)

	result, err := svc.TestRule(context.Background(), tenantID.String(), existingRule.ID().String())
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if result == nil {
		t.Fatal("expected result, got nil")
	}
	if result.RuleID != existingRule.ID().String() {
		t.Errorf("expected rule ID %s, got %s", existingRule.ID().String(), result.RuleID)
	}
	if result.RuleName != "Existing Rule" {
		t.Errorf("expected 'Existing Rule', got '%s'", result.RuleName)
	}
	if result.TargetGroupID != targetGroupID.String() {
		t.Errorf("expected target group ID %s, got %s", targetGroupID.String(), result.TargetGroupID)
	}
}

func TestTestRule_InvalidID(t *testing.T) {
	acRepo := &mockACRepoForRules{}
	groupRepo := &mockGroupRepoForRules{}
	svc := newAssignmentRuleService(acRepo, groupRepo)

	_, err := svc.TestRule(context.Background(), shared.NewID().String(), "bad")
	if err == nil {
		t.Fatal("expected error for invalid ID")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected validation error, got: %v", err)
	}
}

func TestTestRule_NotFound(t *testing.T) {
	acRepo := &mockACRepoForRules{getRuleErr: accesscontrol.ErrAssignmentRuleNotFound}
	groupRepo := &mockGroupRepoForRules{}
	svc := newAssignmentRuleService(acRepo, groupRepo)

	_, err := svc.TestRule(context.Background(), shared.NewID().String(), shared.NewID().String())
	if err == nil {
		t.Fatal("expected not found error")
	}
	if !errors.Is(err, accesscontrol.ErrAssignmentRuleNotFound) {
		t.Errorf("expected ErrAssignmentRuleNotFound, got: %v", err)
	}
}

// =============================================================================
// Edge Case Tests - CreateRule
// =============================================================================

func TestCreateRule_WithAllOptions(t *testing.T) {
	tenantID := shared.NewID()
	activeGroup := makeActiveGroup(tenantID)

	acRepo := &mockACRepoForRules{}
	groupRepo := &mockGroupRepoForRules{getByIDResult: activeGroup}
	svc := newAssignmentRuleService(acRepo, groupRepo)

	input := app.CreateRuleInput{
		TenantID:    tenantID.String(),
		Name:        "Full Rule",
		Description: "Complete rule with all options",
		Priority:    50,
		Conditions: accesscontrol.AssignmentConditions{
			AssetTypes:      []string{"host", "website", "container"},
			FilePathPattern: "/prod/**",
			FindingSeverity: []string{"critical", "high"},
			FindingType:     []string{"vulnerability", "misconfiguration"},
			FindingSource:   []string{"sast", "dast"},
			AssetTags:       []string{"production", "public-facing"},
		},
		TargetGroupID: shared.NewID().String(),
		Options: accesscontrol.AssignmentOptions{
			NotifyGroup:        true,
			SetFindingPriority: "critical",
		},
	}

	rule, err := svc.CreateRule(context.Background(), input, shared.NewID().String())
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	if rule.Description() != "Complete rule with all options" {
		t.Errorf("expected description set, got '%s'", rule.Description())
	}
	if rule.Priority() != 50 {
		t.Errorf("expected priority 50, got %d", rule.Priority())
	}
	if len(rule.Conditions().AssetTypes) != 3 {
		t.Errorf("expected 3 asset types, got %d", len(rule.Conditions().AssetTypes))
	}
	if rule.Conditions().FilePathPattern != "/prod/**" {
		t.Errorf("expected file path pattern '/prod/**', got '%s'", rule.Conditions().FilePathPattern)
	}
	if !rule.Options().NotifyGroup {
		t.Error("expected NotifyGroup to be true")
	}
	if rule.Options().SetFindingPriority != "critical" {
		t.Errorf("expected SetFindingPriority 'critical', got '%s'", rule.Options().SetFindingPriority)
	}
}

func TestCreateRule_WithNilCreatedBy(t *testing.T) {
	tenantID := shared.NewID()
	activeGroup := makeActiveGroup(tenantID)

	acRepo := &mockACRepoForRules{}
	groupRepo := &mockGroupRepoForRules{getByIDResult: activeGroup}
	svc := newAssignmentRuleService(acRepo, groupRepo)

	input := app.CreateRuleInput{
		TenantID:      tenantID.String(),
		Name:          "No Creator Rule",
		TargetGroupID: shared.NewID().String(),
	}

	// Empty string for createdBy
	rule, err := svc.CreateRule(context.Background(), input, "")
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	// CreatedBy should be nil when empty string is passed
	if rule.CreatedBy() != nil {
		t.Error("expected nil CreatedBy for empty string")
	}
}

func TestCreateRule_WithInvalidCreatedBy(t *testing.T) {
	tenantID := shared.NewID()
	activeGroup := makeActiveGroup(tenantID)

	acRepo := &mockACRepoForRules{}
	groupRepo := &mockGroupRepoForRules{getByIDResult: activeGroup}
	svc := newAssignmentRuleService(acRepo, groupRepo)

	input := app.CreateRuleInput{
		TenantID:      tenantID.String(),
		Name:          "Bad Creator Rule",
		TargetGroupID: shared.NewID().String(),
	}

	// Invalid UUID for createdBy - should be silently ignored
	rule, err := svc.CreateRule(context.Background(), input, "not-a-uuid")
	if err != nil {
		t.Fatalf("expected no error (invalid createdBy silently ignored), got: %v", err)
	}
	if rule.CreatedBy() != nil {
		t.Error("expected nil CreatedBy for invalid UUID")
	}
}

func TestCreateRule_EmptyName(t *testing.T) {
	tenantID := shared.NewID()
	activeGroup := makeActiveGroup(tenantID)

	acRepo := &mockACRepoForRules{}
	groupRepo := &mockGroupRepoForRules{getByIDResult: activeGroup}
	svc := newAssignmentRuleService(acRepo, groupRepo)

	input := app.CreateRuleInput{
		TenantID:      tenantID.String(),
		Name:          "", // empty
		TargetGroupID: shared.NewID().String(),
	}

	_, err := svc.CreateRule(context.Background(), input, "")
	if err == nil {
		t.Fatal("expected error for empty name")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected validation error, got: %v", err)
	}
}

// =============================================================================
// Edge Case Tests - UpdateRule
// =============================================================================

func TestUpdateRule_PartialUpdate_OnlyName(t *testing.T) {
	tenantID := shared.NewID()
	existingRule := makeExistingRule(tenantID, shared.NewID())

	acRepo := &mockACRepoForRules{getRuleResult: existingRule}
	groupRepo := &mockGroupRepoForRules{}
	svc := newAssignmentRuleService(acRepo, groupRepo)

	newName := "Only Name Changed"
	input := app.UpdateRuleInput{Name: &newName}

	rule, err := svc.UpdateRule(context.Background(), tenantID.String(), existingRule.ID().String(), input)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if rule.Name() != "Only Name Changed" {
		t.Errorf("expected updated name, got '%s'", rule.Name())
	}
	// Other fields should remain unchanged
	if rule.Description() != "A test rule" {
		t.Errorf("expected description unchanged, got '%s'", rule.Description())
	}
	if rule.Priority() != 10 {
		t.Errorf("expected priority unchanged, got %d", rule.Priority())
	}
}

func TestUpdateRule_Activate(t *testing.T) {
	tenantID := shared.NewID()
	existingRule := makeExistingRule(tenantID, shared.NewID())
	existingRule.Deactivate() // make it inactive first

	acRepo := &mockACRepoForRules{getRuleResult: existingRule}
	groupRepo := &mockGroupRepoForRules{}
	svc := newAssignmentRuleService(acRepo, groupRepo)

	isActive := true
	input := app.UpdateRuleInput{IsActive: &isActive}

	rule, err := svc.UpdateRule(context.Background(), tenantID.String(), existingRule.ID().String(), input)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if !rule.IsActive() {
		t.Error("expected rule to be activated")
	}
}

func TestUpdateRule_UpdateConditions(t *testing.T) {
	tenantID := shared.NewID()
	existingRule := makeExistingRule(tenantID, shared.NewID())

	acRepo := &mockACRepoForRules{getRuleResult: existingRule}
	groupRepo := &mockGroupRepoForRules{}
	svc := newAssignmentRuleService(acRepo, groupRepo)

	newConditions := accesscontrol.AssignmentConditions{
		AssetTypes:      []string{"container", "kubernetes_cluster"},
		FindingSeverity: []string{"critical"},
		AssetTags:       []string{"staging"},
	}
	input := app.UpdateRuleInput{Conditions: &newConditions}

	rule, err := svc.UpdateRule(context.Background(), tenantID.String(), existingRule.ID().String(), input)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if len(rule.Conditions().AssetTypes) != 2 {
		t.Errorf("expected 2 asset types, got %d", len(rule.Conditions().AssetTypes))
	}
	if rule.Conditions().AssetTypes[0] != "container" {
		t.Errorf("expected first asset type 'container', got '%s'", rule.Conditions().AssetTypes[0])
	}
}

func TestUpdateRule_UpdateOptions(t *testing.T) {
	tenantID := shared.NewID()
	existingRule := makeExistingRule(tenantID, shared.NewID())

	acRepo := &mockACRepoForRules{getRuleResult: existingRule}
	groupRepo := &mockGroupRepoForRules{}
	svc := newAssignmentRuleService(acRepo, groupRepo)

	newOptions := accesscontrol.AssignmentOptions{
		NotifyGroup:        true,
		SetFindingPriority: "high",
	}
	input := app.UpdateRuleInput{Options: &newOptions}

	rule, err := svc.UpdateRule(context.Background(), tenantID.String(), existingRule.ID().String(), input)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if !rule.Options().NotifyGroup {
		t.Error("expected NotifyGroup to be true")
	}
}

func TestUpdateRule_InvalidTargetGroupID(t *testing.T) {
	tenantID := shared.NewID()
	existingRule := makeExistingRule(tenantID, shared.NewID())

	acRepo := &mockACRepoForRules{getRuleResult: existingRule}
	groupRepo := &mockGroupRepoForRules{}
	svc := newAssignmentRuleService(acRepo, groupRepo)

	invalidID := "not-a-uuid"
	input := app.UpdateRuleInput{TargetGroupID: &invalidID}

	_, err := svc.UpdateRule(context.Background(), tenantID.String(), existingRule.ID().String(), input)
	if err == nil {
		t.Fatal("expected error for invalid target group ID")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected validation error, got: %v", err)
	}
}

func TestUpdateRule_TargetGroupNotFound(t *testing.T) {
	tenantID := shared.NewID()
	existingRule := makeExistingRule(tenantID, shared.NewID())

	acRepo := &mockACRepoForRules{getRuleResult: existingRule}
	groupRepo := &mockGroupRepoForRules{getByIDErr: group.ErrGroupNotFound}
	svc := newAssignmentRuleService(acRepo, groupRepo)

	newGroupID := shared.NewID().String()
	input := app.UpdateRuleInput{TargetGroupID: &newGroupID}

	_, err := svc.UpdateRule(context.Background(), tenantID.String(), existingRule.ID().String(), input)
	if err == nil {
		t.Fatal("expected error for missing target group")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected validation error, got: %v", err)
	}
}

func TestUpdateRule_RepoError(t *testing.T) {
	tenantID := shared.NewID()
	existingRule := makeExistingRule(tenantID, shared.NewID())

	acRepo := &mockACRepoForRules{
		getRuleResult: existingRule,
		updateRuleErr: errors.New("db error"),
	}
	groupRepo := &mockGroupRepoForRules{}
	svc := newAssignmentRuleService(acRepo, groupRepo)

	newName := "Should Fail"
	input := app.UpdateRuleInput{Name: &newName}

	_, err := svc.UpdateRule(context.Background(), tenantID.String(), existingRule.ID().String(), input)
	if err == nil {
		t.Fatal("expected repo error")
	}
}

func TestUpdateRule_NoFieldsChanged(t *testing.T) {
	tenantID := shared.NewID()
	existingRule := makeExistingRule(tenantID, shared.NewID())

	acRepo := &mockACRepoForRules{getRuleResult: existingRule}
	groupRepo := &mockGroupRepoForRules{}
	svc := newAssignmentRuleService(acRepo, groupRepo)

	// Empty update input - no fields to change
	input := app.UpdateRuleInput{}

	rule, err := svc.UpdateRule(context.Background(), tenantID.String(), existingRule.ID().String(), input)
	if err != nil {
		t.Fatalf("expected no error for no-op update, got: %v", err)
	}
	// Still calls repo.Update (by design)
	if acRepo.updateRuleCalls != 1 {
		t.Errorf("expected 1 update call, got %d", acRepo.updateRuleCalls)
	}
	if rule.Name() != "Existing Rule" {
		t.Errorf("expected name unchanged, got '%s'", rule.Name())
	}
}

// =============================================================================
// Edge Case Tests - ListRules
// =============================================================================

func TestListRules_ListRepoError(t *testing.T) {
	acRepo := &mockACRepoForRules{
		listRulesErr: errors.New("db error"),
	}
	groupRepo := &mockGroupRepoForRules{}
	svc := newAssignmentRuleService(acRepo, groupRepo)

	input := app.ListAssignmentRulesInput{
		TenantID: shared.NewID().String(),
	}

	_, err := svc.ListRules(context.Background(), input)
	if err == nil {
		t.Fatal("expected error on list failure")
	}
}

func TestListRules_CountRepoError(t *testing.T) {
	acRepo := &mockACRepoForRules{
		listRulesResult: []*accesscontrol.AssignmentRule{},
		countRulesErr:   errors.New("db error"),
	}
	groupRepo := &mockGroupRepoForRules{}
	svc := newAssignmentRuleService(acRepo, groupRepo)

	input := app.ListAssignmentRulesInput{
		TenantID: shared.NewID().String(),
	}

	_, err := svc.ListRules(context.Background(), input)
	if err == nil {
		t.Fatal("expected error on count failure")
	}
}

func TestListRules_EmptyResult(t *testing.T) {
	acRepo := &mockACRepoForRules{
		listRulesResult:  []*accesscontrol.AssignmentRule{},
		countRulesResult: 0,
	}
	groupRepo := &mockGroupRepoForRules{}
	svc := newAssignmentRuleService(acRepo, groupRepo)

	input := app.ListAssignmentRulesInput{
		TenantID: shared.NewID().String(),
		Limit:    10,
	}

	output, err := svc.ListRules(context.Background(), input)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if len(output.Rules) != 0 {
		t.Errorf("expected 0 rules, got %d", len(output.Rules))
	}
	if output.TotalCount != 0 {
		t.Errorf("expected total count 0, got %d", output.TotalCount)
	}
}

func TestListRules_NegativeLimit(t *testing.T) {
	acRepo := &mockACRepoForRules{
		listRulesResult:  []*accesscontrol.AssignmentRule{},
		countRulesResult: 0,
	}
	groupRepo := &mockGroupRepoForRules{}
	svc := newAssignmentRuleService(acRepo, groupRepo)

	input := app.ListAssignmentRulesInput{
		TenantID: shared.NewID().String(),
		Limit:    -5, // negative should default to 50
	}

	_, err := svc.ListRules(context.Background(), input)
	if err != nil {
		t.Fatalf("expected no error (negative limit should default), got: %v", err)
	}
}

// =============================================================================
// Edge Case Tests - DeleteRule
// =============================================================================

func TestDeleteRule_RepoError(t *testing.T) {
	acRepo := &mockACRepoForRules{deleteRuleErr: errors.New("db error")}
	groupRepo := &mockGroupRepoForRules{}
	svc := newAssignmentRuleService(acRepo, groupRepo)

	err := svc.DeleteRule(context.Background(), shared.NewID().String(), shared.NewID().String())
	if err == nil {
		t.Fatal("expected repo error")
	}
}

// =============================================================================
// TestRule Edge Cases
// =============================================================================

func TestTestRule_WithEngineWired_MatchesFindings(t *testing.T) {
	tenantID := shared.NewID()
	targetGroupID := shared.NewID()

	// Rule that matches critical severity
	rule := accesscontrol.ReconstituteAssignmentRule(
		shared.NewID(), tenantID,
		"Critical Only", "",
		10, true,
		accesscontrol.AssignmentConditions{FindingSeverity: []string{"critical"}},
		targetGroupID,
		accesscontrol.AssignmentOptions{},
		time.Now(), time.Now(),
		nil,
	)

	// Create findings: 2 critical, 1 high
	critFinding1 := makeTestFinding(t, tenantID, vulnerability.SeverityCritical, "tool1", vulnerability.FindingSourceSAST)
	critFinding2 := makeTestFinding(t, tenantID, vulnerability.SeverityCritical, "tool2", vulnerability.FindingSourceDAST)
	highFinding := makeTestFinding(t, tenantID, vulnerability.SeverityHigh, "tool3", vulnerability.FindingSourceSCA)

	acRepo := &mockACRepoForRules{getRuleResult: rule}
	groupRepo := &mockGroupRepoForRules{}
	findingRepo := &mockFindingRepoForRules{
		listResult: pagination.Result[*vulnerability.Finding]{
			Data:  []*vulnerability.Finding{critFinding1, critFinding2, highFinding},
			Total: 3,
		},
	}

	log := logger.New(logger.Config{Level: "error"})
	svc := app.NewAssignmentRuleService(acRepo, groupRepo, log)
	engine := app.NewAssignmentEngine(acRepo, log)
	svc.SetAssignmentEngine(engine)
	svc.SetFindingRepository(findingRepo)

	result, err := svc.TestRule(context.Background(), tenantID.String(), rule.ID().String())
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.Equal(t, int64(2), result.MatchingFindings)
	assert.Len(t, result.SampleFindings, 2)
	assert.Equal(t, "critical", result.SampleFindings[0].Severity)
}

func TestTestRule_WithEngineWired_NoMatches(t *testing.T) {
	tenantID := shared.NewID()
	targetGroupID := shared.NewID()

	rule := accesscontrol.ReconstituteAssignmentRule(
		shared.NewID(), tenantID,
		"Critical Only", "",
		10, true,
		accesscontrol.AssignmentConditions{FindingSeverity: []string{"critical"}},
		targetGroupID,
		accesscontrol.AssignmentOptions{},
		time.Now(), time.Now(),
		nil,
	)

	lowFinding := makeTestFinding(t, tenantID, vulnerability.SeverityLow, "tool1", vulnerability.FindingSourceSAST)

	acRepo := &mockACRepoForRules{getRuleResult: rule}
	groupRepo := &mockGroupRepoForRules{}
	findingRepo := &mockFindingRepoForRules{
		listResult: pagination.Result[*vulnerability.Finding]{
			Data:  []*vulnerability.Finding{lowFinding},
			Total: 1,
		},
	}

	log := logger.New(logger.Config{Level: "error"})
	svc := app.NewAssignmentRuleService(acRepo, groupRepo, log)
	engine := app.NewAssignmentEngine(acRepo, log)
	svc.SetAssignmentEngine(engine)
	svc.SetFindingRepository(findingRepo)

	result, err := svc.TestRule(context.Background(), tenantID.String(), rule.ID().String())
	require.NoError(t, err)
	assert.Equal(t, int64(0), result.MatchingFindings)
	assert.Empty(t, result.SampleFindings)
}

func TestTestRule_WithEngineWired_FindingRepoError(t *testing.T) {
	tenantID := shared.NewID()
	targetGroupID := shared.NewID()

	rule := accesscontrol.ReconstituteAssignmentRule(
		shared.NewID(), tenantID,
		"Test Rule", "",
		10, true,
		accesscontrol.AssignmentConditions{},
		targetGroupID,
		accesscontrol.AssignmentOptions{},
		time.Now(), time.Now(),
		nil,
	)

	acRepo := &mockACRepoForRules{getRuleResult: rule}
	groupRepo := &mockGroupRepoForRules{}
	findingRepo := &mockFindingRepoForRules{listErr: errors.New("db error")}

	log := logger.New(logger.Config{Level: "error"})
	svc := app.NewAssignmentRuleService(acRepo, groupRepo, log)
	engine := app.NewAssignmentEngine(acRepo, log)
	svc.SetAssignmentEngine(engine)
	svc.SetFindingRepository(findingRepo)

	// Should return result with 0 matches (graceful degradation), not error
	result, err := svc.TestRule(context.Background(), tenantID.String(), rule.ID().String())
	require.NoError(t, err)
	assert.Equal(t, int64(0), result.MatchingFindings)
}

func TestTestRule_WithEngineWired_SampleCappedAt5(t *testing.T) {
	tenantID := shared.NewID()
	targetGroupID := shared.NewID()

	// Catch-all rule (empty conditions matches everything)
	rule := accesscontrol.ReconstituteAssignmentRule(
		shared.NewID(), tenantID,
		"Catch All", "",
		10, true,
		accesscontrol.AssignmentConditions{},
		targetGroupID,
		accesscontrol.AssignmentOptions{},
		time.Now(), time.Now(),
		nil,
	)

	// Create 10 findings (all should match catch-all)
	findings := make([]*vulnerability.Finding, 10)
	for i := 0; i < 10; i++ {
		findings[i] = makeTestFinding(t, tenantID, vulnerability.SeverityHigh, "tool", vulnerability.FindingSourceSAST)
	}

	acRepo := &mockACRepoForRules{getRuleResult: rule}
	groupRepo := &mockGroupRepoForRules{}
	findingRepo := &mockFindingRepoForRules{
		listResult: pagination.Result[*vulnerability.Finding]{
			Data:  findings,
			Total: 10,
		},
	}

	log := logger.New(logger.Config{Level: "error"})
	svc := app.NewAssignmentRuleService(acRepo, groupRepo, log)
	engine := app.NewAssignmentEngine(acRepo, log)
	svc.SetAssignmentEngine(engine)
	svc.SetFindingRepository(findingRepo)

	result, err := svc.TestRule(context.Background(), tenantID.String(), rule.ID().String())
	require.NoError(t, err)
	assert.Equal(t, int64(10), result.MatchingFindings)
	assert.Len(t, result.SampleFindings, 5, "samples should be capped at 5")
}

func TestTestRule_ReturnsCorrectInfo(t *testing.T) {
	tenantID := shared.NewID()
	targetGroupID := shared.NewID()
	conditions := accesscontrol.AssignmentConditions{
		AssetTypes:      []string{"host", "website"},
		FindingSeverity: []string{"critical"},
	}
	rule := accesscontrol.ReconstituteAssignmentRule(
		shared.NewID(), tenantID,
		"Critical Web Rule", "Find critical web issues",
		100, true,
		conditions, targetGroupID,
		accesscontrol.AssignmentOptions{NotifyGroup: true},
		time.Now(), time.Now(),
		nil,
	)

	acRepo := &mockACRepoForRules{getRuleResult: rule}
	groupRepo := &mockGroupRepoForRules{}
	svc := newAssignmentRuleService(acRepo, groupRepo)

	result, err := svc.TestRule(context.Background(), tenantID.String(), rule.ID().String())
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	if result.RuleName != "Critical Web Rule" {
		t.Errorf("expected 'Critical Web Rule', got '%s'", result.RuleName)
	}
	if result.TargetGroupID != targetGroupID.String() {
		t.Errorf("expected target group %s, got %s", targetGroupID.String(), result.TargetGroupID)
	}
	if result.MatchingFindings != 0 {
		t.Errorf("expected 0 matching findings (no engine wired in test), got %d", result.MatchingFindings)
	}
}

// =============================================================================
// Mock FindingRepository for TestRule tests
// =============================================================================

type mockFindingRepoForRules struct {
	vulnerability.FindingRepository // embed to satisfy interface
	listResult                      pagination.Result[*vulnerability.Finding]
	listErr                         error
}

func (m *mockFindingRepoForRules) List(_ context.Context, _ vulnerability.FindingFilter, _ vulnerability.FindingListOptions, _ pagination.Pagination) (pagination.Result[*vulnerability.Finding], error) {
	return m.listResult, m.listErr
}

// =============================================================================
// Test Finding Helper
// =============================================================================

func makeTestFinding(t *testing.T, tenantID shared.ID, sev vulnerability.Severity, toolName string, source vulnerability.FindingSource) *vulnerability.Finding {
	t.Helper()
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
		FindingType:     vulnerability.FindingTypeVulnerability,
		Status:          vulnerability.FindingStatusNew,
		SLAStatus:       vulnerability.SLAStatusNotApplicable,
		FirstDetectedAt: f.FirstDetectedAt(),
		LastSeenAt:      f.LastSeenAt(),
		CreatedAt:       f.CreatedAt(),
		UpdatedAt:       f.UpdatedAt(),
	}
	return vulnerability.ReconstituteFinding(data)
}

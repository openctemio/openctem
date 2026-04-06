package unit

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/openctemio/api/internal/app"
	"github.com/openctemio/api/pkg/domain/accesscontrol"
	"github.com/openctemio/api/pkg/domain/group"
	"github.com/openctemio/api/pkg/domain/permission"
	"github.com/openctemio/api/pkg/domain/permissionset"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/logger"
)

// =============================================================================
// Mock Permission Set Repository
// =============================================================================

type mockPermissionSetRepo struct {
	// Storage
	sets   map[string]*permissionset.PermissionSet
	items  map[string][]*permissionset.Item // key = permissionSetID
	slugs  map[string]bool                  // key = "tenantID:slug"

	// Error overrides
	createErr         error
	getByIDErr        error
	getBySlugErr      error
	updateErr         error
	deleteErr         error
	existsBySlugErr   error
	listErr           error
	countErr          error
	addItemErr        error
	removeItemErr     error
	getWithItemsErr   error
	getLatestVerErr   error
	getInheritChainErr error
	countGroupsErr    error

	// Call tracking
	createCalls       int
	getByIDCalls      int
	updateCalls       int
	deleteCalls       int
	addItemCalls      int
	removeItemCalls   int

	// Additional behavior
	existsBySlugResult bool
	countGroupsResult  int64
	listResult         []*permissionset.PermissionSet
	countResult        int64
	latestVersion      *permissionset.Version
	inheritanceChain   []*permissionset.PermissionSet
	withItemsResult    *permissionset.PermissionSetWithItems
}

func newMockPermissionSetRepo() *mockPermissionSetRepo {
	return &mockPermissionSetRepo{
		sets:  make(map[string]*permissionset.PermissionSet),
		items: make(map[string][]*permissionset.Item),
		slugs: make(map[string]bool),
	}
}

func (m *mockPermissionSetRepo) Create(_ context.Context, ps *permissionset.PermissionSet) error {
	m.createCalls++
	if m.createErr != nil {
		return m.createErr
	}
	m.sets[ps.ID().String()] = ps
	return nil
}

func (m *mockPermissionSetRepo) GetByID(_ context.Context, id shared.ID) (*permissionset.PermissionSet, error) {
	m.getByIDCalls++
	if m.getByIDErr != nil {
		return nil, m.getByIDErr
	}
	ps, ok := m.sets[id.String()]
	if !ok {
		return nil, permissionset.ErrPermissionSetNotFound
	}
	return ps, nil
}

func (m *mockPermissionSetRepo) GetByTenantAndID(_ context.Context, _, id shared.ID) (*permissionset.PermissionSet, error) {
	return nil, nil
}

func (m *mockPermissionSetRepo) GetBySlug(_ context.Context, _ *shared.ID, slug string) (*permissionset.PermissionSet, error) {
	if m.getBySlugErr != nil {
		return nil, m.getBySlugErr
	}
	for _, ps := range m.sets {
		if ps.Slug() == slug {
			return ps, nil
		}
	}
	return nil, permissionset.ErrPermissionSetNotFound
}

func (m *mockPermissionSetRepo) Update(_ context.Context, ps *permissionset.PermissionSet) error {
	m.updateCalls++
	if m.updateErr != nil {
		return m.updateErr
	}
	m.sets[ps.ID().String()] = ps
	return nil
}

func (m *mockPermissionSetRepo) Delete(_ context.Context, id shared.ID) error {
	m.deleteCalls++
	if m.deleteErr != nil {
		return m.deleteErr
	}
	if _, ok := m.sets[id.String()]; !ok {
		return permissionset.ErrPermissionSetNotFound
	}
	delete(m.sets, id.String())
	return nil
}

func (m *mockPermissionSetRepo) List(_ context.Context, _ permissionset.ListFilter) ([]*permissionset.PermissionSet, error) {
	if m.listErr != nil {
		return nil, m.listErr
	}
	if m.listResult != nil {
		return m.listResult, nil
	}
	result := make([]*permissionset.PermissionSet, 0, len(m.sets))
	for _, ps := range m.sets {
		result = append(result, ps)
	}
	return result, nil
}

func (m *mockPermissionSetRepo) Count(_ context.Context, _ permissionset.ListFilter) (int64, error) {
	if m.countErr != nil {
		return 0, m.countErr
	}
	if m.countResult > 0 {
		return m.countResult, nil
	}
	return int64(len(m.sets)), nil
}

func (m *mockPermissionSetRepo) ExistsBySlug(_ context.Context, tenantID *shared.ID, slug string) (bool, error) {
	if m.existsBySlugErr != nil {
		return false, m.existsBySlugErr
	}
	if m.existsBySlugResult {
		return true, nil
	}
	key := ""
	if tenantID != nil {
		key = tenantID.String()
	}
	key += ":" + slug
	return m.slugs[key], nil
}

func (m *mockPermissionSetRepo) ListByIDs(_ context.Context, _ []shared.ID) ([]*permissionset.PermissionSet, error) {
	return nil, nil
}

func (m *mockPermissionSetRepo) ListSystemSets(_ context.Context) ([]*permissionset.PermissionSet, error) {
	return nil, nil
}

func (m *mockPermissionSetRepo) ListByTenant(_ context.Context, _ shared.ID, _ bool) ([]*permissionset.PermissionSet, error) {
	return nil, nil
}

func (m *mockPermissionSetRepo) AddItem(_ context.Context, item *permissionset.Item) error {
	m.addItemCalls++
	if m.addItemErr != nil {
		return m.addItemErr
	}
	key := item.PermissionSetID().String()
	m.items[key] = append(m.items[key], item)
	return nil
}

func (m *mockPermissionSetRepo) RemoveItem(_ context.Context, permissionSetID shared.ID, _ string) error {
	m.removeItemCalls++
	if m.removeItemErr != nil {
		return m.removeItemErr
	}
	_ = permissionSetID
	return nil
}

func (m *mockPermissionSetRepo) ListItems(_ context.Context, _ shared.ID) ([]*permissionset.Item, error) {
	return nil, nil
}

func (m *mockPermissionSetRepo) GetWithItems(_ context.Context, id shared.ID) (*permissionset.PermissionSetWithItems, error) {
	if m.getWithItemsErr != nil {
		return nil, m.getWithItemsErr
	}
	if m.withItemsResult != nil {
		return m.withItemsResult, nil
	}
	ps, ok := m.sets[id.String()]
	if !ok {
		return nil, permissionset.ErrPermissionSetNotFound
	}
	return &permissionset.PermissionSetWithItems{
		PermissionSet: ps,
		Items:         m.items[id.String()],
	}, nil
}

func (m *mockPermissionSetRepo) BatchAddItems(_ context.Context, _ []*permissionset.Item) error {
	return nil
}

func (m *mockPermissionSetRepo) ReplaceItems(_ context.Context, _ shared.ID, _ []*permissionset.Item) error {
	return nil
}

func (m *mockPermissionSetRepo) CreateVersion(_ context.Context, _ *permissionset.Version) error {
	return nil
}

func (m *mockPermissionSetRepo) GetLatestVersion(_ context.Context, _ shared.ID) (*permissionset.Version, error) {
	if m.getLatestVerErr != nil {
		return nil, m.getLatestVerErr
	}
	return m.latestVersion, nil
}

func (m *mockPermissionSetRepo) ListVersions(_ context.Context, _ shared.ID) ([]*permissionset.Version, error) {
	return nil, nil
}

func (m *mockPermissionSetRepo) GetParent(_ context.Context, _ shared.ID) (*permissionset.PermissionSet, error) {
	return nil, nil
}

func (m *mockPermissionSetRepo) ListChildren(_ context.Context, _ shared.ID) ([]*permissionset.PermissionSet, error) {
	return nil, nil
}

func (m *mockPermissionSetRepo) GetInheritanceChain(_ context.Context, _ shared.ID) ([]*permissionset.PermissionSet, error) {
	if m.getInheritChainErr != nil {
		return nil, m.getInheritChainErr
	}
	return m.inheritanceChain, nil
}

func (m *mockPermissionSetRepo) CountGroupsUsing(_ context.Context, _ shared.ID) (int64, error) {
	if m.countGroupsErr != nil {
		return 0, m.countGroupsErr
	}
	return m.countGroupsResult, nil
}

func (m *mockPermissionSetRepo) ListGroupIDsUsing(_ context.Context, _ shared.ID) ([]shared.ID, error) {
	return nil, nil
}

// =============================================================================
// Mock Group Repository
// =============================================================================

type mockGroupRepoForPermission struct {
	groups          map[string]*group.Group
	userGroups      map[string][]*group.GroupWithRole // key = "tenantID:userID"
	permissionSets  map[string][]shared.ID           // key = groupID
	getByIDErr      error
	listGroupsByUserErr error
	listPermSetIDsErr   error
}

func newMockGroupRepoForPermission() *mockGroupRepoForPermission {
	return &mockGroupRepoForPermission{
		groups:         make(map[string]*group.Group),
		userGroups:     make(map[string][]*group.GroupWithRole),
		permissionSets: make(map[string][]shared.ID),
	}
}

func (m *mockGroupRepoForPermission) Create(_ context.Context, _ *group.Group) error { return nil }
func (m *mockGroupRepoForPermission) GetByID(_ context.Context, id shared.ID) (*group.Group, error) {
	if m.getByIDErr != nil {
		return nil, m.getByIDErr
	}
	g, ok := m.groups[id.String()]
	if !ok {
		return nil, errors.New("group not found")
	}
	return g, nil
}
func (m *mockGroupRepoForPermission) GetByTenantAndID(_ context.Context, _, id shared.ID) (*group.Group, error) {
	return nil, nil
}
func (m *mockGroupRepoForPermission) GetBySlug(_ context.Context, _ shared.ID, _ string) (*group.Group, error) {
	return nil, nil
}
func (m *mockGroupRepoForPermission) Update(_ context.Context, _ *group.Group) error { return nil }
func (m *mockGroupRepoForPermission) Delete(_ context.Context, _ shared.ID) error    { return nil }
func (m *mockGroupRepoForPermission) List(_ context.Context, _ shared.ID, _ group.ListFilter) ([]*group.Group, error) {
	return nil, nil
}
func (m *mockGroupRepoForPermission) Count(_ context.Context, _ shared.ID, _ group.ListFilter) (int64, error) {
	return 0, nil
}
func (m *mockGroupRepoForPermission) ExistsBySlug(_ context.Context, _ shared.ID, _ string) (bool, error) {
	return false, nil
}
func (m *mockGroupRepoForPermission) ListByIDs(_ context.Context, _ []shared.ID) ([]*group.Group, error) {
	return nil, nil
}
func (m *mockGroupRepoForPermission) GetByExternalID(_ context.Context, _ shared.ID, _ group.ExternalSource, _ string) (*group.Group, error) {
	return nil, nil
}
func (m *mockGroupRepoForPermission) AddMember(_ context.Context, _ *group.Member) error { return nil }
func (m *mockGroupRepoForPermission) GetMember(_ context.Context, _, _ shared.ID) (*group.Member, error) {
	return nil, nil
}
func (m *mockGroupRepoForPermission) UpdateMember(_ context.Context, _ *group.Member) error {
	return nil
}
func (m *mockGroupRepoForPermission) RemoveMember(_ context.Context, _, _ shared.ID) error {
	return nil
}
func (m *mockGroupRepoForPermission) ListMembers(_ context.Context, _ shared.ID) ([]*group.Member, error) {
	return nil, nil
}
func (m *mockGroupRepoForPermission) ListMembersWithUserInfo(_ context.Context, _ shared.ID, _, _ int) ([]*group.MemberWithUser, int64, error) {
	return nil, 0, nil
}
func (m *mockGroupRepoForPermission) CountMembers(_ context.Context, _ shared.ID) (int64, error) {
	return 0, nil
}
func (m *mockGroupRepoForPermission) CountMembersByGroups(_ context.Context, _ []shared.ID) (map[shared.ID]int, error) {
	return nil, nil
}
func (m *mockGroupRepoForPermission) CountUniqueMembers(_ context.Context, _ []shared.ID) (int, error) {
	return 0, nil
}
func (m *mockGroupRepoForPermission) GetMemberStats(_ context.Context, _ shared.ID) (*group.MemberStats, error) {
	return nil, nil
}
func (m *mockGroupRepoForPermission) IsMember(_ context.Context, _, _ shared.ID) (bool, error) {
	return false, nil
}
func (m *mockGroupRepoForPermission) ListGroupsByUser(_ context.Context, tenantID, userID shared.ID) ([]*group.GroupWithRole, error) {
	if m.listGroupsByUserErr != nil {
		return nil, m.listGroupsByUserErr
	}
	key := tenantID.String() + ":" + userID.String()
	return m.userGroups[key], nil
}
func (m *mockGroupRepoForPermission) ListGroupIDsByUser(_ context.Context, _, _ shared.ID) ([]shared.ID, error) {
	return nil, nil
}
func (m *mockGroupRepoForPermission) AssignPermissionSet(_ context.Context, _, _ shared.ID, _ *shared.ID) error {
	return nil
}
func (m *mockGroupRepoForPermission) RemovePermissionSet(_ context.Context, _, _ shared.ID) error {
	return nil
}
func (m *mockGroupRepoForPermission) ListPermissionSetIDs(_ context.Context, groupID shared.ID) ([]shared.ID, error) {
	if m.listPermSetIDsErr != nil {
		return nil, m.listPermSetIDsErr
	}
	return m.permissionSets[groupID.String()], nil
}
func (m *mockGroupRepoForPermission) ListGroupsWithPermissionSet(_ context.Context, _ shared.ID) ([]*group.Group, error) {
	return nil, nil
}

// =============================================================================
// Mock Access Control Repository
// =============================================================================

type mockAccessControlRepoForPermission struct {
	groupPermissions map[string][]*accesscontrol.GroupPermission // key = groupID
	createErr        error
	listErr          error
	deleteErr        error
}

func newMockAccessControlRepoForPermission() *mockAccessControlRepoForPermission {
	return &mockAccessControlRepoForPermission{
		groupPermissions: make(map[string][]*accesscontrol.GroupPermission),
	}
}

func (m *mockAccessControlRepoForPermission) CreateAssetOwner(_ context.Context, _ *accesscontrol.AssetOwner) error {
	return nil
}
func (m *mockAccessControlRepoForPermission) GetAssetOwner(_ context.Context, _, _ shared.ID) (*accesscontrol.AssetOwner, error) {
	return nil, nil
}
func (m *mockAccessControlRepoForPermission) UpdateAssetOwner(_ context.Context, _ *accesscontrol.AssetOwner) error {
	return nil
}
func (m *mockAccessControlRepoForPermission) DeleteAssetOwner(_ context.Context, _, _ shared.ID) error {
	return nil
}
func (m *mockAccessControlRepoForPermission) ListAssetOwners(_ context.Context, _ shared.ID) ([]*accesscontrol.AssetOwner, error) {
	return nil, nil
}
func (m *mockAccessControlRepoForPermission) ListAssetsByGroup(_ context.Context, _ shared.ID) ([]shared.ID, error) {
	return nil, nil
}
func (m *mockAccessControlRepoForPermission) ListGroupsByAsset(_ context.Context, _ shared.ID) ([]shared.ID, error) {
	return nil, nil
}
func (m *mockAccessControlRepoForPermission) CountAssetOwners(_ context.Context, _ shared.ID) (int64, error) {
	return 0, nil
}
func (m *mockAccessControlRepoForPermission) CountAssetsByGroups(_ context.Context, _ []shared.ID) (map[shared.ID]int, error) {
	return nil, nil
}
func (m *mockAccessControlRepoForPermission) ListAssetOwnersByGroupWithDetails(_ context.Context, _ shared.ID, _, _ int) ([]*accesscontrol.AssetOwnerWithAsset, int64, error) {
	return nil, 0, nil
}
func (m *mockAccessControlRepoForPermission) HasPrimaryOwner(_ context.Context, _ shared.ID) (bool, error) {
	return false, nil
}
func (m *mockAccessControlRepoForPermission) ListAccessibleAssets(_ context.Context, _, _ shared.ID) ([]shared.ID, error) {
	return nil, nil
}
func (m *mockAccessControlRepoForPermission) CanAccessAsset(_ context.Context, _, _ shared.ID) (bool, error) {
	return false, nil
}
func (m *mockAccessControlRepoForPermission) GetUserAssetAccess(_ context.Context, _, _ shared.ID) (*accesscontrol.UserAssetAccess, error) {
	return nil, nil
}
func (m *mockAccessControlRepoForPermission) HasAnyScopeAssignment(_ context.Context, _, _ shared.ID) (bool, error) {
	return false, nil
}
func (m *mockAccessControlRepoForPermission) CreateGroupPermission(_ context.Context, gp *accesscontrol.GroupPermission) error {
	if m.createErr != nil {
		return m.createErr
	}
	key := gp.GroupID().String()
	m.groupPermissions[key] = append(m.groupPermissions[key], gp)
	return nil
}
func (m *mockAccessControlRepoForPermission) GetGroupPermission(_ context.Context, groupID shared.ID, permissionID string) (*accesscontrol.GroupPermission, error) {
	for _, gp := range m.groupPermissions[groupID.String()] {
		if gp.PermissionID() == permissionID {
			return gp, nil
		}
	}
	return nil, errors.New("not found")
}
func (m *mockAccessControlRepoForPermission) UpdateGroupPermission(_ context.Context, _ *accesscontrol.GroupPermission) error {
	return nil
}
func (m *mockAccessControlRepoForPermission) DeleteGroupPermission(_ context.Context, _ shared.ID, _ string) error {
	if m.deleteErr != nil {
		return m.deleteErr
	}
	return nil
}
func (m *mockAccessControlRepoForPermission) ListGroupPermissions(_ context.Context, groupID shared.ID) ([]*accesscontrol.GroupPermission, error) {
	if m.listErr != nil {
		return nil, m.listErr
	}
	return m.groupPermissions[groupID.String()], nil
}
func (m *mockAccessControlRepoForPermission) ListGroupPermissionsByEffect(_ context.Context, _ shared.ID, _ accesscontrol.PermissionEffect) ([]*accesscontrol.GroupPermission, error) {
	return nil, nil
}
func (m *mockAccessControlRepoForPermission) CreateAssignmentRule(_ context.Context, _ *accesscontrol.AssignmentRule) error {
	return nil
}
func (m *mockAccessControlRepoForPermission) GetAssignmentRule(_ context.Context, _, _ shared.ID) (*accesscontrol.AssignmentRule, error) {
	return nil, nil
}
func (m *mockAccessControlRepoForPermission) UpdateAssignmentRule(_ context.Context, _ shared.ID, _ *accesscontrol.AssignmentRule) error {
	return nil
}
func (m *mockAccessControlRepoForPermission) DeleteAssignmentRule(_ context.Context, _, _ shared.ID) error {
	return nil
}
func (m *mockAccessControlRepoForPermission) ListAssignmentRules(_ context.Context, _ shared.ID, _ accesscontrol.AssignmentRuleFilter) ([]*accesscontrol.AssignmentRule, error) {
	return nil, nil
}
func (m *mockAccessControlRepoForPermission) CountAssignmentRules(_ context.Context, _ shared.ID, _ accesscontrol.AssignmentRuleFilter) (int64, error) {
	return 0, nil
}
func (m *mockAccessControlRepoForPermission) ListActiveRulesByPriority(_ context.Context, _ shared.ID) ([]*accesscontrol.AssignmentRule, error) {
	return nil, nil
}
func (m *mockAccessControlRepoForPermission) BulkCreateFindingGroupAssignments(_ context.Context, _ []*accesscontrol.FindingGroupAssignment) (int, error) {
	return 0, nil
}
func (m *mockAccessControlRepoForPermission) ListFindingGroupAssignments(_ context.Context, _, _ shared.ID) ([]*accesscontrol.FindingGroupAssignment, error) {
	return nil, nil
}
func (m *mockAccessControlRepoForPermission) CountFindingsByGroupFromRules(_ context.Context, _, _ shared.ID) (int64, error) {
	return 0, nil
}
func (m *mockAccessControlRepoForPermission) BulkCreateAssetOwners(_ context.Context, _ []*accesscontrol.AssetOwner) (int, error) {
	return 0, nil
}
func (m *mockAccessControlRepoForPermission) RefreshUserAccessibleAssets(_ context.Context) error {
	return nil
}
func (m *mockAccessControlRepoForPermission) RefreshAccessForAssetAssign(_ context.Context, _, _ shared.ID, _ string) error {
	return nil
}
func (m *mockAccessControlRepoForPermission) RefreshAccessForAssetUnassign(_ context.Context, _, _ shared.ID) error {
	return nil
}
func (m *mockAccessControlRepoForPermission) RefreshAccessForMemberAdd(_ context.Context, _, _ shared.ID) error {
	return nil
}
func (m *mockAccessControlRepoForPermission) RefreshAccessForMemberRemove(_ context.Context, _, _ shared.ID) error {
	return nil
}
func (m *mockAccessControlRepoForPermission) CreateScopeRule(_ context.Context, _ *accesscontrol.ScopeRule) error {
	return nil
}
func (m *mockAccessControlRepoForPermission) GetScopeRule(_ context.Context, _, _ shared.ID) (*accesscontrol.ScopeRule, error) {
	return nil, nil
}
func (m *mockAccessControlRepoForPermission) UpdateScopeRule(_ context.Context, _ shared.ID, _ *accesscontrol.ScopeRule) error {
	return nil
}
func (m *mockAccessControlRepoForPermission) DeleteScopeRule(_ context.Context, _, _ shared.ID) error {
	return nil
}
func (m *mockAccessControlRepoForPermission) ListScopeRules(_ context.Context, _, _ shared.ID, _ accesscontrol.ScopeRuleFilter) ([]*accesscontrol.ScopeRule, error) {
	return nil, nil
}
func (m *mockAccessControlRepoForPermission) CountScopeRules(_ context.Context, _, _ shared.ID, _ accesscontrol.ScopeRuleFilter) (int64, error) {
	return 0, nil
}
func (m *mockAccessControlRepoForPermission) ListActiveScopeRulesByTenant(_ context.Context, _ shared.ID) ([]*accesscontrol.ScopeRule, error) {
	return nil, nil
}
func (m *mockAccessControlRepoForPermission) ListActiveScopeRulesByGroup(_ context.Context, _, _ shared.ID) ([]*accesscontrol.ScopeRule, error) {
	return nil, nil
}
func (m *mockAccessControlRepoForPermission) CreateAssetOwnerWithSource(_ context.Context, _ *accesscontrol.AssetOwner, _ string, _ *shared.ID) error {
	return nil
}
func (m *mockAccessControlRepoForPermission) BulkCreateAssetOwnersWithSource(_ context.Context, _ []*accesscontrol.AssetOwner, _ string, _ *shared.ID) (int, error) {
	return 0, nil
}
func (m *mockAccessControlRepoForPermission) DeleteAutoAssignedByRule(_ context.Context, _, _ shared.ID) (int, error) {
	return 0, nil
}
func (m *mockAccessControlRepoForPermission) DeleteAutoAssignedForAsset(_ context.Context, _, _ shared.ID) error {
	return nil
}
func (m *mockAccessControlRepoForPermission) BulkDeleteAutoAssignedForAssets(_ context.Context, _ []shared.ID, _ shared.ID) (int, error) {
	return 0, nil
}
func (m *mockAccessControlRepoForPermission) ListAutoAssignedAssets(_ context.Context, _, _ shared.ID) ([]shared.ID, error) {
	return nil, nil
}
func (m *mockAccessControlRepoForPermission) ListAutoAssignedGroupsForAsset(_ context.Context, _ shared.ID) ([]shared.ID, error) {
	return nil, nil
}
func (m *mockAccessControlRepoForPermission) DeleteScopeRuleWithCleanup(_ context.Context, _, _ shared.ID) (int, error) {
	return 0, nil
}
func (m *mockAccessControlRepoForPermission) FindAssetsByTagMatch(_ context.Context, _ shared.ID, _ []string, _ accesscontrol.MatchLogic) ([]shared.ID, error) {
	return nil, nil
}
func (m *mockAccessControlRepoForPermission) FindAssetsByAssetGroupMatch(_ context.Context, _ shared.ID, _ []shared.ID) ([]shared.ID, error) {
	return nil, nil
}
func (m *mockAccessControlRepoForPermission) GetAssetOwnerByID(_ context.Context, _ shared.ID) (*accesscontrol.AssetOwner, error) {
	return nil, nil
}
func (m *mockAccessControlRepoForPermission) GetAssetOwnerByUser(_ context.Context, _, _ shared.ID) (*accesscontrol.AssetOwner, error) {
	return nil, nil
}
func (m *mockAccessControlRepoForPermission) DeleteAssetOwnerByID(_ context.Context, _ shared.ID) error {
	return nil
}
func (m *mockAccessControlRepoForPermission) DeleteAssetOwnerByUser(_ context.Context, _, _ shared.ID) error {
	return nil
}
func (m *mockAccessControlRepoForPermission) ListAssetOwnersWithNames(_ context.Context, _, _ shared.ID) ([]*accesscontrol.AssetOwnerWithNames, error) {
	return nil, nil
}
func (m *mockAccessControlRepoForPermission) GetPrimaryOwnerBrief(_ context.Context, _, _ shared.ID) (*accesscontrol.OwnerBrief, error) {
	return nil, nil
}
func (m *mockAccessControlRepoForPermission) RefreshAccessForDirectOwnerAdd(_ context.Context, _, _ shared.ID, _ string) error {
	return nil
}
func (m *mockAccessControlRepoForPermission) RefreshAccessForDirectOwnerRemove(_ context.Context, _, _ shared.ID) error {
	return nil
}
func (m *mockAccessControlRepoForPermission) GetPrimaryOwnersByAssetIDs(_ context.Context, _ shared.ID, _ []shared.ID) (map[string]*accesscontrol.OwnerBrief, error) {
	return nil, nil
}
func (m *mockAccessControlRepoForPermission) ListTenantsWithActiveScopeRules(_ context.Context) ([]shared.ID, error) {
	return nil, nil
}
func (m *mockAccessControlRepoForPermission) ListGroupsWithActiveScopeRules(_ context.Context, _ shared.ID) ([]shared.ID, error) {
	return nil, nil
}
func (m *mockAccessControlRepoForPermission) ListGroupsWithAssetGroupMatchRule(_ context.Context, _ shared.ID) ([]shared.ID, error) {
	return nil, nil
}

// =============================================================================
// Helper: create a PermissionService for testing
// =============================================================================

func newTestPermissionService() (*app.PermissionService, *mockPermissionSetRepo, *mockGroupRepoForPermission, *mockAccessControlRepoForPermission) {
	psRepo := newMockPermissionSetRepo()
	groupRepo := newMockGroupRepoForPermission()
	acRepo := newMockAccessControlRepoForPermission()
	log := logger.NewNop()

	svc := app.NewPermissionService(
		psRepo,
		log,
		app.WithPermissionGroupRepository(groupRepo),
		app.WithPermissionAccessControlRepository(acRepo),
	)

	return svc, psRepo, groupRepo, acRepo
}

// Helper: create a custom permission set and store it in the mock repo.
func seedCustomPermissionSet(repo *mockPermissionSetRepo, tenantID shared.ID, name, slug string) *permissionset.PermissionSet {
	ps, _ := permissionset.NewPermissionSet(tenantID, name, slug, "test description")
	repo.sets[ps.ID().String()] = ps
	return ps
}

// Helper: create a system permission set and store it in the mock repo.
func seedSystemPermissionSet(repo *mockPermissionSetRepo, name, slug string) *permissionset.PermissionSet {
	now := time.Now().UTC()
	ps := permissionset.Reconstitute(
		shared.NewID(),
		nil, // nil tenantID = system
		name,
		slug,
		"system template",
		permissionset.SetTypeSystem,
		nil,
		nil,
		true,
		now,
		now,
	)
	repo.sets[ps.ID().String()] = ps
	return ps
}

// Helper: create a group and store it in the mock group repo.
func seedGroupForPermission(repo *mockGroupRepoForPermission, tenantID shared.ID, name, slug string) *group.Group {
	g, _ := group.NewGroup(tenantID, name, slug, group.GroupTypeTeam)
	repo.groups[g.ID().String()] = g
	return g
}

// =============================================================================
// CreatePermissionSet Tests
// =============================================================================

func TestCreatePermissionSet_Success(t *testing.T) {
	svc, repo, _, _ := newTestPermissionService()
	tenantID := shared.NewID()

	input := app.CreatePermissionSetInput{
		TenantID:    tenantID.String(),
		Name:        "Security Analyst Set",
		Slug:        "security-analyst-set",
		Description: "Permissions for security analysts",
		SetType:     "custom",
	}

	ps, err := svc.CreatePermissionSet(context.Background(), input, app.AuditContext{})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if ps == nil {
		t.Fatal("expected permission set, got nil")
	}
	if ps.Name() != "Security Analyst Set" {
		t.Errorf("expected name 'Security Analyst Set', got %q", ps.Name())
	}
	if ps.Slug() != "security-analyst-set" {
		t.Errorf("expected slug 'security-analyst-set', got %q", ps.Slug())
	}
	if ps.IsSystem() {
		t.Error("custom permission set should not be system")
	}
	if repo.createCalls != 1 {
		t.Errorf("expected 1 create call, got %d", repo.createCalls)
	}
}

func TestCreatePermissionSet_DuplicateSlug(t *testing.T) {
	svc, repo, _, _ := newTestPermissionService()
	tenantID := shared.NewID()

	// Mark slug as existing
	repo.existsBySlugResult = true

	input := app.CreatePermissionSetInput{
		TenantID: tenantID.String(),
		Name:     "Duplicate Set",
		Slug:     "existing-slug",
		SetType:  "custom",
	}

	_, err := svc.CreatePermissionSet(context.Background(), input, app.AuditContext{})
	if err == nil {
		t.Fatal("expected error for duplicate slug")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected ErrValidation, got %v", err)
	}
}

func TestCreatePermissionSet_ExtendedRequiresParent(t *testing.T) {
	svc, _, _, _ := newTestPermissionService()
	tenantID := shared.NewID()

	input := app.CreatePermissionSetInput{
		TenantID: tenantID.String(),
		Name:     "Extended Set",
		Slug:     "extended-set",
		SetType:  "extended",
		// No ParentSetID provided
	}

	_, err := svc.CreatePermissionSet(context.Background(), input, app.AuditContext{})
	if err == nil {
		t.Fatal("expected error for extended type without parent")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected ErrValidation, got %v", err)
	}
}

func TestCreatePermissionSet_ExtendedWithNonExistentParent(t *testing.T) {
	svc, _, _, _ := newTestPermissionService()
	tenantID := shared.NewID()
	nonExistentID := shared.NewID().String()

	input := app.CreatePermissionSetInput{
		TenantID:    tenantID.String(),
		Name:        "Extended Set",
		Slug:        "extended-set",
		SetType:     "extended",
		ParentSetID: &nonExistentID,
	}

	_, err := svc.CreatePermissionSet(context.Background(), input, app.AuditContext{})
	if err == nil {
		t.Fatal("expected error for non-existent parent")
	}
}

// =============================================================================
// UpdatePermissionSet Tests
// =============================================================================

func TestUpdatePermissionSet_Success(t *testing.T) {
	svc, repo, _, _ := newTestPermissionService()
	tenantID := shared.NewID()
	ps := seedCustomPermissionSet(repo, tenantID, "Original Name", "original-slug")

	newName := "Updated Name"
	input := app.UpdatePermissionSetInput{
		Name: &newName,
	}

	updated, err := svc.UpdatePermissionSet(context.Background(), ps.ID().String(), input, app.AuditContext{})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if updated.Name() != "Updated Name" {
		t.Errorf("expected name 'Updated Name', got %q", updated.Name())
	}
	if repo.updateCalls != 1 {
		t.Errorf("expected 1 update call, got %d", repo.updateCalls)
	}
}

func TestUpdatePermissionSet_CannotUpdateSystemSet(t *testing.T) {
	svc, repo, _, _ := newTestPermissionService()
	sysPS := seedSystemPermissionSet(repo, "System Set", "system-set")

	newName := "Hacked Name"
	input := app.UpdatePermissionSetInput{
		Name: &newName,
	}

	_, err := svc.UpdatePermissionSet(context.Background(), sysPS.ID().String(), input, app.AuditContext{})
	if err == nil {
		t.Fatal("expected error for system set modification")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected ErrValidation, got %v", err)
	}
}

// =============================================================================
// DeletePermissionSet Tests
// =============================================================================

func TestDeletePermissionSet_Success(t *testing.T) {
	svc, repo, _, _ := newTestPermissionService()
	tenantID := shared.NewID()
	ps := seedCustomPermissionSet(repo, tenantID, "To Delete", "to-delete")

	err := svc.DeletePermissionSet(context.Background(), ps.ID().String(), app.AuditContext{})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if repo.deleteCalls != 1 {
		t.Errorf("expected 1 delete call, got %d", repo.deleteCalls)
	}
	// Verify removed from store
	if _, ok := repo.sets[ps.ID().String()]; ok {
		t.Error("expected permission set to be removed from store")
	}
}

func TestDeletePermissionSet_CannotDeleteSystemSet(t *testing.T) {
	svc, repo, _, _ := newTestPermissionService()
	sysPS := seedSystemPermissionSet(repo, "System Set", "system-set")

	err := svc.DeletePermissionSet(context.Background(), sysPS.ID().String(), app.AuditContext{})
	if err == nil {
		t.Fatal("expected error for system set deletion")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected ErrValidation, got %v", err)
	}
}

func TestDeletePermissionSet_CannotDeleteIfInUseByGroups(t *testing.T) {
	svc, repo, _, _ := newTestPermissionService()
	tenantID := shared.NewID()
	ps := seedCustomPermissionSet(repo, tenantID, "In Use Set", "in-use-set")

	// Simulate that 3 groups are using this permission set
	repo.countGroupsResult = 3

	err := svc.DeletePermissionSet(context.Background(), ps.ID().String(), app.AuditContext{})
	if err == nil {
		t.Fatal("expected error for permission set in use")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected ErrValidation, got %v", err)
	}
}

// =============================================================================
// GetPermissionSet Tests
// =============================================================================

func TestGetPermissionSet_Success(t *testing.T) {
	svc, repo, _, _ := newTestPermissionService()
	tenantID := shared.NewID()
	ps := seedCustomPermissionSet(repo, tenantID, "Test Set", "test-set")

	found, err := svc.GetPermissionSet(context.Background(), ps.ID().String())
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if found.ID() != ps.ID() {
		t.Errorf("expected ID %s, got %s", ps.ID(), found.ID())
	}
	if repo.getByIDCalls != 1 {
		t.Errorf("expected 1 GetByID call, got %d", repo.getByIDCalls)
	}
}

func TestGetPermissionSet_NotFound(t *testing.T) {
	svc, _, _, _ := newTestPermissionService()

	_, err := svc.GetPermissionSet(context.Background(), shared.NewID().String())
	if err == nil {
		t.Fatal("expected error for permission set not found")
	}
	if !errors.Is(err, permissionset.ErrPermissionSetNotFound) {
		t.Errorf("expected ErrPermissionSetNotFound, got %v", err)
	}
}

func TestGetPermissionSet_InvalidID(t *testing.T) {
	svc, _, _, _ := newTestPermissionService()

	_, err := svc.GetPermissionSet(context.Background(), "not-a-valid-uuid")
	if err == nil {
		t.Fatal("expected error for invalid ID")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected ErrValidation, got %v", err)
	}
}

// =============================================================================
// ListPermissionSets Tests
// =============================================================================

func TestListPermissionSets_SuccessWithPagination(t *testing.T) {
	svc, repo, _, _ := newTestPermissionService()
	tenantID := shared.NewID()

	seedCustomPermissionSet(repo, tenantID, "Set A", "set-a")
	seedCustomPermissionSet(repo, tenantID, "Set B", "set-b")
	seedCustomPermissionSet(repo, tenantID, "Set C", "set-c")

	// Set explicit count for pagination test
	repo.countResult = 3

	input := app.ListPermissionSetsInput{
		TenantID: tenantID.String(),
		Limit:    10,
		Offset:   0,
	}

	output, err := svc.ListPermissionSets(context.Background(), input)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if output == nil {
		t.Fatal("expected output, got nil")
	}
	if len(output.PermissionSets) != 3 {
		t.Errorf("expected 3 permission sets, got %d", len(output.PermissionSets))
	}
	if output.TotalCount != 3 {
		t.Errorf("expected total count 3, got %d", output.TotalCount)
	}
}

func TestListPermissionSets_InvalidTenantID(t *testing.T) {
	svc, _, _, _ := newTestPermissionService()

	input := app.ListPermissionSetsInput{
		TenantID: "bad-uuid",
		Limit:    10,
	}

	_, err := svc.ListPermissionSets(context.Background(), input)
	if err == nil {
		t.Fatal("expected error for invalid tenant ID")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected ErrValidation, got %v", err)
	}
}

// =============================================================================
// AddPermissionToSet Tests
// =============================================================================

func TestAddPermissionToSet_Success(t *testing.T) {
	svc, repo, _, _ := newTestPermissionService()
	tenantID := shared.NewID()
	ps := seedCustomPermissionSet(repo, tenantID, "My Set", "my-set")

	input := app.AddPermissionToSetInput{
		PermissionSetID: ps.ID().String(),
		PermissionID:    "findings:read",
	}

	err := svc.AddPermissionToSet(context.Background(), input, app.AuditContext{})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if repo.addItemCalls != 1 {
		t.Errorf("expected 1 AddItem call, got %d", repo.addItemCalls)
	}
}

func TestAddPermissionToSet_CannotModifySystemSet(t *testing.T) {
	svc, repo, _, _ := newTestPermissionService()
	sysPS := seedSystemPermissionSet(repo, "System Template", "system-template")

	input := app.AddPermissionToSetInput{
		PermissionSetID: sysPS.ID().String(),
		PermissionID:    "findings:read",
	}

	err := svc.AddPermissionToSet(context.Background(), input, app.AuditContext{})
	if err == nil {
		t.Fatal("expected error for modifying system set")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected ErrValidation, got %v", err)
	}
}

func TestAddPermissionToSet_InvalidPermissionSetID(t *testing.T) {
	svc, _, _, _ := newTestPermissionService()

	input := app.AddPermissionToSetInput{
		PermissionSetID: "invalid-id",
		PermissionID:    "findings:read",
	}

	err := svc.AddPermissionToSet(context.Background(), input, app.AuditContext{})
	if err == nil {
		t.Fatal("expected error for invalid permission set ID")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected ErrValidation, got %v", err)
	}
}

// =============================================================================
// RemovePermissionFromSet Tests
// =============================================================================

func TestRemovePermissionFromSet_Success(t *testing.T) {
	svc, repo, _, _ := newTestPermissionService()
	tenantID := shared.NewID()
	ps := seedCustomPermissionSet(repo, tenantID, "My Set", "my-set")

	err := svc.RemovePermissionFromSet(context.Background(), ps.ID().String(), "findings:read", app.AuditContext{})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if repo.removeItemCalls != 1 {
		t.Errorf("expected 1 RemoveItem call, got %d", repo.removeItemCalls)
	}
}

func TestRemovePermissionFromSet_CannotModifySystemSet(t *testing.T) {
	svc, repo, _, _ := newTestPermissionService()
	sysPS := seedSystemPermissionSet(repo, "System Template", "system-template")

	err := svc.RemovePermissionFromSet(context.Background(), sysPS.ID().String(), "findings:read", app.AuditContext{})
	if err == nil {
		t.Fatal("expected error for modifying system set")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected ErrValidation, got %v", err)
	}
}

// =============================================================================
// HasPermission Tests
// =============================================================================

func TestPermissionService_HasPermission_True(t *testing.T) {
	svc, psRepo, groupRepo, acRepo := newTestPermissionService()
	tenantID := shared.NewID()
	userID := shared.NewID()

	// Create a group with a permission set that grants "dashboard:read"
	g := seedGroupForPermission(groupRepo, tenantID, "Dev Team", "dev-team")
	ps := seedCustomPermissionSet(psRepo, tenantID, "Dev Perms", "dev-perms")

	// Add permission item to set
	item, _ := permissionset.NewItem(ps.ID(), string(permission.DashboardRead), permissionset.ModificationAdd)
	psRepo.items[ps.ID().String()] = []*permissionset.Item{item}

	// Link group to permission set
	groupRepo.permissionSets[g.ID().String()] = []shared.ID{ps.ID()}

	// Link user to group
	key := tenantID.String() + ":" + userID.String()
	groupRepo.userGroups[key] = []*group.GroupWithRole{
		{Group: g, Role: "member"},
	}

	// No custom group permissions
	_ = acRepo

	has, err := svc.HasPermission(context.Background(), tenantID.String(), userID, permission.DashboardRead)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if !has {
		t.Error("expected user to have 'dashboard:read' permission")
	}
}

func TestPermissionService_HasPermission_False(t *testing.T) {
	svc, psRepo, groupRepo, _ := newTestPermissionService()
	tenantID := shared.NewID()
	userID := shared.NewID()

	// Create a group with a permission set that grants "dashboard:read" only
	g := seedGroupForPermission(groupRepo, tenantID, "Dev Team", "dev-team")
	ps := seedCustomPermissionSet(psRepo, tenantID, "Dev Perms", "dev-perms")

	// Add only dashboard:read
	item, _ := permissionset.NewItem(ps.ID(), string(permission.DashboardRead), permissionset.ModificationAdd)
	psRepo.items[ps.ID().String()] = []*permissionset.Item{item}

	// Link group to permission set
	groupRepo.permissionSets[g.ID().String()] = []shared.ID{ps.ID()}

	// Link user to group
	key := tenantID.String() + ":" + userID.String()
	groupRepo.userGroups[key] = []*group.GroupWithRole{
		{Group: g, Role: "member"},
	}

	// Check for a permission the user does NOT have
	has, err := svc.HasPermission(context.Background(), tenantID.String(), userID, permission.SettingsWrite)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if has {
		t.Error("expected user NOT to have 'settings:write' permission")
	}
}

// =============================================================================
// HasAnyPermission Tests
// =============================================================================

func TestHasAnyPermission_True(t *testing.T) {
	svc, psRepo, groupRepo, _ := newTestPermissionService()
	tenantID := shared.NewID()
	userID := shared.NewID()

	// Setup: user has dashboard:read through a group
	g := seedGroupForPermission(groupRepo, tenantID, "Viewers", "viewers")
	ps := seedCustomPermissionSet(psRepo, tenantID, "Viewer Perms", "viewer-perms")

	item, _ := permissionset.NewItem(ps.ID(), string(permission.DashboardRead), permissionset.ModificationAdd)
	psRepo.items[ps.ID().String()] = []*permissionset.Item{item}

	groupRepo.permissionSets[g.ID().String()] = []shared.ID{ps.ID()}
	key := tenantID.String() + ":" + userID.String()
	groupRepo.userGroups[key] = []*group.GroupWithRole{
		{Group: g, Role: "member"},
	}

	has, err := svc.HasAnyPermission(context.Background(), tenantID.String(), userID,
		permission.SettingsWrite,   // user does NOT have this
		permission.DashboardRead,  // user DOES have this
	)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if !has {
		t.Error("expected HasAnyPermission to return true")
	}
}

func TestHasAnyPermission_FalseWhenNoMatch(t *testing.T) {
	svc, psRepo, groupRepo, _ := newTestPermissionService()
	tenantID := shared.NewID()
	userID := shared.NewID()

	// Setup: user has dashboard:read only
	g := seedGroupForPermission(groupRepo, tenantID, "Viewers", "viewers")
	ps := seedCustomPermissionSet(psRepo, tenantID, "Viewer Perms", "viewer-perms")

	item, _ := permissionset.NewItem(ps.ID(), string(permission.DashboardRead), permissionset.ModificationAdd)
	psRepo.items[ps.ID().String()] = []*permissionset.Item{item}

	groupRepo.permissionSets[g.ID().String()] = []shared.ID{ps.ID()}
	key := tenantID.String() + ":" + userID.String()
	groupRepo.userGroups[key] = []*group.GroupWithRole{
		{Group: g, Role: "member"},
	}

	has, err := svc.HasAnyPermission(context.Background(), tenantID.String(), userID,
		permission.SettingsWrite, // user does NOT have this
		permission.AuditRead,    // user does NOT have this either
	)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if has {
		t.Error("expected HasAnyPermission to return false when user has none of the requested permissions")
	}
}

// =============================================================================
// HasAllPermissions Tests
// =============================================================================

func TestHasAllPermissions_FalseMissingOne(t *testing.T) {
	svc, psRepo, groupRepo, _ := newTestPermissionService()
	tenantID := shared.NewID()
	userID := shared.NewID()

	// Setup: user has dashboard:read but NOT settings:write
	g := seedGroupForPermission(groupRepo, tenantID, "Partial", "partial")
	ps := seedCustomPermissionSet(psRepo, tenantID, "Partial Perms", "partial-perms")

	item, _ := permissionset.NewItem(ps.ID(), string(permission.DashboardRead), permissionset.ModificationAdd)
	psRepo.items[ps.ID().String()] = []*permissionset.Item{item}

	groupRepo.permissionSets[g.ID().String()] = []shared.ID{ps.ID()}
	key := tenantID.String() + ":" + userID.String()
	groupRepo.userGroups[key] = []*group.GroupWithRole{
		{Group: g, Role: "member"},
	}

	has, err := svc.HasAllPermissions(context.Background(), tenantID.String(), userID,
		permission.DashboardRead, // user HAS this
		permission.SettingsWrite, // user does NOT have this
	)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if has {
		t.Error("expected HasAllPermissions to return false when missing one permission")
	}
}

func TestHasAllPermissions_TrueWhenAllPresent(t *testing.T) {
	svc, psRepo, groupRepo, _ := newTestPermissionService()
	tenantID := shared.NewID()
	userID := shared.NewID()

	// Setup: user has both dashboard:read and settings:read
	g := seedGroupForPermission(groupRepo, tenantID, "Full", "full")
	ps := seedCustomPermissionSet(psRepo, tenantID, "Full Perms", "full-perms")

	item1, _ := permissionset.NewItem(ps.ID(), string(permission.DashboardRead), permissionset.ModificationAdd)
	item2, _ := permissionset.NewItem(ps.ID(), string(permission.SettingsRead), permissionset.ModificationAdd)
	psRepo.items[ps.ID().String()] = []*permissionset.Item{item1, item2}

	groupRepo.permissionSets[g.ID().String()] = []shared.ID{ps.ID()}
	key := tenantID.String() + ":" + userID.String()
	groupRepo.userGroups[key] = []*group.GroupWithRole{
		{Group: g, Role: "member"},
	}

	has, err := svc.HasAllPermissions(context.Background(), tenantID.String(), userID,
		permission.DashboardRead,
		permission.SettingsRead,
	)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if !has {
		t.Error("expected HasAllPermissions to return true when all permissions present")
	}
}

// =============================================================================
// Edge Case Tests
// =============================================================================

func TestCreatePermissionSet_InvalidTenantID(t *testing.T) {
	svc, _, _, _ := newTestPermissionService()

	input := app.CreatePermissionSetInput{
		TenantID: "not-a-uuid",
		Name:     "Test",
		Slug:     "test",
		SetType:  "custom",
	}

	_, err := svc.CreatePermissionSet(context.Background(), input, app.AuditContext{})
	if err == nil {
		t.Fatal("expected error for invalid tenant ID")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected ErrValidation, got %v", err)
	}
}

func TestCreatePermissionSet_InvalidSetType(t *testing.T) {
	svc, _, _, _ := newTestPermissionService()
	tenantID := shared.NewID()

	input := app.CreatePermissionSetInput{
		TenantID: tenantID.String(),
		Name:     "Bad Type",
		Slug:     "bad-type",
		SetType:  "invalid_type",
	}

	_, err := svc.CreatePermissionSet(context.Background(), input, app.AuditContext{})
	if err == nil {
		t.Fatal("expected error for invalid set type")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected ErrValidation, got %v", err)
	}
}

func TestDeletePermissionSet_InvalidID(t *testing.T) {
	svc, _, _, _ := newTestPermissionService()

	err := svc.DeletePermissionSet(context.Background(), "bad-uuid", app.AuditContext{})
	if err == nil {
		t.Fatal("expected error for invalid ID")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected ErrValidation, got %v", err)
	}
}

func TestDeletePermissionSet_NotFound(t *testing.T) {
	svc, _, _, _ := newTestPermissionService()

	err := svc.DeletePermissionSet(context.Background(), shared.NewID().String(), app.AuditContext{})
	if err == nil {
		t.Fatal("expected error for not found")
	}
	if !errors.Is(err, permissionset.ErrPermissionSetNotFound) {
		t.Errorf("expected ErrPermissionSetNotFound, got %v", err)
	}
}

func TestUpdatePermissionSet_NotFound(t *testing.T) {
	svc, _, _, _ := newTestPermissionService()

	newName := "Ghost"
	input := app.UpdatePermissionSetInput{
		Name: &newName,
	}

	_, err := svc.UpdatePermissionSet(context.Background(), shared.NewID().String(), input, app.AuditContext{})
	if err == nil {
		t.Fatal("expected error for not found")
	}
	if !errors.Is(err, permissionset.ErrPermissionSetNotFound) {
		t.Errorf("expected ErrPermissionSetNotFound, got %v", err)
	}
}

func TestUpdatePermissionSet_InvalidID(t *testing.T) {
	svc, _, _, _ := newTestPermissionService()

	newName := "Test"
	input := app.UpdatePermissionSetInput{
		Name: &newName,
	}

	_, err := svc.UpdatePermissionSet(context.Background(), "bad-uuid", input, app.AuditContext{})
	if err == nil {
		t.Fatal("expected error for invalid ID")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected ErrValidation, got %v", err)
	}
}

func TestCreatePermissionSet_WithPermissions(t *testing.T) {
	svc, repo, _, _ := newTestPermissionService()
	tenantID := shared.NewID()

	input := app.CreatePermissionSetInput{
		TenantID:    tenantID.String(),
		Name:        "Full Set",
		Slug:        "full-set",
		SetType:     "custom",
		Permissions: []string{"findings:read", "assets:read"},
	}

	ps, err := svc.CreatePermissionSet(context.Background(), input, app.AuditContext{})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if ps == nil {
		t.Fatal("expected permission set, got nil")
	}
	if repo.createCalls != 1 {
		t.Errorf("expected 1 create call, got %d", repo.createCalls)
	}
	// Should have attempted to add 2 permission items
	if repo.addItemCalls != 2 {
		t.Errorf("expected 2 addItem calls, got %d", repo.addItemCalls)
	}
}

func TestUpdatePermissionSet_ActivateDeactivate(t *testing.T) {
	svc, repo, _, _ := newTestPermissionService()
	tenantID := shared.NewID()
	ps := seedCustomPermissionSet(repo, tenantID, "Toggle Set", "toggle-set")

	// Deactivate
	isActiveFalse := false
	input := app.UpdatePermissionSetInput{
		IsActive: &isActiveFalse,
	}

	updated, err := svc.UpdatePermissionSet(context.Background(), ps.ID().String(), input, app.AuditContext{})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if updated.IsActive() {
		t.Error("expected permission set to be deactivated")
	}

	// Reactivate
	isActiveTrue := true
	input2 := app.UpdatePermissionSetInput{
		IsActive: &isActiveTrue,
	}

	updated2, err := svc.UpdatePermissionSet(context.Background(), ps.ID().String(), input2, app.AuditContext{})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if !updated2.IsActive() {
		t.Error("expected permission set to be reactivated")
	}
}

func TestPermissionService_HasPermission_NoGroups(t *testing.T) {
	svc, _, groupRepo, _ := newTestPermissionService()
	tenantID := shared.NewID()
	userID := shared.NewID()

	// User has no groups
	key := tenantID.String() + ":" + userID.String()
	groupRepo.userGroups[key] = []*group.GroupWithRole{}

	has, err := svc.HasPermission(context.Background(), tenantID.String(), userID, permission.DashboardRead)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if has {
		t.Error("expected user with no groups to have no permissions")
	}
}

func (m *mockAccessControlRepoForPermission) BatchListFindingGroupIDs(_ context.Context, _ shared.ID, _ []shared.ID) (map[shared.ID][]shared.ID, error) {
	return make(map[shared.ID][]shared.ID), nil
}

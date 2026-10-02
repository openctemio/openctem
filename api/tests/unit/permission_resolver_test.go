package unit

import (
	"testing"
	"time"

	"github.com/openctemio/api/pkg/domain/accesscontrol"
	"github.com/openctemio/api/pkg/domain/permission"
	"github.com/openctemio/api/pkg/domain/permissionset"
	"github.com/openctemio/api/pkg/domain/shared"
)

// Helper function to create a test permission set.
func createTestPermissionSet(_ *testing.T, id shared.ID, tenantID *shared.ID, name, slug string, setType permissionset.SetType, parentSetID *shared.ID) *permissionset.PermissionSet {
	now := time.Now().UTC()
	return permissionset.Reconstitute(
		id,
		tenantID,
		name,
		slug,
		"Test description",
		setType,
		parentSetID,
		nil, // clonedFromVersion
		true,
		now,
		now,
	)
}

// Helper function to create a test permission set item.
func createTestItem(permissionSetID shared.ID, permissionID string, modType permissionset.ModificationType) *permissionset.Item {
	return permissionset.ReconstituteItem(permissionSetID, permissionID, modType)
}

// Helper function to create a test group permission.
func createTestGroupPermission(groupID shared.ID, permissionID string, effect accesscontrol.PermissionEffect) *accesscontrol.GroupPermission {
	now := time.Now().UTC()
	return accesscontrol.ReconstituteGroupPermission(
		groupID,
		permissionID,
		effect,
		nil, // scopeType
		nil, // scopeValue
		now,
		nil, // createdBy
	)
}

func TestPermissionResolver_ResolveDirectPermissions(t *testing.T) {
	resolver := accesscontrol.NewPermissionResolver()
	tenantID := shared.NewID()
	psID := shared.NewID()

	// Create a custom permission set with some permissions
	ps := createTestPermissionSet(t, psID, &tenantID, "Custom Set", "custom-set", permissionset.SetTypeCustom, nil)
	items := []*permissionset.Item{
		createTestItem(psID, string(permission.AssetsRead), permissionset.ModificationAdd),
		createTestItem(psID, string(permission.AssetsWrite), permissionset.ModificationAdd),
		createTestItem(psID, string(permission.FindingsRead), permissionset.ModificationAdd),
	}

	psWithItems := &permissionset.PermissionSetWithItems{
		PermissionSet: ps,
		Items:         items,
	}

	// Resolve permissions
	perms := resolver.ResolvePermissionSetPermissions(psWithItems, nil)

	// Verify
	if len(perms) != 3 {
		t.Errorf("expected 3 permissions, got %d", len(perms))
	}

	// Check that all expected permissions are present
	permStrings := make(map[string]bool)
	for _, p := range perms {
		permStrings[p.String()] = true
	}

	expectedPerms := []string{
		string(permission.AssetsRead),
		string(permission.AssetsWrite),
		string(permission.FindingsRead),
	}
	for _, ep := range expectedPerms {
		if !permStrings[ep] {
			t.Errorf("expected permission %s not found", ep)
		}
	}
}

func TestPermissionResolver_ResolveExtendedPermissions(t *testing.T) {
	resolver := accesscontrol.NewPermissionResolver()
	tenantID := shared.NewID()
	parentID := shared.NewID()
	childID := shared.NewID()

	// Create parent permission set (system template)
	parentPS := createTestPermissionSet(t, parentID, nil, "Security Team Base", "security-team-base", permissionset.SetTypeSystem, nil)
	parentItems := []*permissionset.Item{
		createTestItem(parentID, string(permission.AssetsRead), permissionset.ModificationAdd),
		createTestItem(parentID, string(permission.AssetsWrite), permissionset.ModificationAdd),
		createTestItem(parentID, string(permission.FindingsRead), permissionset.ModificationAdd),
		createTestItem(parentID, string(permission.FindingsWrite), permissionset.ModificationAdd),
		createTestItem(parentID, string(permission.DashboardRead), permissionset.ModificationAdd),
	}
	parentWithItems := &permissionset.PermissionSetWithItems{
		PermissionSet: parentPS,
		Items:         parentItems,
	}

	// Create child (extended) permission set that adds and removes permissions
	childPS := createTestPermissionSet(t, childID, &tenantID, "Extended Security", "extended-security", permissionset.SetTypeExtended, &parentID)
	childItems := []*permissionset.Item{
		// Add new permission
		createTestItem(childID, string(permission.AuditRead), permissionset.ModificationAdd),
		// Remove a permission from parent
		createTestItem(childID, string(permission.AssetsWrite), permissionset.ModificationRemove),
	}
	childWithItems := &permissionset.PermissionSetWithItems{
		PermissionSet: childPS,
		Items:         childItems,
	}

	// Parent chain for resolution
	parentChain := []*permissionset.PermissionSetWithItems{parentWithItems}

	// Resolve permissions for extended set
	perms := resolver.ResolvePermissionSetPermissions(childWithItems, parentChain)

	// Expected: Parent permissions + additions - removals
	// Parent: AssetsRead, AssetsWrite, FindingsRead, FindingsWrite, DashboardRead
	// Add: AuditRead
	// Remove: AssetsWrite
	// Result: AssetsRead, FindingsRead, FindingsWrite, DashboardRead, AuditRead (5 permissions)

	if len(perms) != 5 {
		t.Errorf("expected 5 permissions, got %d", len(perms))
	}

	permStrings := make(map[string]bool)
	for _, p := range perms {
		permStrings[p.String()] = true
	}

	// Should have these permissions
	expectedPerms := []string{
		string(permission.AssetsRead),
		string(permission.FindingsRead),
		string(permission.FindingsWrite),
		string(permission.DashboardRead),
		string(permission.AuditRead),
	}
	for _, ep := range expectedPerms {
		if !permStrings[ep] {
			t.Errorf("expected permission %s not found", ep)
		}
	}

	// Should NOT have AssetsWrite (removed)
	if permStrings[string(permission.AssetsWrite)] {
		t.Error("AssetsWrite should have been removed")
	}
}

func TestPermissionResolver_ResolveExtendedChain(t *testing.T) {
	resolver := accesscontrol.NewPermissionResolver()
	tenantID := shared.NewID()
	rootID := shared.NewID()
	midID := shared.NewID()
	leafID := shared.NewID()

	// Root permission set (system)
	rootPS := createTestPermissionSet(t, rootID, nil, "Root", "root", permissionset.SetTypeSystem, nil)
	rootItems := []*permissionset.Item{
		createTestItem(rootID, string(permission.AssetsRead), permissionset.ModificationAdd),
		createTestItem(rootID, string(permission.AssetsWrite), permissionset.ModificationAdd),
		createTestItem(rootID, string(permission.FindingsRead), permissionset.ModificationAdd),
	}
	rootWithItems := &permissionset.PermissionSetWithItems{
		PermissionSet: rootPS,
		Items:         rootItems,
	}

	// Mid-level extended set
	midPS := createTestPermissionSet(t, midID, &tenantID, "Mid Level", "mid-level", permissionset.SetTypeExtended, &rootID)
	midItems := []*permissionset.Item{
		createTestItem(midID, string(permission.DashboardRead), permissionset.ModificationAdd),
		createTestItem(midID, string(permission.AssetsWrite), permissionset.ModificationRemove),
	}
	midWithItems := &permissionset.PermissionSetWithItems{
		PermissionSet: midPS,
		Items:         midItems,
	}

	// Leaf extended set
	leafPS := createTestPermissionSet(t, leafID, &tenantID, "Leaf Level", "leaf-level", permissionset.SetTypeExtended, &midID)
	leafItems := []*permissionset.Item{
		createTestItem(leafID, string(permission.AuditRead), permissionset.ModificationAdd),
		createTestItem(leafID, string(permission.FindingsRead), permissionset.ModificationRemove),
	}
	leafWithItems := &permissionset.PermissionSetWithItems{
		PermissionSet: leafPS,
		Items:         leafItems,
	}

	// Full parent chain: root -> mid -> leaf
	parentChain := []*permissionset.PermissionSetWithItems{rootWithItems, midWithItems}

	// Resolve permissions for leaf
	perms := resolver.ResolvePermissionSetPermissions(leafWithItems, parentChain)

	// Expected chain resolution:
	// Root: AssetsRead, AssetsWrite, FindingsRead
	// After Mid: AssetsRead, FindingsRead, DashboardRead (AssetsWrite removed, DashboardRead added)
	// After Leaf: AssetsRead, DashboardRead, AuditRead (FindingsRead removed, AuditRead added)

	if len(perms) != 3 {
		t.Errorf("expected 3 permissions, got %d", len(perms))
	}

	permStrings := make(map[string]bool)
	for _, p := range perms {
		permStrings[p.String()] = true
	}

	expectedPerms := []string{
		string(permission.AssetsRead),
		string(permission.DashboardRead),
		string(permission.AuditRead),
	}
	for _, ep := range expectedPerms {
		if !permStrings[ep] {
			t.Errorf("expected permission %s not found", ep)
		}
	}

	// Should NOT have these (removed in chain)
	removedPerms := []string{
		string(permission.AssetsWrite),
		string(permission.FindingsRead),
	}
	for _, rp := range removedPerms {
		if permStrings[rp] {
			t.Errorf("permission %s should have been removed", rp)
		}
	}
}

func TestPermissionResolver_ResolveGroupPermissions(t *testing.T) {
	resolver := accesscontrol.NewPermissionResolver()
	tenantID := shared.NewID()
	groupID := shared.NewID()
	psID1 := shared.NewID()
	psID2 := shared.NewID()

	// Create two permission sets for the group
	ps1 := createTestPermissionSet(t, psID1, &tenantID, "Set 1", "set-1", permissionset.SetTypeCustom, nil)
	ps1Items := []*permissionset.Item{
		createTestItem(psID1, string(permission.AssetsRead), permissionset.ModificationAdd),
		createTestItem(psID1, string(permission.FindingsRead), permissionset.ModificationAdd),
	}
	ps1WithItems := &permissionset.PermissionSetWithItems{
		PermissionSet: ps1,
		Items:         ps1Items,
	}

	ps2 := createTestPermissionSet(t, psID2, &tenantID, "Set 2", "set-2", permissionset.SetTypeCustom, nil)
	ps2Items := []*permissionset.Item{
		createTestItem(psID2, string(permission.DashboardRead), permissionset.ModificationAdd),
		createTestItem(psID2, string(permission.AuditRead), permissionset.ModificationAdd),
	}
	ps2WithItems := &permissionset.PermissionSetWithItems{
		PermissionSet: ps2,
		Items:         ps2Items,
	}

	// Custom permissions: allow one, deny another
	customPerms := []*accesscontrol.GroupPermission{
		createTestGroupPermission(groupID, string(permission.ReportsRead), accesscontrol.EffectAllow),
		createTestGroupPermission(groupID, string(permission.AuditRead), accesscontrol.EffectDeny),
	}

	// Resolve group permissions
	perms := resolver.ResolveGroupPermissions(
		[]*permissionset.PermissionSetWithItems{ps1WithItems, ps2WithItems},
		make(map[shared.ID][]*permissionset.PermissionSetWithItems), // no parent chains for custom sets
		customPerms,
	)

	// Expected:
	// From sets: AssetsRead, FindingsRead, DashboardRead, AuditRead
	// Custom allow: ReportsRead
	// Custom deny: AuditRead (removes from set)
	// Result: AssetsRead, FindingsRead, DashboardRead, ReportsRead

	if len(perms) != 4 {
		t.Errorf("expected 4 permissions, got %d", len(perms))
	}

	permStrings := make(map[string]bool)
	for _, p := range perms {
		permStrings[p.String()] = true
	}

	expectedPerms := []string{
		string(permission.AssetsRead),
		string(permission.FindingsRead),
		string(permission.DashboardRead),
		string(permission.ReportsRead),
	}
	for _, ep := range expectedPerms {
		if !permStrings[ep] {
			t.Errorf("expected permission %s not found", ep)
		}
	}

	// AuditRead should be denied
	if permStrings[string(permission.AuditRead)] {
		t.Error("AuditRead should have been denied")
	}
}

func TestPermissionResolver_ResolveUserPermissions(t *testing.T) {
	resolver := accesscontrol.NewPermissionResolver()

	// User belongs to multiple groups with different permissions
	group1Perms := []permission.Permission{
		permission.AssetsRead,
		permission.FindingsRead,
		permission.DashboardRead,
	}
	group2Perms := []permission.Permission{
		permission.AssetsRead, // overlapping
		permission.AssetsWrite,
		permission.AuditRead,
	}
	group3Perms := []permission.Permission{
		permission.ReportsRead,
		permission.ReportsWrite,
	}

	groupPermissions := [][]permission.Permission{
		group1Perms,
		group2Perms,
		group3Perms,
	}

	// Resolve user permissions (union of all groups)
	perms := resolver.ResolveUserPermissions(groupPermissions)

	// Expected: union of all unique permissions
	// AssetsRead, FindingsRead, DashboardRead, AssetsWrite, AuditRead, ReportsRead, ReportsWrite
	if len(perms) != 7 {
		t.Errorf("expected 7 permissions, got %d", len(perms))
	}

	permStrings := make(map[string]bool)
	for _, p := range perms {
		permStrings[p.String()] = true
	}

	expectedPerms := []string{
		string(permission.AssetsRead),
		string(permission.AssetsWrite),
		string(permission.FindingsRead),
		string(permission.DashboardRead),
		string(permission.AuditRead),
		string(permission.ReportsRead),
		string(permission.ReportsWrite),
	}
	for _, ep := range expectedPerms {
		if !permStrings[ep] {
			t.Errorf("expected permission %s not found", ep)
		}
	}
}

func TestPermissionResolver_HasPermission(t *testing.T) {
	resolver := accesscontrol.NewPermissionResolver()
	tenantID := shared.NewID()
	psID := shared.NewID()

	ps := createTestPermissionSet(t, psID, &tenantID, "Test Set", "test-set", permissionset.SetTypeCustom, nil)
	items := []*permissionset.Item{
		createTestItem(psID, string(permission.AssetsRead), permissionset.ModificationAdd),
		createTestItem(psID, string(permission.AssetsWrite), permissionset.ModificationAdd),
	}
	psWithItems := &permissionset.PermissionSetWithItems{
		PermissionSet: ps,
		Items:         items,
	}

	tests := []struct {
		name     string
		target   permission.Permission
		expected bool
	}{
		{
			name:     "has permission",
			target:   permission.AssetsRead,
			expected: true,
		},
		{
			name:     "has another permission",
			target:   permission.AssetsWrite,
			expected: true,
		},
		{
			name:     "does not have permission",
			target:   permission.FindingsRead,
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := resolver.HasPermission(psWithItems, nil, tt.target)
			if result != tt.expected {
				t.Errorf("HasPermission() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestPermissionResolver_HasAnyPermission(t *testing.T) {
	resolver := accesscontrol.NewPermissionResolver()
	tenantID := shared.NewID()
	psID := shared.NewID()

	ps := createTestPermissionSet(t, psID, &tenantID, "Test Set", "test-set", permissionset.SetTypeCustom, nil)
	items := []*permissionset.Item{
		createTestItem(psID, string(permission.AssetsRead), permissionset.ModificationAdd),
		createTestItem(psID, string(permission.AssetsWrite), permissionset.ModificationAdd),
	}
	psWithItems := &permissionset.PermissionSetWithItems{
		PermissionSet: ps,
		Items:         items,
	}

	tests := []struct {
		name     string
		targets  []permission.Permission
		expected bool
	}{
		{
			name:     "has one of the permissions",
			targets:  []permission.Permission{permission.AssetsRead, permission.FindingsRead},
			expected: true,
		},
		{
			name:     "has none of the permissions",
			targets:  []permission.Permission{permission.FindingsRead, permission.DashboardRead},
			expected: false,
		},
		{
			name:     "has all of the permissions",
			targets:  []permission.Permission{permission.AssetsRead, permission.AssetsWrite},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := resolver.HasAnyPermission(psWithItems, nil, tt.targets...)
			if result != tt.expected {
				t.Errorf("HasAnyPermission() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestPermissionResolver_HasAllPermissions(t *testing.T) {
	resolver := accesscontrol.NewPermissionResolver()
	tenantID := shared.NewID()
	psID := shared.NewID()

	ps := createTestPermissionSet(t, psID, &tenantID, "Test Set", "test-set", permissionset.SetTypeCustom, nil)
	items := []*permissionset.Item{
		createTestItem(psID, string(permission.AssetsRead), permissionset.ModificationAdd),
		createTestItem(psID, string(permission.AssetsWrite), permissionset.ModificationAdd),
		createTestItem(psID, string(permission.FindingsRead), permissionset.ModificationAdd),
	}
	psWithItems := &permissionset.PermissionSetWithItems{
		PermissionSet: ps,
		Items:         items,
	}

	tests := []struct {
		name     string
		targets  []permission.Permission
		expected bool
	}{
		{
			name:     "has all permissions",
			targets:  []permission.Permission{permission.AssetsRead, permission.AssetsWrite},
			expected: true,
		},
		{
			name:     "has all three permissions",
			targets:  []permission.Permission{permission.AssetsRead, permission.AssetsWrite, permission.FindingsRead},
			expected: true,
		},
		{
			name:     "missing one permission",
			targets:  []permission.Permission{permission.AssetsRead, permission.DashboardRead},
			expected: false,
		},
		{
			name:     "missing all permissions",
			targets:  []permission.Permission{permission.DashboardRead, permission.AuditRead},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := resolver.HasAllPermissions(psWithItems, nil, tt.targets...)
			if result != tt.expected {
				t.Errorf("HasAllPermissions() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestPermissionResolver_ResolveWithSources(t *testing.T) {
	resolver := accesscontrol.NewPermissionResolver()
	tenantID := shared.NewID()
	groupID := shared.NewID()
	psID := shared.NewID()

	ps := createTestPermissionSet(t, psID, &tenantID, "Test Set", "test-set", permissionset.SetTypeCustom, nil)
	psItems := []*permissionset.Item{
		createTestItem(psID, string(permission.AssetsRead), permissionset.ModificationAdd),
		createTestItem(psID, string(permission.FindingsRead), permissionset.ModificationAdd),
	}
	psWithItems := &permissionset.PermissionSetWithItems{
		PermissionSet: ps,
		Items:         psItems,
	}

	customPerms := []*accesscontrol.GroupPermission{
		createTestGroupPermission(groupID, string(permission.AuditRead), accesscontrol.EffectAllow),
		createTestGroupPermission(groupID, string(permission.FindingsRead), accesscontrol.EffectDeny),
	}

	result := resolver.ResolveWithSources(
		[]*permissionset.PermissionSetWithItems{psWithItems},
		make(map[shared.ID][]*permissionset.PermissionSetWithItems),
		customPerms,
	)

	// Expected permissions: AssetsRead, AuditRead (FindingsRead denied)
	if len(result.Permissions) != 2 {
		t.Errorf("expected 2 permissions, got %d", len(result.Permissions))
	}

	// Check sources are tracked
	if len(result.Sources) == 0 {
		t.Error("expected sources to be tracked")
	}

	// Verify we can find source information
	foundPermSetSource := false
	foundCustomSource := false
	foundDenySource := false

	for _, source := range result.Sources {
		if source.SourceType == "permission_set" && source.SourceID == psID {
			foundPermSetSource = true
		}
		if source.SourceType == "custom_permission" && source.PermissionID == string(permission.AuditRead) {
			foundCustomSource = true
		}
		if source.ModificationType == "remove" && source.PermissionID == string(permission.FindingsRead) {
			foundDenySource = true
		}
	}

	if !foundPermSetSource {
		t.Error("expected to find permission set source")
	}
	if !foundCustomSource {
		t.Error("expected to find custom permission source")
	}
	if !foundDenySource {
		t.Error("expected to find deny source")
	}
}

func TestPermissionResolver_NilPermissionSet(t *testing.T) {
	resolver := accesscontrol.NewPermissionResolver()

	perms := resolver.ResolvePermissionSetPermissions(nil, nil)
	if perms != nil {
		t.Errorf("expected nil for nil permission set, got %v", perms)
	}
}

func TestPermissionResolver_EmptyParentChain(t *testing.T) {
	resolver := accesscontrol.NewPermissionResolver()
	tenantID := shared.NewID()
	psID := shared.NewID()
	parentID := shared.NewID()

	// Extended set with empty parent chain
	ps := createTestPermissionSet(t, psID, &tenantID, "Extended Set", "extended-set", permissionset.SetTypeExtended, &parentID)
	items := []*permissionset.Item{
		createTestItem(psID, string(permission.AssetsRead), permissionset.ModificationAdd),
	}
	psWithItems := &permissionset.PermissionSetWithItems{
		PermissionSet: ps,
		Items:         items,
	}

	// Empty parent chain - only the additions from this set should apply
	perms := resolver.ResolvePermissionSetPermissions(psWithItems, nil)

	if len(perms) != 1 {
		t.Errorf("expected 1 permission with empty parent chain, got %d", len(perms))
	}
}

func TestPermissionResolver_DuplicatePermissionsInSet(t *testing.T) {
	resolver := accesscontrol.NewPermissionResolver()
	tenantID := shared.NewID()
	psID := shared.NewID()

	// Set with duplicate permissions
	ps := createTestPermissionSet(t, psID, &tenantID, "Duplicate Set", "duplicate-set", permissionset.SetTypeCustom, nil)
	items := []*permissionset.Item{
		createTestItem(psID, string(permission.AssetsRead), permissionset.ModificationAdd),
		createTestItem(psID, string(permission.AssetsRead), permissionset.ModificationAdd), // duplicate
		createTestItem(psID, string(permission.FindingsRead), permissionset.ModificationAdd),
	}
	psWithItems := &permissionset.PermissionSetWithItems{
		PermissionSet: ps,
		Items:         items,
	}

	perms := resolver.ResolvePermissionSetPermissions(psWithItems, nil)

	// Should deduplicate
	if len(perms) != 2 {
		t.Errorf("expected 2 unique permissions, got %d", len(perms))
	}
}

func TestPermissionResolver_EmptyUserGroups(t *testing.T) {
	resolver := accesscontrol.NewPermissionResolver()

	perms := resolver.ResolveUserPermissions(nil)
	if len(perms) != 0 {
		t.Errorf("expected 0 permissions for empty groups, got %d", len(perms))
	}

	perms = resolver.ResolveUserPermissions([][]permission.Permission{})
	if len(perms) != 0 {
		t.Errorf("expected 0 permissions for empty groups slice, got %d", len(perms))
	}
}

func TestPermissionResolver_OnlyRemoveModifications(t *testing.T) {
	resolver := accesscontrol.NewPermissionResolver()
	tenantID := shared.NewID()
	parentID := shared.NewID()
	childID := shared.NewID()

	// Parent with some permissions
	parentPS := createTestPermissionSet(t, parentID, nil, "Parent", "parent", permissionset.SetTypeSystem, nil)
	parentItems := []*permissionset.Item{
		createTestItem(parentID, string(permission.AssetsRead), permissionset.ModificationAdd),
		createTestItem(parentID, string(permission.AssetsWrite), permissionset.ModificationAdd),
		createTestItem(parentID, string(permission.FindingsRead), permissionset.ModificationAdd),
	}
	parentWithItems := &permissionset.PermissionSetWithItems{
		PermissionSet: parentPS,
		Items:         parentItems,
	}

	// Child that only removes permissions
	childPS := createTestPermissionSet(t, childID, &tenantID, "Child", "child", permissionset.SetTypeExtended, &parentID)
	childItems := []*permissionset.Item{
		createTestItem(childID, string(permission.AssetsWrite), permissionset.ModificationRemove),
		createTestItem(childID, string(permission.FindingsRead), permissionset.ModificationRemove),
	}
	childWithItems := &permissionset.PermissionSetWithItems{
		PermissionSet: childPS,
		Items:         childItems,
	}

	perms := resolver.ResolvePermissionSetPermissions(childWithItems, []*permissionset.PermissionSetWithItems{parentWithItems})

	// Should only have AssetsRead left
	if len(perms) != 1 {
		t.Errorf("expected 1 permission, got %d", len(perms))
	}

	if len(perms) > 0 && perms[0] != permission.AssetsRead {
		t.Errorf("expected AssetsRead, got %s", perms[0])
	}
}

func TestPermissionResolver_CustomDenyOverridesSet(t *testing.T) {
	resolver := accesscontrol.NewPermissionResolver()
	tenantID := shared.NewID()
	groupID := shared.NewID()
	psID := shared.NewID()

	// Permission set with permissions
	ps := createTestPermissionSet(t, psID, &tenantID, "Set", "set", permissionset.SetTypeCustom, nil)
	psItems := []*permissionset.Item{
		createTestItem(psID, string(permission.AssetsRead), permissionset.ModificationAdd),
		createTestItem(psID, string(permission.AssetsWrite), permissionset.ModificationAdd),
		createTestItem(psID, string(permission.AssetsDelete), permissionset.ModificationAdd),
	}
	psWithItems := &permissionset.PermissionSetWithItems{
		PermissionSet: ps,
		Items:         psItems,
	}

	// Custom deny for AssetsDelete
	customPerms := []*accesscontrol.GroupPermission{
		createTestGroupPermission(groupID, string(permission.AssetsDelete), accesscontrol.EffectDeny),
	}

	perms := resolver.ResolveGroupPermissions(
		[]*permissionset.PermissionSetWithItems{psWithItems},
		make(map[shared.ID][]*permissionset.PermissionSetWithItems),
		customPerms,
	)

	// Should have AssetsRead, AssetsWrite but NOT AssetsDelete
	if len(perms) != 2 {
		t.Errorf("expected 2 permissions, got %d", len(perms))
	}

	permStrings := make(map[string]bool)
	for _, p := range perms {
		permStrings[p.String()] = true
	}

	if permStrings[string(permission.AssetsDelete)] {
		t.Error("AssetsDelete should be denied by custom permission")
	}
}

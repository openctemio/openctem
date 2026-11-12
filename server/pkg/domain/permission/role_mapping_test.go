package permission

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/openctemio/openctem/api/pkg/domain/tenant"
)

// =============================================================================
// Test: FindingsApprove Permission Assignment
// =============================================================================

func TestFindingsApprovePermission(t *testing.T) {
	t.Run("owner has FindingsApprove", func(t *testing.T) {
		assert.True(t, HasPermission(tenant.RoleOwner, FindingsApprove),
			"Owner should have findings:approve")
	})

	t.Run("admin has FindingsApprove", func(t *testing.T) {
		assert.True(t, HasPermission(tenant.RoleAdmin, FindingsApprove),
			"Admin should have findings:approve")
	})

	t.Run("member does NOT have FindingsApprove", func(t *testing.T) {
		assert.False(t, HasPermission(tenant.RoleMember, FindingsApprove),
			"Member should NOT have findings:approve")
	})

	t.Run("viewer does NOT have FindingsApprove", func(t *testing.T) {
		assert.False(t, HasPermission(tenant.RoleViewer, FindingsApprove),
			"Viewer should NOT have findings:approve")
	})
}

// =============================================================================
// Test: Role Permission Separation of Duties
// =============================================================================

func TestApprovalSeparationOfDuties(t *testing.T) {
	t.Run("member can request but not approve", func(t *testing.T) {
		assert.True(t, HasPermission(tenant.RoleMember, FindingsWrite),
			"Member should have findings:write (can request approval)")
		assert.False(t, HasPermission(tenant.RoleMember, FindingsApprove),
			"Member should NOT have findings:approve (cannot approve)")
	})

	t.Run("viewer cannot request or approve", func(t *testing.T) {
		assert.False(t, HasPermission(tenant.RoleViewer, FindingsWrite),
			"Viewer should NOT have findings:write")
		assert.False(t, HasPermission(tenant.RoleViewer, FindingsApprove),
			"Viewer should NOT have findings:approve")
	})

	t.Run("admin can both request and approve", func(t *testing.T) {
		assert.True(t, HasPermission(tenant.RoleAdmin, FindingsWrite),
			"Admin should have findings:write")
		assert.True(t, HasPermission(tenant.RoleAdmin, FindingsApprove),
			"Admin should have findings:approve")
	})
}

// =============================================================================
// Test: FindingsApprove in AllPermissions
// =============================================================================

func TestFindingsApproveInAllPermissions(t *testing.T) {
	all := AllPermissions()
	found := false
	for _, p := range all {
		if p == FindingsApprove {
			found = true
			break
		}
	}
	assert.True(t, found, "FindingsApprove should be in AllPermissions()")
}

// =============================================================================
// Test: FindingsApprove Constant Value
// =============================================================================

func TestFindingsApproveConstantValue(t *testing.T) {
	assert.Equal(t, Permission("findings:approve"), FindingsApprove,
		"FindingsApprove should equal 'findings:approve'")
}

// =============================================================================
// Test: Role Permission Counts (sanity check)
// =============================================================================

func TestRolePermissionCounts(t *testing.T) {
	ownerPerms := GetPermissionsForRole(tenant.RoleOwner)
	adminPerms := GetPermissionsForRole(tenant.RoleAdmin)
	memberPerms := GetPermissionsForRole(tenant.RoleMember)
	viewerPerms := GetPermissionsForRole(tenant.RoleViewer)

	// Owner should have the most permissions
	assert.Greater(t, len(ownerPerms), len(adminPerms),
		"Owner should have more permissions than Admin")
	assert.Greater(t, len(adminPerms), len(memberPerms),
		"Admin should have more permissions than Member")
	assert.Greater(t, len(memberPerms), len(viewerPerms),
		"Member should have more permissions than Viewer")
}

// =============================================================================
// Test: Owner-Only Permissions Not in Admin
// =============================================================================

func TestOwnerOnlyPermissions(t *testing.T) {
	// suppressions:approve is seeded for admin too, and administrators pass
	// every permission check anyway, so listing it here only described a
	// rule nothing enforced.
	ownerOnly := []Permission{TeamDelete}

	for _, perm := range ownerOnly {
		assert.True(t, HasPermission(tenant.RoleOwner, perm),
			"Owner should have %s", perm)
		assert.False(t, HasPermission(tenant.RoleAdmin, perm),
			"Admin should NOT have %s", perm)
	}
}

// =============================================================================
// Test: Helper Functions
// =============================================================================

func TestGetPermissionStringsForRole(t *testing.T) {
	strings := GetPermissionStringsForRole(tenant.RoleOwner)
	assert.Contains(t, strings, "findings:approve",
		"Owner permission strings should contain findings:approve")
}

func TestHasAnyPermission(t *testing.T) {
	assert.True(t, HasAnyPermission(tenant.RoleMember, FindingsApprove, FindingsWrite),
		"Member should have at least FindingsWrite")
	assert.False(t, HasAnyPermission(tenant.RoleViewer, FindingsApprove, FindingsWrite),
		"Viewer should have neither FindingsApprove nor FindingsWrite")
}

func TestHasAllPermissions(t *testing.T) {
	assert.True(t, HasAllPermissions(tenant.RoleOwner, FindingsApprove, FindingsWrite),
		"Owner should have both FindingsApprove and FindingsWrite")
	assert.False(t, HasAllPermissions(tenant.RoleMember, FindingsApprove, FindingsWrite),
		"Member should NOT have both (missing FindingsApprove)")
}

// Approving a scope exclusion (which suppresses scanning) is separate from
// scope:write: owners and admins hold it by default, members and viewers do not.
func TestScopeExclusionsApprovePermission(t *testing.T) {
	assert.Equal(t, Permission("attack_surface:scope:exclusions:approve"), ScopeExclusionsApprove)
	assert.True(t, HasPermission(tenant.RoleOwner, ScopeExclusionsApprove))
	assert.True(t, HasPermission(tenant.RoleAdmin, ScopeExclusionsApprove))
	assert.False(t, HasPermission(tenant.RoleMember, ScopeExclusionsApprove))
	assert.True(t, HasPermission(tenant.RoleMember, ScopeWrite), "members still request exclusions")
	assert.False(t, HasPermission(tenant.RoleViewer, ScopeExclusionsApprove))
	assert.Contains(t, AllPermissions(), ScopeExclusionsApprove)
}

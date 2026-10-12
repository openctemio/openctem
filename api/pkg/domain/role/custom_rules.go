package role

import "strings"

// Rules a tenant's custom role must follow.
//
// A user's team role (owner/admin/member/viewer: the token's role and admin
// flag, RequireTeamAdmin/Owner, IsOwner) is derived only from the four system
// role IDs, never from a custom role. These rules keep custom roles from even
// looking like a system role: they cannot take a system slug and cannot rank at
// or above the system admin role. Migration 000245 adds the same rules as
// CHECK constraints on roles.

// AdminHierarchyLevel is the hierarchy level of the system admin role.
const AdminHierarchyLevel = 80

// MaxCustomHierarchyLevel is the highest hierarchy level a custom role may
// have: just below the system admin role.
const MaxCustomHierarchyLevel = AdminHierarchyLevel - 1

// reservedSlugs are the system role slugs. No custom role may use one.
var reservedSlugs = map[string]bool{
	"owner":      true,
	"admin":      true,
	"member":     true,
	"viewer":     true,
	"researcher": true,
}

// IsReservedSlug reports whether slug is a system role slug (case-insensitive).
func IsReservedSlug(slug string) bool {
	return reservedSlugs[strings.ToLower(strings.TrimSpace(slug))]
}

// IsSystemRoleID reports whether id is one of the system roles.
func IsSystemRoleID(id ID) bool {
	return id == OwnerRoleID || id == AdminRoleID || id == MemberRoleID || id == ViewerRoleID || id == ResearcherRoleID
}

// ValidCustomHierarchyLevel reports whether level is allowed for a custom role.
func ValidCustomHierarchyLevel(level int) bool {
	return level >= 0 && level <= MaxCustomHierarchyLevel
}

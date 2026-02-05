package accesscontrol

import (
	"github.com/openctemio/api/pkg/domain/permission"
	"github.com/openctemio/api/pkg/domain/permissionset"
	"github.com/openctemio/api/pkg/domain/shared"
)

// PermissionResolver resolves effective permissions for users and groups.
// It handles permission inheritance, additions, and removals.
type PermissionResolver struct{}

// NewPermissionResolver creates a new PermissionResolver.
func NewPermissionResolver() *PermissionResolver {
	return &PermissionResolver{}
}

// ResolvePermissionSetPermissions resolves the effective permissions for a permission set.
// For extended sets, it applies: Parent Permissions + Additions - Removals.
// For other sets, it returns the direct permissions.
func (r *PermissionResolver) ResolvePermissionSetPermissions(
	ps *permissionset.PermissionSetWithItems,
	parentChain []*permissionset.PermissionSetWithItems,
) []permission.Permission {
	if ps == nil {
		return nil
	}

	// For non-extended sets, return direct permissions
	if !ps.PermissionSet.IsExtended() {
		return r.resolveDirectPermissions(ps)
	}

	// For extended sets, resolve from parent chain
	return r.resolveExtendedPermissions(ps, parentChain)
}

// resolveDirectPermissions resolves permissions for custom/system/cloned sets.
func (r *PermissionResolver) resolveDirectPermissions(ps *permissionset.PermissionSetWithItems) []permission.Permission {
	permSet := make(map[string]struct{})

	for _, item := range ps.Items {
		if item.IsAdd() {
			permSet[item.PermissionID()] = struct{}{}
		}
	}

	result := make([]permission.Permission, 0, len(permSet))
	for permID := range permSet {
		if p, ok := permission.ParsePermission(permID); ok {
			result = append(result, p)
		}
	}
	return result
}

// resolveExtendedPermissions resolves permissions for extended sets.
// Formula: Parent Permissions + Additions - Removals
func (r *PermissionResolver) resolveExtendedPermissions(
	ps *permissionset.PermissionSetWithItems,
	parentChain []*permissionset.PermissionSetWithItems,
) []permission.Permission {
	// Start with parent permissions
	parentPerms := r.resolveParentChainPermissions(parentChain)
	permSet := make(map[string]struct{}, len(parentPerms))
	for _, p := range parentPerms {
		permSet[p.String()] = struct{}{}
	}

	// Apply modifications from this set
	for _, item := range ps.Items {
		if item.IsAdd() {
			permSet[item.PermissionID()] = struct{}{}
		} else if item.IsRemove() {
			delete(permSet, item.PermissionID())
		}
	}

	result := make([]permission.Permission, 0, len(permSet))
	for permID := range permSet {
		if p, ok := permission.ParsePermission(permID); ok {
			result = append(result, p)
		}
	}
	return result
}

// resolveParentChainPermissions resolves permissions from the parent chain.
func (r *PermissionResolver) resolveParentChainPermissions(
	parentChain []*permissionset.PermissionSetWithItems,
) []permission.Permission {
	if len(parentChain) == 0 {
		return nil
	}

	// Start from the root (first in chain) and work down
	permSet := make(map[string]struct{})

	for _, ps := range parentChain {
		if ps.PermissionSet.IsExtended() {
			// For extended sets, apply additions and removals
			for _, item := range ps.Items {
				if item.IsAdd() {
					permSet[item.PermissionID()] = struct{}{}
				} else if item.IsRemove() {
					delete(permSet, item.PermissionID())
				}
			}
		} else {
			// For non-extended sets (base), collect all add items
			for _, item := range ps.Items {
				if item.IsAdd() {
					permSet[item.PermissionID()] = struct{}{}
				}
			}
		}
	}

	result := make([]permission.Permission, 0, len(permSet))
	for permID := range permSet {
		if p, ok := permission.ParsePermission(permID); ok {
			result = append(result, p)
		}
	}
	return result
}

// ResolveGroupPermissions resolves the effective permissions for a group.
// It combines permissions from permission sets and custom group permissions.
func (r *PermissionResolver) ResolveGroupPermissions(
	permissionSets []*permissionset.PermissionSetWithItems,
	parentChains map[shared.ID][]*permissionset.PermissionSetWithItems,
	customPermissions []*GroupPermission,
) []permission.Permission {
	// Collect permissions from all permission sets
	permSet := make(map[string]struct{})

	for _, ps := range permissionSets {
		chain := parentChains[ps.PermissionSet.ID()]
		perms := r.ResolvePermissionSetPermissions(ps, chain)
		for _, p := range perms {
			permSet[p.String()] = struct{}{}
		}
	}

	// Apply custom permissions (allow/deny overrides)
	deniedPerms := make(map[string]struct{})
	for _, cp := range customPermissions {
		if cp.IsAllow() {
			permSet[cp.PermissionID()] = struct{}{}
		} else if cp.IsDeny() {
			deniedPerms[cp.PermissionID()] = struct{}{}
		}
	}

	// Remove denied permissions
	for permID := range deniedPerms {
		delete(permSet, permID)
	}

	result := make([]permission.Permission, 0, len(permSet))
	for permID := range permSet {
		if p, ok := permission.ParsePermission(permID); ok {
			result = append(result, p)
		}
	}
	return result
}

// ResolveUserPermissions resolves the effective permissions for a user.
// It merges permissions from all groups the user belongs to.
func (r *PermissionResolver) ResolveUserPermissions(
	groupPermissions [][]permission.Permission,
) []permission.Permission {
	permSet := make(map[string]struct{})

	// Union of all group permissions
	for _, perms := range groupPermissions {
		for _, p := range perms {
			permSet[p.String()] = struct{}{}
		}
	}

	result := make([]permission.Permission, 0, len(permSet))
	for permID := range permSet {
		if p, ok := permission.ParsePermission(permID); ok {
			result = append(result, p)
		}
	}
	return result
}

// HasPermission checks if a permission set grants a specific permission.
func (r *PermissionResolver) HasPermission(
	ps *permissionset.PermissionSetWithItems,
	parentChain []*permissionset.PermissionSetWithItems,
	target permission.Permission,
) bool {
	perms := r.ResolvePermissionSetPermissions(ps, parentChain)
	return permission.Contains(perms, target)
}

// HasAnyPermission checks if a permission set grants any of the specified permissions.
func (r *PermissionResolver) HasAnyPermission(
	ps *permissionset.PermissionSetWithItems,
	parentChain []*permissionset.PermissionSetWithItems,
	targets ...permission.Permission,
) bool {
	perms := r.ResolvePermissionSetPermissions(ps, parentChain)
	return permission.ContainsAny(perms, targets...)
}

// HasAllPermissions checks if a permission set grants all of the specified permissions.
func (r *PermissionResolver) HasAllPermissions(
	ps *permissionset.PermissionSetWithItems,
	parentChain []*permissionset.PermissionSetWithItems,
	targets ...permission.Permission,
) bool {
	perms := r.ResolvePermissionSetPermissions(ps, parentChain)
	return permission.ContainsAll(perms, targets...)
}

// EffectivePermissions represents the resolved permissions for an entity.
type EffectivePermissions struct {
	Permissions []permission.Permission
	Sources     []PermissionSource
}

// PermissionSource describes where a permission came from.
type PermissionSource struct {
	PermissionID     string
	SourceType       string    // "permission_set", "custom_permission"
	SourceID         shared.ID // Permission set ID or group ID
	SourceName       string    // Human-readable name
	ModificationType string    // "add", "remove", "inherited"
}

// ResolveWithSources resolves permissions and tracks their sources.
// This is useful for auditing and debugging permission issues.
func (r *PermissionResolver) ResolveWithSources(
	permissionSets []*permissionset.PermissionSetWithItems,
	parentChains map[shared.ID][]*permissionset.PermissionSetWithItems,
	customPermissions []*GroupPermission,
) *EffectivePermissions {
	sources := make([]PermissionSource, 0)
	permSet := make(map[string]struct{})
	permSourceMap := make(map[string]PermissionSource)

	// Process permission sets
	for _, ps := range permissionSets {
		chain := parentChains[ps.PermissionSet.ID()]
		perms := r.ResolvePermissionSetPermissions(ps, chain)
		for _, p := range perms {
			permID := p.String()
			permSet[permID] = struct{}{}
			permSourceMap[permID] = PermissionSource{
				PermissionID:     permID,
				SourceType:       "permission_set",
				SourceID:         ps.PermissionSet.ID(),
				SourceName:       ps.PermissionSet.Name(),
				ModificationType: "add",
			}
		}
	}

	// Process custom permissions
	deniedPerms := make(map[string]struct{})
	for _, cp := range customPermissions {
		permID := cp.PermissionID()
		if cp.IsAllow() {
			permSet[permID] = struct{}{}
			permSourceMap[permID] = PermissionSource{
				PermissionID:     permID,
				SourceType:       "custom_permission",
				SourceID:         cp.GroupID(),
				SourceName:       "Custom Override",
				ModificationType: "add",
			}
		} else if cp.IsDeny() {
			deniedPerms[permID] = struct{}{}
			sources = append(sources, PermissionSource{
				PermissionID:     permID,
				SourceType:       "custom_permission",
				SourceID:         cp.GroupID(),
				SourceName:       "Custom Override",
				ModificationType: "remove",
			})
		}
	}

	// Remove denied permissions
	for permID := range deniedPerms {
		delete(permSet, permID)
		delete(permSourceMap, permID)
	}

	// Build result
	result := make([]permission.Permission, 0, len(permSet))
	for permID := range permSet {
		if p, ok := permission.ParsePermission(permID); ok {
			result = append(result, p)
			if source, exists := permSourceMap[permID]; exists {
				sources = append(sources, source)
			}
		}
	}

	return &EffectivePermissions{
		Permissions: result,
		Sources:     sources,
	}
}

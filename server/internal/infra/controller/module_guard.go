package controller

import "context"

// ModuleGuard answers "which modules has this tenant disabled" so a per-tenant
// controller loop can cheaply skip work for a module the tenant did not
// subscribe to. Satisfied by *app.ModuleService (its TenantDisabledModules).
//
// Fail-open by construction: the underlying service returns an empty set when a
// tenant has no bundle subscription, so a guard never skips work for existing
// tenants — the compute guard is a strict no-op unless a tenant has explicitly
// subsetted its modules.
type ModuleGuard interface {
	TenantDisabledModules(ctx context.Context, tenantID string) map[string]bool
}

// tenantModuleCache memoizes TenantDisabledModules within a single reconcile
// pass, so a loop over many rows does not re-query the module service once per
// tenant. Construct one per Reconcile; it is not safe for concurrent use.
//
// A nil guard (not wired) makes every lookup report "enabled", preserving the
// prior always-run behavior.
type tenantModuleCache struct {
	guard ModuleGuard
	cache map[string]map[string]bool
}

// newTenantModuleCache builds a per-run cache around an optional guard.
func newTenantModuleCache(guard ModuleGuard) *tenantModuleCache {
	return &tenantModuleCache{guard: guard, cache: make(map[string]map[string]bool)}
}

// disabled reports whether moduleID is disabled for tenantID. A nil guard, an
// empty tenant id, or a tenant with no subscription all yield false ("run it"),
// so a controller only ever skips a tenant that has explicitly subsetted its
// modules to exclude this one.
func (t *tenantModuleCache) disabled(ctx context.Context, tenantID, moduleID string) bool {
	if t == nil || t.guard == nil || tenantID == "" {
		return false
	}
	set, ok := t.cache[tenantID]
	if !ok {
		set = t.guard.TenantDisabledModules(ctx, tenantID)
		t.cache[tenantID] = set
	}
	return set[moduleID]
}

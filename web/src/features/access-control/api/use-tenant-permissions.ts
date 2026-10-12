'use client'

/**
 * Tenant Permission Modules Hook
 *
 * Returns permission modules filtered by tenant's enabled modules.
 * This ensures that roles UI only shows permissions for features
 * the tenant has access to based on their enabled modules.
 *
 * For example, a tenant without the findings module won't see Findings
 * permissions since they don't have access to that module.
 */

import { useMemo } from 'react'
import { ADMIN_ONLY_PERMISSIONS } from '@/lib/permissions/constants'
import { usePermissionModules } from './use-roles'
import { useTenantModules } from '@/features/integrations/api/use-tenant-modules'
// Note: PermissionModule is re-exported from usePermissionModules, no need to import here

/**
 * Whether a permission module is on for the organization. The modules come
 * from GET /api/v1/permissions/modules, whose ids are the real catalog module
 * ids (every active permission belongs to an active module), so they compare
 * directly with the organization's enabled module ids.
 */
function isModuleAvailable(moduleId: string, enabledModuleIds: string[]): boolean {
  return enabledModuleIds.includes(moduleId)
}

/**
 * Hook to get permission modules filtered by tenant's subscription
 *
 * @param filterByPlan - If true, filters modules by tenant's plan. Default: true
 * @returns Filtered permission modules and loading states
 *
 * @example
 * ```tsx
 * function PermissionPicker() {
 *   const { modules, isLoading } = useTenantPermissionModules();
 *   // modules only includes permissions for tenant's enabled features
 * }
 * ```
 */
export function useTenantPermissionModules(
  filterByPlan: boolean = true,
  { forCustomRole = false }: { forCustomRole?: boolean } = {}
) {
  const {
    modules: rawModules,
    isLoading: modulesLoading,
    error: modulesError,
  } = usePermissionModules()
  // A custom role may not carry the admin-only permissions (settings decision
  // B1; the API refuses them), so the role editors do not offer them.
  const allModules = useMemo(
    () =>
      forCustomRole
        ? rawModules.map((m) => ({
            ...m,
            permissions: m.permissions.filter((p) => !ADMIN_ONLY_PERMISSIONS.includes(p.id)),
          }))
        : rawModules,
    [rawModules, forCustomRole]
  )
  const { moduleIds: enabledModuleIds, isLoading: tenantModulesLoading } = useTenantModules()

  const filteredModules = useMemo(() => {
    // If not filtering or tenant modules not loaded yet, return all (but still filter empty modules)
    if (!filterByPlan || tenantModulesLoading || enabledModuleIds.length === 0) {
      // Still filter out modules with no permissions
      return allModules.filter((module) => module.permissions.length > 0)
    }

    // Filter modules based on tenant's enabled modules AND has permissions
    return allModules.filter(
      (module) => module.permissions.length > 0 && isModuleAvailable(module.id, enabledModuleIds)
    )
  }, [allModules, enabledModuleIds, filterByPlan, tenantModulesLoading])

  // Calculate stats
  const totalPermissions = useMemo(() => {
    return filteredModules.reduce((sum, m) => sum + m.permissions.length, 0)
  }, [filteredModules])

  const hiddenModulesCount = allModules.length - filteredModules.length

  return {
    /** Filtered permission modules based on tenant's plan */
    modules: filteredModules,
    /** Total number of available permissions */
    totalPermissions,
    /** Number of modules hidden due to plan restrictions */
    hiddenModulesCount,
    /** All modules (unfiltered) */
    allModules,
    /** Tenant's enabled module IDs */
    enabledModuleIds,
    /** Loading state */
    isLoading: modulesLoading || tenantModulesLoading,
    /** Error if any */
    error: modulesError,
  }
}

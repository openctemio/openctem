/**
 * Route Guard Component
 *
 * Protects routes based on tenant's module access and user permissions.
 * Shows "Access Denied" page when user doesn't have required access.
 *
 * Access Control Layers (checked in order):
 * 1. Module (Licensing) - Does tenant's plan include this module?
 * 2. Permission (RBAC) - Does user have the required permission?
 *
 * IMPORTANT: This component uses the same access control logic as the sidebar
 * filtering (useFilteredSidebarData) to ensure consistency:
 * - Owner/Admin bypass both module and permission checks
 * - Module check uses fail-open for Owner/Admin when API fails
 * - Permission check uses `can()` from hooks which includes Owner/Admin bypass
 *
 * @example
 * ```tsx
 * // In layout.tsx
 * <RouteGuard>
 *   {children}
 * </RouteGuard>
 * ```
 */

'use client'

import { useTranslation } from '@/context/i18n-provider'
import * as React from 'react'
import Link from '@/components/link'
import { usePathname, useRouter } from 'next/navigation'
import { ArrowLeft, Home, Settings, Lock } from 'lucide-react'
import { usePermissions } from '@/lib/permissions/hooks'
import { Permission } from '@/lib/permissions/constants'
import { useBootstrapModules, useBootstrapContextSafe } from '@/context/bootstrap-provider'
import { matchRoutePermission } from '@/config/route-permissions'
import { Button } from '@/components/ui/button'
import { AccessNotice } from '@/features/shared/components/access-notice'
import { PageStack } from '@/features/shared/components/page-stack'
import { activeSettingsItem } from '@/config/settings-nav'
import { MainRegion } from '@/components/layout/main'

interface RouteGuardProps {
  children: React.ReactNode
}

type AccessDeniedReason = 'module' | 'permission'

/**
 * RouteGuard Component
 *
 * Wraps children and checks if user has access to current route.
 * Checks both module access (licensing) and permission (RBAC).
 *
 * IMPORTANT: No Owner/Admin bypass! Permissions from API are the source of truth.
 * Owner role has 215 permissions, Admin has 213 - all defined in database.
 * This ensures RBAC is properly enforced for all users.
 *
 * If not, shows an "Access Denied" page.
 */
export function RouteGuard({ children }: RouteGuardProps) {
  const pathname = usePathname()
  // Use the same permission hook as sidebar for consistency
  const { can, isLoading: permissionsLoading } = usePermissions()
  const {
    moduleIds,
    notEntitledModuleIds,
    readOnlyModules,
    isLoading: modulesLoading,
  } = useBootstrapModules()
  const { isBootstrapped } = useBootstrapContextSafe()

  // Ensure permission sync has fully settled during tenant switches
  // We mirror TenantGate by only waiting for isBootstrapped to avoid 60s race conditions
  const isDataReady = isBootstrapped

  // Find the route permission config for current pathname
  const routeConfig = React.useMemo(() => {
    return matchRoutePermission(pathname)
  }, [pathname])

  /**
   * Check module access
   * Returns true if module is in tenant's plan or no module required
   */
  const hasModuleAccess = React.useCallback(
    (moduleId: string): boolean => {
      // If moduleIds has data, use it (source of truth from API)
      if (moduleIds.length > 0) {
        return moduleIds.includes(moduleId)
      }

      // moduleIds is empty - could be:
      // 1. Bootstrap not finished yet (handled by isLoading check above)
      // 2. API returned empty - fail-closed for security
      // Backend will still enforce authorization
      return false
    },
    [moduleIds]
  )

  // Check access - returns { hasAccess, deniedReason }
  const accessCheck = React.useMemo(() => {
    // If no route config, allow access (public route within dashboard)
    if (!routeConfig) {
      return { hasAccess: true, deniedReason: null }
    }

    // Layer 1: Check module access (Licensing)
    if (routeConfig.module) {
      if (!hasModuleAccess(routeConfig.module)) {
        // The API filters the module list by the user's permissions, so a
        // missing module also means "you may not use this", not only "not
        // available for this organization". Without the route's permission,
        // say so instead of telling the user the feature is unavailable.
        const reason: AccessDeniedReason = can(routeConfig.permission) ? 'module' : 'permission'
        return { hasAccess: false, deniedReason: reason }
      }
    }

    // Layer 2: Check permission (RBAC)
    // Permissions are source of truth from API - no bypass
    if (!can(routeConfig.permission)) {
      return { hasAccess: false, deniedReason: 'permission' as AccessDeniedReason }
    }

    return { hasAccess: true, deniedReason: null }
  }, [routeConfig, can, hasModuleAccess])

  // Before the first bootstrap of this organization: an unprotected route
  // renders at once; a protected one waits. Rendering its page before the
  // check let it fire reads the person may not make (403s, each a refused-
  // action audit row) and flash its content before the access notice.
  if (!isDataReady) {
    if (!routeConfig) return <>{children}</>
    return <MainRegion aria-busy="true" className="flex-1" data-route-checking="" />
  }
  // A background refresh (permissions changed, a module switched) keeps the
  // page mounted, so a half-filled form is not lost; the check runs when the
  // refresh lands.
  if (permissionsLoading || modulesLoading) {
    return <>{children}</>
  }

  if (!accessCheck.hasAccess && routeConfig) {
    return (
      <AccessDenied
        reason={accessCheck.deniedReason!}
        permission={routeConfig.permission}
        canManageModules={can(Permission.TeamUpdate)}
        notAvailable={!!routeConfig.module && notEntitledModuleIds.includes(routeConfig.module)}
      />
    )
  }

  // A module the organization lost recently is read-only until its grace ends:
  // the page renders, and says why saving is refused.
  const readOnlyUntil = routeConfig?.module ? readOnlyModules?.[routeConfig.module] : undefined
  if (readOnlyUntil) {
    return (
      <>
        <ReadOnlyModuleBanner until={readOnlyUntil} />
        {children}
      </>
    )
  }

  // User has access - render children
  return <>{children}</>
}

/** Formats an RFC 3339 instant as a date, or returns it as is. */
function formatDate(value: string): string {
  const d = new Date(value)
  return Number.isNaN(d.getTime())
    ? value
    : d.toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' })
}

/**
 * Shown above a module's pages while the module is in read-only grace: it is
 * no longer available for the organization, data can still be read and
 * exported, changes are refused.
 */
export function ReadOnlyModuleBanner({ until }: { until: string }) {
  const { t } = useTranslation()
  return (
    <div
      role="status"
      className="flex items-start gap-2 border-b border-warning/30 bg-warning/10 px-4 py-2 text-sm"
    >
      <Lock className="mt-0.5 h-4 w-4 shrink-0 text-warning" aria-hidden />
      <p>
        <span className="font-medium">
          {t('limits.banner.readOnlyUntil', 'Read-only until {date}.', { date: formatDate(until) })}
        </span>{' '}
        <span className="text-muted-foreground">
          {t(
            'limits.banner.readOnlyBody',
            'This feature is no longer available for this organization. You can still view and export its data; changes are turned off. Contact the administrator of this installation to keep it.'
          )}
        </span>
      </p>
    </div>
  )
}

/**
 * Access denied page: the shared AccessNotice in the page frame (main
 * landmark, PageStack), so a refused page reads like a refused read inside a
 * page. It names the page (its settings title when it has one), the
 * permission or module, which built-in roles hold the permission and who can
 * grant it, with a way back.
 */
interface AccessDeniedProps {
  reason: AccessDeniedReason
  permission: string
  /** Whether the user may switch modules on (Settings > Modules). */
  canManageModules?: boolean
  /** The module is not available for the organization (not just switched off). */
  notAvailable?: boolean
}

function AccessDenied({
  reason,
  permission,
  canManageModules = false,
  notAvailable = false,
}: AccessDeniedProps) {
  const { t } = useTranslation()
  const pathname = usePathname()
  const router = useRouter()
  const item = activeSettingsItem(pathname)
  const isModuleDenied = reason === 'module'
  const pageTitle = item
    ? t(`settings.item.${item.id}`, item.title)
    : isModuleDenied
      ? t('common.access.thisFeature', 'This feature')
      : t('common.access.thisPage', 'this page')
  const handleGoBack = () => {
    if (typeof window !== 'undefined' && window.history.length > 1) router.back()
    else router.push('/')
  }

  const canTurnOn = isModuleDenied && !notAvailable && canManageModules
  const kind = !isModuleDenied ? 'no_access' : notAvailable ? 'module_unavailable' : 'module_off'
  const hint = !isModuleDenied
    ? undefined
    : notAvailable
      ? undefined
      : canManageModules
        ? t('common.access.moduleTurnOn', 'You can turn it on in Settings, Modules.')
        : t('common.access.moduleAsk', 'Ask an administrator of your organization to turn it on.')

  return (
    <MainRegion className="p-4 sm:p-6" data-route-denied="">
      <PageStack className="mx-auto w-full max-w-2xl">
        <AccessNotice
          kind={kind}
          title={pageTitle}
          details={isModuleDenied ? undefined : { missing_permissions: [permission] }}
          hint={hint}
          actions={
            <>
              <Button variant="outline" size="sm" onClick={handleGoBack}>
                <ArrowLeft className="me-2 h-4 w-4" aria-hidden />
                {t('common.goBack', 'Go back')}
              </Button>
              {canTurnOn ? (
                <Button size="sm" asChild>
                  <Link href="/settings/modules">
                    <Settings className="me-2 h-4 w-4" aria-hidden />
                    {t('common.access.manageModules', 'Manage modules')}
                  </Link>
                </Button>
              ) : (
                <Button size="sm" variant="outline" asChild>
                  <Link href="/">
                    <Home className="me-2 h-4 w-4" aria-hidden />
                    {t('common.access.toDashboard', 'Go to the dashboard')}
                  </Link>
                </Button>
              )}
            </>
          }
        />
      </PageStack>
    </MainRegion>
  )
}

export default RouteGuard

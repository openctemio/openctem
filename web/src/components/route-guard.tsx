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

import * as React from 'react'
import Link from '@/components/link'
import { usePathname } from 'next/navigation'
import { ShieldX, ArrowLeft, Home, Package, Settings, Lock } from 'lucide-react'
import { usePermissions } from '@/lib/permissions/hooks'
import { Permission } from '@/lib/permissions/constants'
import { useBootstrapModules, useBootstrapContextSafe } from '@/context/bootstrap-provider'
import { matchRoutePermission } from '@/config/route-permissions'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
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
        // missing module also means "you may not use this", not only "your
        // plan does not include it". Without the route's permission, say so
        // instead of telling the user to upgrade a plan that has the feature.
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

  // Show children (loading screen from TenantGate) while bootstrap hasn't completed
  // or permissions are still being fetched — prevents flash of AccessDenied
  if (!isDataReady || permissionsLoading || modulesLoading) {
    return <>{children}</>
  }

  if (!accessCheck.hasAccess && routeConfig) {
    return (
      <AccessDenied
        reason={accessCheck.deniedReason!}
        permission={routeConfig.permission}
        module={routeConfig.module}
        message={routeConfig.message}
        canManageModules={can(Permission.TeamUpdate)}
        notInPlan={!!routeConfig.module && notEntitledModuleIds.includes(routeConfig.module)}
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
 * Shown above a module's pages while the module is in read-only grace: the
 * organization's plan no longer includes it, data can still be read and
 * exported, changes are refused.
 */
export function ReadOnlyModuleBanner({ until }: { until: string }) {
  return (
    <div
      role="status"
      className="flex items-start gap-2 border-b border-warning/30 bg-warning/10 px-4 py-2 text-sm"
    >
      <Lock className="mt-0.5 h-4 w-4 shrink-0 text-warning" aria-hidden />
      <p>
        <span className="font-medium">Read-only until {formatDate(until)}.</span>{' '}
        <span className="text-muted-foreground">
          Your organization&apos;s plan no longer includes this feature. You can still view and
          export its data; changes are turned off. Contact your platform administrator to keep it.
        </span>
      </p>
    </div>
  )
}

/**
 * Access Denied Page
 *
 * Shown when user doesn't have access to a route.
 * Handles both module (licensing) and permission (RBAC) denied reasons.
 */
interface AccessDeniedProps {
  reason: AccessDeniedReason
  permission: string
  module?: string
  message?: string
  /** Whether the user may switch modules on (Settings > Modules). */
  canManageModules?: boolean
  /** The organization's plan does not include the module (not just switched off). */
  notInPlan?: boolean
}

function AccessDenied({
  reason,
  permission,
  module,
  message,
  canManageModules = false,
  notInPlan = false,
}: AccessDeniedProps) {
  const handleGoBack = () => {
    if (typeof window !== 'undefined' && window.history.length > 1) {
      window.history.back()
    } else {
      window.location.href = '/'
    }
  }

  const handleGoHome = () => {
    window.location.href = '/'
  }

  // Determine icon and title based on reason
  const isModuleDenied = reason === 'module'
  const Icon = isModuleDenied ? Package : ShieldX
  // A module missing for a user who holds the route's permission is switched
  // off for the organization (by an administrator or its products), not a
  // plan matter: plans do not gate modules.
  const title = !isModuleDenied
    ? 'Access Denied'
    : notInPlan
      ? 'Not in your plan'
      : 'Turned off for your organization'
  const defaultMessage = !isModuleDenied
    ? "You don't have permission to access this page."
    : notInPlan
      ? "Your organization's plan does not include this feature."
      : 'This feature is switched off for your organization.'
  // Only an organization's own switch can be turned back on from Settings.
  const canTurnOn = isModuleDenied && !notInPlan && canManageModules

  // This view replaces the page header and the layout's <main>, so it is the
  // page's main landmark and the skip link's #content target itself.
  return (
    <MainRegion className="flex flex-1 items-center justify-center p-8">
      <Card className="w-full max-w-md">
        <CardHeader className="text-center">
          <div
            className={`mx-auto mb-4 flex h-16 w-16 items-center justify-center rounded-full ${isModuleDenied ? 'bg-warning/10' : 'bg-destructive/10'}`}
          >
            <Icon className={`h-8 w-8 ${isModuleDenied ? 'text-warning' : 'text-destructive'}`} />
          </div>
          <CardTitle className="text-xl">{title}</CardTitle>
          <CardDescription className="mt-2">{message || defaultMessage}</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          {/* Access info (for debugging) */}
          <div className="rounded-md bg-muted p-3 text-center space-y-1">
            {isModuleDenied && module && (
              <p className="text-xs text-muted-foreground">
                Required module: <code className="font-mono text-foreground">{module}</code>
              </p>
            )}
            {!isModuleDenied && (
              <p className="text-xs text-muted-foreground">
                Required permission: <code className="font-mono text-foreground">{permission}</code>
              </p>
            )}
          </div>

          {/* Help text */}
          <p className="text-center text-sm text-muted-foreground">
            {!isModuleDenied
              ? 'If you believe you should have access, please contact your administrator.'
              : notInPlan
                ? 'Contact your platform administrator to add it to your plan.'
                : canManageModules
                  ? 'You can turn it on in Settings > Modules.'
                  : 'Ask an administrator of your organization to turn it on.'}
          </p>

          {/* Actions */}
          <div className="flex justify-center gap-3">
            <Button variant="outline" onClick={handleGoBack}>
              <ArrowLeft className="me-2 h-4 w-4" />
              Go Back
            </Button>
            {canTurnOn ? (
              <Button asChild>
                <Link href="/settings/modules">
                  <Settings className="me-2 h-4 w-4" />
                  Manage modules
                </Link>
              </Button>
            ) : (
              <Button onClick={handleGoHome}>
                <Home className="me-2 h-4 w-4" />
                Dashboard
              </Button>
            )}
          </div>
        </CardContent>
      </Card>
    </MainRegion>
  )
}

export default RouteGuard

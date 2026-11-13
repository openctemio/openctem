/**
 * Tenant Context Provider
 *
 * Manages current tenant state and provides team switching functionality.
 * - Reads current tenant from cookie
 * - Fetches all user's tenants
 * - Provides switchTeam function for changing teams
 */

'use client'

import * as React from 'react'
import { toast } from 'sonner'
import { useSWRConfig } from 'swr'
import { clearSwrCache } from '@/lib/swr-config'
import { devLog } from '@/lib/logger'
import { useMyTenants, invalidateMyTenantsCache } from '@/lib/api/user-tenant-hooks'
import type { TenantMembership, TenantRole } from '@/lib/api/user-tenant-types'
import { getCookie, setCookie, removeCookie } from '@/lib/cookies'
import { env } from '@/lib/env'
import { csrfHeaders } from '@/lib/csrf-client'
import { clearPrimedViews } from '@/lib/api/view-prime'
import { clearOrgScopedClientState } from '@/lib/org-scoped-storage'
import {
  announceTenantSwitch,
  endTenantEpoch,
  onTenantChangedElsewhere,
  setActiveTenantId,
} from '@/lib/tenant-epoch'
import { useTranslation } from '@/context/i18n-provider'

// ============================================
// TYPES
// ============================================

export interface CurrentTenant {
  id: string
  slug: string
  name?: string
  role: TenantRole
  logo_url?: string
}

interface TenantContextValue {
  /** Current active tenant */
  currentTenant: CurrentTenant | null
  /** All tenants user has access to */
  tenants: TenantMembership[]
  /** Loading state for tenants */
  isLoading: boolean
  /** Error fetching tenants */
  error: Error | null
  /**
   * Switch to another organization. The dashboard then starts a new
   * organization epoch (TenantEpochBoundary): fresh data cache, every
   * component remounted, the address reset to the section's list root.
   * `keepLocation` keeps the address (a link that names the new
   * organization, OrgLinkGate; the MCP consent page).
   */
  switchTeam: (tenantId: string, options?: SwitchTeamOptions) => Promise<void>
  /** Increases on every change of organization in this tab. */
  epoch: number
  /** Whether the current epoch keeps the address it started on. */
  epochKeepsLocation: boolean
  /** Switching in progress */
  isSwitching: boolean
  /** Refresh tenant list */
  refreshTenants: () => Promise<void>
  /** Update current tenant info (name, slug) without full reload */
  updateCurrentTenant: (updates: Partial<Pick<CurrentTenant, 'name' | 'slug'>>) => void
  /** Trigger eager fetch of tenant list (call when opening dropdown) */
  loadTenants: () => void
}

export interface SwitchTeamOptions {
  /** Keep the current address (it already names the new organization's page). */
  keepLocation?: boolean
}

// ============================================
// CONTEXT
// ============================================

const TenantContext = React.createContext<TenantContextValue | undefined>(undefined)

// Cookie name for storing current tenant (from env config)
const TENANT_COOKIE = env.cookies.tenant

// ============================================
// PROVIDER
// ============================================

interface TenantProviderProps {
  children: React.ReactNode
}

// Helper to read tenant from cookie synchronously (for initial state)
function readTenantFromCookie(): { tenant: CurrentTenant | null; hasCookie: boolean } {
  if (typeof window === 'undefined') {
    return { tenant: null, hasCookie: false }
  }
  const tenantCookie = getCookie(TENANT_COOKIE)
  if (tenantCookie) {
    try {
      const parsed = JSON.parse(tenantCookie) as CurrentTenant
      return { tenant: parsed, hasCookie: true }
    } catch {
      // Old cookie format - will be cleared in useEffect
      return { tenant: null, hasCookie: false }
    }
  }
  return { tenant: null, hasCookie: false }
}

export function TenantProvider({ children }: TenantProviderProps) {
  const { t } = useTranslation()
  // The cache this provider sits in (the app's default cache). The dashboard
  // keeps organization data in a per-epoch cache below it; pages that host a
  // TenantProvider without the dashboard shell (consent, device sign-in) read
  // through this one.
  const { mutate: globalMutate } = useSWRConfig()

  // Start with null, read from cookie in useLayoutEffect to avoid hydration mismatch
  const [currentTenant, setCurrentTenant] = React.useState<CurrentTenant | null>(null)
  // The organization epoch of this tab (src/lib/tenant-epoch.ts).
  const [epochState, setEpochState] = React.useState({ epoch: 0, keepLocation: false })
  const currentTenantRef = React.useRef<CurrentTenant | null>(null)
  React.useEffect(() => {
    currentTenantRef.current = currentTenant
  }, [currentTenant])
  // True while this tab's own switch runs: the cookie already names the new
  // organization before the epoch begins, which is not "another tab".
  const ownSwitchRef = React.useRef(false)
  const [isSwitching, setIsSwitching] = React.useState(false)
  const [hasTenantCookie, setHasTenantCookie] = React.useState<boolean | null>(null)
  // Track if dropdown has been opened (trigger eager fetch when user wants to switch)
  const [shouldEagerFetch, setShouldEagerFetch] = React.useState(false)
  // Track if initial read has been done
  const initialReadDoneRef = React.useRef(false)

  // Read tenant from cookie on mount (client-side only)
  // This runs immediately after hydration, before paint
  React.useLayoutEffect(() => {
    if (initialReadDoneRef.current) return
    initialReadDoneRef.current = true

    const { tenant, hasCookie } = readTenantFromCookie()
    devLog.log('[TenantProvider] Initial read:', { tenant: tenant?.id, hasCookie })
    setActiveTenantId(tenant?.id ?? null)
    setCurrentTenant(tenant)
    setHasTenantCookie(hasCookie)

    // Handle invalid cookie format
    if (!tenant && hasCookie) {
      const tenantCookie = getCookie(TENANT_COOKIE)
      if (tenantCookie) {
        devLog.warn('[TenantProvider] Invalid tenant cookie format, clearing cookie')
        removeCookie(TENANT_COOKIE)
        setHasTenantCookie(false)
      }
    }
  }, [])

  // Outside this provider no tab tenant is known: the request guard stands down.
  React.useEffect(() => () => setActiveTenantId(null), [])

  // OPTIMIZATION: Only fetch tenants on page load if:
  // 1. No tenant cookie exists (need to check if user needs onboarding)
  // 2. User has opened the dropdown (wants to switch teams)
  // Otherwise, skip the API call to reduce load time
  const skipTenantsFetch = hasTenantCookie === null || (hasTenantCookie && !shouldEagerFetch)
  const { data: tenants = [], error, isLoading, mutate } = useMyTenants({ skip: skipTenantsFetch })

  // Update current tenant with additional info from tenants list
  // Use ref to prevent unnecessary updates
  const lastUpdatedTenantId = React.useRef<string | null>(null)

  React.useEffect(() => {
    if (currentTenant && tenants.length > 0) {
      // Skip if we already updated this tenant
      if (lastUpdatedTenantId.current === currentTenant.id && currentTenant.name) {
        return
      }

      const fullTenant = tenants.find((t) => t.id === currentTenant.id)
      if (fullTenant && (!currentTenant.name || currentTenant.name !== fullTenant.name)) {
        lastUpdatedTenantId.current = currentTenant.id
        setCurrentTenant({
          ...currentTenant,
          name: fullTenant.name,
        })
      }
    }
  }, [currentTenant, tenants])

  /**
   * Ends the previous organization's epoch in this tab and starts the next
   * one. Order matters: reads in flight are aborted and the tab's tenant is
   * updated before React renders again, so nothing the old organization
   * started can write into the new one's view, and no request leaves with
   * the old organization's state.
   */
  const beginEpoch = React.useCallback(
    (previousId: string | null, next: CurrentTenant, keepLocation: boolean) => {
      endTenantEpoch()
      clearPrimedViews()
      clearOrgScopedClientState(previousId)
      setActiveTenantId(next.id)
      setCurrentTenant(next)
      setEpochState((s) => ({ epoch: s.epoch + 1, keepLocation }))
      void clearSwrCache(globalMutate)
    },
    [globalMutate]
  )

  // Switch to a different team
  const switchTeam = React.useCallback(
    async (tenantId: string, options?: SwitchTeamOptions) => {
      if (isSwitching) return

      // Find the target tenant
      const targetTenant = tenants.find((t) => t.id === tenantId)
      if (!targetTenant) {
        devLog.error('[TenantProvider] Tenant not found:', tenantId)
        return
      }

      // Don't switch if already on this tenant
      if (currentTenant?.id === tenantId) {
        return
      }

      setIsSwitching(true)
      ownSwitchRef.current = true

      try {
        // Call the switch team API endpoint
        const response = await fetch('/api/auth/switch-team', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            ...csrfHeaders(),
          },
          credentials: 'include',
          body: JSON.stringify({
            tenant_id: tenantId,
            tenant_name: targetTenant.name, // Include name for cookie storage
          }),
        })

        if (!response.ok) {
          const body = (await response.json().catch(() => ({}))) as {
            error?: { code?: unknown }
          }
          const failure = new Error('Failed to switch organization')
          if (typeof body.error?.code === 'string') {
            ;(failure as Error & { code?: string }).code = body.error.code
          }
          throw failure
        }

        const data = await response.json()

        const newTenant: CurrentTenant = {
          id: data.data.tenant_id,
          slug: data.data.tenant_slug,
          name: targetTenant.name,
          role: data.data.role as TenantRole,
        }

        // Update cookie (non-httpOnly for client read)
        setCookie(
          TENANT_COOKIE,
          JSON.stringify({
            id: newTenant.id,
            slug: newTenant.slug,
            name: newTenant.name,
            role: newTenant.role,
          }),
          { path: '/', maxAge: 7 * 24 * 60 * 60 }
        )

        // A new epoch: the dashboard remounts with a fresh data cache and the
        // address goes to the section's list root (TenantEpochBoundary).
        beginEpoch(currentTenant?.id ?? null, newTenant, options?.keepLocation === true)
        // Other tabs of this browser now hold the new session too.
        announceTenantSwitch(newTenant.id)

        devLog.log('[TenantProvider] Switched to team:', newTenant.name)
      } catch (error) {
        devLog.error('[TenantProvider] Failed to switch team:', error)
        throw error
      } finally {
        ownSwitchRef.current = false
        setIsSwitching(false)
      }
    },
    [currentTenant, tenants, isSwitching, beginEpoch]
  )

  // Another tab switched (or the session changed under this tab): adopt the
  // session's organization the same way, before anything else renders.
  React.useEffect(
    () =>
      onTenantChangedElsewhere(() => {
        if (ownSwitchRef.current) return
        const next = getCurrentTenantFromCookie()
        const previous = currentTenantRef.current
        if (!next?.id || next.id === previous?.id) return
        beginEpoch(previous?.id ?? null, next, false)
        toast.info(
          t('org.switchedElsewhere', 'Another tab switched to {name}. This tab shows it now.', {
            name: next.name || next.slug,
          })
        )
      }),
    [beginEpoch, t]
  )

  // Refresh tenants
  const refreshTenants = React.useCallback(async () => {
    await mutate()
    await invalidateMyTenantsCache()
  }, [mutate])

  // Update current tenant info (name, slug) without full reload
  const updateCurrentTenant = React.useCallback(
    (updates: Partial<Pick<CurrentTenant, 'name' | 'slug'>>) => {
      if (!currentTenant) return

      const updatedTenant: CurrentTenant = {
        ...currentTenant,
        ...updates,
      }

      setCurrentTenant(updatedTenant)

      // Update cookie with new info
      setCookie(
        TENANT_COOKIE,
        JSON.stringify({
          id: updatedTenant.id,
          slug: updatedTenant.slug,
          name: updatedTenant.name,
          role: updatedTenant.role,
        }),
        { path: '/', maxAge: 7 * 24 * 60 * 60 }
      )
    },
    [currentTenant]
  )

  // Load tenants on demand (for dropdown)
  const loadTenants = React.useCallback(() => {
    if (!shouldEagerFetch) {
      setShouldEagerFetch(true)
    }
  }, [shouldEagerFetch])

  const value = React.useMemo<TenantContextValue>(
    () => ({
      currentTenant,
      tenants,
      isLoading,
      error: error || null,
      switchTeam,
      epoch: epochState.epoch,
      epochKeepsLocation: epochState.keepLocation,
      isSwitching,
      refreshTenants,
      updateCurrentTenant,
      loadTenants,
    }),
    [
      epochState,
      currentTenant,
      tenants,
      isLoading,
      error,
      switchTeam,
      isSwitching,
      refreshTenants,
      updateCurrentTenant,
      loadTenants,
    ]
  )

  return <TenantContext.Provider value={value}>{children}</TenantContext.Provider>
}

// ============================================
// HOOK
// ============================================

export function useTenant() {
  const context = React.useContext(TenantContext)
  if (context === undefined) {
    throw new Error('useTenant must be used within a TenantProvider')
  }
  return context
}

/**
 * The active organization's id, or null outside a TenantProvider (never
 * throws). Used by long-lived connections that must follow an organization
 * switch, such as the WebSocket.
 */
export function useCurrentTenantId(): string | null {
  return React.useContext(TenantContext)?.currentTenant?.id ?? null
}

// ============================================
// UTILITIES
// ============================================

/**
 * Get current tenant from cookie (can be used server-side)
 */
export function getCurrentTenantFromCookie(): CurrentTenant | null {
  if (typeof window === 'undefined') return null

  const tenantCookie = getCookie(TENANT_COOKIE)
  if (!tenantCookie) return null

  try {
    return JSON.parse(tenantCookie) as CurrentTenant
  } catch {
    return null
  }
}

'use client'

import { useState, useEffect, useMemo, useRef, useTransition } from 'react'
import { devLog } from '@/lib/logger'
import { useRouter } from 'next/navigation'
import { Building2, Check, Loader2, LogOut, Plus, Search } from 'lucide-react'
import { toast } from 'sonner'
import { navigateAfterSessionChange } from '@/lib/session-navigation'

import { EntryActions, EntryCard, EntryHeader } from '@/components/entry'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { getCookie } from '@/lib/cookies'
import { cn } from '@/lib/utils'
import { env } from '@/lib/env'
import {
  selectTenantAction,
  localLogoutAction,
  type LoginTenant,
} from '@/features/auth/actions/local-auth-actions'
import { getErrorMessage } from '@/lib/api/error-handler'
import { useCanCreateOrganization } from '@/features/auth/hooks/use-can-create-organization'
import { useTranslation } from '@/context/i18n-provider'

// Show the search input only when the user has more than this many teams.
// Below this threshold scanning visually is faster than typing.
const SEARCH_THRESHOLD = 6

interface PendingState {
  tenants: LoginTenant[]
  error: boolean
}

// Parse tenants from a cookie. Client-only (the cookie is HttpOnly=false but
// only meaningful at the browser); the SSR pass returns null and the page
// shows a stable loading state until the effect runs.
function parsePendingTenants(): PendingState {
  const pendingTenantsStr = getCookie(env.cookies.pendingTenants)
  if (!pendingTenantsStr) {
    return { tenants: [], error: true }
  }
  try {
    const parsed = JSON.parse(pendingTenantsStr) as LoginTenant[]
    return { tenants: parsed, error: false }
  } catch {
    return { tenants: [], error: true }
  }
}

export default function SelectTenantPage() {
  const router = useRouter()
  const { t } = useTranslation()
  // Read through a ref so the redirect effect below does not depend on t.
  const listExpiredRef = useRef(
    t('auth.selectTenant.listExpired', 'Your organization list expired. Sign in again to continue.')
  )
  const { canCreate: canCreateTeam } = useCanCreateOrganization()
  const [isPending, startTransition] = useTransition()
  const [selectedId, setSelectedId] = useState<string | null>(null)
  const [isLoggingOut, setIsLoggingOut] = useState(false)
  const [searchQuery, setSearchQuery] = useState('')

  // Defer cookie parsing to a client effect so SSR and the first client
  // render produce the SAME HTML (the loading card). Without this, the
  // server returns "no tenants → loading state" while the client immediately
  // reads the cookie and renders the "select a team" state, causing a
  // hydration mismatch at the <CardContent> / <CardHeader> level.
  const [pendingState, setPendingState] = useState<PendingState | null>(null)
  useEffect(() => {
    setPendingState(parsePendingTenants())
  }, [])

  // Memoise the empty fallback so the array reference is stable across
  // renders and the filteredTenants useMemo below doesn't recompute on
  // every parent render.
  const tenants = useMemo(() => pendingState?.tenants ?? [], [pendingState])
  const parseError = pendingState?.error ?? false

  // Check if user already has a tenant selected - redirect to dashboard
  useEffect(() => {
    const tenantCookie = getCookie(env.cookies.tenant)
    if (tenantCookie) {
      navigateAfterSessionChange('/')
    }
  }, [])

  // Handle redirect on error - use effect only for side effects (navigation).
  // The cookie is set with a 1-hour TTL on login, so this normally only fires
  // if the user has been idle on this page for >1 hour. Message is intentional:
  // "session" is misleading because refresh_token is probably still valid —
  // we just lost the cached tenant list. The /login page handles this case
  // gracefully by rendering the login form (NOT redirecting to onboarding).
  useEffect(() => {
    if (parseError) {
      toast.error(listExpiredRef.current)
      router.push('/login')
    }
  }, [parseError, router])

  // Handle tenant selection
  function handleSelectTenant(tenantId: string) {
    setSelectedId(tenantId)
    startTransition(async () => {
      const result = await selectTenantAction(tenantId)

      if (result.success) {
        // Brief delay to ensure Set-Cookie headers are fully processed by browser
        // before hard redirect. Without this, dashboard bootstrap may race with
        // cookie initialization and flash a 401 error before auto-recovering.
        await new Promise((resolve) => setTimeout(resolve, 100))
        navigateAfterSessionChange('/', {
          flash: {
            kind: 'success',
            title: t('auth.selectTenant.selected', 'Organization selected'),
          },
        })
      } else {
        setSelectedId(null)
        toast.error(
          getErrorMessage(
            result.error,
            t('auth.selectTenant.selectFailed', 'Failed to select organization')
          )
        )
      }
    })
  }

  // Handle cancel/logout
  async function handleCancel() {
    setIsLoggingOut(true)
    // Use server action to properly clear all httpOnly cookies
    try {
      await localLogoutAction('/login')
    } catch (error) {
      // localLogoutAction uses redirect() which throws, this is expected
      devLog.log('[SelectTenant] Logout redirect:', error)
    }
  }

  // Filter tenants by search query (case-insensitive on name and slug).
  // Memoised so the filter only re-runs when query or list changes.
  const filteredTenants = useMemo(() => {
    if (!searchQuery.trim()) return tenants
    const q = searchQuery.trim().toLowerCase()
    return tenants.filter(
      (t) => t.name.toLowerCase().includes(q) || t.slug.toLowerCase().includes(q)
    )
  }, [tenants, searchQuery])

  const showSearch = tenants.length > SEARCH_THRESHOLD

  // Show loading if parsing or redirecting due to error
  if (parseError || tenants.length === 0) {
    return (
      <EntryCard>
        <div className="flex items-center justify-center py-12">
          <Loader2 className="text-muted-foreground size-8 animate-spin" />
        </div>
      </EntryCard>
    )
  }

  const rowClass =
    'flex w-full min-w-0 items-center gap-2.5 rounded-md border px-2.5 py-2 text-start transition-colors disabled:cursor-not-allowed disabled:opacity-50'

  return (
    <EntryCard>
      <EntryHeader
        title={t('auth.selectTenant.title', 'Select an organization')}
        description={
          tenants.length === 1
            ? t(
                'auth.selectTenant.one',
                'You have access to one organization. Select it to continue.'
              )
            : t(
                'auth.selectTenant.many',
                'You have access to {count} organizations. Pick one to continue.',
                {
                  count: tenants.length,
                }
              )
        }
      />

      {/* Search: only above SEARCH_THRESHOLD teams; below that scanning is
          faster than typing. */}
      {showSearch && (
        <div className="relative">
          <Search className="text-muted-foreground pointer-events-none absolute start-3 top-1/2 size-4 -translate-y-1/2" />
          <Input
            type="search"
            placeholder={t('auth.selectTenant.search', 'Search organizations…')}
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            disabled={isPending || isLoggingOut}
            className="ps-9"
            aria-label={t('auth.selectTenant.searchLabel', 'Search organizations')}
            autoFocus
          />
        </div>
      )}

      {/* The list is the only part that scrolls, so a person with many teams
          still sees the create and sign-out actions under it. */}
      <ul
        aria-label={t('auth.selectTenant.listLabel', 'Organizations')}
        className="flex max-h-[min(50svh,26rem)] flex-col gap-2 overflow-y-auto"
      >
        {filteredTenants.map((tenant) => {
          const isSelected = selectedId === tenant.id

          return (
            <li key={tenant.id}>
              <button
                type="button"
                onClick={() => handleSelectTenant(tenant.id)}
                disabled={isPending}
                className={cn(
                  rowClass,
                  isSelected ? 'border-border-strong bg-accent' : 'border-border hover:bg-accent'
                )}
              >
                <span className="bg-surface-sunken flex size-8 shrink-0 items-center justify-center rounded-sm">
                  {isSelected && isPending ? (
                    <Loader2 aria-hidden className="size-4 animate-spin" />
                  ) : (
                    <Building2 aria-hidden className="size-4" />
                  )}
                </span>
                <span className="flex min-w-0 flex-1 flex-col">
                  <span className="text-body truncate font-medium">{tenant.name}</span>
                  <span className="text-cap text-muted-foreground truncate">
                    {t(`org.role.${tenant.role}`, tenant.role)}
                  </span>
                </span>
                {isSelected && !isPending && <Check aria-hidden className="size-4 shrink-0" />}
              </button>
            </li>
          )
        })}

        {filteredTenants.length === 0 && (
          <li className="flex flex-col items-center gap-1 py-6 text-center">
            <p className="text-dense text-muted-foreground">
              {t('auth.selectTenant.noMatch', 'No organizations match “{query}”', {
                query: searchQuery,
              })}
            </p>
            <Button variant="link" onClick={() => setSearchQuery('')}>
              {t('auth.selectTenant.clearSearch', 'Clear search')}
            </Button>
          </li>
        )}
      </ul>

      {/* Hidden when only the platform administrator creates organizations
          (the admin_only sign-up policy). */}
      {canCreateTeam && (
        <button
          type="button"
          onClick={() => router.push('/onboarding/create-team')}
          disabled={isPending || isLoggingOut}
          className={cn(rowClass, 'border-border hover:bg-accent border-dashed')}
        >
          <span className="bg-surface-sunken flex size-8 shrink-0 items-center justify-center rounded-sm">
            <Plus aria-hidden className="size-4" />
          </span>
          <span className="flex min-w-0 flex-1 flex-col">
            <span className="text-body font-medium">
              {t('auth.selectTenant.createTitle', 'Create a new organization')}
            </span>
            <span className="text-cap text-muted-foreground truncate">
              {t(
                'auth.selectTenant.createBody',
                'Start a fresh workspace for a different organization'
              )}
            </span>
          </span>
        </button>
      )}

      <EntryActions>
        <Button variant="ghost" onClick={handleCancel} disabled={isPending || isLoggingOut}>
          {isLoggingOut ? (
            <Loader2 aria-hidden className="size-4 animate-spin" />
          ) : (
            <LogOut aria-hidden className="size-4" />
          )}
          <span className="truncate">
            {isLoggingOut
              ? t('auth.selectTenant.signingOut', 'Signing out...')
              : t('auth.selectTenant.signOut', 'Sign out and use a different account')}
          </span>
        </Button>
      </EntryActions>
    </EntryCard>
  )
}

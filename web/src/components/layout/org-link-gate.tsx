'use client'

/**
 * Opens an organization-qualified link (`?org=<id or slug>`, src/lib/org-link.ts)
 * in the organization it names.
 *
 * A person who belongs to several organizations can open a link from an
 * e-mail or a notification while another organization is selected. When the
 * person is a member of the named organization, this switches to it through
 * the organization switcher's own flow (`switchTeam`: the API checks the
 * membership and issues the new session) and only then renders the page, so
 * the page never asks the wrong organization for the record.
 *
 * Only the person's own membership list is consulted. A link to an
 * organization the person does not belong to, or to an unknown one, renders
 * the page in the selected organization, which answers with the same
 * "not found" as before: nothing tells the two cases apart.
 *
 * The parameter is removed from the address once handled, so a later manual
 * switch on the same page is not undone.
 */
import * as React from 'react'
import { usePathname, useRouter, useSearchParams } from 'next/navigation'
import { Loader2 } from 'lucide-react'
import { toast } from 'sonner'
import { useTenant } from '@/context/tenant-provider'
import { useTranslation } from '@/context/i18n-provider'
import { devLog } from '@/lib/logger'
import { ORG_LINK_PARAM, withoutOrgParam } from '@/lib/org-link'

export function OrgLinkGate({ children }: { children: React.ReactNode }) {
  const searchParams = useSearchParams()
  const pathname = usePathname()
  const router = useRouter()
  const { t } = useTranslation()
  const { currentTenant, tenants, error, switchTeam, loadTenants } = useTenant()

  const requested = searchParams?.get(ORG_LINK_PARAM)?.trim() || null
  // The org value already handled; the page renders once the current
  // request is handled (the address may still carry it for a moment).
  const [handled, setHandled] = React.useState<string | null>(null)
  const startedRef = React.useRef<string | null>(null)

  const pending = requested !== null && handled !== requested

  React.useEffect(() => {
    if (!requested || handled === requested || startedRef.current === requested) return

    const finish = () => {
      setHandled(requested)
      const search = withoutOrgParam(searchParams?.toString() ?? '')
      const hash = typeof window === 'undefined' ? '' : window.location.hash
      router.replace(`${pathname ?? ''}${search}${hash}`, { scroll: false })
    }

    // Already in that organization.
    if (currentTenant && (currentTenant.id === requested || currentTenant.slug === requested)) {
      startedRef.current = requested
      finish()
      return
    }

    // The membership list loads on demand; wait for it.
    if (tenants.length === 0 && !error) {
      loadTenants()
      return
    }

    startedRef.current = requested
    const target = tenants.find((m) => m.id === requested || m.slug === requested)
    if (!target) {
      // Not a member, or no such organization: the page answers as it
      // would without the parameter.
      finish()
      return
    }
    switchTeam(target.id)
      .then(() => {
        toast.success(t('org.switched', 'Switched to {name}', { name: target.name }))
      })
      .catch((err: unknown) => {
        devLog.error('[OrgLinkGate] organization switch failed:', err)
      })
      .finally(finish)
  }, [
    requested,
    handled,
    currentTenant,
    tenants,
    error,
    loadTenants,
    switchTeam,
    searchParams,
    pathname,
    router,
    t,
  ])

  if (pending) {
    return (
      <div
        role="status"
        aria-live="polite"
        className="flex flex-1 items-center justify-center py-24"
        data-testid="org-link-gate"
      >
        <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" aria-hidden="true" />
        <span className="sr-only">{t('common.loading', 'Loading…')}</span>
      </div>
    )
  }
  return <>{children}</>
}

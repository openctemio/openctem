'use client'

/**
 * The dashboard's organization epoch (rule: web/docs/organization-switch.md).
 *
 * Everything below this boundary belongs to one organization. When the
 * organization changes (TenantProvider.switchTeam, or another tab's switch),
 * the boundary:
 *
 * 1. stops rendering the old tree at once, so no page of the previous
 *    organization stays mounted, fires a read with its ids or filters, or
 *    keeps its rows, selection, open panel or page number in memory;
 * 2. replaces the address with the section's list root without any query
 *    (src/lib/org-switch-landing.ts), unless the switch keeps the address
 *    (a link that names the new organization) or the address carries
 *    nothing of an organization;
 * 3. then mounts the whole tree again under a key of the new epoch, with a
 *    fresh SWR cache: no cached answer, dedupe entry or in-flight read of
 *    the previous organization can reach it, by construction rather than
 *    by every page remembering to reset.
 *
 * The back button: an address last shown in another organization (the old
 * organization's page 5, its finding) is replaced the same way when the
 * browser returns to it, in this document or in one the back button loads.
 */

import * as React from 'react'
import { usePathname, useRouter, useSearchParams } from 'next/navigation'
import { SWRConfig, useSWRConfig } from 'swr'
import { Loader2 } from 'lucide-react'
import { useTenant } from '@/context/tenant-provider'
import { useTranslation } from '@/context/i18n-provider'
import { isOrgNeutralAddress, orgSwitchLanding } from '@/lib/org-switch-landing'
import { bindEpochMutate } from '@/lib/swr-mutate'
import {
  getActiveTenantId,
  loadedByHistory,
  noteRendered,
  readTenantCookieId,
  renderedUnderOtherOrg,
} from '@/lib/tenant-epoch'

/** The landing the boundary sent the tab to after a switch (read by RouteGuard). */
let switchLanding: string | null = null

/**
 * True once for the page the boundary landed on after a switch. RouteGuard
 * sends the person to the dashboard instead of an access notice when the new
 * organization does not grant that section.
 */
export function takeSwitchLanding(pathname: string): boolean {
  if (switchLanding === null || switchLanding !== pathname) return false
  switchLanding = null
  return true
}

/** Points module-level `mutate` (src/lib/swr-mutate.ts) at this epoch's cache. */
function BindEpochMutate() {
  const { mutate } = useSWRConfig()
  React.useLayoutEffect(() => bindEpochMutate(mutate), [mutate])
  return null
}

const freshCache = () => new Map()

export function TenantEpochBoundary({ children }: { children: React.ReactNode }) {
  const { epoch, epochKeepsLocation, currentTenant } = useTenant()
  const { t } = useTranslation()
  const router = useRouter()
  const pathname = usePathname() ?? '/'
  const search = useSearchParams()?.toString() ?? ''
  const url = search ? `${pathname}?${search}` : pathname

  // The epoch whose address has been settled (landed, or kept).
  const [settledEpoch, setSettledEpoch] = React.useState(epoch)
  // The address the browser's back or forward button went to.
  const [poppedUrl, setPoppedUrl] = React.useState<string | null>(null)
  // The address of a document the back button loaded, until it is checked.
  const historyLoad = React.useRef<string | null>(null)
  React.useEffect(() => {
    const here = () => window.location.pathname + window.location.search
    // A document the back button loaded counts as a back navigation too.
    if (loadedByHistory()) {
      historyLoad.current = here()
      setPoppedUrl(here())
    }
    const onPop = () => setPoppedUrl(here())
    window.addEventListener('popstate', onPop)
    return () => window.removeEventListener('popstate', onPop)
  }, [])
  const shownOrgId = currentTenant?.id ?? getActiveTenantId() ?? readTenantCookieId()

  // The address being replaced (until the router reports the landing).
  const [leaving, setLeaving] = React.useState<string | null>(null)

  const neutral = isOrgNeutralAddress(pathname, search)
  const mustLeave =
    url === leaving ||
    (!neutral &&
      (settledEpoch !== epoch
        ? !epochKeepsLocation
        : poppedUrl === url && !!shownOrgId && renderedUnderOtherOrg(url, shownOrgId)))

  React.useEffect(() => {
    if (mustLeave) {
      if (leaving === url) return
      const landing = orgSwitchLanding(pathname)
      switchLanding = landing
      historyLoad.current = null
      setLeaving(url)
      setPoppedUrl(null)
      router.replace(landing, { scroll: false })
      return
    }
    if (leaving !== null) setLeaving(null)
    // Not yet checked: the render that sees the popped address decides.
    if (historyLoad.current === url && poppedUrl !== url) return
    historyLoad.current = null
    if (poppedUrl === url) setPoppedUrl(null)
    setSettledEpoch(epoch)
    if (shownOrgId) noteRendered(url, shownOrgId)
  }, [mustLeave, leaving, poppedUrl, pathname, url, epoch, shownOrgId, router])

  if (mustLeave) {
    return (
      <div
        role="status"
        aria-live="polite"
        className="flex h-svh w-full items-center justify-center"
        data-testid="org-switch-pending"
      >
        <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" aria-hidden="true" />
        <span className="sr-only">{t('org.switching', 'Switching organization…')}</span>
      </div>
    )
  }

  return (
    <SWRConfig key={epoch} value={{ provider: freshCache }}>
      <BindEpochMutate />
      {children}
    </SWRConfig>
  )
}

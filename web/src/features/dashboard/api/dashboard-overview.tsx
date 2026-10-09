'use client'

/**
 * The dashboard's reads in one request (research/81).
 *
 * GET /api/v1/dashboard/overview answers each read the CTEM dashboard makes
 * (risk trend, executive summary, stats, coverage, chains, ...) keyed by the
 * exact URL of its endpoint, each through that endpoint's own permission,
 * module and data-scope gates. The provider below hands the answers to the
 * dashboard's hooks as SWR fallback data under those same URLs, so the hooks
 * keep their transforms and keys and send nothing on mount. A part the caller
 * may not read (or an older API without the route) is simply not handed
 * over: its hook then asks its own endpoint, as before.
 */
import type { ReactNode } from 'react'
import useSWR, { SWRConfig } from 'swr'

import { get } from '@/lib/api/client'
import { useTenant } from '@/context/tenant-provider'
import { useBootstrapPending } from '@/context/bootstrap-provider'
import { Permission, usePermissions } from '@/lib/permissions'

export const DASHBOARD_OVERVIEW_URL = '/api/v1/dashboard/overview'

interface DashboardOverviewPart {
  status: number
  body?: unknown
}

export interface DashboardOverview {
  parts: Record<string, DashboardOverviewPart>
}

/** The successful parts, by URL: SWR fallback data. */
export function overviewFallback(overview: DashboardOverview | undefined): Record<string, unknown> {
  const out: Record<string, unknown> = {}
  for (const [url, part] of Object.entries(overview?.parts ?? {})) {
    if (part.status === 200 && part.body !== undefined) out[url] = part.body
  }
  return out
}

/**
 * Loads the overview, then renders the dashboard with its answers as the
 * fallback data of its hooks. Until it settles, `loading` is shown, so no hook
 * sends its own request in parallel.
 */
export function DashboardOverviewProvider({
  children,
  loading,
}: {
  children: ReactNode
  loading: ReactNode
}) {
  const { currentTenant } = useTenant()
  const { can } = usePermissions()
  // Until the session is known (tenant and permissions come with the
  // bootstrap), nothing renders: a widget mounted now would ask its own
  // endpoint in parallel with the overview.
  const sessionPending = useBootstrapPending() || !currentTenant
  const key = !sessionPending && can(Permission.DashboardRead) ? DASHBOARD_OVERVIEW_URL : null
  const { data, error, isLoading } = useSWR<DashboardOverview>(key, (url: string) =>
    get<DashboardOverview>(url)
  )
  if (sessionPending || (key && isLoading && !data && !error)) return <>{loading}</>
  return (
    <SWRConfig
      value={{
        fallback: overviewFallback(data),
        // A hook whose answer came in the overview does not ask again on mount.
        revalidateIfStale: false,
      }}
    >
      {children}
    </SWRConfig>
  )
}

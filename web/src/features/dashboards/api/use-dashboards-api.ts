/**
 * Customizable dashboards API hooks (RFC-021 Phase-1b).
 *
 * SWR reads + plain mutation helpers over the self-scoped `/me/dashboards`
 * endpoints. Tenant + user are derived from the token server-side.
 */

'use client'

import { useEffect, useState } from 'react'
import useSWR, { useSWRConfig, type SWRConfiguration } from 'swr'
import { get, post, put, del } from '@/lib/api/client'
import { useTenant } from '@/context/tenant-provider'
import type {
  Dashboard,
  DashboardHomeResponse,
  DashboardKind,
  DashboardListResponse,
  DashboardRefreshSchedule,
  FlowPanelResult,
  CreateDashboardInput,
  UpdateDashboardInput,
} from './dashboards.types'

export const DASHBOARDS_KEY = '/api/v1/me/dashboards'

const fetchList = (url: string) => get<DashboardListResponse>(url)
const fetchOne = (url: string) => get<Dashboard>(url)

/** List the current user's saved dashboards. `enabled: false` makes no request. */
export function useMyDashboards(config?: SWRConfiguration & { enabled?: boolean }) {
  const { currentTenant } = useTenant()
  const { enabled = true, ...swr } = config ?? {}
  const key = currentTenant && enabled ? DASHBOARDS_KEY : null
  return useSWR<DashboardListResponse>(key, fetchList, swr)
}

export const DASHBOARD_HOME_PATH = '/api/v1/me/dashboards/home'

export type DashboardHomeState =
  | { status: 'loading' }
  /** The home read failed: the page's own list reads take over. */
  | { status: 'failed' }
  | {
      status: 'ready'
      /** The server says this person can read organization dashboards. */
      hasOrg: boolean
      /** The key the response seeded with the landing dashboard's figures. */
      dataKey: string | null
    }

/**
 * Opens the dashboard home with one request: the server returns both lists,
 * the landing dashboard (it applies the landing rule to `choice`, the
 * viewer's remembered dashboard) and that dashboard's figures. The response
 * seeds the cache keys the page's regular reads use, so they do not fetch
 * again; if this read fails they simply fetch on their own.
 */
export function useDashboardHome(choice: string | null): DashboardHomeState {
  const { currentTenant } = useTenant()
  const { mutate } = useSWRConfig()
  const tenantId = currentTenant?.id
  const [state, setState] = useState<DashboardHomeState>({ status: 'loading' })
  useEffect(() => {
    if (!tenantId) return
    let cancelled = false
    const path = choice
      ? `${DASHBOARD_HOME_PATH}?choice=${encodeURIComponent(choice)}`
      : DASHBOARD_HOME_PATH
    get<DashboardHomeResponse>(path)
      .then(async (home) => {
        const seeds: Promise<unknown>[] = [
          mutate(DASHBOARDS_KEY, { data: home.personal }, { revalidate: false }),
        ]
        if (home.organization) {
          seeds.push(mutate(ORG_DASHBOARDS_KEY, { data: home.organization }, { revalidate: false }))
        }
        let dataKey: string | null = null
        if (home.landing && home.data) {
          const base = home.landing.kind === 'organization' ? ORG_DASHBOARDS_KEY : DASHBOARDS_KEY
          dataKey = `${base}/${home.landing.id}/data`
          seeds.push(mutate(dataKey, home.data, { revalidate: false }))
        }
        await Promise.all(seeds)
        if (!cancelled) setState({ status: 'ready', hasOrg: !!home.organization, dataKey })
      })
      .catch(() => {
        if (!cancelled) setState({ status: 'failed' })
      })
    return () => {
      cancelled = true
    }
    // One read per visit: the remembered choice is what it was on arrival.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [tenantId, mutate])
  return state
}

/** Fetch one saved dashboard by id. */
export function useMyDashboard(id: string | null, config?: SWRConfiguration) {
  const { currentTenant } = useTenant()
  const key = currentTenant && id ? `${DASHBOARDS_KEY}/${id}` : null
  return useSWR<Dashboard>(key, fetchOne, config)
}

/** Revalidate the dashboards list (call after any mutation). */
export function useRevalidateDashboards() {
  const { mutate } = useSWRConfig()
  return () => mutate(DASHBOARDS_KEY)
}

export function createDashboard(input: CreateDashboardInput) {
  return post<Dashboard>(DASHBOARDS_KEY, input)
}

export function updateDashboard(id: string, input: UpdateDashboardInput) {
  return put<Dashboard>(`${DASHBOARDS_KEY}/${id}`, input)
}

export function deleteDashboard(id: string) {
  return del(`${DASHBOARDS_KEY}/${id}`)
}

export function setDefaultDashboard(id: string) {
  return post(`${DASHBOARDS_KEY}/${id}/default`, {})
}

export const ORG_DASHBOARDS_KEY = '/api/v1/organization/dashboards'

/**
 * The organization dashboards the caller may read (dashboards:org:view and
 * each dashboard's audience, decided by the server). Pass `enabled: false`
 * without the permission so no request is made.
 */
export function useOrgDashboards(enabled: boolean, config?: SWRConfiguration) {
  const { currentTenant } = useTenant()
  const key = currentTenant && enabled ? ORG_DASHBOARDS_KEY : null
  return useSWR<DashboardListResponse>(key, fetchList, config)
}

/** Fetch one organization dashboard by id (dashboards:org:view, inside its audience). */
export function useOrgDashboard(id: string | null, config?: SWRConfiguration) {
  const { currentTenant } = useTenant()
  const key = currentTenant && id ? `${ORG_DASHBOARDS_KEY}/${id}` : null
  return useSWR<Dashboard>(key, fetchOne, config)
}

/** Revalidate both dashboard lists (call after any mutation). */
export function useRevalidateAllDashboards() {
  const { mutate } = useSWRConfig()
  return () => Promise.all([mutate(DASHBOARDS_KEY), mutate(ORG_DASHBOARDS_KEY)])
}

function basePath(kind: DashboardKind) {
  return kind === 'organization' ? ORG_DASHBOARDS_KEY : DASHBOARDS_KEY
}

/**
 * Sets a dashboard's refresh schedule. Empty = the organization default.
 * Personal: the owner; organization: dashboards:org:manage.
 */
export function setDashboardSchedule(
  kind: DashboardKind,
  id: string,
  schedule: DashboardRefreshSchedule,
  dailyMinute?: number
) {
  return put<Dashboard>(`${basePath(kind)}/${id}/schedule`, {
    refresh_schedule: schedule,
    refresh_daily_minute: schedule === 'daily' ? (dailyMinute ?? 0) : null,
  })
}

/** Makes an organization dashboard the organization's default (dashboards:org:manage). */
export function setOrgDefaultDashboard(id: string) {
  return post(`${ORG_DASHBOARDS_KEY}/${id}/default`, {})
}

/** "Duplicate to mine": a personal copy of an organization dashboard's layout. */
export function duplicateOrgDashboard(id: string) {
  return post<Dashboard>(DASHBOARDS_KEY, {
    from_organization_dashboard_id: id,
    name: '',
    layout: [],
  })
}

/** Replaces an organization dashboard's name, columns and layout (dashboards:org:manage). */
export function updateOrgDashboard(id: string, input: UpdateDashboardInput) {
  return put<Dashboard>(`${ORG_DASHBOARDS_KEY}/${id}`, input)
}

/**
 * Offers the exposure flow panel once on a dashboard that has never been
 * offered it (personal: the owner; organization: dashboards:org:manage).
 * Idempotent on the server: a second call returns `added: false`.
 */
export function addFlowPanel(id: string, kind: DashboardKind) {
  return post<FlowPanelResult>(`${basePath(kind)}/${id}/flow-panels`, {})
}

/** Undo of the add: removes that widget when it is the flow panel. It is never added again. */
export function undoFlowPanel(id: string, kind: DashboardKind, widgetId: string) {
  return del<Dashboard>(`${basePath(kind)}/${id}/flow-panels/${encodeURIComponent(widgetId)}`)
}

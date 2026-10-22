/**
 * Customizable dashboards API hooks (RFC-021 Phase-1b).
 *
 * SWR reads + plain mutation helpers over the self-scoped `/me/dashboards`
 * endpoints. Tenant + user are derived from the token server-side.
 */

'use client'

import useSWR, { useSWRConfig, type SWRConfiguration } from 'swr'
import { get, post, put, del } from '@/lib/api/client'
import { useTenant } from '@/context/tenant-provider'
import type {
  Dashboard,
  DashboardKind,
  DashboardListResponse,
  DashboardRefreshSchedule,
  CreateDashboardInput,
  UpdateDashboardInput,
} from './dashboards.types'

export const DASHBOARDS_KEY = '/api/v1/me/dashboards'

const fetchList = (url: string) => get<DashboardListResponse>(url)
const fetchOne = (url: string) => get<Dashboard>(url)

/** List the current user's saved dashboards. */
export function useMyDashboards(config?: SWRConfiguration) {
  const { currentTenant } = useTenant()
  const key = currentTenant ? DASHBOARDS_KEY : null
  return useSWR<DashboardListResponse>(key, fetchList, config)
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

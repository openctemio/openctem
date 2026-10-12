/**
 * Account Activity API Hook
 *
 * Fetches the current user's own activity (audit) events from the dedicated
 * per-user audit endpoint, which is scoped to the requesting user.
 */

import useSWR from 'swr'
import { get } from '@/lib/api/client'
import { auditLogEndpoints } from '@/lib/api/endpoints'
import type { AuditLog, AuditLogListResponse } from '@/features/organization/types/audit.types'

/**
 * One server page of the current user's activity, newest first. The SWR key
 * is null until a userId is known, so we never fall back to an unscoped
 * (all-tenant) query.
 *
 * It used to load 100 events and page them in the browser, so anything older
 * than the 100th event could not be reached (23a B20).
 *
 * @param userId   current user id (from the auth store)
 * @param page     1-based page, as the API pages
 * @param perPage  events per page
 */
export function useAccountActivity(userId: string | undefined, page = 1, perPage = 10) {
  const key = userId
    ? `${auditLogEndpoints.userActivity(userId)}?page=${Math.max(1, page)}&per_page=${perPage}&sort_order=desc`
    : null

  const { data, error, isLoading, mutate } = useSWR<AuditLogListResponse>(
    key,
    (url: string) => get<AuditLogListResponse>(url),
    { revalidateOnFocus: false, dedupingInterval: 10000 }
  )

  const activities: AuditLog[] = data?.data ?? []
  const total = data?.total ?? 0

  return {
    activities,
    total,
    totalPages: data?.total_pages ?? Math.ceil(total / perPage),
    isLoading: !!userId && isLoading,
    isError: !!error,
    error,
    mutate,
  }
}

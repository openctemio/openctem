'use client'

import useSWR from 'swr'
import { adminFetcher } from './admin-client'
import type { AdminAuditEntry, Paged } from '../types'

/** Admin audit outcome filter: every row, only successes, only refusals/failures. */
export type AuditOutcome = '' | 'success' | 'failure'

export function useAdminAuditLogs(query: {
  page?: number
  action?: string
  adminEmail?: string
  outcome?: AuditOutcome
  /** Only rows about this resource (e.g. one organization). */
  resourceId?: string
  perPage?: number
  /** RFC 3339 bounds of created_at. */
  from?: string
  to?: string
}) {
  const q = new URLSearchParams({
    page: String(query.page ?? 1),
    per_page: String(query.perPage ?? 50),
  })
  if (query.action?.trim()) q.set('action', query.action.trim())
  if (query.adminEmail?.trim()) q.set('admin_email', query.adminEmail.trim())
  if (query.from) q.set('from', query.from)
  if (query.to) q.set('to', query.to)
  if (query.resourceId) q.set('resource_id', query.resourceId)
  if (query.outcome) q.set('success', query.outcome === 'success' ? 'true' : 'false')
  return useSWR<Paged<AdminAuditEntry>>(`/audit-logs?${q.toString()}`, adminFetcher, {
    keepPreviousData: true,
  })
}

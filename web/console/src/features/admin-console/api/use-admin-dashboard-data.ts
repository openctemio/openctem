'use client'

import useSWR from 'swr'
import { adminFetch, adminFetcher } from '@console/lib/admin-api/client'

/** GET /api/v1/admin/tenants/{id}/dashboard-data: an organization's dashboard fact status. */
export interface AdminDashboardDataStatus {
  rebuilt_at: string | null
  reconciled_at: string | null
  last_drift: number | null
  rebuild_requested_at: string | null
  running?: 'initial' | 'requested' | 'nightly'
  pending: boolean
  queue_depth: number
  next_rebuild_at: string | null
}

export function useDashboardDataStatus(tenantId: string | null) {
  return useSWR<AdminDashboardDataStatus>(
    tenantId ? `/tenants/${tenantId}/dashboard-data` : null,
    adminFetcher,
    { revalidateOnFocus: false }
  )
}

/** Asks for a rebuild (ops_admin+; once per hour per organization, 429 otherwise). */
export function rebuildDashboardData(tenantId: string) {
  return adminFetch<AdminDashboardDataStatus>(`/tenants/${tenantId}/dashboard-data/rebuild`, {
    method: 'POST',
  })
}

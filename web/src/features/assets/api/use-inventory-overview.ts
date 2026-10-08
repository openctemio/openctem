'use client'

import useSWR from 'swr'
import { fetcher } from '@/lib/api/client'
import { useTenant } from '@/context/tenant-provider'
import { Permission, usePermissions } from '@/lib/permissions'

/** One (lens, type, sub-type) of GET /api/v1/assets/overview. */
export interface InventoryOverviewRow {
  lens: string
  type: string
  sub_type: string
  /** Assets the default inventory lists (attribution confirmed, dependency, monitor only or none). */
  total: number
  unowned: number
  /** Risk score 70 or more. */
  high_risk: number
  /** First seen in the last 7 days. */
  new_7d: number
  /** Names in the attribution review queue (not part of total). */
  needs_review: number
}

/**
 * The inventory overview: the caller's assets counted per lens, type and
 * sub-type in one aggregate, within its tenant and data scope.
 */
export function useInventoryOverview() {
  const { currentTenant } = useTenant()
  const { can } = usePermissions()
  const key = currentTenant && can(Permission.AssetsRead) ? '/api/v1/assets/overview' : null
  const { data, error, isLoading, mutate } = useSWR<{ data: InventoryOverviewRow[] }>(
    key,
    fetcher<{ data: InventoryOverviewRow[] }>,
    { revalidateOnFocus: false }
  )
  return { rows: data?.data ?? [], error, isLoading, mutate }
}

'use client'

import useSWR from 'swr'
import { get } from '@/lib/api/client'
import type { EASMSummary } from '@/lib/api/generated'
import { usePermissions, Permission } from '@/lib/permissions'

/** GET /api/v1/easm/summary — the external attack surface in one call. */
export function useEASMSummary() {
  const { can } = usePermissions()
  const key = can(Permission.AssetsRead) ? '/api/v1/easm/summary' : null
  const { data, error, isLoading, mutate } = useSWR<EASMSummary>(key, get, {
    revalidateOnFocus: false,
  })
  return { summary: data, error, isLoading, mutate }
}

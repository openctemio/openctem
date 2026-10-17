'use client'

import useSWR from 'swr'
import { adminFetcher } from '@console/lib/admin-api/client'
import type { AdminSystem } from '../types'

/** The System page's data, refreshed every minute while open. */
export function useAdminSystem() {
  return useSWR<AdminSystem>('/system', adminFetcher, {
    refreshInterval: 60_000,
    keepPreviousData: true,
  })
}

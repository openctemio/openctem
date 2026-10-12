'use client'

import useSWR from 'swr'
import { adminFetcher } from './admin-client'
import type { AdminOverview } from '../types'

/** The console's attention counts, refreshed every minute while open. */
export function useAdminOverview() {
  return useSWR<AdminOverview>('/overview', adminFetcher, {
    refreshInterval: 60_000,
    keepPreviousData: true,
  })
}

'use client'

import useSWR from 'swr'
import { adminFetcher } from './admin-client'
import type { AdminOperations } from '../types'

/** The installation's health, refreshed every 30 seconds while open. */
export function useAdminOperations() {
  return useSWR<AdminOperations>('/operations', adminFetcher, {
    refreshInterval: 30_000,
    keepPreviousData: true,
  })
}

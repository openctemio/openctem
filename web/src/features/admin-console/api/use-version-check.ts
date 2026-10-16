'use client'

import useSWR from 'swr'
import { adminFetch, adminFetcher } from './admin-client'
import type { VersionCheckStatus } from '../types'

const KEY = '/version-check/'

/**
 * The version check (System > Software updates and the console banner). Any
 * administrator reads it; it changes at most daily, so it refreshes slowly.
 */
export function useVersionCheck() {
  return useSWR<VersionCheckStatus>(KEY, adminFetcher, {
    refreshInterval: 15 * 60_000,
    revalidateOnFocus: false,
    shouldRetryOnError: false,
  })
}

/**
 * Imports the signed release feed file (super admin, step-up). The file is
 * sent as read; the API verifies its signatures, sequence and expiry.
 */
export function importReleaseFeed(file: unknown) {
  return adminFetch<VersionCheckStatus>(`${KEY}import`, { method: 'POST', body: file })
}

'use client'

import useSWR from 'swr'
import { adminFetch, adminFetcher } from '@console/lib/admin-api/client'
import type { VersionCheckStatus } from '../types'

const KEY = '/version-check/'

/**
 * The version check (System > Software updates and the console banner). Any
 * administrator reads it; it changes at most daily, so it is read when a
 * console page mounts and never polled.
 */
export function useVersionCheck() {
  return useSWR<VersionCheckStatus>(KEY, adminFetcher, {
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

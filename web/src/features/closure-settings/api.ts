'use client'

import useSWR, { type SWRConfiguration } from 'swr'
import { del, get, put } from '@/lib/api/client'
import { usePermissions, Permission } from '@/lib/permissions'
import type { ClosureSettings } from './types'

export const CLOSURE_SETTINGS_ENDPOINT = '/api/v1/organization/settings/closure'

const quietConfig: SWRConfiguration = {
  revalidateOnFocus: false,
  shouldRetryOnError: (error) => !(error?.statusCode >= 400 && error?.statusCode < 500),
  errorRetryCount: 2,
}

/** The organization's closing mode (owners and admins). */
export function useClosureSettings(config?: SWRConfiguration) {
  const { can } = usePermissions()
  const key = can(Permission.TeamUpdate) ? CLOSURE_SETTINGS_ENDPOINT : null
  return useSWR<ClosureSettings>(key, (url: string) => get<ClosureSettings>(url), {
    ...quietConfig,
    ...config,
  })
}

/**
 * Chooses the mode. A loosening asks for a recent sign-in (the client
 * retries after the step-up dialog) and waits 24 hours; etag guards against
 * a change someone else made since the page loaded.
 */
export async function updateClosureSettings(
  payload: Pick<ClosureSettings, 'mode' | 'critical_auto_close'>,
  etag?: string
): Promise<ClosureSettings> {
  return put<ClosureSettings>(CLOSURE_SETTINGS_ENDPOINT, payload, {
    headers: etag ? { 'If-Match': etag } : undefined,
  })
}

/** Cancels a waiting loosening; the mode in force stays. */
export async function cancelPendingClosureSettings(): Promise<ClosureSettings> {
  return del<ClosureSettings>(`${CLOSURE_SETTINGS_ENDPOINT}/pending`)
}

'use client'

import useSWR from 'swr'
import { adminFetch, adminFetcher } from './admin-client'
import type { AdminConsoleSession } from '../types'

/** Every administrator's open console session (super admin). */
export function useAdminSessions(enabled: boolean) {
  return useSWR<{ data: AdminConsoleSession[] }>(
    enabled ? '/console-sessions' : null,
    adminFetcher,
    {
      refreshInterval: 30_000,
    }
  )
}

/** Ends another administrator's session (reason + fresh authenticator code). */
export function endAdminSession(id: string, proof: { reason: string; totp_code?: string }) {
  return adminFetch<void>(`/console-sessions/${encodeURIComponent(id)}`, {
    method: 'DELETE',
    body: proof,
  })
}

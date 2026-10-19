'use client'

/**
 * The organization's AI triage consent (API: GET/PUT
 * /api/v1/tenants/{tenant}/settings/ai, owners and administrators; turning it
 * on needs a recent sign-in and is audited). Nothing is sent to an AI
 * provider until it is on.
 */
import useSWR from 'swr'

import { get, put } from '@/lib/api/client'

export interface AISettings {
  enabled: boolean
  /** When an administrator turned it on. */
  enabled_at?: string
  /** Who turned it on: a user id, or "upgrade" (used before consent existed). */
  enabled_by?: string
}

export const aiSettingsUrl = (tenantId: string) => `/api/v1/tenants/${tenantId}/settings/ai`

export function useAISettings(tenantId: string | undefined, enabled: boolean) {
  return useSWR<AISettings>(enabled && tenantId ? aiSettingsUrl(tenantId) : null, (url: string) =>
    get<AISettings>(url)
  )
}

export async function updateAISettings(tenantId: string, on: boolean): Promise<AISettings> {
  return put<AISettings>(aiSettingsUrl(tenantId), { enabled: on })
}

'use client'

/**
 * The organization's AI triage consent (API: GET/PUT
 * /api/v1/organization/settings/ai, owners and administrators; turning it
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

export const AI_SETTINGS_URL = '/api/v1/organization/settings/ai'

export function useAISettings(enabled: boolean) {
  return useSWR<AISettings>(enabled ? AI_SETTINGS_URL : null, (url: string) => get<AISettings>(url))
}

export async function updateAISettings(on: boolean): Promise<AISettings> {
  return put<AISettings>(AI_SETTINGS_URL, { enabled: on })
}

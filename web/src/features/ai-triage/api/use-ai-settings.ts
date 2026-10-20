'use client'

/**
 * The organization's AI settings (API: GET/PUT
 * /api/v1/organization/settings/ai and POST .../test, owners and
 * administrators; a change needs a recent sign-in and is audited). Nothing is
 * sent to an AI provider until AI triage is on. The provider key is
 * write-only: the API returns only whether it is set, its last four
 * characters and when and by whom it was set.
 */
import useSWR from 'swr'

import { get, post, put } from '@/lib/api/client'

export type AISource = 'platform' | 'own' | 'off'
export type AIProviderKind = 'claude' | 'openai' | 'gemini' | 'openai_compatible'

export interface AIKeyInfo {
  set: boolean
  last4?: string
  updated_at?: string
  /** The user who set it. */
  updated_by?: string
}

export interface AISettings {
  enabled: boolean
  /** When an administrator turned it on. */
  enabled_at?: string
  /** Who turned it on: a user id, or "upgrade" (used before consent existed). */
  enabled_by?: string
  source: AISource
  provider: AIProviderKind | ''
  base_url: string
  model: string
  key: AIKeyInfo
  /** The platform policy: organizations may use their own provider. */
  own_provider_allowed: boolean
  providers: AIProviderKind[]
  updated_at?: string
  updated_by?: string
}

/** A partial change: omitted fields keep their value. api_key: omit to keep, "" to remove. */
export interface AISettingsPatch {
  enabled?: boolean
  source?: AISource
  provider?: AIProviderKind | ''
  base_url?: string
  model?: string
  api_key?: string
}

export type AITestCode =
  | 'ok'
  | 'invalid_url'
  | 'blocked_address'
  | 'key_required'
  | 'not_configured'
  | 'auth_failed'
  | 'rate_limited'
  | 'timeout'
  | 'unreachable'
  | 'provider_error'

export interface AITestResult {
  ok: boolean
  code: AITestCode
}

export const AI_SETTINGS_URL = '/api/v1/organization/settings/ai'

export function useAISettings(enabled: boolean) {
  return useSWR<AISettings>(enabled ? AI_SETTINGS_URL : null, (url: string) => get<AISettings>(url))
}

export async function updateAISettings(patch: AISettingsPatch): Promise<AISettings> {
  return put<AISettings>(AI_SETTINGS_URL, patch)
}

/** Calls the provider from the server with one tiny prompt (no finding data). */
export async function testAIProvider(values: AISettingsPatch): Promise<AITestResult> {
  return post<AITestResult>(`${AI_SETTINGS_URL}/test`, values)
}

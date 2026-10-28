'use client'

/**
 * AI analysts (API docs: architecture/ai-analysis.md): service accounts that
 * take part in triage like a person, each with accountable owners (people or
 * teams). Creating one, changing its owners or preset, resuming and deleting
 * it need a recent sign-in: the shared API client asks for it and retries.
 */
import useSWR from 'swr'

import { del, get, post, put } from '@/lib/api/client'

export type AIAnalystPreset = 'suggest' | 'triage'
export type AIAnalystStatus = 'active' | 'paused' | 'disabled'
export type AIAnalystPauseReason =
  'no_active_owner' | 'attestation_expired' | 'admin' | 'no_permissions'

export type AIOwnerKind = 'user' | 'team'

export interface AIOwnerInput {
  kind: AIOwnerKind
  id: string
}

export interface AIOwner extends AIOwnerInput {
  name: string
}

export interface AIAnalyst {
  id: string
  name: string
  description?: string
  preset: AIAnalystPreset
  status: AIAnalystStatus
  pause_reason?: AIAnalystPauseReason | ''
  data_class_ceiling?: string
  executor?: string
  runs_per_hour?: number
  actions_per_hour?: number
  tokens_month?: number
  attested_at?: string
  attest_due_at?: string
  owners: AIOwner[]
  created_at: string
}

export interface CreateAIAnalyst {
  name: string
  description?: string
  preset: AIAnalystPreset
  owners: AIOwnerInput[]
}

export const AI_ANALYSTS_URL = '/api/v1/ai/analysts'

const analystUrl = (id: string, tail = '') => `${AI_ANALYSTS_URL}/${encodeURIComponent(id)}${tail}`

export function useAIAnalysts(enabled = true) {
  return useSWR<AIAnalyst[]>(
    enabled ? AI_ANALYSTS_URL : null,
    async (url: string) => (await get<{ data: AIAnalyst[] }>(url)).data ?? [],
    { revalidateOnFocus: false, shouldRetryOnError: false }
  )
}

export const createAIAnalyst = (body: CreateAIAnalyst) => post<AIAnalyst>(AI_ANALYSTS_URL, body)

export const setAIAnalystOwners = (id: string, owners: AIOwnerInput[]) =>
  put<AIAnalyst>(analystUrl(id, '/owners'), { owners })

export const setAIAnalystPreset = (id: string, preset: AIAnalystPreset) =>
  put<AIAnalyst>(analystUrl(id, '/preset'), { preset })

export type AIAnalystAction = 'attest' | 'pause' | 'disable' | 'resume'

export const runAIAnalystAction = (id: string, action: AIAnalystAction) =>
  post<AIAnalyst>(analystUrl(id, `/${action}`), {})

export const deleteAIAnalyst = (id: string) => del(analystUrl(id))

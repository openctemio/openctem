'use client'

/**
 * AI agents (API docs: architecture/ai-analysis.md): service accounts that
 * take part in triage like a person, each with accountable owners (people or
 * teams). Creating one, changing its owners or preset, resuming and deleting
 * it need a recent sign-in: the shared API client asks for it and retries.
 */
import useSWR from 'swr'

import { del, get, post, put } from '@/lib/api/client'

export type AIAgentPreset = 'suggest' | 'triage'
export type AIAgentStatus = 'active' | 'paused' | 'disabled'
export type AIAgentPauseReason =
  'no_active_owner' | 'attestation_expired' | 'admin' | 'no_permissions'

export type AIOwnerKind = 'user' | 'team'

export interface AIOwnerInput {
  kind: AIOwnerKind
  id: string
}

export interface AIOwner extends AIOwnerInput {
  name: string
}

export interface AIAgent {
  id: string
  name: string
  description?: string
  /** What the AI agent is for (analyst, remediator, reporter, hunter, router). */
  role?: string
  preset: AIAgentPreset
  status: AIAgentStatus
  pause_reason?: AIAgentPauseReason | ''
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

export interface CreateAIAgent {
  name: string
  description?: string
  preset: AIAgentPreset
  owners: AIOwnerInput[]
}

export const AI_AGENTS_URL = '/api/v1/ai/agents'

const aiAgentUrl = (id: string, tail = '') => `${AI_AGENTS_URL}/${encodeURIComponent(id)}${tail}`

export function useAIAgents(enabled = true) {
  return useSWR<AIAgent[]>(
    enabled ? AI_AGENTS_URL : null,
    async (url: string) => (await get<{ data: AIAgent[] }>(url)).data ?? [],
    { revalidateOnFocus: false, shouldRetryOnError: false }
  )
}

export const createAIAgent = (body: CreateAIAgent) => post<AIAgent>(AI_AGENTS_URL, body)

export const setAIAgentOwners = (id: string, owners: AIOwnerInput[]) =>
  put<AIAgent>(aiAgentUrl(id, '/owners'), { owners })

export const setAIAgentPreset = (id: string, preset: AIAgentPreset) =>
  put<AIAgent>(aiAgentUrl(id, '/preset'), { preset })

export type AIAgentAction = 'attest' | 'pause' | 'disable' | 'resume'

/** The route verb of each action (the API's closed verb vocabulary: suspend and reactivate). */
const AI_AGENT_ACTION_VERB: Record<AIAgentAction, string> = {
  attest: 'attest',
  pause: 'suspend',
  disable: 'disable',
  resume: 'reactivate',
}

export const runAIAgentAction = (id: string, action: AIAgentAction) =>
  post<AIAgent>(aiAgentUrl(id, `/${AI_AGENT_ACTION_VERB[action]}`), {})

export const deleteAIAgent = (id: string) => del(aiAgentUrl(id))

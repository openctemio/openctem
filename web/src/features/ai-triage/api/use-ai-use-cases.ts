'use client'

/**
 * The organization's AI use cases (API: GET /api/v1/organization/settings/ai/use-cases,
 * settings:read; PUT .../use-cases/{use_case}, owners and administrators with
 * settings:write; docs: architecture/ai-use-cases.md). Turning auto-apply on,
 * raising the ceiling above internal, or lowering the minimum confidence while
 * auto-applying needs a recent sign-in (the shared API client asks) and tells
 * every owner and administrator; turning a use case down is immediate.
 */
import useSWR from 'swr'

import { get, put } from '@/lib/api/client'

export type AIUseCase = 'triage' | 'remediation' | 'summary'
export type AIUseCaseMode = 'off' | 'suggest' | 'auto_apply'
export type AIDataCeiling = 'public' | 'internal' | 'restricted'

export const AI_USE_CASE_MODES: AIUseCaseMode[] = ['off', 'suggest', 'auto_apply']
export const AI_DATA_CEILINGS: AIDataCeiling[] = ['public', 'internal', 'restricted']
export const MIN_CONFIDENCE_FLOOR = 0.5
export const MIN_CONFIDENCE_CEILING = 0.99

export interface AIUseCaseDowngrade {
  at: string
  /** Fixed code: override_rate. */
  reason: string
  decisions: number
  overrides: number
}

export interface AIUseCaseSetting {
  use_case: AIUseCase
  mode: AIUseCaseMode
  /** The mode in force: off while AI is turned off for the organization. */
  effective_mode: AIUseCaseMode
  ceiling: AIDataCeiling
  min_confidence: number
  auto_apply_since?: string
  downgrade?: AIUseCaseDowngrade
  updated_at?: string
  updated_by?: string
  /** Answer of a change: why it was a loosening (audited critical, owners told). */
  loosened?: string[]
}

export interface AIUseCaseInput {
  mode: AIUseCaseMode
  ceiling: AIDataCeiling
  min_confidence: number
}

export const AI_USE_CASES_URL = '/api/v1/organization/settings/ai/use-cases'

export function useAIUseCases(enabled: boolean) {
  return useSWR<{ items: AIUseCaseSetting[] }>(enabled ? AI_USE_CASES_URL : null, (url: string) =>
    get<{ items: AIUseCaseSetting[] }>(url)
  )
}

export async function updateAIUseCase(
  useCase: AIUseCase,
  input: AIUseCaseInput
): Promise<AIUseCaseSetting> {
  return put<AIUseCaseSetting>(`${AI_USE_CASES_URL}/${useCase}`, input)
}

const CEILING_RANK: Record<AIDataCeiling, number> = { public: 1, internal: 2, restricted: 3 }

/**
 * A change that lets results apply on their own or sends more data (the API
 * asks for a recent sign-in): auto-apply turned on, the ceiling raised above
 * internal, or a lower minimum confidence while auto-apply stays on.
 */
export function widensUseCase(before: AIUseCaseInput, after: AIUseCaseInput): boolean {
  if (after.mode === 'auto_apply' && before.mode !== 'auto_apply') return true
  if (
    after.mode !== 'off' &&
    CEILING_RANK[after.ceiling] > CEILING_RANK[before.ceiling] &&
    CEILING_RANK[after.ceiling] > CEILING_RANK.internal
  ) {
    return true
  }
  return (
    after.mode === 'auto_apply' &&
    before.mode === 'auto_apply' &&
    after.min_confidence < before.min_confidence
  )
}

/** A valid minimum confidence: 0.50 to 0.99. */
export function validMinConfidence(v: number): boolean {
  return Number.isFinite(v) && v >= MIN_CONFIDENCE_FLOOR && v <= MIN_CONFIDENCE_CEILING
}

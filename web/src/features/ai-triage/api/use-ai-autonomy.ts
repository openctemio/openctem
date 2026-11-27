'use client'

/**
 * The organization's switch and limits on changes AI agents make without a
 * person (API: GET /api/v1/organization/settings/ai/autonomy, settings:read;
 * PUT, owners and administrators with settings:write; docs:
 * architecture/ai-autonomy.md). Pausing and lowering a limit are immediate;
 * resuming, raising a limit or removing it needs a recent sign-in (the shared
 * API client asks) and tells every owner and administrator.
 */
import useSWR from 'swr'

import { get, put } from '@/lib/api/client'

export interface AIAutonomy {
  paused: boolean
  paused_at?: string
  paused_by?: string
  /** Changes without a person in the current clock hour; null: unlimited. */
  per_hour: number | null
  /** Changes without a person in the last 24 hours; null: unlimited. */
  per_day: number | null
  updated_at?: string
  updated_by?: string
  /** Answer of a change: why it was a loosening (audited critical, owners told). */
  loosened?: string[]
}

export interface AIAutonomyInput {
  paused: boolean
  per_hour: number | null
  per_day: number | null
}

export const AI_AUTONOMY_URL = '/api/v1/organization/settings/ai/autonomy'
export const AI_AUTONOMY_MAX_LIMIT = 100000

export function useAIAutonomy(enabled: boolean) {
  return useSWR<AIAutonomy>(enabled ? AI_AUTONOMY_URL : null, (url: string) => get<AIAutonomy>(url))
}

export const updateAIAutonomy = (input: AIAutonomyInput) => put<AIAutonomy>(AI_AUTONOMY_URL, input)

/** A valid limit: unlimited (null) or a whole number from 0 to 100,000. */
export function validLimit(v: number | null): boolean {
  return v === null || (Number.isInteger(v) && v >= 0 && v <= AI_AUTONOMY_MAX_LIMIT)
}

/**
 * A change that lets more happen without a person (the API asks for a recent
 * sign-in): resuming, a higher limit, or a limit made unlimited.
 */
export function loosensAutonomy(before: AIAutonomyInput, after: AIAutonomyInput): boolean {
  if (before.paused && !after.paused) return true
  const raised = (b: number | null, a: number | null) => b !== null && (a === null || a > b)
  return raised(before.per_hour, after.per_hour) || raised(before.per_day, after.per_day)
}

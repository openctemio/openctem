'use client'

/**
 * The organization's automatic AI triage policy (API: GET/PUT
 * /api/v1/organization/settings/ai/auto-triage, owners and administrators;
 * docs: architecture/ai-triage.md, "Automatic triage"). Turning it on or
 * adding a severity needs a recent sign-in (the shared API client asks) and
 * tells every owner and administrator; turning it off is immediate.
 */
import useSWR from 'swr'

import { get, put } from '@/lib/api/client'
import { SEVERITY_LEVELS, type SeverityLevel } from '@/lib/severity'

export type AutoTriageSeverity = SeverityLevel

export const AUTO_TRIAGE_SEVERITIES: AutoTriageSeverity[] = [...SEVERITY_LEVELS]

/** The longest wait before a new finding is triaged, in seconds. */
export const MAX_AUTO_TRIAGE_DELAY_SECONDS = 3600

export interface AIAutoTriagePolicy {
  enabled: boolean
  severities: AutoTriageSeverity[]
  delay_seconds: number
  /** Answer of a change: it widened what is sent (owners and administrators were told). */
  loosened?: boolean
}

export const AI_AUTO_TRIAGE_URL = '/api/v1/organization/settings/ai/auto-triage'

export function useAIAutoTriage(enabled: boolean) {
  return useSWR<AIAutoTriagePolicy>(enabled ? AI_AUTO_TRIAGE_URL : null, (url: string) =>
    get<AIAutoTriagePolicy>(url)
  )
}

export async function updateAIAutoTriage(
  policy: Omit<AIAutoTriagePolicy, 'loosened'>
): Promise<AIAutoTriagePolicy> {
  return put<AIAutoTriagePolicy>(AI_AUTO_TRIAGE_URL, policy)
}

/** A change that sends more without a person asking: on, or a severity added while on. */
export function autoTriageWidens(before: AIAutoTriagePolicy, after: AIAutoTriagePolicy): boolean {
  if (!after.enabled) return false
  if (!before.enabled) return true
  return after.severities.some((s) => !before.severities.includes(s))
}

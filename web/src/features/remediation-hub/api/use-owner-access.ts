'use client'

/**
 * Who can own a task, and what each cannot see: counts only, never finding
 * titles (GET .../owner-candidates). The same rule is enforced on save.
 */

import useSWR from 'swr'
import { get, post } from '@/lib/api/client'

export interface OwnerCandidate {
  type: 'user' | 'team'
  id: string
  name: string
  email?: string
  missing_findings: number
  missing_assets: number
  /** Teams: active members, and how many cannot see some finding. */
  members?: number
  members_missing?: number
}

export interface OwnerCandidates {
  findings: number
  candidates: OwnerCandidate[]
}

const TASKS = '/api/v1/remediation/tasks'

/** The request URL, or null when there is nothing to ask about. */
export function ownerCandidatesUrl(
  scope: { taskId?: string; findingIds?: string[] },
  q: string
): string | null {
  const p = new URLSearchParams()
  if (q.trim()) p.set('q', q.trim())
  if (scope.taskId) return `${TASKS}/${scope.taskId}/owner-candidates?${p.toString()}`
  const ids = (scope.findingIds ?? []).slice(0, 100)
  if (ids.length === 0) return null
  p.set('finding_ids', ids.join(','))
  return `${TASKS}/owner-candidates?${p.toString()}`
}

export function useOwnerCandidates(
  scope: { taskId?: string; findingIds?: string[] },
  q: string,
  enabled: boolean
) {
  const url = enabled ? ownerCandidatesUrl(scope, q) : null
  return useSWR<OwnerCandidates>(url, get, { keepPreviousData: true })
}

/**
 * "Request access" grants nothing: it leaves an internal comment on a
 * finding of the task, naming the person and the counts, for whoever may
 * assign access to read.
 */
export function requestOwnerAccess(findingId: string, text: string) {
  return post(`/api/v1/findings/${findingId}/comments`, { content: text, is_internal: true })
}

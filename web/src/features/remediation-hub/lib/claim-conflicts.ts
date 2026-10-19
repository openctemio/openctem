/**
 * Reads a 409 FINDINGS_IN_OTHER_TASK answer (a finding is in at most one
 * active task, api/docs/rfcs/RFC-098-remediation-tasks.md). The server lists
 * each conflict in details.conflicts; an older server lists only
 * details.finding_ids, which become conflicts nobody may move.
 */

import { ApiClientError } from '@/lib/api/error-handler'
import type { FindingConflict } from '../api/types'

export const FINDINGS_IN_OTHER_TASK = 'FINDINGS_IN_OTHER_TASK'

function str(v: unknown): string | null {
  return typeof v === 'string' && v !== '' ? v : null
}

/**
 * The conflicts of a failed claim, or null when the error is something else.
 * titles names the findings the caller sent, for answers without a title.
 */
export function claimConflicts(
  err: unknown,
  titles: ReadonlyMap<string, string> = new Map()
): FindingConflict[] | null {
  if (!(err instanceof ApiClientError) || err.code !== FINDINGS_IN_OTHER_TASK) return null
  const details = (err.details ?? {}) as Record<string, unknown>
  const raw = Array.isArray(details.conflicts) ? details.conflicts : null
  if (raw) {
    const out: FindingConflict[] = []
    for (const item of raw) {
      if (!item || typeof item !== 'object') continue
      const c = item as Record<string, unknown>
      const id = str(c.finding_id)
      if (!id) continue
      out.push({
        finding_id: id,
        finding_title: str(c.finding_title) ?? titles.get(id) ?? '',
        task_id: str(c.task_id) ?? '',
        task_title: str(c.task_title),
        assignee_user_id: str(c.assignee_user_id),
        assignee_group_id: str(c.assignee_group_id),
        can_move: c.can_move === true,
      })
    }
    return out
  }
  const ids = Array.isArray(details.finding_ids) ? details.finding_ids : []
  return ids
    .map(str)
    .filter((id): id is string => id !== null)
    .map((id) => ({
      finding_id: id,
      finding_title: titles.get(id) ?? '',
      task_id: '',
      task_title: null,
      assignee_user_id: null,
      assignee_group_id: null,
      can_move: false,
    }))
}

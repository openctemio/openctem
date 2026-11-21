/**
 * What a false-positive or accepted-risk decision asks for, one rule for the
 * single request dialog and for bulk Dismiss
 * (server/docs/architecture/finding-status-lifecycle.md, "Approvals"). The
 * reason code is always required. The free-text note is optional only when
 * the person decides alone (applied now) on a finding that is not serious;
 * whenever a second person approves, or the finding is serious (critical or
 * high, known exploited, P0/P1, a validated exploit, a crown jewel or an
 * internet-exposed asset), the note is required with the tier's minimum
 * length, at least one character. The server applies the same rule.
 */

import type { FalsePositivePolicy } from '../api/use-findings-api'
import type { FindingStatus } from '../types/finding.types'
import { PERSON_CLOSURE_REASONS } from './closure'

/** The policy view of one finding (`GET /findings/{id}/approval-policy`). */
type PolicyNote = Pick<FalsePositivePolicy, 'can_decide_alone' | 'material'> & {
  evaluation?: { min_note_length?: number }
}

/** A bulk Dismiss preview: the server already applied the rule to the whole selection. */
type PreviewNote = { note_required: boolean; note_min_length: number }

export type NoteRuleSource = PolicyNote | PreviewNote

/**
 * The shortest note the decision needs; 0 means the note is optional. Without
 * an answer from the server (still loading, it failed, or a status the policy
 * does not cover) the note is required, so the form never promises less than
 * the server asks.
 */
export function noteMinLength(source: NoteRuleSource | undefined | null): number {
  if (!source) return 1
  if ('note_required' in source) {
    return source.note_required ? Math.max(1, source.note_min_length || 0) : 0
  }
  if (source.can_decide_alone === true && source.material === false) return 0
  return Math.max(1, source.evaluation?.min_note_length ?? 0)
}

export function isNoteRequired(source: NoteRuleSource | undefined | null): boolean {
  return noteMinLength(source) > 0
}

/** Browser storage key of the reason picked last, per status (shared by every dismiss form). */
const LAST_REASON_KEY = 'openctem.findings.dismiss.lastReason'

/** The reason last chosen for this status (a convenience only: browser storage may be off). */
export function readLastReason(status: FindingStatus): string {
  try {
    const raw = window.localStorage.getItem(LAST_REASON_KEY)
    const saved = raw ? (JSON.parse(raw) as Record<string, unknown>) : {}
    const reason = saved[status]
    return typeof reason === 'string' && PERSON_CLOSURE_REASONS[status]?.includes(reason as never)
      ? reason
      : ''
  } catch {
    return ''
  }
}

export function writeLastReason(status: FindingStatus, reason: string): void {
  try {
    const raw = window.localStorage.getItem(LAST_REASON_KEY)
    const saved = raw ? (JSON.parse(raw) as Record<string, unknown>) : {}
    window.localStorage.setItem(LAST_REASON_KEY, JSON.stringify({ ...saved, [status]: reason }))
  } catch {
    // Storage is off (private window, blocked site data): nothing to remember.
  }
}

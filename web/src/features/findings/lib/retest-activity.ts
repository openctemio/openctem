/**
 * Retest entries on the finding's activity trail (RFC-039).
 *
 * The API writes `retest_requested` (actor: the user, or the system for an
 * auto-retest) and `retest_completed` (actor "system: retest", with old_status,
 * new_status, moved, outcome, reason and template_id in `changes`). Both the
 * REST activity list and the live WebSocket stream map them through here, so
 * the two never render them differently.
 */
import type { ActivityType } from '../types'

const OUTCOME_TEXT: Record<string, string> = {
  confirmed_fixed: 'Verified fixed',
  still_vulnerable: 'Still vulnerable',
  not_reproduced: 'Not reproduced (not confirmed)',
  inconclusive: 'Inconclusive',
  // Timeline entries written before RFC-057 R2 keep their outcome words.
  fixed: 'Fixed (unverified non-match)',
  still_present: 'Still vulnerable',
  unknown: 'Inconclusive',
}

/**
 * The type and text a retest activity renders with, or null for any other
 * activity. A completed retest that moved the finding renders as a status
 * change (from → to, with the outcome as its note); one that did not renders as
 * a single line.
 */
export function retestActivity(
  apiType: string,
  changes: Record<string, unknown>
): { type: ActivityType; content: string } | null {
  const template = typeof changes.template_id === 'string' ? changes.template_id : ''
  const via = template ? ` (template ${template})` : ''
  if (apiType === 'evidence_revealed') {
    // Who revealed which masked evidence values, and why. Never the values.
    const n = Array.isArray(changes.placeholders) ? changes.placeholders.length : 0
    const values = `${n} masked evidence value${n === 1 ? '' : 's'}`
    const content =
      changes.purpose === 'copy_curl'
        ? `Copied the reproduction curl with ${values}`
        : changes.purpose === 'copy'
          ? `Copied ${values}`
          : `Revealed ${values}`
    return { type: 'evidence_added', content }
  }
  if (apiType === 'retest_requested') {
    const auto = changes.trigger === 'auto'
    return { type: 'verified', content: `${auto ? 'Auto-retest' : 'Retest'} started${via}` }
  }
  if (apiType !== 'retest_completed') return null
  const outcome = OUTCOME_TEXT[String(changes.outcome)] ?? 'Retest finished'
  const reason = typeof changes.reason === 'string' && changes.reason ? ` — ${changes.reason}` : ''
  const regression = changes.regression === true ? ' (regression)' : ''
  return {
    type: changes.moved === true ? 'status_changed' : 'verified',
    content: `Retest: ${outcome}${regression}${via}${reason}`,
  }
}

/**
 * Plain-words sentences for the transition engine's reason codes ("why
 * can't I move this?"), translated (en + vi).
 */

import type { TransitionBlock, EvaluatedTransition } from '../api/use-finding-transitions'

type Translate = (key: string, fallback?: string, vars?: Record<string, string | number>) => string

const FALLBACK: Record<string, string> = {
  missing_permission: 'Needs the {permission} permission',
  not_a_lifecycle_move: 'Not a step of the finding lifecycle from here',
  not_fix_owner: 'Only the assignee, an assigned group member or the asset owner can claim a fix',
  not_a_person: 'A fix is claimed by a person',
  ticket_cannot_close: 'A ticket can only report work state',
  pentest_module: 'Managed in the pentest campaign',
  evidence_required:
    'Needs a retest pass, or the verification checklist completed by another person',
  checklist_required: 'Needs the verification checklist',
  not_found: 'Not found',
}

/** The sentence for one blocked reason. */
export function transitionReason(t: Translate, b: TransitionBlock): string {
  const fallback = FALLBACK[b.code] ?? b.code
  return t(`findings.transitionReason.${b.code}`, fallback, {
    permission: b.params?.permission ?? '',
  })
}

/** The first reason a move is blocked, or undefined when it is allowed. */
export function firstReason(t: Translate, blocked?: TransitionBlock[]): string | undefined {
  return blocked && blocked.length > 0 ? transitionReason(t, blocked[0]) : undefined
}

/** A bulk dry run split into the ids that may move and the reasons the rest may not, with counts. */
export function summarizeDryRun(
  t: Translate,
  results: EvaluatedTransition[]
): { allowed: string[]; refused: { reason: string; count: number }[] } {
  const allowed: string[] = []
  const counts = new Map<string, number>()
  for (const r of results) {
    if (r.decision?.allowed) {
      allowed.push(r.finding_id)
      continue
    }
    const reason = r.not_found
      ? transitionReason(t, { code: 'not_found' })
      : (firstReason(t, r.decision?.blocked) ??
        transitionReason(t, { code: 'not_a_lifecycle_move' }))
    counts.set(reason, (counts.get(reason) ?? 0) + 1)
  }
  return {
    allowed,
    refused: [...counts.entries()].map(([reason, count]) => ({ reason, count })),
  }
}

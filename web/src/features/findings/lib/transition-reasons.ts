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
  not_in_lifecycle: "Not a move of your organization's lifecycle",
  same_sub_status: 'Already there',
  closure_reason_change: 'A different closure reason is a new decision, not a label change',
  platform_sub_status: 'Set by the platform, not by a person',
  lifecycle_permission: 'Your organization requires one of: {any_of}',
  actor_kind_denied: 'Your organization keeps this move to people',
  fields_required: 'Needs {fields}: change these findings one at a time',
  note_too_short: 'Needs a note of at least {n} characters',
}

/** The sentence for one blocked reason. */
export function transitionReason(t: Translate, b: TransitionBlock): string {
  const fallback = FALLBACK[b.code] ?? b.code
  return t(`findings.transitionReason.${b.code}`, fallback, {
    permission: b.params?.permission ?? '',
    any_of: (b.params?.any_of ?? '').split(',').join(', '),
    fields: b.params?.fields ?? '',
    n: b.params?.n ?? '',
  })
}

/** The first reason a move is blocked, or undefined when it is allowed. */
export function firstReason(t: Translate, blocked?: TransitionBlock[]): string | undefined {
  return blocked && blocked.length > 0 ? transitionReason(t, blocked[0]) : undefined
}

/** A bulk dry run split into the ids that may move and the reasons the rest may not, with counts. */
export function summarizeDryRun(
  t: Translate,
  results: EvaluatedTransition[],
  opts: { note?: string } = {}
): { allowed: string[]; refused: { reason: string; count: number }[] } {
  const noteLen = (opts.note ?? '').trim().length
  const allowed: string[] = []
  const counts = new Map<string, number>()
  for (const r of results) {
    // A bulk change carries no field values: a move that requires them is
    // refused for that finding, so the dry run says so up front.
    const needsFields = r.decision?.allowed && (r.decision.fields?.length ?? 0) > 0
    const minLen = r.decision?.note_min_len ?? 0
    const noteTooShort = r.decision?.allowed && !needsFields && minLen > noteLen
    if (r.decision?.allowed && !needsFields && !noteTooShort) {
      allowed.push(r.finding_id)
      continue
    }
    const reason = needsFields
      ? transitionReason(t, {
          code: 'fields_required',
          params: {
            fields: (r.decision?.fields ?? [])
              .map((f) => t(`findingLifecycle.field.${f}`, f))
              .join(', '),
          },
        })
      : noteTooShort
        ? transitionReason(t, { code: 'note_too_short', params: { n: String(minLen) } })
        : r.not_found
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

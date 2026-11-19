/**
 * Bulk "Dismiss" on the findings list: mark many findings a false positive or
 * accept their risk in one action (server/docs/architecture/findings-bulk-by-filter.md,
 * "Bulk dismiss"). The server splits the selection with the same approval
 * policy as a single request: the findings the caller may decide alone are
 * applied now, the others become one approval request, the rest is skipped
 * with a reason. The client only sends the selection and the decision; the
 * preview, the apply and the undo all come from the server.
 */

import { post } from '@/lib/api/client'
import { ApiClientError } from '@/lib/api/error-handler'
import { PERSON_CLOSURE_REASONS } from './closure'

/** The most findings one Dismiss takes (the server's group cap). */
export const BULK_DISMISS_MAX = 500

export type DismissStatus = 'false_positive' | 'accepted'

/** What a Dismiss acts on: checked rows, or every finding the list's filter selects. */
export type DismissSelection =
  { kind: 'ids'; ids: string[] } | { kind: 'filter'; filter: Record<string, string>; total: number }

/** One finding of a preview list (at most 50 per list; the counts are complete). */
export interface DismissItem {
  id: string
  title?: string
  severity?: string
  reason?: string
}

export interface DismissSkip {
  id: string
  reason: string
}

/** `POST /findings/bulk-dismissals[/preview]`: the outcome, or what it would be. */
export interface DismissResult {
  bulk_id?: string
  status: string
  decided: string[] | null
  grouped: { batch_id?: string; count: number; tier: string } | null
  skipped: DismissSkip[] | null
  counts: { decided: number; grouped: number; skipped: number; budget_overflow: number }
  step_up_required: boolean
  note_required: boolean
  note_min_length: number
  replay: boolean
  decided_now?: DismissItem[]
  to_approval?: DismissItem[]
  skipped_items?: DismissItem[]
  same_rule?: { tool: string; rule_id: string; count: number; suggest: boolean }
}

/** `POST /findings/bulk-dismissals/{id}/reopen`. */
export interface DismissUndoResult {
  bulk_id: string
  reopened: string[] | null
  skipped: DismissSkip[] | null
  group_canceled: boolean
}

export interface DismissDecision {
  status: DismissStatus
  closureReason: string
  note: string
  /** RFC 3339; accepted only. */
  expiresAt?: string
}

/** The request body, without the idempotency key. */
export function dismissBody(
  selection: DismissSelection,
  decision: DismissDecision
): Record<string, unknown> {
  const body: Record<string, unknown> =
    selection.kind === 'ids'
      ? { finding_ids: selection.ids }
      : { filter: selection.filter, expected_count: selection.total }
  body.status = decision.status
  body.closure_reason = decision.closureReason
  const note = decision.note.trim()
  if (note) body.note = note
  if (decision.status === 'accepted' && decision.expiresAt) body.expires_at = decision.expiresAt
  return body
}

export function previewBulkDismiss(body: Record<string, unknown>): Promise<DismissResult> {
  return post<DismissResult>('/api/v1/findings/bulk-dismissals/preview', body)
}

/** Applies a Dismiss. A 403 STEP_UP_REQUIRED is answered by the API client's step-up flow. */
export function applyBulkDismiss(
  body: Record<string, unknown>,
  idempotencyKey: string
): Promise<DismissResult> {
  return post<DismissResult>('/api/v1/findings/bulk-dismissals', {
    ...body,
    idempotency_key: idempotencyKey,
  })
}

/** Undo: reopens what this Dismiss decided (the server calls it reopen). */
export function reopenBulkDismiss(bulkId: string): Promise<DismissUndoResult> {
  return post<DismissUndoResult>(
    `/api/v1/findings/bulk-dismissals/${encodeURIComponent(bulkId)}/reopen`
  )
}

/**
 * The shortest note this Dismiss needs; 0 means the note is optional. The
 * server decides (its preview's `note_required` / `note_min_length`): the note
 * is optional only when every finding is decided by the caller alone and none
 * is serious. Without a preview (still loading, or it failed) the note is
 * required, so the form never promises less than the server asks.
 */
export function dismissNoteMinLength(
  preview: Pick<DismissResult, 'note_required' | 'note_min_length'> | null | undefined
): number {
  if (!preview) return 1
  if (!preview.note_required) return 0
  return Math.max(1, preview.note_min_length || 0)
}

/**
 * The reason the preview sends while none is chosen yet: how the selection
 * splits does not depend on which reason it is, and the server requires one.
 */
export function previewReason(status: DismissStatus, chosen: string): string {
  return chosen || (PERSON_CLOSURE_REASONS[status]?.[0] ?? '')
}

type Translate = (
  key: string,
  fallback?: string,
  params?: Record<string, string | number>
) => string

/** A skip reason in plain words. */
export function skipReasonLabel(t: Translate, reason: string): string {
  switch (reason) {
    case 'not_found':
      return t('findings.bulkDismiss.skip.not_found', 'not found, or outside what you can see')
    case 'cannot_move':
      return t('findings.bulkDismiss.skip.cannot_move', 'their status cannot change to this')
    case 'pending_request':
      return t('findings.bulkDismiss.skip.pending_request', 'already waiting for approval')
    case 'note_required':
      return t('findings.bulkDismiss.skip.note_required', 'they now need a note for the approver')
    case 'changed':
      return t('findings.bulkDismiss.skip.changed', 'changed since the dismissal')
    case 'not_allowed':
      return t('findings.bulkDismiss.skip.not_allowed', 'could not be reopened')
    default:
      return t('findings.bulkDismiss.skip.failed', 'could not be saved')
  }
}

/** The one reason all skips share, or null when they differ (or none). */
function sharedReason(reasons: string[]): string | null {
  if (reasons.length === 0) return null
  return reasons.every((r) => r === reasons[0]) ? reasons[0] : null
}

export interface PreviewLine {
  kind: 'decide' | 'group' | 'skip'
  count: number
  text: string
  /** The findings of this part, as the server listed them (at most 50). */
  items: DismissItem[]
}

/**
 * The preview in plain words: "38 will be dismissed now.", "4 go to approval
 * (one request).", "2 skipped: already waiting for approval." Only the parts
 * that hold findings.
 */
export function previewLines(t: Translate, p: DismissResult): PreviewLine[] {
  const lines: PreviewLine[] = []
  const { decided, grouped, skipped } = p.counts
  if (decided > 0) {
    lines.push({
      kind: 'decide',
      count: decided,
      items: p.decided_now ?? [],
      text: t('findings.bulkDismiss.preview.decide', '{count} will be dismissed now.', {
        count: decided,
      }),
    })
  }
  if (grouped > 0) {
    lines.push({
      kind: 'group',
      count: grouped,
      items: p.to_approval ?? [],
      text:
        decided > 0
          ? t(
              'findings.bulkDismiss.preview.groupMixed',
              '{count, plural, one {# needs a second person: it goes to approval (one request).} other {# need a second person: they go to approval (one request).}}',
              { count: grouped }
            )
          : t(
              'findings.bulkDismiss.preview.groupAll',
              '{count, plural, one {# goes to approval (one request).} other {All # go to approval (one request).}}',
              { count: grouped }
            ),
    })
  }
  if (skipped > 0) {
    const items = p.skipped_items ?? []
    const reasons = (items.length > 0 ? items : (p.skipped ?? [])).map((s) => s.reason ?? '')
    const reason = sharedReason(reasons)
    lines.push({
      kind: 'skip',
      count: skipped,
      items,
      text: reason
        ? t('findings.bulkDismiss.preview.skipReason', '{count} skipped: {reason}.', {
            count: skipped,
            reason: skipReasonLabel(t, reason),
          })
        : t('findings.bulkDismiss.preview.skip', '{count} skipped.', { count: skipped }),
    })
  }
  return lines
}

export interface DismissSummary {
  kind: 'success' | 'warning' | 'error'
  message: string
  description?: string
}

/** The applied Dismiss in plain words, for the result toast. */
export function summarizeDismiss(t: Translate, r: DismissResult): DismissSummary {
  const { decided, grouped, skipped, budget_overflow: overflow } = r.counts
  const parts: string[] = []
  if (grouped > 0 && decided > 0) {
    parts.push(
      t('findings.bulkDismiss.result.grouped', '{count} sent for approval (one request).', {
        count: grouped,
      })
    )
  }
  if (overflow > 0) {
    parts.push(
      t(
        'findings.bulkDismiss.result.overflow',
        '{count} of them because you reached the limit of 1,000 dismissed alone in 24 hours.',
        { count: overflow }
      )
    )
  }
  if (skipped > 0) {
    const reason = sharedReason((r.skipped ?? []).map((s) => s.reason))
    parts.push(
      reason
        ? t('findings.bulkDismiss.preview.skipReason', '{count} skipped: {reason}.', {
            count: skipped,
            reason: skipReasonLabel(t, reason),
          })
        : t('findings.bulkDismiss.preview.skip', '{count} skipped.', { count: skipped })
    )
  }
  const description = parts.length > 0 ? parts.join(' ') : undefined
  if (decided === 0 && grouped === 0) {
    return {
      kind: 'error',
      message: t('findings.bulkDismiss.result.none', 'Nothing was dismissed'),
      description,
    }
  }
  const message =
    decided > 0
      ? t(
          'findings.bulkDismiss.result.decided',
          '{count, plural, one {Dismissed # finding} other {Dismissed # findings}}',
          { count: decided }
        )
      : t(
          'findings.bulkDismiss.result.sent',
          '{count, plural, one {# finding sent for approval} other {# findings sent for approval}}',
          { count: grouped }
        )
  return { kind: skipped > 0 ? 'warning' : 'success', message, description }
}

/** The undo in plain words. */
export function summarizeUndo(t: Translate, r: DismissUndoResult): DismissSummary {
  const reopened = r.reopened?.length ?? 0
  const skipped = r.skipped?.length ?? 0
  const parts: string[] = []
  if (r.group_canceled) {
    parts.push(t('findings.bulkDismiss.undo.groupCanceled', 'The approval request was withdrawn.'))
  }
  if (skipped > 0) {
    parts.push(
      t(
        'findings.bulkDismiss.undo.skipped',
        '{count, plural, one {# was left as it is: it changed since.} other {# were left as they are: they changed since.}}',
        { count: skipped }
      )
    )
  }
  return {
    kind: skipped > 0 ? 'warning' : 'success',
    message:
      reopened > 0
        ? t(
            'findings.bulkDismiss.undo.reopened',
            '{count, plural, one {Reopened # finding} other {Reopened # findings}}',
            { count: reopened }
          )
        : t('findings.bulkDismiss.undo.done', 'Dismissal undone'),
    description: parts.length > 0 ? parts.join(' ') : undefined,
  }
}

/** The error code of a refused request, or ''. */
export function errorCode(error: unknown): string {
  return error instanceof ApiClientError ? error.code : ''
}

/** `details.count` of a refused request (SELECTION_CHANGED, BULK_DISMISS_TOO_LARGE). */
export function errorCount(error: unknown): number | null {
  if (!(error instanceof ApiClientError)) return null
  const n = error.details?.count
  return typeof n === 'number' ? n : null
}

/**
 * The idempotency key of an apply: one per dialog open, kept across retries
 * of the same request (a retry after a dropped answer returns the stored
 * result), and replaced when the request changes (another reason, note or
 * count), so a changed request is never refused as a reused key.
 */
export function idempotencyKeyFor(
  prev: { key: string; body: string } | null,
  body: Record<string, unknown>,
  newKey: () => string = () => crypto.randomUUID()
): { key: string; body: string } {
  const text = JSON.stringify(body)
  if (prev && prev.body === text) return prev
  return { key: newKey(), body: text }
}

const LAST_REASON_KEY = 'openctem.findings.dismiss.lastReason'

/** The reason last chosen for this status (a convenience only: browser storage may be off). */
export function readLastReason(status: DismissStatus): string {
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

export function writeLastReason(status: DismissStatus, reason: string): void {
  try {
    const raw = window.localStorage.getItem(LAST_REASON_KEY)
    const saved = raw ? (JSON.parse(raw) as Record<string, unknown>) : {}
    window.localStorage.setItem(LAST_REASON_KEY, JSON.stringify({ ...saved, [status]: reason }))
  } catch {
    // Storage is off (private window, blocked site data): nothing to remember.
  }
}

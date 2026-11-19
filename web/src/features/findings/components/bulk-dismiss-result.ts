/**
 * The toast after a bulk Dismiss: what happened in plain words, and Undo
 * (the server reopens the findings this Dismiss decided that have not changed
 * since, and withdraws its approval request; nothing is deleted).
 */

import { toast } from 'sonner'
import { getErrorMessage } from '@/lib/api/error-handler'
import {
  summarizeDismiss,
  summarizeUndo,
  undoBulkDismiss,
  type DismissResult,
  type DismissSummary,
} from '../lib/bulk-dismiss'

type Translate = (
  key: string,
  fallback?: string,
  params?: Record<string, string | number>
) => string

/** How long the result stays, so Undo can be reached. */
export const DISMISS_TOAST_MS = 15_000

function show(s: DismissSummary, extra: Parameters<typeof toast.success>[1] = {}) {
  const opts = { description: s.description, ...extra }
  if (s.kind === 'success') toast.success(s.message, opts)
  else if (s.kind === 'warning') toast.warning(s.message, opts)
  else toast.error(s.message, opts)
}

/** Whether this result has anything Undo can take back. */
export function canUndoDismiss(r: DismissResult): boolean {
  return !!r.bulk_id && (r.counts.decided > 0 || !!r.grouped?.batch_id)
}

export async function runDismissUndo(
  t: Translate,
  bulkId: string,
  onChanged: () => void
): Promise<void> {
  try {
    const undo = await undoBulkDismiss(bulkId)
    show(summarizeUndo(t, undo))
    onChanged()
  } catch (error) {
    toast.error(
      getErrorMessage(error, t('findings.bulkDismiss.undo.failed', 'Could not undo the dismissal'))
    )
  }
}

/** Shows the result of an applied Dismiss, with Undo when there is something to undo. */
export function announceDismissResult(
  t: Translate,
  result: DismissResult,
  onChanged: () => void
): void {
  const summary = summarizeDismiss(t, result)
  const bulkId = result.bulk_id
  show(
    summary,
    bulkId && canUndoDismiss(result)
      ? {
          duration: DISMISS_TOAST_MS,
          action: {
            label: t('findings.bulkDismiss.undo.action', 'Undo'),
            onClick: () => void runDismissUndo(t, bulkId, onChanged),
          },
        }
      : {}
  )
}

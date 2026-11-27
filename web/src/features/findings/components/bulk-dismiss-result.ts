/**
 * The toast after a bulk Dismiss: what happened in plain words, and Undo
 * (the server reopens the findings this Dismiss decided that have not changed
 * since, and withdraws its approval request; nothing is deleted). When the
 * Dismiss sent findings to approval and the caller is the organization's only
 * member and owner (nobody else can approve), the main action is "Approve
 * myself" and Undo stays beside it.
 */

import { toast } from 'sonner'
import { getErrorMessage } from '@/lib/api/error-handler'
import type { ApprovalBatch } from '../api/use-approval-batches'
import {
  summarizeDismiss,
  summarizeUndo,
  reopenBulkDismiss,
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
    const undo = await reopenBulkDismiss(bulkId)
    show(summarizeUndo(t, undo))
    onChanged()
  } catch (error) {
    toast.error(
      getErrorMessage(error, t('findings.bulkDismiss.undo.failed', 'Could not undo the dismissal'))
    )
  }
}

/** "Approve myself" for the group a Dismiss created, when the caller may approve it alone. */
export interface DismissSelfApprove {
  /** `GET /approvals/batches/{id}`: the server says whether the caller may approve it alone. */
  load: (batchId: string) => Promise<ApprovalBatch>
  /** Opens the self-approve dialog for the group. */
  open: (batch: ApprovalBatch) => void
}

/** The group the caller may approve alone, or null (no group, not allowed, or the lookup failed). */
async function selfApprovableGroup(
  result: DismissResult,
  selfApprove: DismissSelfApprove | undefined
): Promise<ApprovalBatch | null> {
  const batchId = result.grouped?.batch_id
  if (!batchId || !selfApprove) return null
  try {
    const batch = await selfApprove.load(batchId)
    return batch.status === 'pending' && batch.self_approval_available ? batch : null
  } catch {
    // The toast still says what happened; the group is on the Approvals page.
    return null
  }
}

/**
 * Shows the result of an applied Dismiss, with Undo when there is something
 * to undo. The toast shows at once unless the Dismiss created a group and
 * `selfApprove` is given: then it first asks whether the caller may approve
 * that group alone.
 */
export async function announceDismissResult(
  t: Translate,
  result: DismissResult,
  onChanged: () => void,
  selfApprove?: DismissSelfApprove
): Promise<void> {
  const summary = summarizeDismiss(t, result)
  const bulkId = result.bulk_id
  const undo =
    bulkId && canUndoDismiss(result)
      ? {
          label: t('findings.bulkDismiss.undo.action', 'Undo'),
          onClick: () => void runDismissUndo(t, bulkId, onChanged),
        }
      : null
  const group =
    selfApprove && result.grouped?.batch_id ? await selfApprovableGroup(result, selfApprove) : null
  if (group && selfApprove) {
    show(summary, {
      duration: DISMISS_TOAST_MS,
      action: {
        label: t('findingApprovals.selfApprove.cardAction', 'Approve myself'),
        onClick: () => selfApprove.open(group),
      },
      ...(undo ? { cancel: undo } : {}),
    })
    return
  }
  show(summary, undo ? { duration: DISMISS_TOAST_MS, action: undo } : {})
}

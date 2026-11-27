'use client'

/**
 * Deciding many approval requests, or many group exceptions, at once in
 * Findings > Approvals: the bulk bar's "Approve selected" and "Reject
 * selected", their dialogs and the result. Each selected id is decided on
 * the server through its own single path (the policy, the four-eyes rule,
 * the approver's data scope and the step-up per tier are judged per item);
 * approve asks for a recent sign-in once for the call (the API client
 * prompts and retries). What was not decided is reported with a plain reason.
 */

import { useCallback, useMemo, useState } from 'react'
import { Loader2 } from 'lucide-react'
import { toast } from 'sonner'
import { Button } from '@/components/ui/button'
import { ConfirmDialog } from '@/components/confirm-dialog'
import { useTranslation } from '@/context/i18n-provider'
import { getErrorMessage } from '@/lib/api/error-handler'
import { QueueReasonDialog } from '@/features/shared/components/queue'
import type {
  DataTableBulk,
  DataTableSelection,
} from '@/features/shared/components/data-table/data-table-selection'
import {
  APPROVAL_BULK_MAX,
  approvalBulkApi,
  type ApprovalBulkResult,
  type ApprovalBulkSelection,
} from '../api/use-approval-batches'
import { summarizeApprovalBulk } from '../lib/bulk-result'

const REASON_MAX = 2000

export interface ApprovalBulkDecideOptions<T> {
  /** Finding requests or group exceptions. */
  kind: 'approval' | 'batch'
  idOf: (row: T) => string
  /** The row's name in its checkbox label. */
  nameOf: (row: T) => string
  /** The caller holds findings:approve (the API decides again per item). */
  canDecide: boolean
  /** After a call the server answered: refresh the lists and badges. */
  onDecided: () => unknown
  /** Says the outcome to assistive technology. */
  announce?: (text: string) => void
}

export function useApprovalBulkDecide<T>({
  kind,
  idOf,
  nameOf,
  canDecide,
  onDecided,
  announce,
}: ApprovalBulkDecideOptions<T>) {
  const { t } = useTranslation()
  const [selected, setSelected] = useState<T[]>([])
  // Bumped to clear the table's selection after a decision.
  const [resetKey, setResetKey] = useState(0)
  const [mode, setMode] = useState<'approve' | 'reject' | null>(null)
  const [reason, setReason] = useState('')
  const [rejectError, setRejectError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)
  const count = selected.length
  const tooMany = count > APPROVAL_BULK_MAX

  const onSelectionChange = useCallback(
    (selection: DataTableSelection<T> | null) =>
      setSelected(selection?.kind === 'ids' ? selection.rows : []),
    []
  )

  const body = (): ApprovalBulkSelection => {
    const ids = selected.map(idOf)
    return kind === 'batch'
      ? { approval_ids: [], batch_ids: ids }
      : { approval_ids: ids, batch_ids: [] }
  }

  const report = (res: ApprovalBulkResult | undefined) => {
    const summary = summarizeApprovalBulk(res, t)
    const opts = summary.description ? { description: summary.description } : undefined
    announce?.(summary.description ? `${summary.message}. ${summary.description}` : summary.message)
    if (summary.kind === 'success') toast.success(summary.message, opts)
    else if (summary.kind === 'warning') toast.warning(summary.message, opts)
    else toast.error(summary.message, opts)
  }

  const finish = async () => {
    setSelected([])
    setResetKey((k) => k + 1)
    await onDecided()
  }

  const confirmApprove = async () => {
    if (busy || count === 0 || tooMany) return
    setBusy(true)
    try {
      report(await approvalBulkApi.approve(body()))
      setMode(null)
      await finish()
    } catch (err) {
      const message = getErrorMessage(
        err,
        t('findings.bulkDecide.approveFailed', 'Could not approve the selected requests')
      )
      announce?.(message)
      toast.error(message)
      setMode(null)
    } finally {
      setBusy(false)
    }
  }

  const confirmReject = async () => {
    if (busy || count === 0 || tooMany || !reason.trim()) return
    setBusy(true)
    setRejectError(null)
    try {
      report(await approvalBulkApi.reject(body(), reason.trim()))
      setMode(null)
      setReason('')
      await finish()
    } catch (err) {
      // The dialog stays open with the reason as typed.
      setRejectError(
        getErrorMessage(
          err,
          t('findings.bulkDecide.rejectFailed', 'Could not reject the selected requests')
        )
      )
    } finally {
      setBusy(false)
    }
  }

  const open = (next: 'approve' | 'reject') => {
    if (tooMany) {
      toast.error(
        t('findings.bulkDecide.tooMany', 'Select at most {max} at a time.', {
          max: APPROVAL_BULK_MAX,
        })
      )
      return
    }
    if (next === 'reject') {
      setReason('')
      setRejectError(null)
    }
    setMode(next)
  }

  const noun = useCallback(
    (n: number) =>
      kind === 'batch'
        ? t(
            'findings.bulkDecide.nounGroups',
            '{count, plural, one {group selected} other {groups selected}}',
            { count: n }
          )
        : t(
            'findings.bulkDecide.nounRequests',
            '{count, plural, one {request selected} other {requests selected}}',
            { count: n }
          ),
    [kind, t]
  )

  const bulk: DataTableBulk<T> | undefined = useMemo(
    () =>
      canDecide
        ? {
            rowLabel: nameOf,
            noun,
            onSelectionChange,
            actions: (
              <>
                <Button
                  variant="ghost"
                  size="sm"
                  disabled={busy}
                  onClick={() => open('approve')}
                  data-testid="approvals-bulk-approve"
                >
                  {busy && mode === 'approve' && (
                    <Loader2 className="me-1 h-3.5 w-3.5 animate-spin" aria-hidden />
                  )}
                  {t('findings.bulkDecide.approve', 'Approve selected')}
                </Button>
                <Button
                  variant="ghost"
                  size="sm"
                  disabled={busy}
                  onClick={() => open('reject')}
                  data-testid="approvals-bulk-reject"
                >
                  {t('findings.bulkDecide.reject', 'Reject selected')}
                </Button>
              </>
            ),
          }
        : undefined,
    // open() reads the current count; it changes with the selection.
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [canDecide, nameOf, noun, onSelectionChange, busy, mode, tooMany, t]
  )

  const dialogs = (
    <>
      <ConfirmDialog
        open={mode === 'approve'}
        onOpenChange={(o) => !o && !busy && setMode(null)}
        title={
          kind === 'batch'
            ? t(
                'findings.bulkDecide.approveTitleGroups',
                '{count, plural, one {Approve # selected group?} other {Approve # selected groups?}}',
                {
                  count,
                }
              )
            : t(
                'findings.bulkDecide.approveTitle',
                '{count, plural, one {Approve # selected request?} other {Approve # selected requests?}}',
                {
                  count,
                }
              )
        }
        desc={t(
          'findings.bulkDecide.approveDesc',
          'Each one is checked on its own, as if you approved it alone. Any you may not approve is skipped and listed. You confirm your sign-in first.'
        )}
        confirmText={t('findings.bulkDecide.approveConfirm', 'Approve {count}', { count })}
        isLoading={busy}
        handleConfirm={confirmApprove}
      />
      <QueueReasonDialog
        open={mode === 'reject'}
        onOpenChange={(o) => !o && !busy && setMode(null)}
        title={
          kind === 'batch'
            ? t(
                'findings.bulkDecide.rejectTitleGroups',
                '{count, plural, one {Reject # selected group?} other {Reject # selected groups?}}',
                {
                  count,
                }
              )
            : t(
                'findings.bulkDecide.rejectTitle',
                '{count, plural, one {Reject # selected request?} other {Reject # selected requests?}}',
                {
                  count,
                }
              )
        }
        description={t(
          'findings.bulkDecide.rejectDesc',
          'Every finding keeps its status. One reason goes to every requester.'
        )}
        reason={reason}
        onReasonChange={setReason}
        reasonLabel={t('findings.approvals.rejectPlaceholder', 'Reason for rejection…')}
        maxLength={REASON_MAX}
        error={rejectError}
        busy={busy}
        confirmLabel={t('findings.bulkDecide.rejectConfirm', 'Reject {count}', { count })}
        busyLabel={t('findings.approvals.rejecting', 'Rejecting…')}
        cancelLabel={t('findings.approvals.cancel', 'Cancel')}
        onConfirm={confirmReject}
      />
    </>
  )

  return { bulk, dialogs, resetKey }
}

'use client'

/**
 * "Waiting on someone": the band an object shows while a guarded act on it
 * (a status change, an exception, a scope change) is held for approval.
 * Findings were first; every guarded act uses the same band so a requester
 * always finds "Awaiting approval" and Cancel request in the same place.
 *
 * The band is the frame: an hourglass, the pending requests as a list, and
 * the dialogs the owner of the data wants rendered beside them. A request row
 * says what is waiting, who asked and why, offers Cancel to the requester
 * (behind a confirmation) and takes the approver's buttons as `actions`. What
 * the request is about, and who may cancel or decide, stays with the caller
 * (and the API decides again).
 */

import { useState, type ReactNode } from 'react'
import { Hourglass, Loader2 } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { ConfirmDialog } from '@/components/confirm-dialog'
import { useTranslation } from '@/context/i18n-provider'
import { cn } from '@/lib/utils'

export function AwaitingApprovalBand({
  ariaLabel,
  className,
  testId = 'awaiting-approval-band',
  children,
  after,
}: {
  /** Names the region. Default: "Waiting on an approval". */
  ariaLabel?: string
  className?: string
  testId?: string
  /** The requests: AwaitingApprovalRequest rows. */
  children: ReactNode
  /** Rendered inside the band after the list (the approver's dialogs). */
  after?: ReactNode
}) {
  const { t } = useTranslation()
  return (
    <section
      aria-label={ariaLabel ?? t('common.awaitingApproval.aria', 'Waiting on an approval')}
      className={cn(
        'flex gap-3 rounded-lg border border-warning/40 bg-warning/5 p-3 text-sm',
        className
      )}
      data-testid={testId}
    >
      <Hourglass className="mt-0.5 h-4 w-4 shrink-0 text-warning" aria-hidden />
      <ul className="min-w-0 flex-1 space-y-3">{children}</ul>
      {after}
    </section>
  )
}

export function AwaitingApprovalRequest({
  title,
  requestedBy,
  reason,
  details,
  actions,
  onCancel,
  cancelBusy = false,
  cancelDialog,
  error,
  testId = 'awaiting-approval-request',
  cancelTestId = 'awaiting-approval-cancel',
}: {
  /** What is waiting, e.g. "Awaiting approval: False positive". */
  title: ReactNode
  /** Who asked and when, one translated line. */
  requestedBy: ReactNode
  /** The justification the requester gave. */
  reason?: string
  /** Extra lines under the request (badges, what changed since). */
  details?: ReactNode
  /** The approver's buttons. */
  actions?: ReactNode
  /** Present when the viewer may cancel: opens the confirmation, then runs. */
  onCancel?: () => unknown
  cancelBusy?: boolean
  /** The confirmation's copy, when the generic wording does not fit. */
  cancelDialog?: { title?: string; description?: string }
  /** Shown beside the buttons, e.g. when Cancel failed. */
  error?: string
  testId?: string
  cancelTestId?: string
}) {
  const { t } = useTranslation()
  const [cancelOpen, setCancelOpen] = useState(false)
  return (
    <li className="space-y-1" data-testid={testId}>
      <p className="font-medium">{title}</p>
      <p className="text-xs text-muted-foreground">{requestedBy}</p>
      {details}
      {reason && (
        <p className="text-xs break-words whitespace-pre-wrap text-muted-foreground">
          {t('common.awaitingApproval.reason', 'Reason:')} {reason}
        </p>
      )}
      {onCancel && (
        <ConfirmDialog
          open={cancelOpen}
          onOpenChange={setCancelOpen}
          title={
            cancelDialog?.title ??
            t('common.awaitingApproval.cancelTitle', 'Cancel this approval request?')
          }
          desc={
            cancelDialog?.description ??
            t(
              'common.awaitingApproval.cancelDesc',
              'The request is withdrawn and nothing changes. You can send a new request afterwards.'
            )
          }
          cancelBtnText={t('common.awaitingApproval.keep', 'Keep request')}
          confirmText={t('common.awaitingApproval.cancel', 'Cancel request')}
          destructive
          handleConfirm={() => {
            setCancelOpen(false)
            return onCancel()
          }}
        />
      )}
      <div className="flex flex-wrap items-center gap-2 pt-1">
        {onCancel && (
          <Button
            type="button"
            size="sm"
            variant="outline"
            onClick={() => setCancelOpen(true)}
            disabled={cancelBusy}
            data-testid={cancelTestId}
          >
            {cancelBusy && <Loader2 className="me-1 h-3.5 w-3.5 animate-spin" aria-hidden />}
            {t('common.awaitingApproval.cancel', 'Cancel request')}
          </Button>
        )}
        {actions}
        {error && (
          <span role="alert" className="text-xs text-destructive">
            {error}
          </span>
        )}
      </div>
    </li>
  )
}

'use client'

/**
 * Deciding one finding status request: the Approve confirmation and the
 * Reject dialog (a reason is required). One pair of dialogs for every place
 * that decides a request (the approvals inbox, My Work), so the wording, the
 * re-authentication and the error handling are the same everywhere.
 *
 * The API is the authority: approve needs findings:approve and a recent
 * sign-in (the API client asks for re-authentication and retries once), and
 * re-evaluates the approval policy and the four-eyes rule at that moment.
 */

import { useCallback, useState } from 'react'
import { Loader2 } from 'lucide-react'
import { toast } from 'sonner'
import { ConfirmDialog } from '@/components/confirm-dialog'
import { Badge } from '@/components/ui/badge'
import { useTranslation } from '@/context/i18n-provider'
import { getErrorMessage } from '@/lib/api/error-handler'
import { formatCalendarDate } from '@/lib/format-metric'
import { QueueReasonDialog } from '@/features/shared/components/queue'
import { useApproveStatus, useRejectApproval } from '../api/use-findings-api'
import { approveErrorOutcome, approveResultOutcome } from '../lib/approval-policy'
import { closureReasonLabel } from '../lib/closure'
import { FINDING_STATUS_CONFIG, type ApiApproval } from '../types'
import { ApprovalFindingSummary } from './approval-finding-summary'
import { AIProposalBadge } from './ai-proposal-badge'

type Translate = ReturnType<typeof useTranslation>['t']

/** The localised label of a requested finding status. */
export function requestedStatusLabel(t: Translate, status: string): string {
  const config = FINDING_STATUS_CONFIG[status as keyof typeof FINDING_STATUS_CONFIG]
  return config ? t(config.labelKey, config.label) : status
}

const REASON_MAX = 2000

/**
 * The decision dialogs and their state. `onDecided` runs after a decision
 * the server recorded, and after a refusal that changed what the list should
 * show (the request was decided elsewhere, or the policy now refuses it).
 */
export function useApprovalDecision({
  onDecided,
  announce,
}: {
  onDecided: () => unknown
  /** Says each outcome to assistive technology (the queue's status region). */
  announce?: (text: string) => void
}) {
  const { t, locale } = useTranslation()
  const [target, setTarget] = useState<ApiApproval | null>(null)
  const [mode, setMode] = useState<'approve' | 'reject' | null>(null)
  const [reason, setReason] = useState('')
  const [rejectError, setRejectError] = useState<string | null>(null)
  const [busyId, setBusyId] = useState<string | null>(null)

  const { trigger: triggerApprove, isMutating: isApproving } = useApproveStatus(target?.id ?? '')
  const { trigger: triggerReject, isMutating: isRejecting } = useRejectApproval(target?.id ?? '')

  const openApprove = useCallback((a: ApiApproval) => {
    setTarget(a)
    setMode('approve')
  }, [])
  const openReject = useCallback((a: ApiApproval) => {
    setTarget(a)
    setReason('')
    setRejectError(null)
    setMode('reject')
  }, [])
  const close = useCallback(() => setMode(null), [])

  const confirmApprove = async () => {
    if (!target || busyId) return
    setBusyId(target.id)
    try {
      // A re-authentication prompt (STEP_UP_REQUIRED) is answered by the API
      // client, which retries once; a cancelled prompt ends up below.
      const outcome = approveResultOutcome(await triggerApprove())
      if (outcome.kind === 'recorded') {
        announce?.(t('findings.approvals.toast.signed', 'Your approval is recorded'))
        toast.success(t('findings.approvals.toast.signed', 'Your approval is recorded'), {
          description: t(
            'findings.approvals.toast.signedDesc',
            '{count, plural, one {# more approval} other {# more approvals}} needed before the status changes.',
            { count: outcome.remaining }
          ),
        })
      } else {
        announce?.(t('findings.approvals.toast.approved', 'Approval request approved'))
        toast.success(t('findings.approvals.toast.approved', 'Approval request approved'), {
          description: t(
            'findings.approvals.toast.approvedDesc',
            'Finding status will be changed to {status}',
            { status: requestedStatusLabel(t, target.requested_status) }
          ),
        })
      }
      await onDecided()
    } catch (err) {
      const outcome = approveErrorOutcome(t, err)
      const message =
        outcome.kind === 'refused'
          ? outcome.message
          : getErrorMessage(
              err,
              t('findings.approvals.toast.approveFailed', 'Failed to approve request')
            )
      announce?.(message)
      toast.error(message)
      if (outcome.kind === 'refused') await onDecided()
    } finally {
      setBusyId(null)
      setTarget(null)
      setMode(null)
    }
  }

  const confirmReject = async () => {
    if (!target || busyId || !reason.trim()) return
    setBusyId(target.id)
    setRejectError(null)
    try {
      await triggerReject({ reason: reason.trim() })
      announce?.(t('findings.approvals.toast.rejected', 'Approval request rejected'))
      toast.success(t('findings.approvals.toast.rejected', 'Approval request rejected'))
      setReason('')
      setTarget(null)
      setMode(null)
      await onDecided()
    } catch (err) {
      // The dialog stays open with the reason as typed: the approver fixes
      // the cause (or retries) without writing it again.
      setRejectError(
        getErrorMessage(err, t('findings.approvals.toast.rejectFailed', 'Failed to reject request'))
      )
    } finally {
      setBusyId(null)
    }
  }

  const remaining =
    target && (target.approvals_required ?? 0) - (target.approvals_collected ?? 0) > 1
      ? (target.approvals_required ?? 0) - (target.approvals_collected ?? 0) - 1
      : 0

  // The end of an accepted risk: part of what is decided, so both dialogs say it.
  const acceptanceEnd = target?.expires_at ? (
    <p className="text-sm">
      {t('findings.approvals.col.expires', 'Acceptance ends')}{' '}
      {formatCalendarDate(target.expires_at, locale)}
    </p>
  ) : null

  const dialogs = (
    <>
      <ConfirmDialog
        open={mode === 'approve'}
        onOpenChange={(open) => !open && close()}
        title={t('confirm.findingApproval.approveTitle', 'Approve this status change?')}
        desc={
          remaining > 0
            ? t(
                'confirm.findingApproval.approveDescMore',
                'Your approval is recorded. The finding moves to the requested status once {count, plural, one {# more approval is} other {# more approvals are}} in.',
                { count: remaining }
              )
            : t(
                'confirm.findingApproval.approveDesc',
                'The finding moves to the requested status at once.'
              )
        }
        confirmText={
          isApproving ? (
            <>
              <Loader2 className="me-2 h-4 w-4 animate-spin" />
              {t('confirm.suppression.approving', 'Approving…')}
            </>
          ) : (
            t('confirm.suppression.approve', 'Approve')
          )
        }
        isLoading={isApproving}
        handleConfirm={confirmApprove}
      >
        {target && (
          <div className="my-2 grid gap-3 rounded-lg border bg-muted/50 p-3">
            <ApprovalFindingSummary
              findingId={target.finding_id}
              findingTitle={target.finding_title}
              justification={target.justification}
            />
            <p className="text-sm font-medium">
              {t('findings.approvals.changeTo', 'Change to')}{' '}
              <Badge variant="outline" className="ms-1 text-xs">
                {requestedStatusLabel(t, target.requested_status)}
              </Badge>
            </p>
            {target.closure_reason && (
              <p className="text-sm">
                {t('findings.approvalDialog.reasonLabel', 'Reason:')}{' '}
                {closureReasonLabel(t, target.closure_reason)}
              </p>
            )}
            {acceptanceEnd}
            <AIProposalBadge approval={target} withHint />
          </div>
        )}
      </ConfirmDialog>

      <QueueReasonDialog
        open={mode === 'reject'}
        onOpenChange={(open) => !open && close()}
        title={t('findings.approvals.rejectTitle', 'Reject request')}
        description={t(
          'findings.approvals.rejectDesc',
          'Give a reason for rejecting this request.'
        )}
        summary={
          target && (
            <div className="grid gap-3 rounded-lg border bg-muted/50 p-3">
              <ApprovalFindingSummary
                findingId={target.finding_id}
                findingTitle={target.finding_title}
                justification={target.justification}
              />
              <p className="text-sm font-medium">
                {t('findings.approvals.requestedLabel', 'Requested:')}{' '}
                {requestedStatusLabel(t, target.requested_status)}
              </p>
              {acceptanceEnd}
              <AIProposalBadge approval={target} withHint />
            </div>
          )
        }
        reason={reason}
        onReasonChange={setReason}
        reasonLabel={t('findings.approvals.rejectPlaceholder', 'Reason for rejection…')}
        maxLength={REASON_MAX}
        error={rejectError}
        busy={isRejecting}
        confirmLabel={t('findings.approvals.action.reject', 'Reject')}
        busyLabel={t('findings.approvals.rejecting', 'Rejecting…')}
        cancelLabel={t('findings.approvals.cancel', 'Cancel')}
        onConfirm={confirmReject}
      />
    </>
  )

  return { busyId, openApprove, openReject, dialogs }
}

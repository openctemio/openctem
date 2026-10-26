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
import { Loader2, Lock } from 'lucide-react'
import { toast } from 'sonner'
import { ConfirmDialog } from '@/components/confirm-dialog'
import {
  Dialog,
  DialogBody,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip'
import { Textarea } from '@/components/ui/textarea'
import { useTranslation } from '@/context/i18n-provider'
import { getErrorMessage } from '@/lib/api/error-handler'
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
export function useApprovalDecision({ onDecided }: { onDecided: () => unknown }) {
  const { t } = useTranslation()
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
        toast.success(t('findings.approvals.toast.signed', 'Your approval is recorded'), {
          description: t(
            'findings.approvals.toast.signedDesc',
            '{count} more approval(s) needed before the status changes.',
            { count: outcome.remaining }
          ),
        })
      } else {
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
      toast.error(
        outcome.kind === 'refused'
          ? outcome.message
          : getErrorMessage(
              err,
              t('findings.approvals.toast.approveFailed', 'Failed to approve request')
            )
      )
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
                'Your approval is recorded. The finding moves to the requested status once {count} more approval(s) are in.',
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
            <AIProposalBadge approval={target} withHint />
          </div>
        )}
      </ConfirmDialog>

      <Dialog open={mode === 'reject'} onOpenChange={(open) => !open && close()}>
        <DialogContent size="sm">
          <DialogHeader>
            <DialogTitle>{t('findings.approvals.rejectTitle', 'Reject request')}</DialogTitle>
            <DialogDescription>
              {t('findings.approvals.rejectDesc', 'Give a reason for rejecting this request.')}
            </DialogDescription>
          </DialogHeader>
          <DialogBody className="grid gap-4">
            {target && (
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
              </div>
            )}
            <div className="grid gap-2">
              <Textarea
                placeholder={t('findings.approvals.rejectPlaceholder', 'Reason for rejection…')}
                value={reason}
                onChange={(e) => setReason(e.target.value)}
                rows={3}
                maxLength={REASON_MAX}
                aria-label={t('findings.approvals.rejectPlaceholder', 'Reason for rejection…')}
                aria-invalid={rejectError ? true : undefined}
                aria-describedby={rejectError ? 'approval-reject-error' : undefined}
              />
              {rejectError && (
                <p id="approval-reject-error" role="alert" className="text-sm text-destructive">
                  {rejectError}
                </p>
              )}
              <p className="text-end text-xs text-muted-foreground">
                {reason.length}/{REASON_MAX}
              </p>
            </div>
          </DialogBody>
          <DialogFooter>
            <Button variant="outline" onClick={close} disabled={isRejecting}>
              {t('findings.approvals.cancel', 'Cancel')}
            </Button>
            <Button
              variant="destructive"
              onClick={confirmReject}
              disabled={isRejecting || !reason.trim()}
            >
              {isRejecting ? (
                <>
                  <Loader2 className="me-2 h-4 w-4 animate-spin" />
                  {t('findings.approvals.rejecting', 'Rejecting…')}
                </>
              ) : (
                t('findings.approvals.action.reject', 'Reject')
              )}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </>
  )

  return { busyId, openApprove, openReject, dialogs }
}

/**
 * Approve (with the lock that says a sign-in confirmation follows) and
 * Reject for one request: the one pair of decision buttons, in My Work and
 * on the finding page. The buttons open the dialogs of useApprovalDecision.
 */
export function ApprovalDecisionButtons({
  approval,
  busy,
  onApprove,
  onReject,
}: {
  approval: ApiApproval
  busy?: boolean
  onApprove: (a: ApiApproval) => void
  onReject: (a: ApiApproval) => void
}) {
  const { t } = useTranslation()
  const hint = t(
    'myWork.review.stepUpHint',
    'You confirm your sign-in before the approval is saved.'
  )
  const hintId = `stepup-${approval.id}`
  return (
    <>
      <Tooltip>
        <TooltipTrigger asChild>
          <Button
            size="sm"
            disabled={busy}
            onClick={() => onApprove(approval)}
            aria-describedby={hintId}
            data-slot="approval-approve"
          >
            {t('myWork.review.approve', 'Approve')}
            <Lock className="ms-1.5 size-3.5" aria-hidden="true" />
          </Button>
        </TooltipTrigger>
        <TooltipContent className="max-w-xs text-xs">{hint}</TooltipContent>
      </Tooltip>
      <span id={hintId} className="sr-only">
        {hint}
      </span>
      <Button
        size="sm"
        variant="outline"
        disabled={busy}
        onClick={() => onReject(approval)}
        data-slot="approval-reject"
      >
        {t('myWork.review.reject', 'Reject')}
      </Button>
    </>
  )
}

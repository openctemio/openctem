'use client'

/**
 * Under the severity control: whose severity it is ("Analyst · source:
 * Medium", the reason in a tooltip) with "Restore source severity", and a
 * severity downgrade that waits for approval, which an approver approves or
 * rejects and the requester withdraws. The API decides every action (data
 * scope, approval policy, who may approve); the buttons only follow it.
 */

import { useState } from 'react'
import { toast } from 'sonner'
import { Button } from '@/components/ui/button'
import { Textarea } from '@/components/ui/textarea'
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip'
import { useTranslation } from '@/context/i18n-provider'
import { useDisplayUser } from '@/hooks/use-display-user'
import { getErrorMessage } from '@/lib/api/error-handler'
import { Can, Permission } from '@/lib/permissions'
import type { FindingDetail } from '../../types'
import {
  decideSeverityRequest,
  invalidateFindingsCache,
  type SeverityRequestDecision,
} from '../../api/use-findings-api'
import { SEVERITY_REASON_MAX } from '../severity-change-dialog'

interface SeverityProvenanceProps {
  finding: Pick<
    FindingDetail,
    'id' | 'severityOverride' | 'sourceSeverity' | 'pendingSeverityRequest'
  >
  canRescore: boolean
  onRestore: () => void
}

export function SeverityProvenance({ finding, canRescore, onRestore }: SeverityProvenanceProps) {
  const { t } = useTranslation()
  const currentUserId = useDisplayUser()?.id
  const [busy, setBusy] = useState(false)
  const [rejecting, setRejecting] = useState(false)
  const [rejectReason, setRejectReason] = useState('')
  const override = finding.severityOverride
  const pending = finding.pendingSeverityRequest
  if (!override && !pending) return null

  const sevLabel = (s?: string) => (s ? t(`severity.${s}`, s) : '')
  const own = !!pending?.requested_by && pending.requested_by === currentUserId

  const decide = async (decision: SeverityRequestDecision, reason?: string) => {
    if (!pending) return
    setBusy(true)
    try {
      await decideSeverityRequest(finding.id, pending.id, decision, reason)
      await invalidateFindingsCache()
      toast.success(
        decision === 'approve'
          ? t('findings.severityRequest.approved', 'Approval recorded')
          : decision === 'reject'
            ? t('findings.severityRequest.rejected', 'Severity request rejected')
            : t('findings.severityRequest.canceled', 'Severity request withdrawn')
      )
      setRejecting(false)
      setRejectReason('')
    } catch (error) {
      toast.error(
        getErrorMessage(error, t('findings.severityRequest.failed', 'Could not decide the request'))
      )
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="mt-1 space-y-1.5 text-xs">
      {override && (
        <div className="flex flex-wrap items-center gap-x-2 gap-y-1 text-muted-foreground">
          <Tooltip>
            <TooltipTrigger asChild>
              <span className="cursor-help underline decoration-dotted underline-offset-2">
                {t('findings.severityProvenance.analyst', 'Analyst · source: {source}', {
                  source: sevLabel(finding.sourceSeverity),
                })}
              </span>
            </TooltipTrigger>
            <TooltipContent className="max-w-xs whitespace-pre-wrap">
              {t('findings.severityProvenance.reason', 'Reason: {reason}', {
                reason: override.reason,
              })}
            </TooltipContent>
          </Tooltip>
          {canRescore && !pending && (
            <Button variant="link" size="sm" className="h-auto p-0 text-xs" onClick={onRestore}>
              {t('findings.severityProvenance.restore', 'Restore source severity')}
            </Button>
          )}
        </div>
      )}
      {pending && (
        <div
          role="status"
          className="rounded-md border border-amber-300/60 bg-amber-50 p-2 text-amber-900 dark:border-amber-500/40 dark:bg-amber-950/40 dark:text-amber-100"
        >
          <p className="font-medium">
            {pending.restore
              ? t('findings.severityRequest.pendingRestore', 'Restore to {to} waits for approval', {
                  to: sevLabel(pending.requested_severity),
                })
              : t('findings.severityRequest.pending', 'Change to {to} waits for approval', {
                  to: sevLabel(pending.requested_severity),
                })}
          </p>
          <p className="mt-0.5 break-words opacity-90">{pending.reason}</p>
          <p className="mt-0.5 opacity-75">
            {t('findings.severityRequest.approvals', '{done} of {required} approvals', {
              done: pending.approvals_collected,
              required: pending.required_approvals,
            })}
          </p>
          {rejecting ? (
            <div className="mt-2 space-y-1.5">
              <Textarea
                aria-label={t('findings.severityRequest.rejectReason', 'Reason for rejecting')}
                value={rejectReason}
                maxLength={SEVERITY_REASON_MAX}
                rows={2}
                onChange={(e) => setRejectReason(e.target.value)}
              />
              <div className="flex gap-2">
                <Button
                  size="sm"
                  variant="destructive"
                  disabled={busy || !rejectReason.trim()}
                  onClick={() => void decide('reject', rejectReason.trim())}
                >
                  {t('findings.severityRequest.reject', 'Reject')}
                </Button>
                <Button size="sm" variant="outline" onClick={() => setRejecting(false)}>
                  {t('common.cancel', 'Cancel')}
                </Button>
              </div>
            </div>
          ) : (
            <div className="mt-2 flex flex-wrap gap-2">
              {own ? (
                <Button
                  size="sm"
                  variant="outline"
                  disabled={busy}
                  onClick={() => void decide('cancel')}
                >
                  {t('findings.severityRequest.withdraw', 'Withdraw')}
                </Button>
              ) : (
                <Can permission={Permission.FindingsApprove}>
                  <Button size="sm" disabled={busy} onClick={() => void decide('approve')}>
                    {t('findings.severityRequest.approve', 'Approve')}
                  </Button>
                  <Button
                    size="sm"
                    variant="outline"
                    disabled={busy}
                    onClick={() => setRejecting(true)}
                  >
                    {t('findings.severityRequest.reject', 'Reject')}
                  </Button>
                </Can>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  )
}

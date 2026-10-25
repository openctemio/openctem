'use client'

import { useState } from 'react'
import { toast } from 'sonner'
import { Button } from '@/components/ui/button'
import { ConfirmDialog } from '@/components/confirm-dialog'
import { useTranslation } from '@/context/i18n-provider'
import { useDisplayUser } from '@/hooks/use-display-user'
import { refreshPendingApprovalCount } from '@/hooks/use-dynamic-badges'
import { ApiClientError, getErrorMessage } from '@/lib/api/error-handler'
import { remindApprovers } from '@/features/findings/api/use-findings-api'
import { cancelApproval } from '@/features/findings/api/triage-api'
import { canCancelApproval } from '@/features/findings/lib/approvals'
import type { ApiApproval } from '@/features/findings/types'
import { ApprovalRow } from './approval-row'
import { QueueFrame } from './queue-frame'

/**
 * Requested by me: the caller's own pending requests, waiting for someone
 * else. The requester can remind the approvers (at most once an hour, the
 * API's rule) or withdraw the request; they never decide it.
 */
export function RequestedQueue({
  rows,
  total,
  onChanged,
  toolbar,
  empty,
}: {
  rows: ApiApproval[]
  total: number
  onChanged: () => unknown
  toolbar?: React.ReactNode
  empty: React.ReactNode
}) {
  const { t } = useTranslation()
  const currentUserId = useDisplayUser()?.id
  const [busy, setBusy] = useState<string | null>(null)
  const [cancelTarget, setCancelTarget] = useState<ApiApproval | null>(null)

  const remind = async (a: ApiApproval) => {
    if (busy) return
    setBusy(a.id)
    try {
      const res = await remindApprovers(a.id)
      toast.success(
        t('findings.approvals.toast.reminded', 'Reminded {count} approver(s)', {
          count: res?.reminded ?? 0,
        })
      )
    } catch (err) {
      toast.error(
        err instanceof ApiClientError && err.statusCode === 409
          ? t(
              'findings.approvals.toast.remindTooSoon',
              'The approvers were already reminded in the last hour.'
            )
          : getErrorMessage(
              err,
              t('findings.approvals.toast.remindFailed', 'Failed to send the reminder')
            )
      )
    } finally {
      setBusy(null)
    }
  }

  const confirmCancel = async () => {
    const a = cancelTarget
    if (!a || busy) return
    setBusy(a.id)
    try {
      await cancelApproval(a.id)
      toast.success(t('findings.approvals.toast.canceled', 'Approval request canceled'))
      await Promise.all([onChanged(), refreshPendingApprovalCount()])
    } catch (err) {
      toast.error(
        getErrorMessage(err, t('findings.approvals.toast.cancelFailed', 'Failed to cancel request'))
      )
    } finally {
      setBusy(null)
      setCancelTarget(null)
    }
  }

  return (
    <>
      <QueueFrame
        label={t('myWork.tabs.requested', 'Requested by me')}
        toolbar={toolbar}
        footer={
          <span>
            {t(
              'myWork.requested.rule',
              'Another person decides each request. You can remind the approvers once an hour or withdraw a request.'
            )}
          </span>
        }
        shown={rows.length}
        total={total}
      >
        {rows.length === 0 ? (
          empty
        ) : (
          <ul className="divide-y" aria-label={t('myWork.tabs.requested', 'Requested by me')}>
            {rows.map((a) => (
              <ApprovalRow
                key={a.id}
                approval={a}
                currentUserId={currentUserId}
                actions={
                  canCancelApproval(a, currentUserId) ? (
                    <>
                      <Button
                        size="sm"
                        variant="outline"
                        disabled={busy === a.id}
                        onClick={() => void remind(a)}
                      >
                        {t('myWork.requested.remind', 'Remind approvers')}
                      </Button>
                      <Button
                        size="sm"
                        variant="ghost"
                        disabled={busy === a.id}
                        onClick={() => setCancelTarget(a)}
                      >
                        {t('myWork.requested.withdraw', 'Withdraw')}
                      </Button>
                    </>
                  ) : null
                }
              />
            ))}
          </ul>
        )}
      </QueueFrame>
      <ConfirmDialog
        open={cancelTarget !== null}
        onOpenChange={(open) => !open && setCancelTarget(null)}
        title={t('myWork.requested.withdrawTitle', 'Withdraw this request?')}
        desc={t(
          'myWork.requested.withdrawDesc',
          'The finding keeps its status. You can make a new request later.'
        )}
        confirmText={t('myWork.requested.withdraw', 'Withdraw')}
        isLoading={busy !== null}
        handleConfirm={confirmCancel}
      />
    </>
  )
}

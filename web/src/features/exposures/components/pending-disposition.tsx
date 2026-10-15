'use client'

import { useState } from 'react'
import { Clock, Check, X, Loader2, ShieldCheck } from 'lucide-react'
import { toast } from 'sonner'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { useTranslation } from '@/context/i18n-provider'
import { getErrorMessage } from '@/lib/api/error-handler'
import type { ExposureEvent } from '@/lib/api/exposure-types'
import { useAuthStore } from '@/stores/auth-store'
import { SelfApproveDialog } from '@/features/shared/components/self-approve-dialog'
import {
  acceptExposure,
  markExposureFalsePositive,
  rejectExposureDisposition,
} from '../hooks/use-exposures'
import { useCanApproveExposures } from './exposure-state-actions'

type Translate = ReturnType<typeof useTranslation>['t']

/**
 * After a bulk accept or false positive, tell the user how many high or
 * critical exposures now wait for a second approver.
 */
export function notifyPendingDispositions(results: ExposureEvent[], t: Translate) {
  const count = results.filter((r) => r?.pending_disposition).length
  if (count > 0) {
    toast.info(
      t(
        'exposures.disposition.bulkPending',
        '{count} high or critical exposures wait for a second approver.',
        { count }
      )
    )
  }
}

/** Small badge shown next to the state while a disposition is pending. */
export function PendingDispositionBadge({ exposure }: { exposure: ExposureEvent }) {
  const { t } = useTranslation()
  if (!exposure.pending_disposition) return null
  return (
    <Badge variant="outline" className="gap-1">
      <Clock className="h-3 w-3" />
      {t('exposures.disposition.badge', 'Awaiting approval')}
    </Badge>
  )
}

interface PendingDispositionPanelProps {
  exposure: ExposureEvent
  onChanged?: () => void
}

/**
 * Four-eyes panel: who asked for which disposition and why, with Approve for
 * a different approver and Reject (Cancel for the requester). The reason is
 * user text and is rendered as text only.
 */
export function PendingDispositionPanel({ exposure, onChanged }: PendingDispositionPanelProps) {
  const { t } = useTranslation()
  const canApprove = useCanApproveExposures()
  const userId = useAuthStore((s) => s.user?.id)
  const [busy, setBusy] = useState<'approve' | 'reject' | null>(null)
  const [selfOpen, setSelfOpen] = useState(false)
  const pending = exposure.pending_disposition
  if (!pending) return null

  const mine = !!userId && pending.requested_by === userId
  const canSelfApprove = mine && canApprove && !!pending.self_approval_available

  const selfApprove = async (reason: string, code: string) => {
    const input = { reason, self_approve: true, totp_code: code }
    if (pending.requested_state === 'accepted') {
      await acceptExposure(exposure.id, input)
    } else {
      await markExposureFalsePositive(exposure.id, input)
    }
    toast.success(t('exposures.disposition.approved', 'Approved'))
    onChanged?.()
  }
  const what =
    pending.requested_state === 'accepted'
      ? t('exposures.disposition.requestedAccept', 'Accept risk was requested')
      : t('exposures.disposition.requestedFalsePositive', 'False positive was requested')
  const who = mine
    ? t('exposures.disposition.byYou', 'by you')
    : t('exposures.disposition.byOther', 'by another approver')

  const approve = async () => {
    setBusy('approve')
    try {
      if (pending.requested_state === 'accepted') {
        await acceptExposure(exposure.id)
      } else {
        await markExposureFalsePositive(exposure.id)
      }
      toast.success(t('exposures.disposition.approved', 'Approved'))
      onChanged?.()
    } catch (error) {
      toast.error(
        getErrorMessage(error, t('exposures.disposition.failed', 'Could not update the request'))
      )
    } finally {
      setBusy(null)
    }
  }

  const reject = async () => {
    setBusy('reject')
    try {
      await rejectExposureDisposition(exposure.id)
      toast.success(
        mine
          ? t('exposures.disposition.canceled', 'Request canceled')
          : t('exposures.disposition.rejected', 'Request rejected')
      )
      onChanged?.()
    } catch (error) {
      toast.error(
        getErrorMessage(error, t('exposures.disposition.failed', 'Could not update the request'))
      )
    } finally {
      setBusy(null)
    }
  }

  return (
    <div className="rounded-lg border border-dashed p-3 text-sm" role="status">
      <div className="flex items-center gap-2 font-medium">
        <Clock className="h-4 w-4 text-muted-foreground" />
        {t('exposures.disposition.title', 'Waiting for a second approver')}
      </div>
      <p className="mt-1 text-muted-foreground">
        {what} {who}
      </p>
      {pending.reason && (
        <p className="mt-1 break-words">
          <span className="text-muted-foreground">
            {t('exposures.disposition.reason', 'Reason:')}
          </span>{' '}
          {pending.reason}
        </p>
      )}
      {mine && !canSelfApprove && (
        <p className="mt-1 text-xs text-muted-foreground">
          {t('exposures.disposition.ownHint', 'A different approver must confirm your request.')}
        </p>
      )}
      {canSelfApprove && (
        <p className="mt-1 text-xs text-muted-foreground">
          {t(
            'exposures.disposition.selfHint',
            'Nobody else can approve it. As the owner you may approve it yourself with a reason and a code from your authenticator app.'
          )}
        </p>
      )}
      {canApprove && (
        <div className="mt-3 flex flex-wrap gap-2">
          {!mine && (
            <Button size="sm" onClick={approve} disabled={busy !== null}>
              {busy === 'approve' ? (
                <Loader2 className="h-4 w-4 animate-spin" />
              ) : (
                <Check className="h-4 w-4" />
              )}
              {t('exposures.disposition.approve', 'Approve')}
            </Button>
          )}
          {canSelfApprove && (
            <Button size="sm" onClick={() => setSelfOpen(true)} disabled={busy !== null}>
              <ShieldCheck className="h-4 w-4" />
              {t('exposures.disposition.selfApprove', 'Approve my own request')}
            </Button>
          )}
          <Button size="sm" variant="outline" onClick={reject} disabled={busy !== null}>
            {busy === 'reject' ? (
              <Loader2 className="h-4 w-4 animate-spin" />
            ) : (
              <X className="h-4 w-4" />
            )}
            {mine
              ? t('exposures.disposition.cancel', 'Cancel request')
              : t('exposures.disposition.reject', 'Reject')}
          </Button>
        </div>
      )}
      {canSelfApprove && (
        <SelfApproveDialog
          open={selfOpen}
          onOpenChange={setSelfOpen}
          subject={exposure.title}
          onSubmit={selfApprove}
        />
      )}
    </div>
  )
}

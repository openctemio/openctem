'use client'

/**
 * "Waiting on someone": the false-positive / accepted-risk requests that are
 * pending on this finding, on the page and in the drawer. Everyone who may read
 * the finding sees who asked, when, why and for which status; only the
 * requester gets a Cancel button, and approvers get a link to the approvals
 * inbox where the decision is made. This is display only: the API decides who
 * may cancel or approve.
 */

import { useState } from 'react'
import { Hourglass, Loader2 } from 'lucide-react'
import { toast } from 'sonner'
import Link from '@/components/link'
import { Button } from '@/components/ui/button'
import { useTranslation } from '@/context/i18n-provider'
import { usePermissions } from '@/context/permission-provider'
import { useDisplayUser } from '@/hooks/use-display-user'
import { getErrorMessage } from '@/lib/api/error-handler'
import { formatRelative } from '@/lib/format-date'
import { Permission } from '@/lib/permissions'
import { cn } from '@/lib/utils'
import { useCancelApproval, useFindingApprovals } from '../../api/use-findings-api'
import { AIProposalBadge } from '../ai-proposal-badge'
import { approvalRequester, canCancelApproval, isOwnApproval } from '../../lib/approvals'
import { FINDING_STATUS_CONFIG, type ApiApproval, type FindingStatus } from '../../types'

const ACTOR_LABELS: Record<string, string> = {
  ai_triage: 'AI triage',
  vex: 'VEX statement',
  ticket: 'Linked ticket',
}

function requesterLabel(
  t: (key: string, fallback: string) => string,
  approval: ApiApproval,
  currentUserId?: string
): string {
  const who = approvalRequester(approval, currentUserId)
  switch (who.kind) {
    case 'actor':
      return t(`findings.approvals.actor.${who.actor}`, ACTOR_LABELS[who.actor] ?? who.actor)
    case 'you':
      return t('findings.approvals.requesterYou', 'You')
    case 'member':
      return who.name
    default:
      return t('findings.approvals.requesterFormer', 'Former member')
  }
}

function PendingRequest({
  approval,
  currentUserId,
  canApprove,
  canWrite,
  onChanged,
}: {
  approval: ApiApproval
  currentUserId?: string
  canApprove: boolean
  canWrite: boolean
  onChanged: () => void
}) {
  const { t } = useTranslation()
  const { trigger: cancel, isMutating } = useCancelApproval(approval.id)
  const [error, setError] = useState(false)
  const mayCancel = canWrite && canCancelApproval(approval, currentUserId)
  const mayDecide = canApprove && !isOwnApproval(approval, currentUserId) && !approval.batch_id
  const cfg = FINDING_STATUS_CONFIG[approval.requested_status as FindingStatus]
  const target = cfg ? t(cfg.labelKey, cfg.label) : approval.requested_status

  const onCancel = async () => {
    setError(false)
    try {
      await cancel()
      toast.success(t('findings.approvals.toast.canceled', 'Approval request canceled'))
      onChanged()
    } catch (err) {
      setError(true)
      toast.error(
        getErrorMessage(err, t('findings.approvals.toast.cancelFailed', 'Failed to cancel request'))
      )
    }
  }

  return (
    <li className="space-y-1" data-testid="finding-approval-request">
      <p className="font-medium">
        {t('findings.approvalBand.title', 'Awaiting approval: {status}', { status: target })}
      </p>
      <p className="text-xs text-muted-foreground">
        {t('findings.approvalBand.requestedBy', 'Requested by {who} {when}', {
          who: requesterLabel(t, approval, currentUserId),
          when: formatRelative(approval.created_at),
        })}
      </p>
      <AIProposalBadge approval={approval} />
      {approval.justification && (
        <p className="text-xs break-words whitespace-pre-wrap text-muted-foreground">
          {t('findings.approvalBand.reason', 'Reason:')} {approval.justification}
        </p>
      )}
      <div className="flex flex-wrap items-center gap-2 pt-1">
        {mayCancel && (
          <Button
            type="button"
            size="sm"
            variant="outline"
            onClick={onCancel}
            disabled={isMutating}
            data-testid="finding-approval-cancel"
          >
            {isMutating && <Loader2 className="me-1 h-3.5 w-3.5 animate-spin" aria-hidden />}
            {t('findings.approvals.action.cancel', 'Cancel request')}
          </Button>
        )}
        {mayDecide && (
          <Link
            href="/findings/approvals"
            className="text-xs underline-offset-2 hover:underline"
            data-testid="finding-approval-decide-link"
          >
            {t('findings.approvalBand.decide', 'Decide in the approvals inbox')}
          </Link>
        )}
        {error && (
          <span role="alert" className="text-xs text-destructive">
            {t('findings.approvals.toast.cancelFailed', 'Failed to cancel request')}
          </span>
        )}
      </div>
    </li>
  )
}

export function FindingApprovalBand({
  findingId,
  className,
}: {
  findingId: string
  className?: string
}) {
  const { t } = useTranslation()
  const { hasPermission } = usePermissions()
  const currentUserId = useDisplayUser()?.id
  // Regardless of the finding's status: a pending request exists before it.
  const { data, mutate } = useFindingApprovals(findingId || undefined)
  const pending = (data ?? []).filter((a) => a.status === 'pending')
  if (pending.length === 0) return null
  return (
    <section
      aria-label={t('findings.approvalBand.aria', 'Waiting on an approval')}
      className={cn(
        'flex gap-3 rounded-lg border border-warning/40 bg-warning/5 p-3 text-sm',
        className
      )}
      data-testid="finding-approval-band"
    >
      <Hourglass className="mt-0.5 h-4 w-4 shrink-0 text-warning" aria-hidden />
      <ul className="min-w-0 flex-1 space-y-3">
        {pending.map((a) => (
          <PendingRequest
            key={a.id}
            approval={a}
            currentUserId={currentUserId}
            canApprove={hasPermission(Permission.FindingsApprove)}
            canWrite={hasPermission(Permission.FindingsWrite)}
            onChanged={() => void mutate()}
          />
        ))}
      </ul>
    </section>
  )
}

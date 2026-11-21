'use client'

/**
 * "Waiting on someone": the false-positive / accepted-risk requests that are
 * pending on this finding, on the page and in the drawer. The band and its
 * request rows are the shared AwaitingApprovalBand; this file supplies what is
 * finding-specific (the requester, the status asked for, what changed since,
 * the approver's decision dialogs, why the request waits). Everyone who may read
 * the finding sees who asked, when, why and for which status, and what
 * changed on the finding since the request. The requester gets a Cancel
 * button; an approver decides here (Approve with a sign-in confirmation, or
 * Reject with a reason), with the same dialogs as My Work. The card says
 * why the request waits (from the reasons stored with it), links owners and
 * administrators to the setting, and offers the organization's sole member
 * "Approve myself" (authenticator code and a reason). The API decides who
 * may cancel or approve.
 */

import { useSettleSignal } from '@/features/shared/components/settle-group'
import { QueueDecisionActions } from '@/features/shared/components/queue'
import {
  AwaitingApprovalBand,
  AwaitingApprovalRequest,
} from '@/features/shared/components/awaiting-approval-band'
import { useState } from 'react'
import { ShieldCheck } from 'lucide-react'
import { toast } from 'sonner'
import Link from '@/components/link'
import { Button } from '@/components/ui/button'
import { useTranslation } from '@/context/i18n-provider'
import { usePermissions } from '@/context/permission-provider'
import { useDisplayUser } from '@/hooks/use-display-user'
import { getErrorMessage } from '@/lib/api/error-handler'
import { formatRelative } from '@/lib/format-date'
import { Permission, usePermissions as useRoles } from '@/lib/permissions'
import {
  useCancelApproval,
  useFindingApprovalPolicy,
  useFindingApprovals,
} from '../../api/use-findings-api'
import { AIProposalBadge } from '../ai-proposal-badge'
import { closureReasonLabel } from '../../lib/closure'
import { useApprovalDecision } from '../approval-decision'
import { ChangedSinceRequest } from '../changed-since-request'
import { FindingSelfApproveDialog } from '../finding-self-approve-dialog'
import { approvalWaitReasons, needsApprovalLevel } from '../../lib/approval-why'
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

/** Where the false-positive and risk acceptance levels are set. */
const APPROVAL_LEVELS_HREF = '/settings/approvals#approval-levels'

/** Why the request waits, and the way to the setting for those who manage it. */
function WaitReason({
  approval,
  currentUserId,
}: {
  approval: ApiApproval
  currentUserId?: string
}) {
  const { t } = useTranslation()
  const { isAdmin } = useRoles()
  const status = approval.requested_status === 'accepted' ? 'accepted' : 'false_positive'
  // The level in force words the line ("every" or "every serious"); read it
  // only when the level is why the request waits.
  const { data: policy } = useFindingApprovalPolicy(
    approval.finding_id,
    status,
    needsApprovalLevel(approval)
  )
  const level = status === 'accepted' ? policy?.accept_approval : policy?.fp_approval
  const lines = approvalWaitReasons(t, approval, {
    isRequester: isOwnApproval(approval, currentUserId),
    level,
  })
  if (lines.length === 0) return null
  return (
    <p className="break-words">
      {lines.join(' ')}
      {isAdmin() && (
        <>
          {' '}
          <Link
            href={APPROVAL_LEVELS_HREF}
            className="font-medium text-primary underline-offset-2 hover:underline"
            data-testid="finding-approval-settings-link"
          >
            {t('findings.approvalWhy.changeLink', 'Change who approves')}
          </Link>
        </>
      )}
    </p>
  )
}

function PendingRequest({
  approval,
  currentUserId,
  canApprove,
  canWrite,
  onChanged,
  decision,
}: {
  approval: ApiApproval
  currentUserId?: string
  canApprove: boolean
  canWrite: boolean
  onChanged: () => void
  decision: ReturnType<typeof useApprovalDecision>
}) {
  const { t, locale } = useTranslation()
  const { trigger: cancel, isMutating } = useCancelApproval(approval.id)
  const [error, setError] = useState(false)
  const [selfApproveOpen, setSelfApproveOpen] = useState(false)
  // The sole member's own request: the API says when it may be approved
  // this way and checks it again.
  const maySelfApprove = canApprove && approval.self_approval_available === true
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
    <AwaitingApprovalRequest
      testId="finding-approval-request"
      cancelTestId="finding-approval-cancel"
      title={t('findings.approvalBand.title', 'Awaiting approval: {status}', { status: target })}
      requestedBy={t('findings.approvalBand.requestedBy', 'Requested by {who} {when}', {
        who: requesterLabel(t, approval, currentUserId),
        // In the console language ("3 giờ trước"), not the browser's.
        when: formatRelative(approval.created_at, '—', locale),
      })}
      reason={approval.closure_reason ? closureReasonLabel(t, approval.closure_reason) : undefined}
      note={approval.justification || undefined}
      why={<WaitReason approval={approval} currentUserId={currentUserId} />}
      details={
        <>
          <AIProposalBadge approval={approval} />
          <ChangedSinceRequest changes={approval.changed_since_request} className="block" />
        </>
      }
      onCancel={mayCancel ? onCancel : undefined}
      cancelBusy={isMutating}
      cancelDialog={{
        title: t('confirm.findingApproval.cancelTitle', 'Cancel this approval request?'),
        description: t(
          'confirm.findingApproval.cancelDesc',
          'The request is withdrawn and the finding keeps its current status. You can send a new request afterwards.'
        ),
      }}
      error={
        error ? t('findings.approvals.toast.cancelFailed', 'Failed to cancel request') : undefined
      }
      actions={
        maySelfApprove ? (
          <>
            <Button
              type="button"
              size="sm"
              variant="outline"
              onClick={() => setSelfApproveOpen(true)}
              data-testid="finding-approval-self-approve"
            >
              <ShieldCheck className="me-1 h-3.5 w-3.5" aria-hidden />
              {t('findingApprovals.selfApprove.cardAction', 'Approve myself')}
            </Button>
            {selfApproveOpen && (
              <FindingSelfApproveDialog
                approval={approval}
                onOpenChange={setSelfApproveOpen}
                onApproved={onChanged}
              />
            )}
          </>
        ) : mayDecide ? (
          // The queue's decision controls (outline, named "Approve {request}"):
          // the page header keeps the one filled main action.
          <QueueDecisionActions
            name={t('findings.approvalBand.requestName', '{status} request', { status: target })}
            itemId={approval.id}
            layout="card"
            canDecide
            busy={decision.busyId === approval.id}
            onApprove={() => decision.openApprove(approval)}
            onReject={() => decision.openReject(approval)}
            approveLabel={t('findings.approvals.action.approve', 'Approve')}
            rejectLabel={t('findings.approvals.action.reject', 'Reject')}
            stepUpHint={t(
              'myWork.review.stepUpHint',
              'You confirm your sign-in before the approval is saved.'
            )}
          />
        ) : undefined
      }
    />
  )
}

export function FindingApprovalBand({
  findingId,
  className,
  onDecided,
}: {
  findingId: string
  className?: string
  /** After a decision: refresh what else shows the finding's status. */
  onDecided?: () => unknown
}) {
  const { t } = useTranslation()
  const { hasPermission } = usePermissions()
  const currentUserId = useDisplayUser()?.id
  // Regardless of the finding's status: a pending request exists before it.
  const { data, mutate, isLoading } = useFindingApprovals(findingId || undefined)
  useSettleSignal(isLoading)
  // A decision changes the finding (status, activity) as well as the band.
  const decision = useApprovalDecision({ onDecided: () => Promise.all([mutate(), onDecided?.()]) })
  const pending = (data ?? []).filter((a) => a.status === 'pending')
  if (pending.length === 0) return decision.dialogs
  return (
    <AwaitingApprovalBand
      ariaLabel={t('findings.approvalBand.aria', 'Waiting on an approval')}
      className={className}
      testId="finding-approval-band"
      after={decision.dialogs}
    >
      {pending.map((a) => (
        <PendingRequest
          key={a.id}
          approval={a}
          currentUserId={currentUserId}
          canApprove={hasPermission(Permission.FindingsApprove)}
          canWrite={hasPermission(Permission.FindingsWrite)}
          onChanged={() => void mutate()}
          decision={decision}
        />
      ))}
    </AwaitingApprovalBand>
  )
}

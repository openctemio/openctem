'use client'

/**
 * The sole member of an organization approves their own finding request
 * (server/docs/architecture/finding-status-lifecycle.md, "Sole member"). The
 * API decides whether it is allowed (`self_approval_available` on the list);
 * the dialog asks for a reason and a fresh code from the authenticator app.
 * It is audited, announced on the organization's channels and emailed to the
 * backup contact. The same dialog approves the sole member's own group
 * exception (`batch`): one code and one reason apply every pending member.
 */

import { useId, useState } from 'react'
import { toast } from 'sonner'
import { StepUpDialog } from '@/components/security'
import { Label } from '@/components/ui/label'
import { Textarea } from '@/components/ui/textarea'
import { useTranslation } from '@/context/i18n-provider'
import { selfApproveFindingApproval } from '../api/use-findings-api'
import { approvalBatchApi, type ApprovalBatch } from '../api/use-approval-batches'
import type { ApiApproval } from '../types/finding.types'

const MAX_REASON = 2000

type Translate = ReturnType<typeof useTranslation>['t']

/** The message for a refusal code of POST /approvals/{id}/self-approve. */
export function selfApproveErrorMessage(t: Translate, err: unknown): string {
  const e = err as { code?: unknown; message?: unknown } | null | undefined
  switch (typeof e?.code === 'string' ? e.code : '') {
    case 'SELF_APPROVAL_NOT_ALLOWED':
      return t(
        'findingApprovals.selfApprove.error.notAllowed',
        'You can approve your own request only as the owner of an organization with no other active member.'
      )
    case 'SELF_APPROVAL_NEEDS_TOTP':
      return t(
        'findingApprovals.selfApprove.error.needsTotp',
        'Turn on two-factor authentication first: approving your own request needs a code from your authenticator app.'
      )
    case 'SELF_APPROVAL_INVALID_CODE':
      return t(
        'findingApprovals.selfApprove.error.badCode',
        'The code is wrong or was already used. Wait for a new code and try again.'
      )
    case 'SELF_APPROVAL_REASON_REQUIRED':
      return t('findingApprovals.selfApprove.error.reason', 'Give a reason.')
  }
  if (e && typeof e.message === 'string' && e.message) return e.message
  return t('findingApprovals.selfApprove.error.generic', 'Could not approve the request.')
}

interface FindingSelfApproveDialogProps {
  /** The caller's own pending request. */
  approval?: ApiApproval | null
  /** Or the caller's own pending group exception. */
  batch?: ApprovalBatch | null
  onOpenChange: (open: boolean) => void
  onApproved?: () => void
}

export function FindingSelfApproveDialog({
  approval,
  batch,
  onOpenChange,
  onApproved,
}: FindingSelfApproveDialogProps) {
  const { t } = useTranslation()
  const reasonId = useId()
  const [reason, setReason] = useState('')

  if (!approval && !batch) return null
  // The members still waiting (a member left out is not applied).
  const count = batch
    ? (batch.members?.filter((m) => m.status === 'pending').length ?? batch.member_count)
    : 0

  return (
    <StepUpDialog
      open
      onOpenChange={onOpenChange}
      title={
        batch
          ? t('findingApprovals.selfApprove.titleGroup', 'Approve your own group exception')
          : t('findingApprovals.selfApprove.title', 'Approve your own request')
      }
      description={
        batch
          ? t(
              'findingApprovals.selfApprove.descriptionGroup',
              'Nobody else in your organization can decide this group. As its only member and owner you may approve {count, plural, one {its # finding} other {its # findings}} yourself.',
              { count }
            )
          : t(
              'findingApprovals.selfApprove.description',
              'Nobody else in your organization can decide this request. As its only member and owner you may approve it yourself.'
            )
      }
      ready={!!reason.trim()}
      submitLabel={
        batch
          ? t(
              'findingApprovals.selfApprove.submitGroup',
              '{count, plural, one {Approve # finding} other {Approve # findings}}',
              { count }
            )
          : t('findingApprovals.selfApprove.submit', 'Approve')
      }
      onSubmit={async (proof) => {
        if (proof.kind !== 'totp') return
        const input = { reason: reason.trim(), code: proof.code }
        if (batch) {
          const res = await approvalBatchApi.selfApprove(batch.id, input)
          toast.success(
            (res?.shortened ?? 0) > 0
              ? t(
                  'findingApprovals.selfApprove.doneGroupShortened',
                  '{count, plural, one {Approved # finding.} other {Approved # findings.}} Some acceptances were shortened to the limit for a self-approval.',
                  { count: res?.applied ?? count }
                )
              : t(
                  'findingApprovals.selfApprove.doneGroup',
                  '{count, plural, one {Approved # finding} other {Approved # findings}}',
                  {
                    count: res?.applied ?? count,
                  }
                )
          )
        } else if (approval) {
          const res = await selfApproveFindingApproval(approval.id, input)
          toast.success(
            res?.end_shortened
              ? t(
                  'findingApprovals.selfApprove.doneShortened',
                  'Approved. The acceptance was shortened to the limit for a self-approval.'
                )
              : t('findingApprovals.selfApprove.done', 'Approved')
          )
        }
        onApproved?.()
        onOpenChange(false)
      }}
      errorMessage={(err) => selfApproveErrorMessage(t, err)}
    >
      <ul className="text-muted-foreground list-disc space-y-1 ps-5 text-sm">
        <li>
          {t(
            'findingApprovals.selfApprove.audited',
            'It is recorded in the audit log and marked self-approved everywhere.'
          )}
        </li>
        <li>
          {t(
            'findingApprovals.selfApprove.told',
            "Your organization's notification channels and its backup contact are told."
          )}
        </li>
        <li>
          {t(
            'findingApprovals.selfApprove.limit',
            'An accepted risk ends within 7 days (P0 or known exploited), 45 days (P1) or 90 days.'
          )}
        </li>
      </ul>
      <div className="space-y-2">
        <Label htmlFor={reasonId}>
          {t(
            'findingApprovals.selfApprove.reasonLabel',
            'Why may it take effect without a second person?'
          )}
        </Label>
        <Textarea
          id={reasonId}
          rows={3}
          maxLength={MAX_REASON}
          required
          autoFocus
          value={reason}
          onChange={(e) => setReason(e.target.value)}
        />
      </div>
    </StepUpDialog>
  )
}

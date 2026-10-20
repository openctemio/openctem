'use client'

/**
 * An owner approves their own pending request (an exposure disposition or a
 * suppression rule) when nobody else in the organization can approve it.
 * The API decides whether that is allowed; this dialog asks for a reason
 * and a fresh code from the owner's authenticator app. The approval is
 * audited at critical severity, and a refused attempt is audited too.
 */

import { useId, useState } from 'react'
import { StepUpDialog } from '@/components/security'
import { Label } from '@/components/ui/label'
import { Textarea } from '@/components/ui/textarea'
import { useTranslation } from '@/context/i18n-provider'
import { getErrorMessage } from '@/lib/api/error-handler'

interface SelfApproveDialogProps {
  open: boolean
  onOpenChange: (open: boolean) => void
  /** What is being approved, shown in the description (plain text). */
  subject: string
  /** Sends the approval; throws on refusal. */
  onSubmit: (reason: string, code: string) => Promise<void>
}

export function SelfApproveDialog({
  open,
  onOpenChange,
  subject,
  onSubmit,
}: SelfApproveDialogProps) {
  const { t } = useTranslation()
  const reasonId = useId()
  const [reason, setReason] = useState('')

  const close = (next: boolean) => {
    if (!next) setReason('')
    onOpenChange(next)
  }

  return (
    <StepUpDialog
      open={open}
      onOpenChange={close}
      title={t('components.selfApprove.title', 'Approve your own request')}
      description={t(
        'components.selfApprove.description',
        'Nobody else in your organization can approve "{subject}". As the owner you may approve it yourself with a reason and a code from your authenticator app. It is recorded in the audit log.',
        { subject }
      )}
      ready={!!reason.trim()}
      submitLabel={t('components.selfApprove.submit', 'Approve')}
      onSubmit={async (proof) => {
        if (proof.kind !== 'totp') return
        await onSubmit(reason.trim(), proof.code)
        close(false)
      }}
      errorMessage={(err) =>
        getErrorMessage(err, t('components.selfApprove.failed', 'Could not approve the request.'))
      }
    >
      <div className="space-y-2">
        <Label htmlFor={reasonId}>
          {t('components.selfApprove.reason', 'Why may it take effect without a second person?')}
        </Label>
        <Textarea
          id={reasonId}
          rows={3}
          maxLength={500}
          required
          autoFocus
          value={reason}
          onChange={(e) => setReason(e.target.value)}
        />
      </div>
    </StepUpDialog>
  )
}
